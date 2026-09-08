//! Pure byte constructions for the non-final EIP-0045 profile target.
//!
//! This module implements the statement and profile-ID formulas without
//! supplying a final manifest, artifact, profile ID, or activation value.
//! Its payload constructor uses the selected initial profile's 16,384-byte
//! construction target. Generic activated-package code must instead enforce
//! the limit authenticated by the decoded manifest.

use core::fmt;

use blake2::{Blake2b, Digest, digest::consts::U32};

use crate::constants::{
    DIGEST_BYTES, ERGO_STATEMENT_BOUND_DIGESTS, ERGO_STATEMENT_DOMAIN,
    ERGO_STATEMENT_VERSION_BYTES, MANIFEST_BYTES, MANIFEST_LENGTH_PREFIX_BYTES,
    MAX_APPLICATION_PAYLOAD_BYTES, MAX_STATEMENT_BYTES, PAYLOAD_LENGTH_PREFIX_BYTES,
    PROFILE_ID_DOMAIN, PROFILE_ID_DOMAIN_SEPARATOR_BYTES, PROFILE_ID_PREIMAGE_BYTES,
    STATEMENT_PREFIX_BYTES,
};

type Blake2b256 = Blake2b<U32>;

/// Failure returned by an exact profile or statement construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileConstructionError {
    /// The script-controlled payload exceeds the profile-owned maximum.
    ApplicationPayloadTooLarge {
        /// Supplied payload length in bytes.
        actual: usize,
        /// Maximum accepted payload length in bytes.
        maximum: usize,
    },
    /// The raw manifest is not exactly the frozen Manifest V1 length.
    InvalidManifestLength {
        /// Supplied manifest length in bytes.
        actual: usize,
        /// Required manifest length in bytes.
        expected: usize,
    },
    /// Checked length arithmetic overflowed.
    ArithmeticOverflow(&'static str),
    /// Independently derived and frozen lengths disagree.
    DerivedLengthMismatch {
        /// Construction whose length was inconsistent.
        construct: &'static str,
        /// Length produced or derived at runtime.
        actual: usize,
        /// Frozen length required by the profile target.
        expected: usize,
    },
}

impl fmt::Display for ProfileConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApplicationPayloadTooLarge { actual, maximum } => write!(
                formatter,
                "application payload has {actual} bytes, maximum is {maximum}"
            ),
            Self::InvalidManifestLength { actual, expected } => write!(
                formatter,
                "profile manifest has {actual} bytes, expected exactly {expected}"
            ),
            Self::ArithmeticOverflow(construct) => {
                write!(formatter, "length arithmetic overflowed for {construct}")
            }
            Self::DerivedLengthMismatch {
                construct,
                actual,
                expected,
            } => write!(
                formatter,
                "derived {construct} length is {actual}, expected {expected}"
            ),
        }
    }
}

impl std::error::Error for ProfileConstructionError {}

/// Failure returned by exact profile-ID preimage comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileIdPreimageValidationError {
    /// The manifest could not produce the exact frozen-width preimage.
    Construction(ProfileConstructionError),
    /// The supplied preimage differs from the independently reconstructed bytes.
    Mismatch,
}

impl fmt::Display for ProfileIdPreimageValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Construction(error) => write!(formatter, "{error}"),
            Self::Mismatch => formatter.write_str("profile ID preimage mismatch"),
        }
    }
}

impl std::error::Error for ProfileIdPreimageValidationError {}

/// Compute `contractId = BLAKE2b-256(SELF.propositionBytes)`.
#[must_use]
pub fn contract_id(self_proposition_bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    blake2b_256(self_proposition_bytes)
}

/// Construct the exact bytes of `ErgoStatementV1`.
///
/// # Errors
///
/// Returns [`ProfileConstructionError::ApplicationPayloadTooLarge`] when the
/// application payload exceeds 16,384 bytes. Checked-arithmetic or frozen-
/// length inconsistencies return their corresponding invariant error.
pub fn ergo_statement_v1(
    chain_domain_id: &[u8; DIGEST_BYTES],
    profile_id: &[u8; DIGEST_BYTES],
    program_id: &[u8; DIGEST_BYTES],
    self_proposition_bytes: &[u8],
    application_payload: &[u8],
) -> Result<Vec<u8>, ProfileConstructionError> {
    let contract_id = contract_id(self_proposition_bytes);
    ergo_statement_v1_from_contract_id(
        chain_domain_id,
        profile_id,
        program_id,
        &contract_id,
        application_payload,
    )
}

fn ergo_statement_v1_from_contract_id(
    chain_domain_id: &[u8; DIGEST_BYTES],
    profile_id: &[u8; DIGEST_BYTES],
    program_id: &[u8; DIGEST_BYTES],
    contract_id: &[u8; DIGEST_BYTES],
    application_payload: &[u8],
) -> Result<Vec<u8>, ProfileConstructionError> {
    if application_payload.len() > MAX_APPLICATION_PAYLOAD_BYTES {
        return Err(ProfileConstructionError::ApplicationPayloadTooLarge {
            actual: application_payload.len(),
            maximum: MAX_APPLICATION_PAYLOAD_BYTES,
        });
    }

    let payload_length = u32::try_from(application_payload.len()).map_err(|_| {
        ProfileConstructionError::ArithmeticOverflow("application payload length prefix")
    })?;
    let digest_fields_length = ERGO_STATEMENT_BOUND_DIGESTS
        .checked_mul(DIGEST_BYTES)
        .ok_or(ProfileConstructionError::ArithmeticOverflow(
            "statement digest fields",
        ))?;
    let derived_prefix_length = ERGO_STATEMENT_DOMAIN
        .len()
        .checked_add(ERGO_STATEMENT_VERSION_BYTES)
        .and_then(|length| length.checked_add(digest_fields_length))
        .and_then(|length| length.checked_add(PAYLOAD_LENGTH_PREFIX_BYTES))
        .ok_or(ProfileConstructionError::ArithmeticOverflow(
            "statement prefix",
        ))?;
    require_length(
        "statement prefix",
        derived_prefix_length,
        STATEMENT_PREFIX_BYTES,
    )?;

    let expected_length = derived_prefix_length
        .checked_add(application_payload.len())
        .ok_or(ProfileConstructionError::ArithmeticOverflow(
            "complete statement",
        ))?;
    if expected_length > MAX_STATEMENT_BYTES {
        return Err(ProfileConstructionError::DerivedLengthMismatch {
            construct: "maximum statement",
            actual: expected_length,
            expected: MAX_STATEMENT_BYTES,
        });
    }

    let mut statement = Vec::with_capacity(expected_length);
    statement.extend_from_slice(ERGO_STATEMENT_DOMAIN);
    statement.push(0x01);
    statement.extend_from_slice(chain_domain_id);
    statement.extend_from_slice(profile_id);
    statement.extend_from_slice(program_id);
    statement.extend_from_slice(contract_id);
    statement.extend_from_slice(&payload_length.to_le_bytes());
    statement.extend_from_slice(application_payload);

    require_length("complete statement", statement.len(), expected_length)?;
    Ok(statement)
}

/// Construct the exact 485-byte preimage hashed to obtain a profile ID.
///
/// # Errors
///
/// Returns [`ProfileConstructionError::InvalidManifestLength`] unless the raw
/// manifest contains exactly 458 bytes. Checked-arithmetic or frozen-length
/// inconsistencies return their corresponding invariant error.
pub fn profile_id_preimage(
    manifest_bytes: &[u8],
) -> Result<[u8; PROFILE_ID_PREIMAGE_BYTES], ProfileConstructionError> {
    if manifest_bytes.len() != MANIFEST_BYTES {
        return Err(ProfileConstructionError::InvalidManifestLength {
            actual: manifest_bytes.len(),
            expected: MANIFEST_BYTES,
        });
    }

    let manifest_length = u32::try_from(manifest_bytes.len()).map_err(|_| {
        ProfileConstructionError::ArithmeticOverflow("profile manifest length prefix")
    })?;
    let expected_length = PROFILE_ID_DOMAIN
        .len()
        .checked_add(PROFILE_ID_DOMAIN_SEPARATOR_BYTES)
        .and_then(|length| length.checked_add(MANIFEST_LENGTH_PREFIX_BYTES))
        .and_then(|length| length.checked_add(manifest_bytes.len()))
        .ok_or(ProfileConstructionError::ArithmeticOverflow(
            "profile ID preimage",
        ))?;
    require_length(
        "profile ID preimage",
        expected_length,
        PROFILE_ID_PREIMAGE_BYTES,
    )?;

    let mut preimage = Vec::with_capacity(expected_length);
    preimage.extend_from_slice(PROFILE_ID_DOMAIN);
    preimage.push(0x00);
    preimage.extend_from_slice(&manifest_length.to_le_bytes());
    preimage.extend_from_slice(manifest_bytes);
    require_length("profile ID preimage", preimage.len(), expected_length)?;

    preimage.try_into().map_err(
        |bytes: Vec<u8>| ProfileConstructionError::DerivedLengthMismatch {
            construct: "profile ID preimage",
            actual: bytes.len(),
            expected: PROFILE_ID_PREIMAGE_BYTES,
        },
    )
}

/// Compute `profileId = BLAKE2b-256(profile_id_preimage(manifestBytes))`.
///
/// This length-gated byte primitive does not validate the Manifest V1 grammar;
/// callers must decode and validate all 458 bytes before treating the result as
/// a profile identifier.
///
/// # Errors
///
/// Returns the same strict manifest-length or invariant error as
/// [`profile_id_preimage`].
pub fn profile_id(manifest_bytes: &[u8]) -> Result<[u8; DIGEST_BYTES], ProfileConstructionError> {
    let preimage = profile_id_preimage(manifest_bytes)?;
    Ok(blake2b_256(&preimage))
}

/// Compare a claimed profile-ID preimage with the exact independent construction.
///
/// Callers must validate the Manifest V1 grammar before using this byte-level
/// construction as a profile-package policy.
///
/// # Errors
///
/// Returns a typed construction failure for a wrong-width manifest or
/// [`ProfileIdPreimageValidationError::Mismatch`] for unequal preimage bytes.
pub fn validate_profile_id_preimage(
    manifest_bytes: &[u8],
    claimed_preimage: &[u8; PROFILE_ID_PREIMAGE_BYTES],
) -> Result<(), ProfileIdPreimageValidationError> {
    let expected = profile_id_preimage(manifest_bytes)
        .map_err(ProfileIdPreimageValidationError::Construction)?;
    if &expected == claimed_preimage {
        Ok(())
    } else {
        Err(ProfileIdPreimageValidationError::Mismatch)
    }
}

fn require_length(
    construct: &'static str,
    actual: usize,
    expected: usize,
) -> Result<(), ProfileConstructionError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ProfileConstructionError::DerivedLengthMismatch {
            construct,
            actual,
            expected,
        })
    }
}

fn blake2b_256(bytes: &[u8]) -> [u8; DIGEST_BYTES] {
    let digest = Blake2b256::digest(bytes);
    let mut output = [0u8; DIGEST_BYTES];
    output.copy_from_slice(&digest);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC_PROPOSITION: &[u8] = b"EIP-0045 synthetic proposition; non-final";
    const SYNTHETIC_PAYLOAD: &[u8] = b"EIP-0045 synthetic payload; non-final";

    #[test]
    fn synthetic_non_final_contract_and_statement_match_independent_kats() {
        let contract = contract_id(SYNTHETIC_PROPOSITION);
        assert_eq!(
            contract,
            decode_hex_32("96f2898a7d4a18a164943804351e489c38af0f2f6cd897b31e73437fb26f0e7d")
        );

        let statement = ergo_statement_v1(
            &ascending_32(0),
            &ascending_32(32),
            &ascending_32(64),
            SYNTHETIC_PROPOSITION,
            SYNTHETIC_PAYLOAD,
        )
        .unwrap();
        assert_eq!(statement.len(), 196);
        assert_eq!(
            statement,
            decode_hex(
                "4572676f2e566572696679537461726b2e53746174656d656e7401000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f96f2898a7d4a18a164943804351e489c38af0f2f6cd897b31e73437fb26f0e7d250000004549502d303034352073796e746865746963207061796c6f61643b206e6f6e2d66696e616c"
            )
        );
    }

    #[test]
    fn synthetic_non_final_preimage_and_profile_id_match_independent_kats() {
        let manifest = [0x5a; 458];
        let preimage = profile_id_preimage(&manifest).unwrap();
        let mut expected_preimage = [0x5a; 485];
        expected_preimage[..27].copy_from_slice(&[
            0x45, 0x72, 0x67, 0x6f, 0x2e, 0x53, 0x74, 0x61, 0x72, 0x6b, 0x50, 0x72, 0x6f, 0x66,
            0x69, 0x6c, 0x65, 0x49, 0x64, 0x2e, 0x76, 0x31, 0x00, 0xca, 0x01, 0x00, 0x00,
        ]);
        assert_eq!(preimage, expected_preimage);
        assert_eq!(
            profile_id(&manifest).unwrap(),
            decode_hex_32("7f0dda5e6b981003d05fc63b70cee77d776d2f7b27690d19a3c5e7e08fcd7a71")
        );
    }

    #[test]
    fn maximum_payload_is_accepted_with_the_exact_derived_length() {
        let payload = vec![0u8; 16_384];
        let statement =
            ergo_statement_v1(&[0u8; 32], &[0u8; 32], &[0u8; 32], b"", &payload).unwrap();

        assert_eq!(statement.len(), 16_543);
        assert_eq!(&statement[155..159], &[0x00, 0x40, 0x00, 0x00]);
    }

    #[test]
    fn payload_at_16_385_bytes_is_rejected_before_construction() {
        let payload = vec![0u8; 16_385];
        assert_eq!(
            ergo_statement_v1(&[0u8; 32], &[0u8; 32], &[0u8; 32], b"", &payload,),
            Err(ProfileConstructionError::ApplicationPayloadTooLarge {
                actual: 16_385,
                maximum: 16_384,
            })
        );
    }

    #[test]
    fn manifest_lengths_457_and_459_are_rejected() {
        for actual in [457, 459] {
            let manifest = vec![0u8; actual];
            assert_eq!(
                profile_id_preimage(&manifest),
                Err(ProfileConstructionError::InvalidManifestLength {
                    actual,
                    expected: 458,
                })
            );
            assert_eq!(
                profile_id(&manifest),
                Err(ProfileConstructionError::InvalidManifestLength {
                    actual,
                    expected: 458,
                })
            );
        }
    }

    #[test]
    fn profile_id_preimage_comparison_is_exact_and_typed() {
        let manifest = [0x5a; MANIFEST_BYTES];
        let expected = profile_id_preimage(&manifest).unwrap();
        validate_profile_id_preimage(&manifest, &expected).unwrap();

        let mut changed = expected;
        changed[PROFILE_ID_PREIMAGE_BYTES - 1] ^= 1;
        assert_eq!(
            validate_profile_id_preimage(&manifest, &changed),
            Err(ProfileIdPreimageValidationError::Mismatch)
        );
    }

    fn ascending_32(start: u8) -> [u8; 32] {
        let mut output = [0u8; 32];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = start + u8::try_from(index).unwrap();
        }
        output
    }

    fn decode_hex_32(value: &str) -> [u8; 32] {
        decode_hex(value).try_into().unwrap()
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("invalid test hex"),
        }
    }
}
