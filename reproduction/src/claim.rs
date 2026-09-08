//! Independent byte-level construction of the EIP-0045 RISC Zero claim chain.
//!
//! This module implements only the pinned SHA-256 and tagged-struct byte
//! formulas. It does not call RISC Zero, authenticate an image or journal, or
//! promote candidate inputs to final profile or activation values.

use core::{fmt, mem::size_of};

use sha2::{Digest, Sha256};

const DIGEST_BYTES: usize = 32;
const ZERO_DIGEST: [u8; DIGEST_BYTES] = [0; DIGEST_BYTES];

/// Four digests derived for an OK receipt claim with empty assumptions.
///
/// The fields correspond to the EIP names `journalDigest`, `post`, `output`,
/// and `expectedClaim`, without assigning finality to the supplied image ID or
/// journal bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptClaimDigests {
    /// `SHA-256(journal)`.
    pub journal_digest: [u8; DIGEST_BYTES],
    /// Digest of the PC-zero, zero-Merkle-root post state.
    pub post: [u8; DIGEST_BYTES],
    /// Digest of the journal and empty-assumptions output.
    pub output: [u8; DIGEST_BYTES],
    /// Digest of the complete OK receipt claim.
    pub expected_claim: [u8; DIGEST_BYTES],
}

/// Failure returned before hashing an invalid or unrepresentable construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimConstructionError {
    /// A RISC Zero image ID was not exactly one digest.
    InvalidImageIdLength {
        /// Supplied byte length.
        actual: usize,
        /// Required byte length.
        expected: usize,
    },
    /// The child count cannot be represented by the tagged-struct `u16le` suffix.
    TooManyTaggedStructChildren {
        /// Supplied child count.
        actual: usize,
        /// Largest representable child count.
        maximum: usize,
    },
    /// Checked encoded-length arithmetic overflowed.
    ArithmeticOverflow(&'static str),
    /// A SHA-256 preimage cannot be represented by its 64-bit bit-length field.
    Sha256InputTooLong {
        /// Construction whose preimage exceeded the SHA-256 bound.
        construct: &'static str,
        /// Supplied or derived byte length.
        actual: usize,
    },
}

impl fmt::Display for ClaimConstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidImageIdLength { actual, expected } => write!(
                formatter,
                "RISC Zero image ID has {actual} bytes, expected exactly {expected}"
            ),
            Self::TooManyTaggedStructChildren { actual, maximum } => write!(
                formatter,
                "tagged struct has {actual} children, maximum is {maximum}"
            ),
            Self::ArithmeticOverflow(construct) => {
                write!(formatter, "length arithmetic overflowed for {construct}")
            }
            Self::Sha256InputTooLong { construct, actual } => write!(
                formatter,
                "{construct} has {actual} bytes, which exceeds the SHA-256 input bound"
            ),
        }
    }
}

impl std::error::Error for ClaimConstructionError {}

/// Derive the exact digest chain for `ReceiptClaim::ok(imageId, journal)`.
///
/// The result fixes the receipt to `Halted(0)`, PC zero, a zero post-state
/// Merkle root, no input, and empty assumptions. `image_id` is consumed in the
/// exact byte order supplied and must contain exactly 32 bytes.
///
/// # Errors
///
/// Returns [`ClaimConstructionError::InvalidImageIdLength`] unless `image_id`
/// contains exactly 32 bytes. It also rejects any encoded length that cannot be
/// represented by the pinned tagged-struct or SHA-256 formats.
pub fn ok_receipt_claim_digests(
    image_id: &[u8],
    journal: &[u8],
) -> Result<ReceiptClaimDigests, ClaimConstructionError> {
    let image_id: [u8; DIGEST_BYTES] =
        image_id
            .try_into()
            .map_err(|_| ClaimConstructionError::InvalidImageIdLength {
                actual: image_id.len(),
                expected: DIGEST_BYTES,
            })?;
    let journal_digest = sha256_bytes("receipt journal", journal)?;
    let post = ok_post_digest()?;
    let output = ok_output_digest(&journal_digest)?;
    let expected_claim = tagged_struct_sha256(
        "risc0.ReceiptClaim",
        &[ZERO_DIGEST, image_id, post, output],
        &[0, 0],
    )?;

    Ok(ReceiptClaimDigests {
        journal_digest,
        post,
        output,
        expected_claim,
    })
}

fn ok_post_digest() -> Result<[u8; DIGEST_BYTES], ClaimConstructionError> {
    tagged_struct_sha256("risc0.SystemState", &[ZERO_DIGEST], &[0])
}

fn ok_output_digest(
    journal_digest: &[u8; DIGEST_BYTES],
) -> Result<[u8; DIGEST_BYTES], ClaimConstructionError> {
    tagged_struct_sha256("risc0.Output", &[*journal_digest, ZERO_DIGEST], &[])
}

fn tagged_struct_sha256(
    tag: &str,
    down: &[[u8; DIGEST_BYTES]],
    data: &[u32],
) -> Result<[u8; DIGEST_BYTES], ClaimConstructionError> {
    let (down_count, preimage_length) = tagged_struct_preimage_length(down.len(), data.len())?;
    checked_sha256_input_length("tagged-struct preimage", preimage_length)?;

    let tag_digest = sha256_bytes("tagged-struct tag", tag.as_bytes())?;
    let mut hasher = Sha256::new();
    hasher.update(tag_digest);
    for digest in down {
        hasher.update(digest);
    }
    for word in data {
        hasher.update(word.to_le_bytes());
    }
    hasher.update(down_count.to_le_bytes());

    let digest = hasher.finalize();
    let mut output = [0u8; DIGEST_BYTES];
    output.copy_from_slice(&digest);
    Ok(output)
}

fn tagged_struct_preimage_length(
    down_count: usize,
    data_count: usize,
) -> Result<(u16, usize), ClaimConstructionError> {
    let encoded_down_count = u16::try_from(down_count).map_err(|_| {
        ClaimConstructionError::TooManyTaggedStructChildren {
            actual: down_count,
            maximum: usize::from(u16::MAX),
        }
    })?;
    let down_bytes =
        down_count
            .checked_mul(DIGEST_BYTES)
            .ok_or(ClaimConstructionError::ArithmeticOverflow(
                "tagged-struct child digests",
            ))?;
    let data_bytes = data_count.checked_mul(size_of::<u32>()).ok_or(
        ClaimConstructionError::ArithmeticOverflow("tagged-struct data bytes"),
    )?;
    let preimage_length = DIGEST_BYTES
        .checked_add(down_bytes)
        .and_then(|length| length.checked_add(data_bytes))
        .and_then(|length| length.checked_add(size_of::<u16>()))
        .ok_or(ClaimConstructionError::ArithmeticOverflow(
            "complete tagged-struct preimage",
        ))?;

    Ok((encoded_down_count, preimage_length))
}

fn sha256_bytes(
    construct: &'static str,
    bytes: &[u8],
) -> Result<[u8; DIGEST_BYTES], ClaimConstructionError> {
    checked_sha256_input_length(construct, bytes.len())?;
    let digest = Sha256::digest(bytes);
    let mut output = [0u8; DIGEST_BYTES];
    output.copy_from_slice(&digest);
    Ok(output)
}

fn checked_sha256_input_length(
    construct: &'static str,
    byte_length: usize,
) -> Result<(), ClaimConstructionError> {
    let encoded_byte_length =
        u64::try_from(byte_length).map_err(|_| ClaimConstructionError::Sha256InputTooLong {
            construct,
            actual: byte_length,
        })?;
    if encoded_byte_length.checked_mul(8).is_none() {
        return Err(ClaimConstructionError::Sha256InputTooLong {
            construct,
            actual: byte_length,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_independent_kat_derives_the_full_ok_claim_chain() {
        let image_id =
            decode_hex_32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let journal = b"EIP-0045 independent claim oracle KAT";

        let digests = ok_receipt_claim_digests(&image_id, journal).unwrap();

        assert_eq!(
            digests.journal_digest,
            decode_hex_32("67261f6e1ed8c95ccb856bab6331a9a3ea4bb16ba53d1993a2840b0a2f5dfb25")
        );
        assert_eq!(
            digests.post,
            decode_hex_32("a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2")
        );
        assert_eq!(
            digests.output,
            decode_hex_32("63b627d856c66a3a8ed83ba5e1f28b172234e1c7b15d3370977bf157019d38f2")
        );
        assert_eq!(
            digests.expected_claim,
            decode_hex_32("14fd85f19032d53ce5ae85f10dab8c6c3f12ae9e11a9c6b778e26cd751170e16")
        );
    }

    #[test]
    fn current_non_normative_diagnostics_match_reconstructable_intermediates() {
        // The EIP publishes the journal digest but not its journal preimage or
        // image ID. Therefore only `post` and `output` are independently
        // reconstructable from the published diagnostic material.
        let diagnostic_journal_digest =
            decode_hex_32("9b8899bb1fa709880a1d3ce2a5fb87b8c82d067c9ceaa3efd88eb99e37624f89");

        assert_eq!(
            ok_post_digest().unwrap(),
            decode_hex_32("a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2")
        );
        assert_eq!(
            ok_output_digest(&diagnostic_journal_digest).unwrap(),
            decode_hex_32("65071bef11ffec7f370df403257a4cfa56c265bafb6ca28b61b8f0b36a042a33")
        );
    }

    #[test]
    fn empty_journal_is_an_explicit_ok_claim_boundary() {
        let digests = ok_receipt_claim_digests(&[0xff; DIGEST_BYTES], b"").unwrap();

        assert_eq!(
            digests.journal_digest,
            decode_hex_32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            digests.post,
            decode_hex_32("a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2")
        );
        assert_eq!(
            digests.output,
            decode_hex_32("836f175c62c0f353831665427e8b0b34f6d1d21902764daeb406c6b83db575b0")
        );
        assert_eq!(
            digests.expected_claim,
            decode_hex_32("f1a3d6a4ee0e168f73dad0448bd6407dc3e2ae2d2c211970f6c7ace9fa4575db")
        );
    }

    #[test]
    fn image_id_length_is_exactly_32_bytes() {
        for actual in [DIGEST_BYTES - 1, DIGEST_BYTES + 1] {
            assert_eq!(
                ok_receipt_claim_digests(&vec![0; actual], b"journal"),
                Err(ClaimConstructionError::InvalidImageIdLength {
                    actual,
                    expected: DIGEST_BYTES,
                })
            );
        }
    }

    #[test]
    fn tagged_struct_kat_isolates_u32_and_u16_little_endian_encodings() {
        let down = [ascending_32()];

        assert_eq!(
            tagged_struct_sha256("eip0045.test.Tag", &down, &[0x0102_0304, 0xa1b2_c3d4]).unwrap(),
            decode_hex_32("cee52364c4b492833a14d1258fac5bcd6747dae84658dac401de1385b5ad6a9b")
        );
    }

    #[test]
    fn tagged_struct_does_not_append_a_data_count() {
        let tag_digest = Sha256::digest(b"eip0045.test.Tag");
        let mut wrong_preimage = Vec::new();
        wrong_preimage.extend_from_slice(&tag_digest);
        wrong_preimage.extend_from_slice(&ascending_32());
        wrong_preimage.extend_from_slice(&0x0102_0304u32.to_le_bytes());
        wrong_preimage.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
        wrong_preimage.extend_from_slice(&1u16.to_le_bytes());
        wrong_preimage.extend_from_slice(&2u16.to_le_bytes());

        let canonical = tagged_struct_sha256(
            "eip0045.test.Tag",
            &[ascending_32()],
            &[0x0102_0304, 0xa1b2_c3d4],
        )
        .unwrap();
        let with_appended_data_count: [u8; DIGEST_BYTES] = Sha256::digest(&wrong_preimage).into();

        assert_eq!(
            with_appended_data_count,
            decode_hex_32("d4b37c48388216599a16f5db0dd6fa24db49f64c334bb4a5812e1b03ba72bb9f")
        );
        assert_ne!(canonical, with_appended_data_count);
    }

    #[test]
    fn tagged_struct_rejects_a_child_count_above_u16() {
        assert_eq!(
            tagged_struct_preimage_length(usize::from(u16::MAX) + 1, 0),
            Err(ClaimConstructionError::TooManyTaggedStructChildren {
                actual: usize::from(u16::MAX) + 1,
                maximum: usize::from(u16::MAX),
            })
        );
    }

    #[test]
    fn tagged_struct_checks_length_arithmetic_before_hashing() {
        assert_eq!(
            tagged_struct_preimage_length(0, usize::MAX),
            Err(ClaimConstructionError::ArithmeticOverflow(
                "tagged-struct data bytes"
            ))
        );
    }

    #[test]
    fn reversing_the_image_id_changes_only_the_expected_claim() {
        let image_id = ascending_32();
        let mut reversed_image_id = image_id;
        reversed_image_id.reverse();

        let canonical = ok_receipt_claim_digests(&image_id, b"journal").unwrap();
        let reversed = ok_receipt_claim_digests(&reversed_image_id, b"journal").unwrap();

        assert_eq!(canonical.journal_digest, reversed.journal_digest);
        assert_eq!(canonical.post, reversed.post);
        assert_eq!(canonical.output, reversed.output);
        assert_ne!(canonical.expected_claim, reversed.expected_claim);
    }

    fn ascending_32() -> [u8; DIGEST_BYTES] {
        let mut output = [0u8; DIGEST_BYTES];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::try_from(index).unwrap();
        }
        output
    }

    fn decode_hex_32(value: &str) -> [u8; DIGEST_BYTES] {
        hex::decode(value).unwrap().try_into().unwrap()
    }
}
