//! Domain-separated B7 evidence derivations and strict detached signatures.
//!
//! Callers remain responsible for validating the versioned schema and proving
//! that the supplied record bytes are their exact RFC 8785 JCS serialization.

use core::fmt;

use blake2::{Blake2b, Digest as BlakeDigest, digest::consts::U32};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::Identity,
};
use sha2::{Digest as ShaDigest, Sha256, Sha512};

use crate::constants::{MAX_SEGMENT_PO2, MIN_SEGMENT_PO2};

/// Domain tag for the value anchored in the pre-challenge Ergo output.
pub const PRECOMMIT_ANCHOR_DOMAIN: &[u8] = b"Ergo.EIP0045.B7.Precommit.v1";
/// Domain tag for deriving a post-block per-`po2` challenge.
pub const FRESH_RUN_DOMAIN: &[u8] = b"Ergo.EIP0045.B7.FreshRun.v1";
/// Domain tag for the message digest signed by the evidence operator.
pub const RUN_EVIDENCE_SIGNATURE_DOMAIN: &[u8] = b"Ergo.EIP0045.B7.RunEvidenceSignature.v1";
/// Zero byte separating every evidence domain from its first field.
pub const DOMAIN_SEPARATOR: u8 = 0;

type Blake2b256 = Blake2b<U32>;

/// Identifies which encoded Edwards point failed strict validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PointRole {
    /// The operator evidence public key, `Aenc`.
    PublicKey,
    /// The signature commitment, `Renc`.
    SignatureR,
}

impl fmt::Display for PointRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicKey => formatter.write_str("public key"),
            Self::SignatureR => formatter.write_str("signature R"),
        }
    }
}

/// Failure returned by a B7 evidence derivation or signature check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    /// The segment exponent is outside the frozen inclusive range.
    InvalidPo2(u8),
    /// Canonical evidence bytes cannot be represented by the required `u32le` length.
    RunEvidenceTooLarge(usize),
    /// A compressed Edwards point did not decode.
    InvalidPointEncoding(PointRole),
    /// A point decoded but its bytes were not its canonical encoding.
    NonCanonicalPoint(PointRole),
    /// The decoded point was the group identity.
    IdentityPoint(PointRole),
    /// The decoded point was not in the prime-order subgroup.
    NonPrimeOrderPoint(PointRole),
    /// The signature scalar was greater than or equal to the subgroup order.
    NonCanonicalScalar,
    /// The exact uncofactored pure-Ed25519 equation failed.
    SignatureEquationMismatch,
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPo2(po2) => write!(formatter, "unsupported segment po2: {po2}"),
            Self::RunEvidenceTooLarge(length) => {
                write!(
                    formatter,
                    "RunEvidenceV1 is too large for u32le length: {length}"
                )
            }
            Self::InvalidPointEncoding(role) => {
                write!(formatter, "invalid compressed Edwards encoding for {role}")
            }
            Self::NonCanonicalPoint(role) => {
                write!(
                    formatter,
                    "noncanonical compressed Edwards encoding for {role}"
                )
            }
            Self::IdentityPoint(role) => {
                write!(formatter, "identity point is forbidden for {role}")
            }
            Self::NonPrimeOrderPoint(role) => {
                write!(
                    formatter,
                    "point is outside the prime-order subgroup for {role}"
                )
            }
            Self::NonCanonicalScalar => {
                formatter.write_str("signature scalar S is not less than L")
            }
            Self::SignatureEquationMismatch => {
                formatter.write_str("pure Ed25519 signature equation does not hold")
            }
        }
    }
}

impl std::error::Error for EvidenceError {}

/// SHA-256 of the exact canonical `RunPrecommitV1` bytes.
#[must_use]
pub fn precommit_digest(canonical_precommit_bytes: &[u8]) -> [u8; 32] {
    sha256(canonical_precommit_bytes)
}

/// Exact `R4: Coll[Byte]` value used to anchor a B7 precommit.
#[must_use]
pub fn precommit_anchor_value(canonical_precommit_bytes: &[u8]) -> Vec<u8> {
    let digest = precommit_digest(canonical_precommit_bytes);
    let mut anchor = Vec::with_capacity(PRECOMMIT_ANCHOR_DOMAIN.len() + 1 + digest.len());
    anchor.extend_from_slice(PRECOMMIT_ANCHOR_DOMAIN);
    anchor.push(DOMAIN_SEPARATOR);
    anchor.extend_from_slice(&digest);
    anchor
}

/// Derive the 32-byte B7 application payload for one supported segment `po2`.
///
/// # Errors
///
/// Returns [`EvidenceError::InvalidPo2`] unless `po2` is in the frozen range.
pub fn fresh_challenge(
    precommit_digest: &[u8; 32],
    po2: u8,
    challenge_block_id: &[u8; 32],
) -> Result<[u8; 32], EvidenceError> {
    if !(MIN_SEGMENT_PO2..=MAX_SEGMENT_PO2).contains(&po2) {
        return Err(EvidenceError::InvalidPo2(po2));
    }

    let mut hasher = Blake2b256::new();
    hasher.update(FRESH_RUN_DOMAIN);
    hasher.update([DOMAIN_SEPARATOR]);
    hasher.update(precommit_digest);
    hasher.update([po2]);
    hasher.update(challenge_block_id);
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

/// SHA-256 of the exact canonical `RunEvidenceV1` bytes.
#[must_use]
pub fn run_evidence_sha256(canonical_run_evidence_bytes: &[u8]) -> [u8; 32] {
    sha256(canonical_run_evidence_bytes)
}

/// Compute the exact 32-byte message that the external evidence key signs.
///
/// # Errors
///
/// Returns [`EvidenceError::RunEvidenceTooLarge`] if the byte length cannot be
/// encoded by the mandated four-byte little-endian prefix.
pub fn run_evidence_signature_digest(
    canonical_run_evidence_bytes: &[u8],
) -> Result<[u8; 32], EvidenceError> {
    let length = u32::try_from(canonical_run_evidence_bytes.len())
        .map_err(|_| EvidenceError::RunEvidenceTooLarge(canonical_run_evidence_bytes.len()))?;

    let mut hasher = Sha256::new();
    hasher.update(RUN_EVIDENCE_SIGNATURE_DOMAIN);
    hasher.update([DOMAIN_SEPARATOR]);
    hasher.update(length.to_le_bytes());
    hasher.update(canonical_run_evidence_bytes);
    Ok(finalize_32(hasher))
}

/// Verify a detached signature over the domain-separated `RunEvidenceV1` digest.
///
/// This implements pure Ed25519 directly. It rejects noncanonical encodings,
/// identity and mixed-torsion points, and `S >= L`, then checks the exact
/// uncofactored equation `[S]B = R + [k]A`.
///
/// # Errors
///
/// Returns the exact derivation, point, scalar, or signature-equation failure.
pub fn verify_run_evidence_signature(
    operator_evidence_public_key: &[u8; 32],
    canonical_run_evidence_bytes: &[u8],
    signature: &[u8; 64],
) -> Result<(), EvidenceError> {
    let message = run_evidence_signature_digest(canonical_run_evidence_bytes)?;
    verify_strict_pure_ed25519(operator_evidence_public_key, &message, signature)
}

fn verify_strict_pure_ed25519(
    public_key_bytes: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), EvidenceError> {
    let public_key = decode_canonical_prime_order_point(public_key_bytes, PointRole::PublicKey)?;

    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let r = decode_canonical_prime_order_point(&r_bytes, PointRole::SignatureR)?;

    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
        .ok_or(EvidenceError::NonCanonicalScalar)?;

    let k = ed25519_challenge_scalar(&r_bytes, public_key_bytes, message);
    let left = ED25519_BASEPOINT_POINT * s;
    let right = r + public_key * k;

    if left == right {
        Ok(())
    } else {
        Err(EvidenceError::SignatureEquationMismatch)
    }
}

fn decode_canonical_prime_order_point(
    encoded: &[u8; 32],
    role: PointRole,
) -> Result<EdwardsPoint, EvidenceError> {
    let point = CompressedEdwardsY(*encoded)
        .decompress()
        .ok_or(EvidenceError::InvalidPointEncoding(role))?;
    if point.compress().to_bytes() != *encoded {
        return Err(EvidenceError::NonCanonicalPoint(role));
    }
    if point == EdwardsPoint::identity() {
        return Err(EvidenceError::IdentityPoint(role));
    }
    if !point.is_torsion_free() {
        return Err(EvidenceError::NonPrimeOrderPoint(role));
    }
    Ok(point)
}

fn ed25519_challenge_scalar(
    r_bytes: &[u8; 32],
    public_key_bytes: &[u8; 32],
    message: &[u8],
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(r_bytes);
    hasher.update(public_key_bytes);
    hasher.update(message);
    let digest = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    finalize_32(hasher)
}

fn finalize_32(hasher: impl ShaDigest<OutputSize = U32>) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::EIGHT_TORSION;

    const SYNTHETIC_SEED: [u8; 32] = [0x45; 32];
    const L_BYTES: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    #[test]
    fn precommit_anchor_has_the_exact_domain_and_digest() {
        // Synthetic, non-final KAT computed independently with .NET SHA-256.
        let precommit = br#"{"fixture":"synthetic-precommit"}"#;
        let anchor = precommit_anchor_value(precommit);

        let mut expected = PRECOMMIT_ANCHOR_DOMAIN.to_vec();
        expected.push(0);
        expected.extend_from_slice(&sha256(precommit));
        assert_eq!(anchor, expected);
        assert_eq!(
            anchor,
            decode_hex(
                "4572676f2e454950303034352e42372e507265636f6d6d69742e7631003362b7165c4998775caaa54e4db8a8dd67e3c89b0b389693ba1917c4967c650e"
            )
        );
    }

    #[test]
    fn fresh_challenge_binds_every_input() {
        let precommit = precommit_digest(b"synthetic precommit");
        let block_id = [0x42; 32];
        let baseline = fresh_challenge(&precommit, 18, &block_id).unwrap();

        let mut changed_precommit = precommit;
        changed_precommit[0] ^= 1;
        assert_ne!(
            baseline,
            fresh_challenge(&changed_precommit, 18, &block_id).unwrap()
        );
        assert_ne!(
            baseline,
            fresh_challenge(&precommit, 19, &block_id).unwrap()
        );
        let mut changed_block = block_id;
        changed_block[31] ^= 1;
        assert_ne!(
            baseline,
            fresh_challenge(&precommit, 18, &changed_block).unwrap()
        );
        assert_eq!(
            fresh_challenge(&precommit, 14, &block_id),
            Err(EvidenceError::InvalidPo2(14))
        );
        assert_eq!(
            fresh_challenge(&precommit, 23, &block_id),
            Err(EvidenceError::InvalidPo2(23))
        );
    }

    #[test]
    fn fresh_challenge_matches_an_independent_blake2b_256_vector() {
        let mut precommit = [0u8; 32];
        let mut block_id = [0u8; 32];
        for index in 0u8..32 {
            precommit[usize::from(index)] = index;
            block_id[usize::from(index)] = index + 32;
        }

        assert_eq!(
            fresh_challenge(&precommit, 18, &block_id).unwrap(),
            decode_hex_32("590103de921428c37676b03063ad64e6ea6fd706b4e5bad4301a1788c838fd25")
        );
    }

    #[test]
    fn run_evidence_digest_includes_domain_separator_and_u32le_length() {
        // Synthetic, non-final KAT computed independently with .NET SHA-256.
        let evidence = br#"{"fixture":"synthetic-run-evidence"}"#;
        let actual = run_evidence_signature_digest(evidence).unwrap();

        let mut hasher = Sha256::new();
        hasher.update(b"Ergo.EIP0045.B7.RunEvidenceSignature.v1");
        hasher.update([0]);
        hasher.update(u32::try_from(evidence.len()).unwrap().to_le_bytes());
        hasher.update(evidence);
        assert_eq!(actual, finalize_32(hasher));
        assert_eq!(
            actual,
            decode_hex_32("c0f74479be462668947078a38e12802d33beabfe410140447d9e4529267cf89f")
        );
        assert_ne!(actual, run_evidence_sha256(evidence));
    }

    #[test]
    fn synthetic_pure_ed25519_signature_verifies() {
        let evidence = br#"{"fixture":"synthetic-positive"}"#;
        let message = run_evidence_signature_digest(evidence).unwrap();
        // Synthetic, non-final KAT generated with an independent Ed25519
        // implementation over this exact domain-separated message digest.
        assert_eq!(
            message,
            decode_hex_32("cf4dd982ee4a9e0fb913f6f4ec07f3fb3e86c5b0a945bda2243765800bbe0bd2")
        );
        let public_key =
            decode_hex_32("6355691c178a8ff91007a7478afb955ef7352c63e7b25703984cf78b26e21a56");
        let signature = decode_hex_64(
            "49e94de68d6da28436daa4bdbb4ce68864bc4cce4f6d46512c2a9d68b8ef5b90\
             e88b425fd58944dfebd949a7bbcb9134873b922681c2cad4e97bb01c94797f08",
        );

        verify_run_evidence_signature(&public_key, evidence, &signature).unwrap();
    }

    #[test]
    fn rfc8032_pure_ed25519_vector_verifies() {
        let public_key =
            decode_hex_32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let signature = decode_hex_64(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );
        verify_strict_pure_ed25519(&public_key, b"", &signature).unwrap();
    }

    #[test]
    fn high_s_malleability_is_rejected_before_the_equation() {
        let message = [0x5a; 32];
        let (public_key, mut signature) = sign_for_test(SYNTHETIC_SEED, &message);
        let mut s = [0u8; 32];
        s.copy_from_slice(&signature[32..]);
        signature[32..].copy_from_slice(&add_little_endian(s, L_BYTES));

        assert_eq!(
            verify_strict_pure_ed25519(&public_key, &message, &signature),
            Err(EvidenceError::NonCanonicalScalar)
        );
    }

    #[test]
    fn identity_and_mixed_torsion_public_keys_are_rejected() {
        let message = [0x5a; 32];
        let (public_key, signature) = sign_for_test(SYNTHETIC_SEED, &message);

        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            verify_strict_pure_ed25519(&identity, &message, &signature),
            Err(EvidenceError::IdentityPoint(PointRole::PublicKey))
        );

        let point = CompressedEdwardsY(public_key).decompress().unwrap();
        let mixed_torsion = (point + EIGHT_TORSION[1]).compress().to_bytes();
        assert_eq!(
            verify_strict_pure_ed25519(&mixed_torsion, &message, &signature),
            Err(EvidenceError::NonPrimeOrderPoint(PointRole::PublicKey))
        );
    }

    #[test]
    fn mixed_torsion_signature_r_is_rejected() {
        let message = [0x5a; 32];
        let (public_key, mut signature) = sign_for_test(SYNTHETIC_SEED, &message);
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&signature[..32]);
        let r = CompressedEdwardsY(r_bytes).decompress().unwrap();
        signature[..32].copy_from_slice(&(r + EIGHT_TORSION[1]).compress().to_bytes());

        assert_eq!(
            verify_strict_pure_ed25519(&public_key, &message, &signature),
            Err(EvidenceError::NonPrimeOrderPoint(PointRole::SignatureR))
        );
    }

    #[test]
    fn identity_signature_r_is_rejected() {
        let message = [0x5a; 32];
        let (public_key, mut signature) = sign_for_test(SYNTHETIC_SEED, &message);
        signature[..32].fill(0);
        signature[0] = 1;

        assert_eq!(
            verify_strict_pure_ed25519(&public_key, &message, &signature),
            Err(EvidenceError::IdentityPoint(PointRole::SignatureR))
        );
    }

    #[test]
    fn noncanonical_point_encoding_is_rejected() {
        // y = p + 1 reduces to the identity in permissive field decoders, but
        // its canonical compressed encoding is y = 1.
        let mut noncanonical_identity = [0xff; 32];
        noncanonical_identity[0] = 0xee;
        noncanonical_identity[31] = 0x7f;
        let signature = [0u8; 64];

        assert!(matches!(
            verify_strict_pure_ed25519(&noncanonical_identity, b"", &signature),
            Err(EvidenceError::NonCanonicalPoint(PointRole::PublicKey)
                | EvidenceError::InvalidPointEncoding(PointRole::PublicKey))
        ));
    }

    #[test]
    fn signature_is_bound_to_the_exact_run_evidence_bytes() {
        let evidence = br#"{"fixture":"synthetic-bound-message"}"#;
        let message = run_evidence_signature_digest(evidence).unwrap();
        let (public_key, signature) = sign_for_test(SYNTHETIC_SEED, &message);

        assert_eq!(
            verify_run_evidence_signature(
                &public_key,
                br#"{"fixture":"synthetic-bound-message!"}"#,
                &signature,
            ),
            Err(EvidenceError::SignatureEquationMismatch)
        );
    }

    #[test]
    fn signature_from_a_different_evidence_key_is_rejected() {
        let evidence = br#"{"fixture":"synthetic-wrong-key"}"#;
        let message = run_evidence_signature_digest(evidence).unwrap();
        let (_, signature) = sign_for_test(SYNTHETIC_SEED, &message);
        let (wrong_public_key, _) = sign_for_test([0x46; 32], &message);

        assert_eq!(
            verify_run_evidence_signature(&wrong_public_key, evidence, &signature),
            Err(EvidenceError::SignatureEquationMismatch)
        );
    }

    fn sign_for_test(seed: [u8; 32], message: &[u8]) -> ([u8; 32], [u8; 64]) {
        let expanded = Sha512::digest(seed);
        let mut secret_scalar_bytes = [0u8; 32];
        secret_scalar_bytes.copy_from_slice(&expanded[..32]);
        secret_scalar_bytes[0] &= 248;
        secret_scalar_bytes[31] &= 63;
        secret_scalar_bytes[31] |= 64;
        let secret_scalar = Scalar::from_bytes_mod_order(secret_scalar_bytes);

        let public_key = (ED25519_BASEPOINT_POINT * secret_scalar)
            .compress()
            .to_bytes();

        let mut nonce_hasher = Sha512::new();
        nonce_hasher.update(&expanded[32..]);
        nonce_hasher.update(message);
        let nonce_digest = nonce_hasher.finalize();
        let mut nonce_wide = [0u8; 64];
        nonce_wide.copy_from_slice(&nonce_digest);
        let nonce = Scalar::from_bytes_mod_order_wide(&nonce_wide);
        let r_bytes = (ED25519_BASEPOINT_POINT * nonce).compress().to_bytes();

        let k = ed25519_challenge_scalar(&r_bytes, &public_key, message);
        let s = nonce + k * secret_scalar;
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&r_bytes);
        signature[32..].copy_from_slice(&s.to_bytes());
        (public_key, signature)
    }

    fn add_little_endian(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        let mut output = [0u8; 32];
        let mut carry = 0u16;
        for index in 0..32 {
            let sum = u16::from(left[index]) + u16::from(right[index]) + carry;
            output[index] = sum.to_le_bytes()[0];
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        output
    }

    fn decode_hex_32(value: &str) -> [u8; 32] {
        let bytes = decode_hex(value);
        bytes.try_into().unwrap()
    }

    fn decode_hex_64(value: &str) -> [u8; 64] {
        let compact: String = value
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let bytes = decode_hex(&compact);
        bytes.try_into().unwrap()
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = hex_nibble(pair[0]);
                let low = hex_nibble(pair[1]);
                (high << 4) | low
            })
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
