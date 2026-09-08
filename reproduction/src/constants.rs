//! Frozen construction constants for the first EIP-0045 profile.
//!
//! These values describe the selected reproduction construction target. They
//! are not an activation claim and do not include any final profile or evidence
//! instance.

use core::fmt;

/// Canonical upstream repository used for the first profile reproduction.
pub const RISC0_REPOSITORY: &str = "https://github.com/risc0/risc0.git";
/// Exact upstream source commit used for the first profile reproduction.
pub const RISC0_COMMIT: &str = "8eb06ab020a92dc5b63ba6dd0836d432aba6d890";

/// OCI repository containing the pinned guest-builder image.
pub const GUEST_BUILDER_OCI_REPOSITORY: &str = "risczero/risc0-guest-builder";
/// Immutable OCI manifest digest of the pinned guest-builder image.
pub const GUEST_BUILDER_OCI_DIGEST: &str =
    "sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3";
/// Required OCI platform for the guest-builder image.
pub const GUEST_BUILDER_OCI_PLATFORM: &str = "linux/amd64";

/// OCI repository containing the pinned host Rust toolchain.
pub const HOST_RUST_OCI_REPOSITORY: &str = "docker.io/library/rust";
/// Immutable linux/amd64 OCI manifest digest of the host Rust image.
pub const HOST_RUST_OCI_DIGEST: &str =
    "sha256:294917190b5a3fed18d3303213943f40ec9b644b3cd6e5cdc8cd029334a770b3";
/// Required OCI platform for the host Rust image.
pub const HOST_RUST_OCI_PLATFORM: &str = "linux/amd64";

/// Rust toolchain used to build the host-side reproduction utilities.
pub const HOST_RUST_VERSION: &str = "1.89.0";
/// Rust toolchain embedded in the pinned guest-builder image.
pub const GUEST_RUST_VERSION: &str = "1.88.0";

/// `SigmaState` opcode assigned to `VerifyStark`.
pub const VERIFY_STARK_OPCODE: u8 = 0xB9;
/// Consensus-visible expression arity of `VerifyStark`.
pub const VERIFY_STARK_ARITY: usize = 4;

/// Number of little-endian `u32` words in the frozen raw seal.
pub const PROOF_WORDS: usize = 55_667;
/// Serialized byte width of one raw-seal word.
pub const BYTES_PER_PROOF_WORD: usize = 4;
/// Exact frozen raw-seal length in bytes.
pub const PROOF_BYTES: usize = 222_668;
/// Maximum `Coll[Byte]` payload held by one proof chunk.
pub const PROOF_CHUNK_CAPACITY: usize = 65_535;
/// Canonical four-chunk partition of the raw seal.
pub const PROOF_CHUNK_LENGTHS: [usize; 4] = [65_535, 65_535, 65_535, 26_063];

/// Initial profile's selected maximum application payload length.
pub const MAX_APPLICATION_PAYLOAD_BYTES: usize = 16_384;
/// Domain tag at the start of an `ErgoStatementV1` preimage.
pub const ERGO_STATEMENT_DOMAIN: &[u8] = b"Ergo.VerifyStark.Statement";
/// Width of the statement-version field.
pub const ERGO_STATEMENT_VERSION_BYTES: usize = 1;
/// Number of 32-byte digests bound before the application payload.
pub const ERGO_STATEMENT_BOUND_DIGESTS: usize = 4;
/// Byte width of every bound digest.
pub const DIGEST_BYTES: usize = 32;
/// Width of the little-endian application-payload length prefix.
pub const PAYLOAD_LENGTH_PREFIX_BYTES: usize = 4;
/// Fixed byte length preceding the application payload.
pub const STATEMENT_PREFIX_BYTES: usize = 159;
/// Initial profile's selected maximum complete `ErgoStatementV1` length.
pub const MAX_STATEMENT_BYTES: usize = STATEMENT_PREFIX_BYTES + MAX_APPLICATION_PAYLOAD_BYTES;

/// Exact binary `StarkProfileManifestV1` length used by the frozen construction.
pub const MANIFEST_BYTES: usize = 458;
/// Manifest-format discriminator for the RISC Zero succinct-terminal grammar.
pub const MANIFEST_FORMAT_VERSION: u8 = 0x01;
/// Width of the manifest-format discriminator.
pub const MANIFEST_FORMAT_VERSION_BYTES: usize = 1;
/// Width of each manifest-owned unsigned `u32` scalar.
pub const MANIFEST_U32_BYTES: usize = 4;
/// Width of the manifest-owned outer recursion exponent.
pub const MANIFEST_OUTER_PO2_BYTES: usize = 1;
/// Number of fixed-position control entries in Manifest V1.
pub const MANIFEST_CONTROL_COUNT: usize = 10;
/// Width of one `controlKind || parameter || controlId` entry.
pub const MANIFEST_CONTROL_ENTRY_BYTES: usize = 2 + DIGEST_BYTES;
/// Width of one `artifactKind || artifactLength || artifactDigest` reference.
pub const MANIFEST_ARTIFACT_REFERENCE_BYTES: usize = 2 + 4 + DIGEST_BYTES;
/// Initial profile's fixed outer recursion exponent.
pub const RISC0_OUTER_PO2: u8 = 18;
/// Artifact kind assigned to the normative algorithm artifact.
pub const ALGORITHM_ARTIFACT_KIND: u16 = 1;
/// Artifact kind assigned to the normative binary-data artifact.
pub const BINARY_DATA_ARTIFACT_KIND: u16 = 2;
/// Domain tag used to commit one profile artifact.
pub const PROFILE_ARTIFACT_DOMAIN: &[u8] = b"Ergo.StarkProfileArtifact.v1";
/// Exact upstream Poseidon2 inner control root targeted by the initial profile.
pub const RISC0_INNER_CONTROL_ROOT_HEX: &str =
    "a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56";
/// Exact Poseidon2 root of the fixed 26-entry B4 alternate control-ID set.
///
/// This is a negative-campaign witness pin, not an activated profile root.
pub const B4_ALTERNATE_CONTROL_ROOT_HEX: &str =
    "eb798a5b87bc5056c2e6a860a3e1333d7eaf2a0f40469337ed29cc2616ab935a";
/// Decoded bytes of [`B4_ALTERNATE_CONTROL_ROOT_HEX`].
pub const B4_ALTERNATE_CONTROL_ROOT: [u8; DIGEST_BYTES] = [
    0xeb, 0x79, 0x8a, 0x5b, 0x87, 0xbc, 0x50, 0x56, 0xc2, 0xe6, 0xa8, 0x60, 0xa3, 0xe1, 0x33, 0x3d,
    0x7e, 0xaf, 0x2a, 0x0f, 0x40, 0x46, 0x93, 0x37, 0xed, 0x29, 0xcc, 0x26, 0x16, 0xab, 0x93, 0x5a,
];
/// Stock control ID deliberately omitted by the fixed B4 alternate witness.
pub const B4_ALTERNATE_OMITTED_CONTROL_ID_HEX: &str =
    "1688f04cca489638862dba455c1d5c561513f975c885a3491f0fe12df761c847";
/// Verifier-parameter digest corresponding to the fixed alternate root.
pub const B4_ALTERNATE_VERIFIER_PARAMETERS_HEX: &str =
    "ac1a73c07c73a8564547195beec2cee2392f8a86bc75f3c373c94d50260c2b9e";
/// Domain tag at the start of the profile-ID preimage.
pub const PROFILE_ID_DOMAIN: &[u8] = b"Ergo.StarkProfileId.v1";
/// Width of the zero-valued profile-domain separator.
pub const PROFILE_ID_DOMAIN_SEPARATOR_BYTES: usize = 1;
/// Width of the little-endian manifest-length prefix.
pub const MANIFEST_LENGTH_PREFIX_BYTES: usize = 4;
/// Exact length of the profile-ID preimage before hashing.
pub const PROFILE_ID_PREIMAGE_BYTES: usize = 485;

/// Number of normal-lift entries in the initial terminal-control table.
pub const NORMAL_LIFT_CONTROL_COUNT: usize = 8;
/// Manifest terminal-control kind assigned to a normal lift.
pub const TERMINAL_CONTROL_KIND_LIFT: u8 = 1;
/// Manifest terminal-control kind assigned to a join program.
pub const TERMINAL_CONTROL_KIND_JOIN: u8 = 2;
/// Manifest terminal-control kind assigned to a resolve program.
pub const TERMINAL_CONTROL_KIND_RESOLVE: u8 = 3;
/// Smallest supported RISC Zero segment exponent.
pub const MIN_SEGMENT_PO2: u8 = 15;
/// Largest supported RISC Zero segment exponent.
pub const MAX_SEGMENT_PO2: u8 = 22;
/// Exact, contiguous set of supported segment exponents.
pub const SUPPORTED_SEGMENT_PO2: [u8; NORMAL_LIFT_CONTROL_COUNT] = [15, 16, 17, 18, 19, 20, 21, 22];
/// Initial profile's accepted normal-lift control IDs in segment order.
pub const RISC0_NORMAL_LIFT_CONTROL_IDS_HEX: [&str; NORMAL_LIFT_CONTROL_COUNT] = [
    "1ca3ca03030719064ba61b3125bdd326fc57f74e799ef860bdea6f3227381e16",
    "c32b3627d2b3d60c64adf523a98bd16c0ff607471f3d6630d1f26d5e9406d841",
    "c9b08054994f542a6310b00d9b6fc6528ed7bb6f4ca5476a686847127cdfdc5b",
    "e7934a23ddce1423b425cf32aa23be29f48cd40e0b6ff9376dce6f3bf9d0bc35",
    "8c2fdd36ede09a4b9d316a43c51f1160cbd8876659c5f35810c3a119c60d3843",
    "34530b42028fb631c90e1226bb0e750d4b9b593840d45216f75dca449dac7734",
    "fd84d83092a1e1244d423a26d89c892ab098b467c6d82229912deb26e37d2562",
    "9d9dbf33535ab11f52a93839dfd23b352b7626009e81d9459fd04e488898ec6a",
];
/// Initial profile's accepted terminal join control ID.
pub const RISC0_JOIN_CONTROL_ID_HEX: &str =
    "7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e";
/// Initial profile's accepted terminal resolve control ID.
pub const RISC0_RESOLVE_CONTROL_ID_HEX: &str =
    "53a7b23d07f99e5d5685e85874f5181e8486aa267a0ae607ffe9ba47c8bdda4a";

/// Values whose algebraic relationships are checked together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedInvariants {
    /// Frozen raw-seal length in `u32` words.
    pub proof_words: usize,
    /// Frozen raw-seal length in bytes.
    pub proof_bytes: usize,
    /// Frozen canonical proof partition.
    pub proof_chunk_lengths: [usize; 4],
    /// Maximum application payload length.
    pub max_application_payload_bytes: usize,
    /// Fixed statement-prefix length.
    pub statement_prefix_bytes: usize,
    /// Exact canonical profile-manifest length.
    pub manifest_bytes: usize,
    /// Exact profile-ID preimage length.
    pub profile_id_preimage_bytes: usize,
    /// Exact supported segment-exponent set.
    pub supported_segment_po2: [u8; NORMAL_LIFT_CONTROL_COUNT],
}

/// Selected invariant set for the frozen construction target.
pub const PINNED_INVARIANTS: PinnedInvariants = PinnedInvariants {
    proof_words: PROOF_WORDS,
    proof_bytes: PROOF_BYTES,
    proof_chunk_lengths: PROOF_CHUNK_LENGTHS,
    max_application_payload_bytes: MAX_APPLICATION_PAYLOAD_BYTES,
    statement_prefix_bytes: STATEMENT_PREFIX_BYTES,
    manifest_bytes: MANIFEST_BYTES,
    profile_id_preimage_bytes: PROFILE_ID_PREIMAGE_BYTES,
    supported_segment_po2: SUPPORTED_SEGMENT_PO2,
};

/// Failure returned when frozen construction values are internally inconsistent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvariantError {
    /// A source, toolchain, image, or opcode pin is malformed or unexpected.
    InvalidPin(&'static str),
    /// Checked length arithmetic overflowed.
    ArithmeticOverflow(&'static str),
    /// Two independently expressed frozen values disagree.
    Mismatch(&'static str),
    /// A proof chunk is empty, oversized, or not canonically partitioned.
    InvalidChunk(usize),
    /// A segment exponent is missing, duplicated, or out of order.
    InvalidPo2(usize),
}

impl fmt::Display for InvariantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPin(name) => write!(formatter, "invalid frozen pin: {name}"),
            Self::ArithmeticOverflow(name) => {
                write!(formatter, "arithmetic overflow while validating {name}")
            }
            Self::Mismatch(name) => write!(formatter, "frozen invariant mismatch: {name}"),
            Self::InvalidChunk(index) => write!(formatter, "invalid proof chunk at index {index}"),
            Self::InvalidPo2(index) => write!(formatter, "invalid po2 at index {index}"),
        }
    }
}

impl std::error::Error for InvariantError {}

impl PinnedInvariants {
    /// Validate all shape, size, partition, and source-pin relationships.
    ///
    /// # Errors
    ///
    /// Returns the first malformed pin, overflow, or inconsistent relationship.
    pub fn validate(&self) -> Result<(), InvariantError> {
        validate_static_pins()?;

        let proof_bytes = self
            .proof_words
            .checked_mul(BYTES_PER_PROOF_WORD)
            .ok_or(InvariantError::ArithmeticOverflow("proof byte length"))?;
        if proof_bytes != self.proof_bytes {
            return Err(InvariantError::Mismatch("proof words to bytes"));
        }

        let mut chunk_total = 0usize;
        for (index, chunk_len) in self.proof_chunk_lengths.iter().copied().enumerate() {
            if chunk_len == 0 || chunk_len > PROOF_CHUNK_CAPACITY {
                return Err(InvariantError::InvalidChunk(index));
            }
            if index + 1 < self.proof_chunk_lengths.len() && chunk_len != PROOF_CHUNK_CAPACITY {
                return Err(InvariantError::InvalidChunk(index));
            }
            chunk_total = chunk_total
                .checked_add(chunk_len)
                .ok_or(InvariantError::ArithmeticOverflow("proof chunk total"))?;
        }
        if chunk_total != self.proof_bytes {
            return Err(InvariantError::Mismatch("proof chunk total"));
        }

        let expected_statement_prefix = ERGO_STATEMENT_DOMAIN
            .len()
            .checked_add(ERGO_STATEMENT_VERSION_BYTES)
            .and_then(|len| {
                ERGO_STATEMENT_BOUND_DIGESTS
                    .checked_mul(DIGEST_BYTES)
                    .and_then(|digest_bytes| len.checked_add(digest_bytes))
            })
            .and_then(|len| len.checked_add(PAYLOAD_LENGTH_PREFIX_BYTES))
            .ok_or(InvariantError::ArithmeticOverflow("statement prefix"))?;
        if expected_statement_prefix != self.statement_prefix_bytes {
            return Err(InvariantError::Mismatch("statement prefix"));
        }
        let maximum_statement_bytes = self
            .statement_prefix_bytes
            .checked_add(self.max_application_payload_bytes)
            .ok_or(InvariantError::ArithmeticOverflow(
                "maximum statement length",
            ))?;
        if maximum_statement_bytes != MAX_STATEMENT_BYTES {
            return Err(InvariantError::Mismatch("maximum statement length"));
        }

        let expected_profile_preimage = PROFILE_ID_DOMAIN
            .len()
            .checked_add(PROFILE_ID_DOMAIN_SEPARATOR_BYTES)
            .and_then(|len| len.checked_add(MANIFEST_LENGTH_PREFIX_BYTES))
            .and_then(|len| len.checked_add(self.manifest_bytes))
            .ok_or(InvariantError::ArithmeticOverflow("profile ID preimage"))?;
        if expected_profile_preimage != self.profile_id_preimage_bytes {
            return Err(InvariantError::Mismatch("profile ID preimage"));
        }

        let expected_manifest_bytes = MANIFEST_FORMAT_VERSION_BYTES
            .checked_add(MANIFEST_U32_BYTES)
            .and_then(|len| len.checked_add(MANIFEST_U32_BYTES))
            .and_then(|len| len.checked_add(MANIFEST_OUTER_PO2_BYTES))
            .and_then(|len| len.checked_add(DIGEST_BYTES))
            .and_then(|len| {
                MANIFEST_CONTROL_COUNT
                    .checked_mul(MANIFEST_CONTROL_ENTRY_BYTES)
                    .and_then(|control_bytes| len.checked_add(control_bytes))
            })
            .and_then(|len| {
                2usize
                    .checked_mul(MANIFEST_ARTIFACT_REFERENCE_BYTES)
                    .and_then(|artifact_bytes| len.checked_add(artifact_bytes))
            })
            .ok_or(InvariantError::ArithmeticOverflow("profile manifest"))?;
        if expected_manifest_bytes != self.manifest_bytes {
            return Err(InvariantError::Mismatch("profile manifest"));
        }

        let expected_po2_count = MAX_SEGMENT_PO2
            .checked_sub(MIN_SEGMENT_PO2)
            .map(usize::from)
            .and_then(|difference| difference.checked_add(1))
            .ok_or(InvariantError::ArithmeticOverflow("supported po2 count"))?;
        if self.supported_segment_po2.len() != expected_po2_count {
            return Err(InvariantError::Mismatch("supported po2 count"));
        }
        for (index, po2) in self.supported_segment_po2.iter().copied().enumerate() {
            let expected = MIN_SEGMENT_PO2
                .checked_add(
                    u8::try_from(index)
                        .map_err(|_| InvariantError::ArithmeticOverflow("po2 index"))?,
                )
                .ok_or(InvariantError::ArithmeticOverflow("po2 sequence"))?;
            if po2 != expected {
                return Err(InvariantError::InvalidPo2(index));
            }
        }

        Ok(())
    }
}

/// Validate the selected invariant set.
///
/// # Errors
///
/// Returns the first malformed pin, overflow, or inconsistent relationship.
pub fn validate_pinned_invariants() -> Result<(), InvariantError> {
    PINNED_INVARIANTS.validate()
}

fn validate_static_pins() -> Result<(), InvariantError> {
    if RISC0_REPOSITORY != "https://github.com/risc0/risc0.git"
        || RISC0_COMMIT != "8eb06ab020a92dc5b63ba6dd0836d432aba6d890"
    {
        return Err(InvariantError::InvalidPin("RISC Zero source"));
    }
    if !is_lower_hex(RISC0_COMMIT, 40) {
        return Err(InvariantError::InvalidPin("RISC Zero commit"));
    }

    if GUEST_BUILDER_OCI_REPOSITORY != "risczero/risc0-guest-builder"
        || GUEST_BUILDER_OCI_DIGEST
            != "sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3"
    {
        return Err(InvariantError::InvalidPin("guest-builder OCI image"));
    }
    let oci_hex = GUEST_BUILDER_OCI_DIGEST
        .strip_prefix("sha256:")
        .ok_or(InvariantError::InvalidPin("guest-builder OCI digest"))?;
    if !is_lower_hex(oci_hex, 64) {
        return Err(InvariantError::InvalidPin("guest-builder OCI digest"));
    }
    if GUEST_BUILDER_OCI_PLATFORM != "linux/amd64" {
        return Err(InvariantError::InvalidPin("guest-builder OCI platform"));
    }
    if HOST_RUST_OCI_REPOSITORY != "docker.io/library/rust"
        || HOST_RUST_OCI_DIGEST
            != "sha256:294917190b5a3fed18d3303213943f40ec9b644b3cd6e5cdc8cd029334a770b3"
    {
        return Err(InvariantError::InvalidPin("host Rust OCI image"));
    }
    let host_rust_oci_hex = HOST_RUST_OCI_DIGEST
        .strip_prefix("sha256:")
        .ok_or(InvariantError::InvalidPin("host Rust OCI digest"))?;
    if !is_lower_hex(host_rust_oci_hex, 64) {
        return Err(InvariantError::InvalidPin("host Rust OCI digest"));
    }
    if HOST_RUST_OCI_PLATFORM != "linux/amd64" {
        return Err(InvariantError::InvalidPin("host Rust OCI platform"));
    }
    if HOST_RUST_VERSION != "1.89.0" || GUEST_RUST_VERSION != "1.88.0" {
        return Err(InvariantError::InvalidPin("Rust toolchain version"));
    }
    if VERIFY_STARK_OPCODE != 0xB9 || VERIFY_STARK_ARITY != 4 {
        return Err(InvariantError::InvalidPin("VerifyStark opcode shape"));
    }
    if MANIFEST_FORMAT_VERSION != 0x01
        || RISC0_OUTER_PO2 != 18
        || MANIFEST_CONTROL_COUNT != NORMAL_LIFT_CONTROL_COUNT + 2
        || TERMINAL_CONTROL_KIND_LIFT != 1
        || TERMINAL_CONTROL_KIND_JOIN != 2
        || TERMINAL_CONTROL_KIND_RESOLVE != 3
        || ALGORITHM_ARTIFACT_KIND != 1
        || BINARY_DATA_ARTIFACT_KIND != 2
        || PROFILE_ARTIFACT_DOMAIN != b"Ergo.StarkProfileArtifact.v1"
    {
        return Err(InvariantError::InvalidPin("Manifest V1 scalar grammar"));
    }
    if !is_lower_hex(RISC0_INNER_CONTROL_ROOT_HEX, DIGEST_BYTES * 2) {
        return Err(InvariantError::InvalidPin("RISC Zero inner control root"));
    }
    validate_b4_alternate_pins()?;
    for (index, control_id) in RISC0_NORMAL_LIFT_CONTROL_IDS_HEX
        .iter()
        .copied()
        .enumerate()
    {
        if !is_lower_hex(control_id, DIGEST_BYTES * 2)
            || RISC0_NORMAL_LIFT_CONTROL_IDS_HEX[..index].contains(&control_id)
        {
            return Err(InvariantError::InvalidPin(
                "RISC Zero normal-lift control IDs",
            ));
        }
    }
    if !is_lower_hex(RISC0_JOIN_CONTROL_ID_HEX, DIGEST_BYTES * 2)
        || !is_lower_hex(RISC0_RESOLVE_CONTROL_ID_HEX, DIGEST_BYTES * 2)
        || RISC0_JOIN_CONTROL_ID_HEX == RISC0_RESOLVE_CONTROL_ID_HEX
        || RISC0_NORMAL_LIFT_CONTROL_IDS_HEX.contains(&RISC0_JOIN_CONTROL_ID_HEX)
        || RISC0_NORMAL_LIFT_CONTROL_IDS_HEX.contains(&RISC0_RESOLVE_CONTROL_ID_HEX)
    {
        return Err(InvariantError::InvalidPin(
            "RISC Zero join/resolve control IDs",
        ));
    }

    Ok(())
}

fn validate_b4_alternate_pins() -> Result<(), InvariantError> {
    let mut decoded_root = [0u8; DIGEST_BYTES];
    if !is_lower_hex(B4_ALTERNATE_CONTROL_ROOT_HEX, DIGEST_BYTES * 2)
        || !is_lower_hex(B4_ALTERNATE_OMITTED_CONTROL_ID_HEX, DIGEST_BYTES * 2)
        || !is_lower_hex(B4_ALTERNATE_VERIFIER_PARAMETERS_HEX, DIGEST_BYTES * 2)
        || B4_ALTERNATE_CONTROL_ROOT_HEX == RISC0_INNER_CONTROL_ROOT_HEX
        || hex::decode_to_slice(B4_ALTERNATE_CONTROL_ROOT_HEX, &mut decoded_root).is_err()
        || decoded_root != B4_ALTERNATE_CONTROL_ROOT
    {
        return Err(InvariantError::InvalidPin(
            "B4 fixed alternate control-root witness",
        ));
    }
    Ok(())
}

fn is_lower_hex(value: &str, exact_len: usize) -> bool {
    value.len() == exact_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_constants_satisfy_every_invariant() {
        validate_pinned_invariants().unwrap();
        assert_eq!(PROOF_WORDS * BYTES_PER_PROOF_WORD, PROOF_BYTES);
        assert_eq!(PROOF_CHUNK_LENGTHS.iter().sum::<usize>(), PROOF_BYTES);
        assert_eq!(MAX_STATEMENT_BYTES, 16_543);
        assert_eq!(MANIFEST_BYTES, 458);
        assert_eq!(PROFILE_ID_PREIMAGE_BYTES, 485);
        assert_eq!(MANIFEST_CONTROL_COUNT, 10);
        assert_eq!(MANIFEST_CONTROL_ENTRY_BYTES, 34);
        assert_eq!(MANIFEST_ARTIFACT_REFERENCE_BYTES, 38);
    }

    #[test]
    fn validator_rejects_a_mismatched_proof_length() {
        let mut changed = PINNED_INVARIANTS.clone();
        changed.proof_bytes += 1;
        assert_eq!(
            changed.validate(),
            Err(InvariantError::Mismatch("proof words to bytes"))
        );
    }

    #[test]
    fn validator_rejects_a_noncanonical_partition() {
        let mut changed = PINNED_INVARIANTS.clone();
        changed.proof_chunk_lengths = [65_534, 65_535, 65_535, 26_064];
        assert_eq!(changed.validate(), Err(InvariantError::InvalidChunk(0)));
    }

    #[test]
    fn validator_rejects_a_gap_in_the_po2_set() {
        let mut changed = PINNED_INVARIANTS.clone();
        changed.supported_segment_po2[3] = 19;
        assert_eq!(changed.validate(), Err(InvariantError::InvalidPo2(3)));
    }

    #[test]
    fn profile_and_statement_preimages_have_the_frozen_lengths() {
        assert_eq!(
            ERGO_STATEMENT_DOMAIN.len()
                + ERGO_STATEMENT_VERSION_BYTES
                + ERGO_STATEMENT_BOUND_DIGESTS * DIGEST_BYTES
                + PAYLOAD_LENGTH_PREFIX_BYTES,
            STATEMENT_PREFIX_BYTES
        );
        assert_eq!(
            PROFILE_ID_DOMAIN.len()
                + PROFILE_ID_DOMAIN_SEPARATOR_BYTES
                + MANIFEST_LENGTH_PREFIX_BYTES
                + MANIFEST_BYTES,
            PROFILE_ID_PREIMAGE_BYTES
        );
    }
}
