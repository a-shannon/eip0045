//! Shared, bounded codec contract for non-consensus RISC Zero receipt oracles.
//!
//! The byte format is reproduction evidence only. It is deliberately kept out
//! of the consensus profile and is shared by every producer and replay
//! consumer so the legacy bincode configuration cannot drift.

/// Maximum byte length of one receipt-oracle artifact.
pub const RECEIPT_ORACLE_MAX_BYTES: usize = 1024 * 1024;
/// Same receipt-oracle cap in the integer width required by bincode 1.3.3.
pub const RECEIPT_ORACLE_MAX_BYTES_U64: u64 = 1024 * 1024;
/// Complete interoperable identifier for the frozen receipt-oracle codec.
pub const RECEIPT_ORACLE_CODEC_V1: &str =
    "bincode-1.3.3-fixint-little-endian-reject-trailing-limit-1048576";

/// Return the single producer/consumer codec for receipt-oracle artifacts.
///
/// This reproduces bincode 1.3.3's legacy top-level encoding: fixed-width
/// integers, little-endian byte order, exact end of input, and the frozen
/// one-MiB limit.
#[cfg(feature = "receipt-oracle-codec")]
#[must_use]
pub fn receipt_oracle_bincode_options() -> impl bincode::Options {
    use bincode::Options as _;

    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
        .with_limit(RECEIPT_ORACLE_MAX_BYTES_U64)
}

const _: () = {
    assert!(RECEIPT_ORACLE_MAX_BYTES as u64 == RECEIPT_ORACLE_MAX_BYTES_U64);
};
