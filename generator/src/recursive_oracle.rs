//! Bounded Borsh ancestry codec, usable without a prover or embedded guest.
//!
//! These types and their wire order are shared with the recursion producer.
//! Decoding or comparing bytes does not verify a proof, authenticate provenance,
//! or establish campaign authority.

use anyhow::{Context, Result, ensure};
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::{Receipt, ReceiptClaim, SuccinctReceipt};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Maximum encoded size of the candidate-only ancestry oracle.
pub const RECURSIVE_ORACLE_MAX_BYTES: usize = 32 * 1024 * 1024;

/// The three additional pre-activation receipt families required by B4.
#[derive(
    BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum RecursiveFamily {
    /// Exactly two execution segments, ending in stock `join.zkr`.
    TerminalJoin,
    /// One conditional segment, ending in stock `resolve.zkr`.
    TerminalResolve,
    /// A resolved second segment joined to the first, ending in `join.zkr`.
    ResolveThenJoin,
}

/// One stock recursion program invoked while constructing the final receipt.
#[derive(
    BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum RecursiveOperation {
    /// Lift one RV32IM segment receipt.
    Lift,
    /// Join two adjacent continuation receipts.
    Join,
    /// Resolve the one recorded receipt assumption.
    Resolve,
}

/// Exact upstream inputs consumed by one recorded recursion operation.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "kind", deny_unknown_fields)]
pub enum RecursiveInputs {
    /// Lift the source composite's segment at `segment_index`.
    Lift {
        /// Zero-based source composite segment index.
        segment_index: u32,
    },
    /// Join two earlier ancestry steps.
    Join {
        /// Earlier step proving the left continuation span.
        left_step: u32,
        /// Earlier step proving the adjacent right continuation span.
        right_step: u32,
    },
    /// Resolve the exported assumption receipt from one conditional step.
    Resolve {
        /// Earlier step whose claim contains the required assumption.
        conditional_step: u32,
    },
}

/// One replayable intermediate succinct receipt.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecursiveStep {
    /// Zero-based ordinal in the deterministic ancestry graph.
    pub ordinal: u32,
    /// Stock recursion operation which produced this receipt.
    pub operation: RecursiveOperation,
    /// Exact graph inputs for this operation.
    pub inputs: RecursiveInputs,
    /// Full upstream succinct receipt produced at this step.
    pub receipt: SuccinctReceipt<ReceiptClaim>,
}

/// Complete replayable source and ancestry archive for one candidate.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecursiveOracle {
    /// Candidate schema version. This is not a consensus version.
    pub format_version: u8,
    /// Requested recursive family.
    pub family: RecursiveFamily,
    /// Full composite receipt whose segments and assumption receipts are consumed.
    pub source_receipt: Receipt,
    /// Independent same-program receipt used to resolve the conditional execution.
    pub assumption_receipt: Option<Receipt>,
    /// Every upstream-produced intermediate succinct receipt in execution order.
    pub steps: Vec<RecursiveStep>,
    /// Ordinal of the final receipt in `steps`.
    pub final_step: u32,
}

/// Encode one candidate ancestry oracle with upstream-supported Borsh.
///
/// # Errors
///
/// Returns an error if serialization fails or the result exceeds the fixed
/// candidate-only byte limit.
pub fn encode_recursive_oracle(oracle: &RecursiveOracle) -> Result<Vec<u8>> {
    let bytes =
        borsh::to_vec(oracle).context("cannot encode recursive ancestry oracle as Borsh")?;
    ensure!(
        bytes.len() <= RECURSIVE_ORACLE_MAX_BYTES,
        "recursive ancestry oracle exceeds its byte limit"
    );
    Ok(bytes)
}

/// Decode one exact, bounded candidate ancestry oracle encoded with Borsh.
///
/// # Errors
///
/// Returns an error if the input exceeds the byte limit, is malformed, or has
/// trailing bytes. `borsh::from_slice` requires exact end of input.
pub fn decode_recursive_oracle(bytes: &[u8]) -> Result<RecursiveOracle> {
    ensure!(
        bytes.len() <= RECURSIVE_ORACLE_MAX_BYTES,
        "recursive ancestry oracle exceeds its byte limit"
    );
    borsh::from_slice(bytes).context("cannot decode recursive ancestry oracle as exact Borsh")
}

/// Exact identity of a complete outer Receipt encoded with Borsh.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AssumptionByteIdentity {
    /// Length of the complete serialized outer Receipt, not its raw seal.
    pub bytes: usize,
    /// SHA-256 of those complete Borsh bytes.
    pub sha256: [u8; 32],
}

impl AssumptionByteIdentity {
    fn of(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.len(),
            sha256: Sha256::digest(bytes).into(),
        }
    }
}

/// Compare the two retained finals against an independently supplied original.
///
/// This checks byte identity only. The caller separately owns proof acceptance,
/// the provenance of each input pin, and the identity of the original receipt.
///
/// # Errors
///
/// Fails if either oracle is malformed or does not match its final-branch role,
/// their complete assumption bytes differ, or the original identity differs.
pub fn compare_retained_assumption_bytes(
    resolve: &[u8],
    resolve_join: &[u8],
    original: AssumptionByteIdentity,
) -> Result<AssumptionByteIdentity> {
    ensure!(
        (1..=RECURSIVE_ORACLE_MAX_BYTES).contains(&original.bytes),
        "original assumption length is outside the byte limit"
    );
    let left = retained_assumption_bytes(resolve, RecursiveFamily::TerminalResolve)?;
    let right = retained_assumption_bytes(resolve_join, RecursiveFamily::ResolveThenJoin)?;
    ensure!(left == right, "pair assumption bytes differ");
    let actual = AssumptionByteIdentity::of(&left);
    ensure!(actual == original, "original assumption identity differs");
    Ok(actual)
}

fn retained_assumption_bytes(bytes: &[u8], expected_family: RecursiveFamily) -> Result<Vec<u8>> {
    let oracle = decode_recursive_oracle(bytes)?;
    ensure!(
        oracle.format_version == 2,
        "retained oracle version differs"
    );
    ensure!(
        oracle.family == expected_family,
        "retained oracle family differs"
    );
    ensure!(
        encode_recursive_oracle(&oracle)? == bytes,
        "retained oracle encoding differs"
    );
    let receipt = oracle
        .assumption_receipt
        .context("missing retained assumption")?;
    borsh::to_vec(&receipt).context("cannot encode complete retained assumption")
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::ToTokens as _;
    use risc0_zkvm::{Digest, FakeReceipt, InnerReceipt};

    #[test]
    fn embedded_consumer_retains_required_borsh_trait_import() {
        // This consumer is not compiled in the lightweight test configuration.
        // Preserve its existing trait dependency when relocating wire types.
        let source = syn::parse_file(include_str!("recursive.rs")).unwrap();
        assert!(source.items.iter().any(|item| {
            matches!(item, syn::Item::Use(import)
                if import.tree.to_token_stream().to_string() == "borsh :: BorshDeserialize"
                && import.attrs.iter().any(|attribute|
                    attribute.to_token_stream().to_string().contains("embedded-method")))
        }), "embedded Receipt::try_from_slice requires its BorshDeserialize import");
    }

    // Serialization fixtures only. No fake receipt is used as proof evidence.
    fn receipt() -> Receipt {
        Receipt::new(
            InnerReceipt::Fake(FakeReceipt::new(ReceiptClaim::ok(Digest::ZERO, Vec::new()))),
            Vec::new(),
        )
    }

    fn oracle(family: RecursiveFamily, assumption: Receipt) -> Vec<u8> {
        encode_recursive_oracle(&RecursiveOracle {
            format_version: 2,
            family,
            source_receipt: receipt(),
            assumption_receipt: Some(assumption),
            steps: Vec::new(),
            final_step: 0,
        })
        .unwrap()
    }

    #[test]
    fn compares_complete_original_receipt_bytes() {
        let shared = receipt();
        let original = AssumptionByteIdentity::of(&borsh::to_vec(&shared).unwrap());
        let resolve = oracle(RecursiveFamily::TerminalResolve, shared.clone());
        let join = oracle(RecursiveFamily::ResolveThenJoin, shared);
        assert_eq!(
            compare_retained_assumption_bytes(&resolve, &join, original).unwrap(),
            original
        );
    }

    #[test]
    fn rejects_equal_claim_with_different_outer_receipt() {
        let shared = receipt();
        let original = AssumptionByteIdentity::of(&borsh::to_vec(&shared).unwrap());
        let mut replacement = shared.clone();
        replacement.metadata.verifier_parameters = Digest::from([1_u32; 8]);
        assert_eq!(
            borsh::to_vec(&shared.inner).unwrap(),
            borsh::to_vec(&replacement.inner).unwrap(),
        );
        let resolve = oracle(RecursiveFamily::TerminalResolve, shared);
        let join = oracle(RecursiveFamily::ResolveThenJoin, replacement);
        let error = compare_retained_assumption_bytes(&resolve, &join, original).unwrap_err();
        assert!(
            error.to_string().contains("pair assumption bytes differ"),
            "{error:#}"
        );
    }

    fn pair() -> (Vec<u8>, Vec<u8>, AssumptionByteIdentity) {
        let shared = receipt();
        let original = AssumptionByteIdentity::of(&borsh::to_vec(&shared).unwrap());
        (
            oracle(RecursiveFamily::TerminalResolve, shared.clone()),
            oracle(RecursiveFamily::ResolveThenJoin, shared),
            original,
        )
    }

    #[test]
    fn rejects_coordinated_pair_replacement_against_original() {
        let (_, _, original) = pair();
        let mut changed = receipt();
        changed.metadata.verifier_parameters = Digest::from([1_u32; 8]);
        let left = oracle(RecursiveFamily::TerminalResolve, changed.clone());
        let right = oracle(RecursiveFamily::ResolveThenJoin, changed);
        assert_eq!(
            compare_retained_assumption_bytes(&left, &right, original)
                .unwrap_err()
                .to_string(),
            "original assumption identity differs"
        );
    }

    #[test]
    fn rejects_each_original_identity_field() {
        let (left, right, original) = pair();
        let mut changed = original;
        changed.bytes += 1;
        assert_eq!(
            compare_retained_assumption_bytes(&left, &right, changed)
                .unwrap_err()
                .to_string(),
            "original assumption identity differs"
        );
        let mut changed = original;
        changed.sha256[0] ^= 1;
        assert_eq!(
            compare_retained_assumption_bytes(&left, &right, changed)
                .unwrap_err()
                .to_string(),
            "original assumption identity differs"
        );
        for bytes in [0, RECURSIVE_ORACLE_MAX_BYTES + 1, usize::MAX] {
            assert_eq!(
                compare_retained_assumption_bytes(
                    &left,
                    &right,
                    AssumptionByteIdentity { bytes, ..original }
                )
                .unwrap_err()
                .to_string(),
                "original assumption length is outside the byte limit"
            );
        }
    }

    #[test]
    fn rejects_each_branch_role_version_and_missing_assumption() {
        let (left, right, original) = pair();
        for side in 0..2 {
            let base = if side == 0 { &left } else { &right };
            for fault in 0..3 {
                let mut changed = decode_recursive_oracle(base).unwrap();
                let expected = match fault {
                    0 => {
                        changed.family = RecursiveFamily::TerminalJoin;
                        "retained oracle family differs"
                    }
                    1 => {
                        changed.format_version = 3;
                        "retained oracle version differs"
                    }
                    _ => {
                        changed.assumption_receipt = None;
                        "missing retained assumption"
                    }
                };
                let changed = encode_recursive_oracle(&changed).unwrap();
                let result = if side == 0 {
                    compare_retained_assumption_bytes(&changed, &right, original)
                } else {
                    compare_retained_assumption_bytes(&left, &changed, original)
                };
                assert_eq!(
                    result.unwrap_err().to_string(),
                    expected,
                    "side={side} fault={fault}"
                );
            }
        }
        assert_eq!(
            compare_retained_assumption_bytes(&right, &left, original)
                .unwrap_err()
                .to_string(),
            "retained oracle family differs"
        );
    }

    #[test]
    fn rejects_each_malformed_trailing_empty_and_oversized_oracle() {
        let (left, right, original) = pair();
        for side in 0..2 {
            let base = if side == 0 { &left } else { &right };
            let mut trailing = base.clone();
            trailing.push(0);
            for changed in [
                Vec::new(),
                base[..base.len() - 1].to_vec(),
                trailing,
                vec![0; RECURSIVE_ORACLE_MAX_BYTES + 1],
            ] {
                let expected = if changed.len() > RECURSIVE_ORACLE_MAX_BYTES {
                    "recursive ancestry oracle exceeds its byte limit"
                } else {
                    "cannot decode recursive ancestry oracle as exact Borsh"
                };
                let result = if side == 0 {
                    compare_retained_assumption_bytes(&changed, &right, original)
                } else {
                    compare_retained_assumption_bytes(&left, &changed, original)
                };
                assert_eq!(result.unwrap_err().to_string(), expected, "side={side}");
            }
        }
    }
}
