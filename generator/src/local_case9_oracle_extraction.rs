//! Exact byte conversion for the two retained Case-9 direct receipt oracles.
//!
//! Source-pin admission belongs to the caller. Extraction checks wire shape and
//! retained raw-seal equality, not cryptographic validity, provenance or custody.
//! The downstream genuine consumer must independently authenticate both receipts.

use anyhow::{Context as _, Result, ensure};
use eip_0045_reproduction::constants::PROOF_BYTES;
use risc0_zkvm::InnerReceipt;

use crate::{
    receipt_oracle_wire::encode_succinct_receipt_oracle,
    recursive_oracle::{RecursiveFamily, RecursiveInputs, RecursiveOperation,
        decode_recursive_oracle, encode_recursive_oracle},
};

/// Direct receipt encodings only; neither field confers proof or campaign authority.
pub struct Case9DirectOracles {
    /// Direct succinct encoding extracted from the retained outer assumption.
    pub assumption_oracle: Vec<u8>,
    /// Direct succinct encoding extracted from the retained final Resolve step.
    pub final_resolve_oracle: Vec<u8>,
}

/// Convert the two exact retained Case-9 succinct receipts using the existing codec.
///
/// The fixed Case-9 graph and complete raw-seal byte equality are checked before
/// either encoding is returned. Selected claims must be revealed for the later
/// direct-receipt consumer; their contents are not authenticated here.
///
/// # Errors
///
/// Rejects incorrect raw sizes, malformed or nonexact Borsh, another graph shape,
/// missing/non-succinct assumptions, pruned selected claims, raw-byte drift, or
/// failure of the existing direct-receipt codec round trip.
pub fn extract_case9_direct_oracles(
    recursive_borsh: &[u8],
    assumption_raw: &[u8],
    final_raw: &[u8],
) -> Result<Case9DirectOracles> {
    ensure!(assumption_raw.len() == PROOF_BYTES, "Case-9 assumption raw length differs");
    ensure!(final_raw.len() == PROOF_BYTES, "Case-9 final raw length differs");
    let oracle = decode_recursive_oracle(recursive_borsh)?;
    ensure!(encode_recursive_oracle(&oracle)? == recursive_borsh,
        "Case-9 ancestry Borsh round trip differs");
    ensure!(oracle.format_version == 2, "Case-9 ancestry version differs");
    ensure!(oracle.family == RecursiveFamily::TerminalResolve, "Case-9 ancestry family differs");
    ensure!(oracle.steps.len() == 2, "Case-9 ancestry step count differs");
    ensure!(oracle.final_step == 1, "Case-9 ancestry final-step index differs");
    let lift = &oracle.steps[0];
    let resolve = &oracle.steps[1];
    ensure!(lift.ordinal == 0, "Case-9 Lift ordinal differs");
    ensure!(lift.operation == RecursiveOperation::Lift, "Case-9 Lift operation differs");
    ensure!(lift.inputs == (RecursiveInputs::Lift { segment_index: 0 }),
        "Case-9 Lift input differs");
    ensure!(resolve.ordinal == 1, "Case-9 Resolve ordinal differs");
    ensure!(resolve.operation == RecursiveOperation::Resolve, "Case-9 Resolve operation differs");
    ensure!(resolve.inputs == (RecursiveInputs::Resolve { conditional_step: 0 }),
        "Case-9 Resolve input differs");
    let assumption = oracle.assumption_receipt.as_ref().context("Case-9 assumption is missing")?;
    let InnerReceipt::Succinct(assumption) = &assumption.inner else {
        anyhow::bail!("Case-9 assumption is not succinct");
    };
    assumption.claim.as_value().map_err(|_| anyhow::anyhow!("Case-9 assumption claim is pruned"))?;
    resolve.receipt.claim.as_value().map_err(|_| anyhow::anyhow!("Case-9 final claim is pruned"))?;
    ensure!(assumption.get_seal_bytes() == assumption_raw, "Case-9 assumption raw bytes differ");
    ensure!(resolve.receipt.get_seal_bytes() == final_raw, "Case-9 final raw bytes differ");
    Ok(Case9DirectOracles {
        assumption_oracle: encode_succinct_receipt_oracle(assumption)?,
        final_resolve_oracle: encode_succinct_receipt_oracle(&resolve.receipt)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{receipt_oracle_wire::decode_succinct_receipt_oracle,
        recursive_oracle::{RECURSIVE_ORACLE_MAX_BYTES, RecursiveOracle, RecursiveStep}};
    use risc0_zkvm::{Digest, MaybePruned, Receipt, ReceiptClaim, SuccinctReceipt};

    // Serde wire fixtures only: these seals are deliberately not cryptographic proofs.
    // MerkleGroup and all prover-only APIs stay out of this no-proving module.
    fn succinct(tag: u32) -> SuccinctReceipt<ReceiptClaim> {
        serde_json::from_value(serde_json::json!({
            "seal": vec![tag; PROOF_BYTES / 4],
            "control_id": Digest::ZERO,
            "claim": MaybePruned::Value(ReceiptClaim::ok(Digest::ZERO, vec![tag as u8])),
            "hashfn": "poseidon2",
            "verifier_parameters": Digest::ZERO,
            "control_inclusion_proof": {"index": 0, "digests": []},
        })).unwrap()
    }

    fn fixture() -> RecursiveOracle {
        let assumption = Receipt::new(InnerReceipt::Succinct(succinct(1)), vec![1]);
        RecursiveOracle {
            format_version: 2,
            family: RecursiveFamily::TerminalResolve,
            source_receipt: assumption.clone(),
            assumption_receipt: Some(assumption),
            steps: vec![
                RecursiveStep { ordinal: 0, operation: RecursiveOperation::Lift,
                    inputs: RecursiveInputs::Lift { segment_index: 0 }, receipt: succinct(2) },
                RecursiveStep { ordinal: 1, operation: RecursiveOperation::Resolve,
                    inputs: RecursiveInputs::Resolve { conditional_step: 0 }, receipt: succinct(3) },
            ],
            final_step: 1,
        }
    }

    fn raw(oracle: &RecursiveOracle) -> (Vec<u8>, Vec<u8>) {
        let InnerReceipt::Succinct(assumption) = &oracle.assumption_receipt.as_ref().unwrap().inner else {
            panic!("serialization fixture assumption must be succinct")
        };
        (assumption.get_seal_bytes(), oracle.steps[1].receipt.get_seal_bytes())
    }

    fn reject(oracle: &RecursiveOracle, assumption: &[u8], final_raw: &[u8], message: &str) {
        let encoded = encode_recursive_oracle(oracle).unwrap();
        let error = extract_case9_direct_oracles(&encoded, assumption, final_raw).err().unwrap();
        assert_eq!(error.to_string(), message);
    }

    #[test]
    fn serialization_only_extraction_preserves_exact_selected_receipts() {
        let oracle = fixture();
        let (assumption, final_raw) = raw(&oracle);
        let output = extract_case9_direct_oracles(&encode_recursive_oracle(&oracle).unwrap(), &assumption, &final_raw).unwrap();
        let InnerReceipt::Succinct(expected) = &oracle.assumption_receipt.as_ref().unwrap().inner else { unreachable!() };
        assert_eq!(output.assumption_oracle, encode_succinct_receipt_oracle(expected).unwrap());
        assert_eq!(output.final_resolve_oracle, encode_succinct_receipt_oracle(&oracle.steps[1].receipt).unwrap());
        assert_ne!(output.assumption_oracle, output.final_resolve_oracle);
        assert_eq!(decode_succinct_receipt_oracle::<ReceiptClaim>(&output.assumption_oracle).unwrap().get_seal_bytes(), assumption);
        assert_eq!(decode_succinct_receipt_oracle::<ReceiptClaim>(&output.final_resolve_oracle).unwrap().get_seal_bytes(), final_raw);
    }

    #[test]
    fn each_raw_binding_and_role_swap_is_independently_rejected() {
        let oracle = fixture();
        let (assumption, final_raw) = raw(&oracle);
        let mut changed = assumption.clone(); changed[0] ^= 1;
        reject(&oracle, &changed, &final_raw, "Case-9 assumption raw bytes differ");
        let mut changed = final_raw.clone(); changed[0] ^= 1;
        reject(&oracle, &assumption, &changed, "Case-9 final raw bytes differ");
        reject(&oracle, &final_raw, &assumption, "Case-9 assumption raw bytes differ");
        reject(&oracle, &assumption[..PROOF_BYTES - 1], &final_raw, "Case-9 assumption raw length differs");
        reject(&oracle, &assumption, &final_raw[..PROOF_BYTES - 1], "Case-9 final raw length differs");
        let mut changed = assumption.clone(); changed.push(0);
        reject(&oracle, &changed, &final_raw, "Case-9 assumption raw length differs");
        let mut changed = final_raw.clone(); changed.push(0);
        reject(&oracle, &assumption, &changed, "Case-9 final raw length differs");
    }

    #[test]
    fn each_closed_graph_field_rejects_without_changing_other_inputs() {
        let original = fixture();
        let (assumption, final_raw) = raw(&original);
        let mut changed = original.clone(); changed.format_version = 1;
        reject(&changed, &assumption, &final_raw, "Case-9 ancestry version differs");
        for family in [RecursiveFamily::TerminalJoin, RecursiveFamily::ResolveThenJoin] {
            let mut changed = original.clone(); changed.family = family;
            reject(&changed, &assumption, &final_raw, "Case-9 ancestry family differs");
        }
        let mut changed = original.clone(); changed.steps.pop();
        reject(&changed, &assumption, &final_raw, "Case-9 ancestry step count differs");
        let mut changed = original.clone(); changed.steps.push(original.steps[0].clone());
        reject(&changed, &assumption, &final_raw, "Case-9 ancestry step count differs");
        let mut changed = original.clone(); changed.final_step = 0;
        reject(&changed, &assumption, &final_raw, "Case-9 ancestry final-step index differs");
        let mut changed = original.clone(); changed.steps[0].ordinal = 1;
        reject(&changed, &assumption, &final_raw, "Case-9 Lift ordinal differs");
        let mut changed = original.clone(); changed.steps[1].ordinal = 0;
        reject(&changed, &assumption, &final_raw, "Case-9 Resolve ordinal differs");
        let mut changed = original.clone(); changed.steps[0].operation = RecursiveOperation::Join;
        reject(&changed, &assumption, &final_raw, "Case-9 Lift operation differs");
        let mut changed = original.clone(); changed.steps[1].operation = RecursiveOperation::Join;
        reject(&changed, &assumption, &final_raw, "Case-9 Resolve operation differs");
        let mut changed = original.clone(); changed.steps[0].inputs = RecursiveInputs::Lift { segment_index: 1 };
        reject(&changed, &assumption, &final_raw, "Case-9 Lift input differs");
        let mut changed = original.clone(); changed.steps[1].inputs = RecursiveInputs::Resolve { conditional_step: 1 };
        reject(&changed, &assumption, &final_raw, "Case-9 Resolve input differs");
        let mut changed = original.clone(); changed.steps[0].inputs = RecursiveInputs::Resolve { conditional_step: 0 };
        reject(&changed, &assumption, &final_raw, "Case-9 Lift input differs");
        let mut changed = original.clone(); changed.steps[1].inputs = RecursiveInputs::Lift { segment_index: 0 };
        reject(&changed, &assumption, &final_raw, "Case-9 Resolve input differs");
        let mut changed = original.clone(); changed.assumption_receipt = None;
        reject(&changed, &assumption, &final_raw, "Case-9 assumption is missing");
    }

    #[test]
    fn nonsuccinct_serialization_fixture_is_rejected_not_used_as_proof() {
        let mut oracle = fixture();
        let (assumption, final_raw) = raw(&oracle);
        // Fake is a deliberately rejected enum-shape fixture, never proof evidence.
        oracle.assumption_receipt.as_mut().unwrap().inner = InnerReceipt::Fake(
            risc0_zkvm::FakeReceipt::new(ReceiptClaim::ok(Digest::ZERO, vec![1])));
        reject(&oracle, &assumption, &final_raw, "Case-9 assumption is not succinct");
    }

    #[test]
    fn selected_pruned_claims_are_rejected_before_direct_encoding() {
        let original = fixture();
        let (assumption, final_raw) = raw(&original);
        let mut changed = original.clone();
        let InnerReceipt::Succinct(inner) = &mut changed.assumption_receipt.as_mut().unwrap().inner else { unreachable!() };
        inner.claim = MaybePruned::Pruned(Digest::ZERO);
        reject(&changed, &assumption, &final_raw, "Case-9 assumption claim is pruned");
        let mut changed = original.clone(); changed.steps[1].receipt.claim = MaybePruned::Pruned(Digest::ZERO);
        reject(&changed, &assumption, &final_raw, "Case-9 final claim is pruned");
    }

    #[test]
    fn malformed_trailing_and_oversized_borsh_never_convert() {
        let oracle = fixture();
        let (assumption, final_raw) = raw(&oracle);
        let mut encoded = encode_recursive_oracle(&oracle).unwrap(); encoded.push(0);
        assert!(extract_case9_direct_oracles(&encoded, &assumption, &final_raw).is_err());
        assert!(extract_case9_direct_oracles(&[], &assumption, &final_raw).is_err());
        let oversized = vec![0; RECURSIVE_ORACLE_MAX_BYTES + 1];
        assert_eq!(extract_case9_direct_oracles(&oversized, &assumption, &final_raw).err().unwrap().to_string(),
            "recursive ancestry oracle exceeds its byte limit");
    }
}
