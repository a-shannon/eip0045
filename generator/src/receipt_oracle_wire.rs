use anyhow::{Context, Result, ensure};
use bincode::Options as _;
use eip_0045_reproduction::receipt_oracle_codec::{
    RECEIPT_ORACLE_MAX_BYTES as CANDIDATE_RECEIPT_ORACLE_MAX_BYTES, receipt_oracle_bincode_options,
};
#[cfg(feature = "proof-generation")]
use risc0_zkvm::recursion::MerkleProof;
use risc0_zkvm::{Digest, MaybePruned, Receipt, SuccinctReceipt, sha::Digestible};
use serde::{Serialize, de::DeserializeOwned};

#[cfg(feature = "proof-generation")]
// The binary consumes this now; the next terminal-producer tranche will make
// the library call it too and must remove this transitional allowance.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Serialize)]
struct SuccinctReceiptAssembly<Claim> {
    seal: Vec<u32>,
    control_id: Digest,
    claim: MaybePruned<Claim>,
    hashfn: String,
    verifier_parameters: Digest,
    control_inclusion_proof: MerkleProof,
}

#[cfg(feature = "proof-generation")]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn assemble_succinct_receipt<Claim>(
    seal: Vec<u32>,
    control_id: Digest,
    claim: MaybePruned<Claim>,
    hashfn: String,
    verifier_parameters: Digest,
    control_inclusion_proof: MerkleProof,
) -> Result<SuccinctReceipt<Claim>>
where
    Claim: Serialize + Digestible,
    SuccinctReceipt<Claim>: Serialize + DeserializeOwned,
{
    let expected_seal = seal.clone();
    let expected_claim_digest = maybe_pruned_digest(&claim);
    let expected_hashfn = hashfn.clone();
    let expected_inclusion_index = control_inclusion_proof.index;
    let expected_inclusion_digests = control_inclusion_proof.digests.clone();
    let source = receipt_oracle_bincode_options()
        .serialize(&SuccinctReceiptAssembly {
            seal,
            control_id,
            claim,
            hashfn,
            verifier_parameters,
            control_inclusion_proof,
        })
        .context("cannot encode succinct receipt assembly")?;
    require_oracle_byte_bound(&source, "succinct receipt assembly")?;
    let receipt: SuccinctReceipt<Claim> = receipt_oracle_bincode_options()
        .deserialize(&source)
        .context("cannot decode succinct receipt assembly")?;
    let round_trip = receipt_oracle_bincode_options()
        .serialize(&receipt)
        .context("cannot re-encode succinct receipt assembly")?;
    ensure!(
        round_trip == source,
        "succinct receipt assembly changed across its frozen typed wire"
    );
    ensure!(
        receipt.seal == expected_seal
            && receipt.control_id == control_id
            && maybe_pruned_digest(&receipt.claim) == expected_claim_digest
            && receipt.hashfn == expected_hashfn
            && receipt.verifier_parameters == verifier_parameters
            && receipt.control_inclusion_proof.index == expected_inclusion_index
            && receipt.control_inclusion_proof.digests == expected_inclusion_digests,
        "succinct receipt assembly changed a supplied public field"
    );
    Ok(receipt)
}

pub(crate) fn encode_succinct_receipt_oracle<Claim>(
    receipt: &SuccinctReceipt<Claim>,
) -> Result<Vec<u8>>
where
    Claim: Digestible,
    SuccinctReceipt<Claim>: Serialize + DeserializeOwned,
{
    let source = receipt_oracle_bincode_options()
        .serialize(receipt)
        .context("cannot encode direct succinct receipt oracle")?;
    require_oracle_byte_bound(&source, "direct succinct receipt oracle")?;
    let decoded = decode_succinct_receipt_oracle(&source)?;
    require_same_succinct_public_fields(receipt, &decoded)?;
    Ok(source)
}

pub(crate) fn decode_succinct_receipt_oracle<Claim>(source: &[u8]) -> Result<SuccinctReceipt<Claim>>
where
    Claim: Digestible,
    SuccinctReceipt<Claim>: Serialize + DeserializeOwned,
{
    require_oracle_byte_bound(source, "direct succinct receipt oracle")?;
    let receipt: SuccinctReceipt<Claim> = receipt_oracle_bincode_options()
        .deserialize(source)
        .context("cannot decode the direct succinct receipt oracle exactly")?;
    let round_trip = receipt_oracle_bincode_options()
        .serialize(&receipt)
        .context("cannot re-encode the direct succinct receipt oracle")?;
    ensure!(
        round_trip == source,
        "direct succinct receipt oracle changed across its frozen typed wire"
    );
    Ok(receipt)
}

pub(crate) fn decode_outer_receipt_oracle(source: &[u8]) -> Result<Receipt> {
    require_oracle_byte_bound(source, "outer receipt oracle")?;
    let receipt: Receipt = receipt_oracle_bincode_options()
        .deserialize(source)
        .context("cannot decode the outer receipt oracle exactly")?;
    let round_trip = receipt_oracle_bincode_options()
        .serialize(&receipt)
        .context("cannot re-encode the outer receipt oracle")?;
    ensure!(
        round_trip == source,
        "outer receipt oracle changed across its frozen typed wire"
    );
    Ok(receipt)
}

fn require_oracle_byte_bound(source: &[u8], label: &str) -> Result<()> {
    ensure!(
        (1..=CANDIDATE_RECEIPT_ORACLE_MAX_BYTES).contains(&source.len()),
        "{label} is outside the closed nonempty one-MiB byte bound"
    );
    Ok(())
}

fn require_same_succinct_public_fields<Claim>(
    expected: &SuccinctReceipt<Claim>,
    actual: &SuccinctReceipt<Claim>,
) -> Result<()>
where
    Claim: Digestible,
{
    ensure!(
        actual.seal == expected.seal
            && actual.control_id == expected.control_id
            && maybe_pruned_digest(&actual.claim) == maybe_pruned_digest(&expected.claim)
            && actual.hashfn == expected.hashfn
            && actual.verifier_parameters == expected.verifier_parameters
            && actual.control_inclusion_proof.index == expected.control_inclusion_proof.index
            && actual.control_inclusion_proof.digests == expected.control_inclusion_proof.digests,
        "direct succinct receipt changed across its typed round trip"
    );
    Ok(())
}

fn maybe_pruned_digest<Claim>(claim: &MaybePruned<Claim>) -> Digest
where
    Claim: Digestible,
{
    match claim {
        MaybePruned::Value(value) => value.digest(),
        MaybePruned::Pruned(digest) => *digest,
    }
}

#[cfg(all(test, feature = "proof-generation"))]
mod tests {
    use bincode::Options as _;
    use risc0_zkvm::{
        Digest, MaybePruned, ReceiptClaim, SuccinctReceipt, UnionClaim, VerifierContext, WorkClaim,
        recursion::MerkleGroup, sha::Digestible,
    };
    use serde::{Serialize, de::DeserializeOwned};

    use super::{
        CANDIDATE_RECEIPT_ORACLE_MAX_BYTES, assemble_succinct_receipt, decode_outer_receipt_oracle,
        decode_succinct_receipt_oracle, encode_succinct_receipt_oracle,
        receipt_oracle_bincode_options,
    };

    fn fixture_receipt<Claim>(claim: Claim) -> SuccinctReceipt<Claim>
    where
        Claim: Serialize + risc0_zkvm::sha::Digestible,
        SuccinctReceipt<Claim>: Serialize + DeserializeOwned,
    {
        let group = MerkleGroup::new(vec![Digest::from([3_u32; 8])]).unwrap();
        let suites = VerifierContext::default_hash_suites();
        let suite = suites.get("poseidon2").unwrap();
        assemble_succinct_receipt(
            vec![0, 1, 2, 3],
            Digest::from([1_u32; 8]),
            MaybePruned::Value(claim),
            "poseidon2".to_owned(),
            Digest::from([2_u32; 8]),
            group.get_proof_by_index(0, suite.hashfn.as_ref()),
        )
        .unwrap()
    }

    fn require_exact_round_trip<Claim>(receipt: &SuccinctReceipt<Claim>)
    where
        Claim: risc0_zkvm::sha::Digestible,
        SuccinctReceipt<Claim>: Serialize + DeserializeOwned,
    {
        let encoded = encode_succinct_receipt_oracle(receipt).unwrap();
        assert!((1..=CANDIDATE_RECEIPT_ORACLE_MAX_BYTES).contains(&encoded.len()));
        let decoded = decode_succinct_receipt_oracle::<Claim>(&encoded).unwrap();
        assert_eq!(
            receipt_oracle_bincode_options()
                .serialize(&decoded)
                .unwrap(),
            encoded
        );
    }

    #[test]
    fn generic_receipt_wire_round_trips_direct_work_and_union_claims() {
        let application = ReceiptClaim::ok(Digest::from([7_u32; 8]), b"journal".to_vec());
        let direct = fixture_receipt(application.clone());
        let work = fixture_receipt(WorkClaim {
            claim: MaybePruned::Value(application.clone()),
            work: MaybePruned::Pruned(Digest::from([8_u32; 8])),
        });
        let union = fixture_receipt(UnionClaim {
            left: application.digest(),
            right: Digest::from([9_u32; 8]),
        });

        require_exact_round_trip(&direct);
        require_exact_round_trip(&work);
        require_exact_round_trip(&union);
    }

    #[test]
    fn generic_receipt_wire_rejects_trailing_bytes_and_wrong_typed_decode() {
        let direct = fixture_receipt(ReceiptClaim::ok(
            Digest::from([7_u32; 8]),
            b"journal".to_vec(),
        ));
        let mut encoded = encode_succinct_receipt_oracle(&direct).unwrap();
        encoded.push(0);
        assert!(decode_succinct_receipt_oracle::<ReceiptClaim>(&encoded).is_err());

        let exact = encode_succinct_receipt_oracle(&direct).unwrap();
        assert!(decode_succinct_receipt_oracle::<UnionClaim>(&exact).is_err());
    }

    #[test]
    fn generic_receipt_wire_rejects_empty_and_over_cap_sources_before_decode() {
        assert!(decode_succinct_receipt_oracle::<ReceiptClaim>(&[]).is_err());
        let oversized = vec![0_u8; CANDIDATE_RECEIPT_ORACLE_MAX_BYTES + 1];
        assert!(decode_succinct_receipt_oracle::<ReceiptClaim>(&oversized).is_err());
    }

    #[test]
    fn outer_receipt_wire_rejects_empty_and_over_cap_sources_before_decode() {
        assert!(decode_outer_receipt_oracle(&[]).is_err());
        let oversized = vec![0_u8; CANDIDATE_RECEIPT_ORACLE_MAX_BYTES + 1];
        assert!(decode_outer_receipt_oracle(&oversized).is_err());
    }
}
