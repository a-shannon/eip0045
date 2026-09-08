//! Closed wire model for `candidate-metadata.json`.
//!
//! Candidate metadata is reproduction provenance, not receipt-bound consensus
//! input.  Keeping its producer and consumer on one owned DTO prevents either
//! side from silently accepting a different JSON shape.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::canonical::{canonical_json_bytes, validate_canonical_json_source};

/// Maximum exact canonical-JCS size of one candidate metadata document.
pub const CANDIDATE_METADATA_V1_MAX_BYTES: usize = 16 * 1024;

/// Complete closed V1 candidate-metadata wire document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateMetadataV1 {
    /// Non-final candidate classification.
    pub candidate_status: String,
    /// Metadata format version; semantic consumers require `1`.
    pub format_version: u32,
    /// Pinned upstream implementation identity.
    pub upstream: CandidateUpstreamMetadataV1,
    /// Guest method identity.
    pub method: CandidateMethodMetadataV1,
    /// Values cryptographically bound by the receipt.
    pub proof_bound: CandidateProofBoundMetadataV1,
    /// Private, non-receipt-bound workload calibration.
    pub private_calibration: CandidatePrivateCalibrationMetadataV1,
    /// Private, non-receipt-bound execution observation.
    pub local_execution_observation: CandidateLocalExecutionObservationV1,
    /// Succinct-proof shape observations.
    pub proof: CandidateProofMetadataV1,
    /// Verification actions and their exact authority.
    pub verification: CandidateVerificationMetadataV1,
    /// Ordered physical artifact observations.
    pub files: Vec<CandidateFileMetadataV1>,
}

impl CandidateMetadataV1 {
    /// Parse one complete, bounded, exact RFC 8785 candidate-metadata document.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized, malformed, duplicate-key, trailing,
    /// non-canonical, unknown-field, or incomplete document.
    pub fn from_canonical_jcs(source: &[u8]) -> Result<Self> {
        ensure!(
            source.len() <= CANDIDATE_METADATA_V1_MAX_BYTES,
            "candidate metadata exceeds its 16 KiB canonical-JCS bound"
        );
        let value = validate_canonical_json_source(source)
            .context("candidate metadata is not exact RFC 8785 JCS")?;
        serde_json::from_value(value).context("candidate metadata has the wrong closed V1 shape")
    }

    /// Serialize this closed DTO as bounded exact RFC 8785 bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when JSON conversion or canonical serialization fails,
    /// or when the resulting document exceeds 16 KiB.
    pub fn to_canonical_jcs(&self) -> Result<Vec<u8>> {
        let value =
            serde_json::to_value(self).context("cannot encode candidate metadata V1 as JSON")?;
        let bytes = canonical_json_bytes(&value)
            .context("cannot canonicalize candidate metadata V1 as RFC 8785 JCS")?;
        ensure!(
            bytes.len() <= CANDIDATE_METADATA_V1_MAX_BYTES,
            "candidate metadata exceeds its 16 KiB canonical-JCS bound"
        );
        Ok(bytes)
    }
}

/// Pinned upstream source and receipt-oracle codec identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateUpstreamMetadataV1 {
    /// Canonical upstream repository URL.
    pub repository: String,
    /// Full pinned upstream commit.
    pub commit: String,
    /// Pinned RISC Zero zkVM version.
    pub risc0_zkvm_version: String,
    /// Exact non-consensus receipt-oracle codec.
    pub receipt_oracle_codec: String,
}

/// Guest method identity recorded by the candidate generator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateMethodMetadataV1 {
    /// Lowercase hexadecimal guest image ID.
    pub image_id: String,
    /// Canonical unsigned-decimal guest ELF length.
    pub elf_length: String,
    /// Lowercase hexadecimal SHA-256 of the guest ELF.
    pub elf_sha256: String,
}

/// Candidate fields that are cryptographically bound by the receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateProofBoundMetadataV1 {
    /// Must be true for this receipt-bound section.
    pub receipt_bound: bool,
    /// Canonical unsigned-decimal statement length.
    pub statement_length: String,
    /// Lowercase hexadecimal SHA-256 of the statement.
    pub statement_sha256: String,
    /// Lowercase hexadecimal journal digest.
    pub journal_digest: String,
    /// Lowercase hexadecimal successful-claim digest.
    pub claim_digest: String,
}

/// Private calibration provenance that is not authenticated by the receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidatePrivateCalibrationMetadataV1 {
    /// Must be false for this non-receipt-bound section.
    pub receipt_bound: bool,
    /// Exact scope label for local reproduction provenance.
    pub candidate_scope: String,
    /// Exact closed calibration selection rule.
    pub selection_rule: String,
    /// Whether the selected observation matched the requested shape exactly.
    pub selected_observation_is_exact: bool,
    /// Canonical unsigned-decimal selected workload.
    pub workload_iterations: String,
    /// Lowercase hexadecimal workload seed.
    pub workload_seed_hex: String,
}

/// Local execution observation that is not authenticated by the receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateLocalExecutionObservationV1 {
    /// Must be false for this non-receipt-bound section.
    pub receipt_bound: bool,
    /// Exact scope label for local reproduction provenance.
    pub candidate_scope: String,
    /// Canonical unsigned-decimal segment count.
    pub segment_count: String,
    /// Executor segment cycle-limit exponent.
    pub executor_segment_limit_po2: u32,
    /// Observed segment cycle exponent.
    pub segment_po2: u32,
    /// Canonical unsigned-decimal user-cycle observation.
    pub user_cycles: String,
    /// Canonical unsigned-decimal total-cycle observation.
    pub total_cycles: String,
    /// Canonical unsigned-decimal paging-cycle observation.
    pub paging_cycles: String,
    /// Canonical unsigned-decimal reserved-cycle observation.
    pub reserved_cycles: String,
}

/// Succinct-proof shape and digest observations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateProofMetadataV1 {
    /// Exact candidate receipt-kind label.
    pub receipt_kind: String,
    /// Exact succinct receipt hash-function label.
    pub hash_function: String,
    /// Lowercase hexadecimal terminal control ID.
    pub control_id: String,
    /// Lowercase hexadecimal inner control root.
    pub inner_control_root: String,
    /// Lowercase hexadecimal verifier-parameters digest.
    pub verifier_parameters: String,
    /// Frozen outer recursion exponent.
    pub outer_po2: u32,
    /// Canonical unsigned-decimal raw-seal word count.
    pub raw_seal_words: String,
    /// Canonical unsigned-decimal raw-seal byte count.
    pub raw_seal_bytes: String,
    /// Lowercase hexadecimal successful-claim digest.
    pub claim_digest: String,
    /// Lowercase hexadecimal journal digest.
    pub journal_digest: String,
}

/// Verification actions and the context that authorized them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct CandidateVerificationMetadataV1 {
    /// Must be false because verification actions are not receipt-bound.
    pub receipt_bound: bool,
    /// Exact verifier-context authority used for this candidate.
    pub verification_authority: String,
    /// Whether an explicit local prover was used.
    pub explicit_local_prover: bool,
    /// Whether development verification mode was enabled.
    pub dev_mode: bool,
    /// Whether guest errors were accepted as successful proofs.
    pub prove_guest_errors: bool,
    /// Whether the prover returned a work receipt.
    pub work_receipt_present: bool,
    /// Whether upstream receipt verification succeeded.
    pub upstream_receipt_verify: bool,
    /// Whether the stock profile-owned shape verifier succeeded.
    pub profile_owned_shape_verify: bool,
    /// Whether the receipt-oracle codec is a consensus encoding.
    pub receipt_oracle_is_consensus_encoding: bool,
}

/// One ordered physical artifact observation in candidate metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CandidateFileMetadataV1 {
    /// Exact flat artifact path.
    pub path: String,
    /// Canonical unsigned-decimal artifact length.
    pub length: String,
    /// Lowercase hexadecimal SHA-256 of the artifact.
    pub sha256: String,
    /// Exact semantic artifact role.
    pub role: String,
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::*;

    fn fixture() -> CandidateMetadataV1 {
        CandidateMetadataV1 {
            candidate_status: "non-final-reproduction-candidate".to_owned(),
            format_version: 1,
            upstream: CandidateUpstreamMetadataV1 {
                repository: "https://github.com/risc0/risc0".to_owned(),
                commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                risc0_zkvm_version: "3.0.5".to_owned(),
                receipt_oracle_codec: "bincode-1.3.3-upstream-host-serialization".to_owned(),
            },
            method: CandidateMethodMetadataV1 {
                image_id: "11".repeat(32),
                elf_length: "123".to_owned(),
                elf_sha256: "22".repeat(32),
            },
            proof_bound: CandidateProofBoundMetadataV1 {
                receipt_bound: true,
                statement_length: "3".to_owned(),
                statement_sha256: "33".repeat(32),
                journal_digest: "44".repeat(32),
                claim_digest: "55".repeat(32),
            },
            private_calibration: CandidatePrivateCalibrationMetadataV1 {
                receipt_bound: false,
                candidate_scope: "local-reproduction-provenance-only".to_owned(),
                selection_rule: "canonical-monotone-ranking-v1-not-global-minimum".to_owned(),
                selected_observation_is_exact: true,
                workload_iterations: "37".to_owned(),
                workload_seed_hex: "4549503030343501".to_owned(),
            },
            local_execution_observation: CandidateLocalExecutionObservationV1 {
                receipt_bound: false,
                candidate_scope: "local-reproduction-provenance-only".to_owned(),
                segment_count: "1".to_owned(),
                executor_segment_limit_po2: 22,
                segment_po2: 18,
                user_cycles: "100".to_owned(),
                total_cycles: "110".to_owned(),
                paging_cycles: "5".to_owned(),
                reserved_cycles: "5".to_owned(),
            },
            proof: CandidateProofMetadataV1 {
                receipt_kind: "succinct-single-lift".to_owned(),
                hash_function: "poseidon2".to_owned(),
                control_id: "66".repeat(32),
                inner_control_root: "77".repeat(32),
                verifier_parameters: "88".repeat(32),
                outer_po2: 17,
                raw_seal_words: "55667".to_owned(),
                raw_seal_bytes: "222668".to_owned(),
                claim_digest: "55".repeat(32),
                journal_digest: "44".repeat(32),
            },
            verification: CandidateVerificationMetadataV1 {
                receipt_bound: false,
                verification_authority: "pinned-stock-verifier-context".to_owned(),
                explicit_local_prover: true,
                dev_mode: false,
                prove_guest_errors: false,
                work_receipt_present: false,
                upstream_receipt_verify: true,
                profile_owned_shape_verify: true,
                receipt_oracle_is_consensus_encoding: false,
            },
            files: vec![CandidateFileMetadataV1 {
                path: "candidate-raw-seal.bin".to_owned(),
                length: "222668".to_owned(),
                sha256: "99".repeat(32),
                role: "raw-succinct-seal".to_owned(),
            }],
        }
    }

    #[test]
    fn full_fixture_has_byte_exact_roundtrip_and_golden_identity() {
        let expected = fixture();
        let source = expected.to_canonical_jcs().unwrap();
        assert_eq!(source.len(), 2283);
        assert_eq!(
            hex::encode(Sha256::digest(&source)),
            "92827e3fd14ed36106c1addb895c181cb263590d7d1e3141f740d86d179a4ffc"
        );
        assert_eq!(
            CandidateMetadataV1::from_canonical_jcs(&source).unwrap(),
            expected
        );
        assert_eq!(
            CandidateMetadataV1::from_canonical_jcs(&source)
                .unwrap()
                .to_canonical_jcs()
                .unwrap(),
            source
        );
    }

    #[test]
    fn closed_parser_rejects_unknown_missing_trailing_and_noncanonical_input() {
        let source = fixture().to_canonical_jcs().unwrap();
        let mut unknown = validate_canonical_json_source(&source).unwrap();
        unknown["verification"]["unexpected"] = serde_json::json!(false);
        let unknown = canonical_json_bytes(&unknown).unwrap();
        assert!(CandidateMetadataV1::from_canonical_jcs(&unknown).is_err());

        let mut missing = validate_canonical_json_source(&source).unwrap();
        missing["verification"]
            .as_object_mut()
            .unwrap()
            .remove("verificationAuthority");
        let missing = canonical_json_bytes(&missing).unwrap();
        assert!(CandidateMetadataV1::from_canonical_jcs(&missing).is_err());

        let mut trailing = source.clone();
        trailing.extend_from_slice(b"{}");
        assert!(CandidateMetadataV1::from_canonical_jcs(&trailing).is_err());

        let value = validate_canonical_json_source(&source).unwrap();
        let noncanonical = serde_json::to_vec_pretty(&value).unwrap();
        assert!(CandidateMetadataV1::from_canonical_jcs(&noncanonical).is_err());
    }

    #[test]
    fn canonical_api_enforces_the_exact_sixteen_kibibyte_bound() {
        let mut oversized = fixture();
        oversized.candidate_status = "x".repeat(CANDIDATE_METADATA_V1_MAX_BYTES);
        assert!(oversized.to_canonical_jcs().is_err());
        let oversized_source = vec![b' '; CANDIDATE_METADATA_V1_MAX_BYTES + 1];
        assert!(CandidateMetadataV1::from_canonical_jcs(&oversized_source).is_err());
    }
}
