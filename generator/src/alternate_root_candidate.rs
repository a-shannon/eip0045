//! Closed, in-memory generation of the fixed alternate-control-root witness.
//!
//! The public generation boundary accepts only canonical statement bytes. The
//! guest, control set, segment exponent, workload selection, prover mode, and
//! verifier contexts are pinned by this crate.

use anyhow::{Context, Result, bail, ensure};
use bincode::Options as _;
use eip_0045_methods::{EIP_0045_GUEST_ELF, EIP_0045_GUEST_ID, GuestInputHeader};
use eip_0045_reproduction::{
    b4_alternate_root_authority::B4GeneratedAlternateRootProofBundleV1,
    candidate_metadata::{
        CandidateFileMetadataV1 as FileMetadata,
        CandidateLocalExecutionObservationV1 as LocalExecutionObservation,
        CandidateMetadataV1 as CandidateMetadata, CandidateMethodMetadataV1 as MethodMetadata,
        CandidatePrivateCalibrationMetadataV1 as PrivateCalibrationMetadata,
        CandidateProofBoundMetadataV1 as ProofBoundMetadata,
        CandidateProofMetadataV1 as ProofMetadata, CandidateUpstreamMetadataV1 as UpstreamMetadata,
        CandidateVerificationMetadataV1 as VerificationMetadata,
    },
    canonical::canonical_json_bytes,
    claim::ok_receipt_claim_digests,
    constants::{PROOF_BYTES, PROOF_WORDS, RISC0_COMMIT, RISC0_REPOSITORY},
    manifest::{ManifestEntry, validate_manifest_shape},
};
use risc0_zkp::verify::VerificationError;
use risc0_zkvm::{
    ALLOWED_CONTROL_ROOT, Digest, Executor, ExecutorEnv, ExitCode, InnerReceipt, LocalProver,
    MaybePruned, Prover, ProverOpts, Receipt, SessionInfo, VerifierContext, compute_image_id,
    recursion::Prover as RecursionProver, sha::Digestible,
};
use sha2::{Digest as _, Sha256};

use crate::{
    ALTERNATE_ROOT_SEGMENT_PO2, CANDIDATE_RECEIPT_ORACLE_MAX_BYTES_U64, EXECUTOR_SEGMENT_LIMIT_PO2,
    EXPECTED_ALTERNATE_CONTROL_ROOT_HEX, EXPECTED_ALTERNATE_VERIFIER_PARAMETERS_HEX,
    EXPECTED_OUTER_PO2, EXPECTED_VERIFIER_PARAMETERS_HEX, SegmentObservation, WORKLOAD_SEED,
    alternate_control_root_profile, expected_normal_lift_control_id,
    receipt_oracle_bincode_options, receipt_oracle_wire, select_canonical_iterations,
    validate_alternate_root_succinct_shape, validate_ergo_statement_v1,
};

/// Canonical path of the in-memory manifest that inventories the seven files.
pub const FIXED_ALTERNATE_ROOT_MANIFEST_PATH: &str = "candidate-proof-output-manifest.json";
/// Canonical candidate metadata file name.
pub const FIXED_ALTERNATE_ROOT_METADATA_PATH: &str = "candidate-metadata.json";
/// Canonical raw succinct-seal file name.
pub const FIXED_ALTERNATE_ROOT_RAW_SEAL_PATH: &str = "candidate-raw-seal.bin";
/// Canonical typed receipt-oracle file name.
pub const FIXED_ALTERNATE_ROOT_RECEIPT_ORACLE_PATH: &str = "candidate-receipt-oracle.bincode";
/// Canonical receipt journal file name.
pub const FIXED_ALTERNATE_ROOT_JOURNAL_PATH: &str = "candidate-journal.bin";
/// Canonical guest image-ID file name.
pub const FIXED_ALTERNATE_ROOT_IMAGE_ID_PATH: &str = "candidate-image-id.bin";
/// Canonical receipt-claim digest file name.
pub const FIXED_ALTERNATE_ROOT_CLAIM_DIGEST_PATH: &str = "candidate-claim-digest.bin";
/// Canonical terminal control-ID file name.
pub const FIXED_ALTERNATE_ROOT_CONTROL_ID_PATH: &str = "candidate-control-id.bin";

const FIXED_ARTIFACT_COUNT: usize = 7;

/// Generate the sole fixed alternate-control-root proof bundle.
///
/// The statement is the only caller-supplied input. It must be a canonical
/// `ErgoStatementV1` for the embedded guest. All proof-shaping inputs and both
/// verifier contexts are pinned internally.
///
/// # Errors
///
/// Returns an error for a runtime override, a noncanonical statement, execution
/// or calibration drift, proof failure, unexpected receipt shape, failure of
/// the fixed alternate verifier, acceptance by the stock verifier, or
/// noncanonical output bytes.
#[allow(clippy::too_many_lines)]
pub fn generate_fixed_alternate_root_proof_bundle(
    statement: &[u8],
) -> Result<B4GeneratedAlternateRootProofBundleV1> {
    reject_runtime_overrides()?;
    let image_id = embedded_artifact_identity()?;
    validate_ergo_statement_v1(statement, &image_id)
        .context("statement is not canonical ErgoStatementV1 for the pinned guest")?;

    let prover = LocalProver::new("eip-0045-pinned-local");
    let calibration = select_canonical_iterations(ALTERNATE_ROOT_SEGMENT_PO2, |iterations| {
        let session = execute_once(&prover, statement, iterations)?;
        validate_execution(&session, statement)?;
        segment_observation(&session)
    })?;

    let selected_session = execute_once(&prover, statement, calibration.workload_iterations)?;
    validate_execution(&selected_session, statement)?;
    ensure!(
        segment_observation(&selected_session)? == calibration.observation,
        "selected execution shape differs from calibrated execution shape"
    );
    let expected_claim = selected_session
        .receipt_claim
        .as_ref()
        .context("selected execution did not return a receipt claim")?;
    let expected_claim_digest = expected_claim.digest();
    let independent_claim = ok_receipt_claim_digests(image_id.as_bytes(), statement)
        .context("independent byte-level receipt-claim derivation failed")?;
    ensure!(
        expected_claim_digest.as_bytes() == independent_claim.expected_claim,
        "preflight execution claim differs from the independent byte-level OK-claim derivation"
    );

    let stock_verifier_context = VerifierContext::default().with_dev_mode(false);
    ensure!(
        !stock_verifier_context.dev_mode(),
        "stock verifier context enabled dev mode"
    );
    let generated = prove_fixed_alternate_root(
        &prover,
        statement,
        image_id,
        calibration.workload_iterations,
        expected_claim_digest,
        &stock_verifier_context,
    )?;
    let receipt = generated.receipt;
    ensure!(
        receipt.journal.bytes == statement,
        "alternate-root receipt journal differs from statement"
    );
    ensure!(
        receipt.metadata.verifier_parameters == receipt.inner.verifier_parameters(),
        "alternate-root receipt metadata verifier parameters differ from inner receipt"
    );
    ensure!(
        receipt.claim()?.digest() == expected_claim_digest,
        "alternate-root receipt claim differs from preflight execution claim"
    );

    let receipt_oracle = serialize_receipt_oracle(&receipt)?;
    let journal_digest = receipt.journal.digest();
    ensure!(
        journal_digest.as_bytes() == independent_claim.journal_digest,
        "alternate-root journal digest differs from independent SHA-256 derivation"
    );
    let control_id = expected_normal_lift_control_id(ALTERNATE_ROOT_SEGMENT_PO2)?;

    let metadata = CandidateMetadata {
        candidate_status: "non-final-alternate-root-negative-witness".to_owned(),
        format_version: 1,
        upstream: UpstreamMetadata {
            repository: RISC0_REPOSITORY.to_owned(),
            commit: RISC0_COMMIT.to_owned(),
            risc0_zkvm_version: risc0_zkvm::VERSION.to_owned(),
            receipt_oracle_codec: "bincode-1.3.3-upstream-host-serialization".to_owned(),
        },
        method: MethodMetadata {
            image_id: hex::encode(image_id.as_bytes()),
            elf_length: EIP_0045_GUEST_ELF.len().to_string(),
            elf_sha256: sha256_hex(EIP_0045_GUEST_ELF),
        },
        proof_bound: ProofBoundMetadata {
            receipt_bound: true,
            statement_length: statement.len().to_string(),
            statement_sha256: sha256_hex(statement),
            journal_digest: hex::encode(journal_digest.as_bytes()),
            claim_digest: hex::encode(expected_claim_digest.as_bytes()),
        },
        private_calibration: PrivateCalibrationMetadata {
            receipt_bound: false,
            candidate_scope: "local-reproduction-provenance-only".to_owned(),
            selection_rule: "canonical-monotone-ranking-v1-not-global-minimum".to_owned(),
            selected_observation_is_exact: true,
            workload_iterations: calibration.workload_iterations.to_string(),
            workload_seed_hex: format!("{WORKLOAD_SEED:016x}"),
        },
        local_execution_observation: LocalExecutionObservation {
            receipt_bound: false,
            candidate_scope: "local-reproduction-provenance-only".to_owned(),
            segment_count: generated.stats.segments.to_string(),
            executor_segment_limit_po2: EXECUTOR_SEGMENT_LIMIT_PO2,
            segment_po2: ALTERNATE_ROOT_SEGMENT_PO2,
            user_cycles: generated.stats.user_cycles.to_string(),
            total_cycles: generated.stats.total_cycles.to_string(),
            paging_cycles: generated.stats.paging_cycles.to_string(),
            reserved_cycles: generated.stats.reserved_cycles.to_string(),
        },
        proof: ProofMetadata {
            receipt_kind: "succinct-single-lift-fixed-alternate-root".to_owned(),
            hash_function: "poseidon2".to_owned(),
            control_id: hex::encode(control_id.as_bytes()),
            inner_control_root: EXPECTED_ALTERNATE_CONTROL_ROOT_HEX.to_owned(),
            verifier_parameters: EXPECTED_ALTERNATE_VERIFIER_PARAMETERS_HEX.to_owned(),
            outer_po2: EXPECTED_OUTER_PO2,
            raw_seal_words: PROOF_WORDS.to_string(),
            raw_seal_bytes: PROOF_BYTES.to_string(),
            claim_digest: hex::encode(expected_claim_digest.as_bytes()),
            journal_digest: hex::encode(journal_digest.as_bytes()),
        },
        verification: VerificationMetadata {
            receipt_bound: false,
            verification_authority: "fixed-alternate-control-root-verifier-context".to_owned(),
            explicit_local_prover: true,
            dev_mode: false,
            prove_guest_errors: false,
            work_receipt_present: false,
            upstream_receipt_verify: true,
            profile_owned_shape_verify: false,
            receipt_oracle_is_consensus_encoding: false,
        },
        files: vec![
            file_metadata(
                FIXED_ALTERNATE_ROOT_RAW_SEAL_PATH,
                &generated.raw_seal,
                "raw-succinct-seal",
            ),
            file_metadata(
                FIXED_ALTERNATE_ROOT_RECEIPT_ORACLE_PATH,
                &receipt_oracle,
                "upstream-bincode-receipt-oracle",
            ),
            file_metadata(
                FIXED_ALTERNATE_ROOT_JOURNAL_PATH,
                &receipt.journal.bytes,
                "journal",
            ),
            file_metadata(
                FIXED_ALTERNATE_ROOT_IMAGE_ID_PATH,
                image_id.as_bytes(),
                "guest-image-id",
            ),
            file_metadata(
                FIXED_ALTERNATE_ROOT_CLAIM_DIGEST_PATH,
                expected_claim_digest.as_bytes(),
                "receipt-claim-digest",
            ),
            file_metadata(
                FIXED_ALTERNATE_ROOT_CONTROL_ID_PATH,
                control_id.as_bytes(),
                "normal-lift-control-id",
            ),
        ],
    };
    let metadata_bytes = metadata
        .to_canonical_jcs()
        .context("cannot encode canonical alternate-root candidate metadata")?;

    let claim_digest: [u8; 32] = expected_claim_digest
        .as_bytes()
        .try_into()
        .context("claim digest is not exactly 32 bytes")?;
    let control_id: [u8; 32] = control_id
        .as_bytes()
        .try_into()
        .context("control ID is not exactly 32 bytes")?;
    let image_id: [u8; 32] = image_id
        .as_bytes()
        .try_into()
        .context("image ID is not exactly 32 bytes")?;
    let journal = receipt.journal.bytes;
    let raw_seal = generated.raw_seal;
    let manifest_jcs = build_manifest_jcs([
        (FIXED_ALTERNATE_ROOT_CLAIM_DIGEST_PATH, &claim_digest),
        (FIXED_ALTERNATE_ROOT_CONTROL_ID_PATH, &control_id),
        (FIXED_ALTERNATE_ROOT_IMAGE_ID_PATH, &image_id),
        (FIXED_ALTERNATE_ROOT_JOURNAL_PATH, &journal),
        (FIXED_ALTERNATE_ROOT_METADATA_PATH, &metadata_bytes),
        (FIXED_ALTERNATE_ROOT_RAW_SEAL_PATH, &raw_seal),
        (FIXED_ALTERNATE_ROOT_RECEIPT_ORACLE_PATH, &receipt_oracle),
    ])?;
    Ok(B4GeneratedAlternateRootProofBundleV1::new(
        manifest_jcs,
        claim_digest,
        control_id,
        image_id,
        journal,
        metadata_bytes,
        raw_seal,
        receipt_oracle,
    ))
}

struct GeneratedAlternateRootProof {
    receipt: Receipt,
    stats: risc0_zkvm::SessionStats,
    raw_seal: Vec<u8>,
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn prove_fixed_alternate_root(
    prover: &LocalProver,
    statement: &[u8],
    image_id: Digest,
    workload_iterations: u32,
    expected_claim_digest: Digest,
    stock_verifier_context: &VerifierContext,
) -> Result<GeneratedAlternateRootProof> {
    let composite_opts = closed_prover_opts(ProverOpts::composite())?;
    let prove_info = prover
        .prove_with_ctx(
            build_env(statement, workload_iterations)?,
            stock_verifier_context,
            EIP_0045_GUEST_ELF,
            &composite_opts,
        )
        .context("pinned local segment proving for alternate-root lift failed")?;
    ensure!(
        prove_info.work_receipt.is_none(),
        "alternate-root segment prover unexpectedly returned a work receipt"
    );
    ensure!(
        prove_info.stats.segments == 1,
        "alternate-root segment prover reported {} segments, expected one",
        prove_info.stats.segments
    );
    ensure!(
        prove_info.receipt.journal.bytes == statement,
        "alternate-root segment receipt journal differs from statement"
    );
    let InnerReceipt::Composite(mut composite) = prove_info.receipt.inner else {
        bail!("alternate-root segment prover did not return a composite receipt");
    };
    ensure!(
        composite.segments.len() == 1 && composite.assumption_receipts.is_empty(),
        "alternate-root source is not one unconditional segment"
    );
    let segment = composite
        .segments
        .pop()
        .context("alternate-root composite has no segment")?;
    ensure!(
        segment.index == 0 && segment.claim.digest() == expected_claim_digest,
        "alternate-root source segment differs from the preflight claim"
    );

    let profile = alternate_control_root_profile()?;
    ensure!(
        profile.control_root() != ALLOWED_CONTROL_ROOT,
        "alternate-root profile reproduced the stock root"
    );
    let opts = closed_prover_opts(
        ProverOpts::succinct().with_control_ids(profile.control_ids().to_vec()),
    )?;
    let mut recursion_prover = RecursionProver::new_lift(&segment, opts)
        .context("cannot construct the fixed alternate-root lift")?;
    ensure!(
        *recursion_prover.control_id() == profile.terminal_control_id(),
        "alternate-root lift selected the wrong terminal control ID"
    );
    let control_inclusion_proof = recursion_prover
        .control_inclusion_proof()
        .context("cannot derive alternate-root terminal inclusion proof")?;
    ensure!(
        control_inclusion_proof.index == profile.terminal_control_index(),
        "alternate-root terminal inclusion index changed"
    );
    let recursion_receipt = recursion_prover
        .run()
        .context("fixed alternate-root lift proving failed")?;
    let succinct = receipt_oracle_wire::assemble_succinct_receipt(
        recursion_receipt.seal,
        profile.terminal_control_id(),
        MaybePruned::Value(segment.claim),
        "poseidon2".to_owned(),
        profile.verifier_parameters_digest(),
        control_inclusion_proof,
    )?;
    let raw_seal =
        validate_alternate_root_succinct_shape(&succinct, &expected_claim_digest, &profile)?;
    let alternate_context = VerifierContext::default()
        .with_dev_mode(false)
        .with_succinct_verifier_parameters(profile.verifier_parameters().clone());
    let receipt = Receipt::new(InnerReceipt::Succinct(succinct), statement.to_vec());
    receipt
        .verify_with_context(&alternate_context, image_id)
        .context("upstream alternate-root receipt verification failed")?;
    let stock_error = receipt
        .verify_with_context(stock_verifier_context, image_id)
        .expect_err("stock verifier context accepted the alternate-root receipt");
    match stock_error {
        VerificationError::VerifierParametersMismatch { expected, received } => {
            ensure!(
                hex::encode(expected.as_bytes()) == EXPECTED_VERIFIER_PARAMETERS_HEX,
                "stock rejection reported an unexpected verifier-parameter digest"
            );
            ensure!(
                received == profile.verifier_parameters_digest(),
                "stock rejection did not report the alternate verifier-parameter digest"
            );
        }
        other => bail!(
            "stock verifier context rejected the alternate-root receipt at the wrong boundary: {other:?}"
        ),
    }

    Ok(GeneratedAlternateRootProof {
        receipt,
        stats: prove_info.stats,
        raw_seal,
    })
}

fn build_manifest_jcs(artifacts: [(&str, &[u8]); FIXED_ARTIFACT_COUNT]) -> Result<Vec<u8>> {
    let manifest = artifacts
        .iter()
        .map(|(path, bytes)| ManifestEntry {
            path: (*path).to_owned(),
            length: bytes.len().to_string(),
            sha256: sha256_hex(bytes),
        })
        .collect::<Vec<_>>();
    validate_manifest_shape(&manifest)?;
    let value = serde_json::to_value(&manifest).context("cannot encode alternate-root manifest")?;
    canonical_json_bytes(&value).context("cannot canonicalize alternate-root manifest")
}

fn file_metadata(path: &str, bytes: &[u8], role: &str) -> FileMetadata {
    FileMetadata {
        path: path.to_owned(),
        length: bytes.len().to_string(),
        sha256: sha256_hex(bytes),
        role: role.to_owned(),
    }
}

fn embedded_artifact_identity() -> Result<Digest> {
    let declared = Digest::from(EIP_0045_GUEST_ID);
    let computed =
        compute_image_id(EIP_0045_GUEST_ELF).context("cannot compute the guest ELF image ID")?;
    ensure!(
        computed == declared,
        "computed guest ELF image ID differs from the generated methods constant"
    );
    Ok(computed)
}

fn build_env(statement: &[u8], workload_iterations: u32) -> Result<ExecutorEnv<'static>> {
    let header = GuestInputHeader::new(statement.len(), workload_iterations, WORKLOAD_SEED)
        .map_err(|error| anyhow::anyhow!("cannot construct exact guest input header: {error}"))?;
    let mut input = Vec::with_capacity(header.encoded_input_length());
    input.extend_from_slice(&header.encode());
    input.extend_from_slice(statement);
    ensure!(
        input.len() == header.encoded_input_length(),
        "constructed guest input length differs from header"
    );
    ensure!(
        ALTERNATE_ROOT_SEGMENT_PO2 < EXECUTOR_SEGMENT_LIMIT_PO2,
        "fixed alternate segment po2 must remain below the executor segmentation ceiling"
    );
    let mut builder = ExecutorEnv::builder();
    builder
        .segment_limit_po2(EXECUTOR_SEGMENT_LIMIT_PO2)
        .write_slice(&input);
    builder
        .build()
        .context("cannot build exact executor environment")
}

fn execute_once(
    prover: &LocalProver,
    statement: &[u8],
    workload_iterations: u32,
) -> Result<SessionInfo> {
    prover
        .execute(
            build_env(statement, workload_iterations)?,
            EIP_0045_GUEST_ELF,
        )
        .context("local alternate-root candidate execution failed")
}

fn validate_execution(session: &SessionInfo, statement: &[u8]) -> Result<()> {
    ensure!(
        session.exit_code == ExitCode::Halted(0),
        "guest execution did not halt successfully: {:?}",
        session.exit_code
    );
    ensure!(
        session.journal.bytes == statement,
        "execution journal differs from statement"
    );
    ensure!(
        session.receipt_claim.is_some(),
        "execution did not return a receipt claim"
    );
    Ok(())
}

fn segment_observation(session: &SessionInfo) -> Result<SegmentObservation> {
    SegmentObservation::new(
        session.segments.len(),
        (session.segments.len() == 1).then(|| session.segments[0].po2),
    )
}

fn closed_prover_opts(opts: ProverOpts) -> Result<ProverOpts> {
    let opts = opts.with_dev_mode(false).with_prove_guest_errors(false);
    ensure!(
        opts.hashfn == "poseidon2",
        "prover options are not Poseidon2"
    );
    ensure!(!opts.dev_mode(), "prover options enabled dev mode");
    ensure!(
        !opts.prove_guest_errors,
        "prover options enabled guest-error proving"
    );
    Ok(opts)
}

fn serialize_receipt_oracle(receipt: &Receipt) -> Result<Vec<u8>> {
    let bytes = receipt_oracle_bincode_options()
        .serialize(receipt)
        .context("upstream bincode receipt serialization failed within the one-MiB limit")?;
    ensure!(
        u64::try_from(bytes.len()).context("serialized receipt length does not fit u64")?
            <= CANDIDATE_RECEIPT_ORACLE_MAX_BYTES_U64,
        "serialized receipt oracle exceeds the one-MiB limit"
    );
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn reject_runtime_overrides() -> Result<()> {
    const FORBIDDEN: &[&str] = &[
        "RISC0_DEV_MODE",
        "RISC0_PROVER",
        "RISC0_EXECUTOR",
        "RISC0_SERVER_PATH",
        "RISC0_WITGEN_DEBUG",
        "RECURSION_SRC_PATH",
    ];
    for name in FORBIDDEN {
        if std::env::var_os(name).is_some() {
            bail!("candidate generator forbids runtime environment override {name}");
        }
    }
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy();
        if name.starts_with("BONSAI_") {
            bail!("candidate generator forbids runtime environment override {name}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_provider_type_accepts_only_statement_bytes() {
        let _: fn(&[u8]) -> Result<B4GeneratedAlternateRootProofBundleV1> =
            generate_fixed_alternate_root_proof_bundle;
    }

    #[test]
    fn in_memory_bundle_requires_exact_canonical_seven_file_inventory() {
        let artifacts = [
            (FIXED_ALTERNATE_ROOT_CLAIM_DIGEST_PATH, b"claim".as_slice()),
            (FIXED_ALTERNATE_ROOT_CONTROL_ID_PATH, b"control".as_slice()),
            (FIXED_ALTERNATE_ROOT_IMAGE_ID_PATH, b"image".as_slice()),
            (FIXED_ALTERNATE_ROOT_JOURNAL_PATH, b"journal".as_slice()),
            (FIXED_ALTERNATE_ROOT_METADATA_PATH, b"metadata".as_slice()),
            (FIXED_ALTERNATE_ROOT_RAW_SEAL_PATH, b"seal".as_slice()),
            (
                FIXED_ALTERNATE_ROOT_RECEIPT_ORACLE_PATH,
                b"receipt".as_slice(),
            ),
        ];
        let manifest_jcs = build_manifest_jcs(artifacts).unwrap();
        let parsed: Vec<ManifestEntry> = serde_json::from_slice(&manifest_jcs).unwrap();
        assert_eq!(parsed.len(), FIXED_ARTIFACT_COUNT);
        assert_eq!(
            parsed
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            artifacts.iter().map(|(path, _)| *path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn retained_kat_cannot_be_promoted_as_current_provider_output() {
        let journal = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/alternate-root-lift-po2-15-v1/",
            "candidate-proof-export/proof-output/candidate-journal.bin"
        ));
        let metadata = CandidateMetadata::from_canonical_jcs(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/alternate-root-lift-po2-15-v1/",
            "candidate-proof-export/proof-output/candidate-metadata.json"
        )))
        .unwrap();
        let image_id = embedded_artifact_identity().unwrap();

        let error = validate_ergo_statement_v1(journal, &image_id).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("program ID differs from the expected guest image ID"),
            "{error:#}"
        );
        assert_ne!(metadata.method.image_id, hex::encode(image_id.as_bytes()));
        assert_ne!(
            metadata.method.image_id,
            hex::encode(Digest::from(EIP_0045_GUEST_ID).as_bytes())
        );
        assert_ne!(metadata.method.elf_sha256, sha256_hex(EIP_0045_GUEST_ELF));
        assert_eq!(metadata.proof_bound.statement_sha256, sha256_hex(journal));
    }

    #[test]
    fn provider_source_exposes_no_root_or_proof_shape_selector() {
        let source = include_str!("alternate_root_candidate.rs");
        let public_boundary = source
            .split("#[cfg(test)]")
            .next()
            .expect("provider source has a production section");
        assert_eq!(
            public_boundary
                .matches("pub fn generate_fixed_alternate_root_proof_bundle")
                .count(),
            1
        );
        for forbidden in [
            "pub fn generate_fixed_alternate_root_proof_bundle(\n    statement: &[u8],\n    root",
            "pub fn generate_fixed_alternate_root_proof_bundle(\n    statement: &[u8],\n    segment",
            "pub fn generate_fixed_alternate_root_proof_bundle(\n    statement: &[u8],\n    workload",
            "pub fn generate_fixed_alternate_root_proof_bundle(\n    statement: &[u8],\n    mode",
            "pub fn generate_fixed_alternate_root_proof_bundle(\n    statement: &[u8],\n    path",
        ] {
            assert!(
                !public_boundary.contains(forbidden),
                "provider exposed forbidden selector signature fragment {forbidden:?}"
            );
        }
    }
}
