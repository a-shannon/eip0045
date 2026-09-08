//! Closed candidate export for the three stock recursive receipt families.
//!
//! The final succinct receipt authenticates its successful claim, but it does
//! not authenticate the route by which the receipt was produced. The retained
//! source receipt and intermediate receipts therefore form a replayable oracle,
//! not consensus provenance. The verifier below checks both layers explicitly.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata},
    io::Read as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use bincode::Options as _;
use eip_0045_reproduction::{
    canonical::{canonical_json_bytes, validate_canonical_json_source},
    constants::{MAX_STATEMENT_BYTES, PROOF_BYTES},
    manifest::{
        ManifestEntry, ProofOutputManifest, build_proof_output_manifest,
        require_empty_before_generation, validate_manifest_shape, validate_proof_output_manifest,
    },
    parse_ergo_statement_v1,
    recursive_ancestry::{
        RECURSIVE_ANCESTRY_MAX_BYTES, recursive_ancestry_expected_auxiliary_paths,
    },
};
use risc0_zkvm::{
    Digest, InnerReceipt, LocalProver, Receipt, ReceiptClaim, VerifierContext, compute_image_id,
    sha::Digestible,
};
use sha2::{Digest as _, Sha256};

use crate::{
    CANDIDATE_RECEIPT_ORACLE_MAX_BYTES, CandidateTerminal, receipt_oracle_bincode_options,
    receipt_oracle_wire::decode_outer_receipt_oracle,
    recursive::{
        RECURSIVE_ORACLE_MAX_BYTES, RecursiveFamily, RecursiveOracle, decode_recursive_oracle,
        encode_recursive_oracle, generate_recursive_oracle_unreplayed,
        observe_recursive_calibration_shape, validate_recursive_oracle,
        validate_recursive_oracle_calibration_with_recipe,
    },
    recursive_ancestry::{build_projection_bundle, project_family, validate_projection_bundle},
    recursive_calibration::{
        RECURSIVE_CALIBRATION_MAX_BYTES, RecursiveCalibrationRecipe,
        RecursiveCalibrationReport, create_atomic_candidate_file, verify_recursive_calibration_with_recipe,
    },
    validate_candidate_terminal_shape, validate_ergo_statement_v1,
};

const PROOF_OUTPUT_DIRECTORY: &str = "proof-output";
const OUTPUT_MANIFEST_FILE: &str = "candidate-recursive-output-manifest.json";
const FINAL_EXPORT_DIRECTORY: &str = "candidate-recursive-proof-export";
const STAGING_EXPORT_DIRECTORY: &str = ".candidate-recursive-proof-export.staging";
const CHECKPOINT_FILE: &str = ".candidate-recursive-final-receipt.checkpoint.bincode";
const ORACLE_FILE: &str = "candidate-recursive-oracle.borsh";
const RAW_SEAL_FILE: &str = "candidate-raw-seal.bin";
const JOURNAL_FILE: &str = "candidate-journal.bin";
const IMAGE_ID_FILE: &str = "candidate-image-id.bin";
const CLAIM_DIGEST_FILE: &str = "candidate-claim-digest.bin";
const CONTROL_ID_FILE: &str = "candidate-control-id.bin";
const ANCESTRY_FILE: &str = "candidate-ancestry.json";
const CALIBRATION_FILE: &str = "candidate-recursive-calibration.json";

const MANIFEST_MAX_BYTES: usize = 16 * 1024;
const DIGEST_BYTES: usize = 32;

const MANIFEST_PATHS: [&str; 8] = [
    ANCESTRY_FILE,
    CLAIM_DIGEST_FILE,
    CONTROL_ID_FILE,
    IMAGE_ID_FILE,
    JOURNAL_FILE,
    RAW_SEAL_FILE,
    CALIBRATION_FILE,
    ORACLE_FILE,
];

/// Recomputed identities from one verified recursive candidate export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRecursiveExport {
    /// Exact recursive family required by the caller and proven by the oracle.
    pub family: RecursiveFamily,
    /// Exact guest image ID.
    pub image_id: Digest,
    /// Final successful receipt-claim digest.
    pub claim_digest: Digest,
    /// Final stock join or resolve control ID.
    pub control_id: Digest,
    /// Number of RV32IM source segments (one or two by family).
    pub source_segment_count: usize,
    /// Number of retained stock recursion receipts.
    pub ancestry_step_count: usize,
}

/// Generate, verify, and atomically publish one candidate-only recursive export.
///
/// `output_root` must already exist and be empty. Proof generation happens
/// before publication. Once the costly final receipt exists, it is atomically
/// retained in a create-only local salvage checkpoint at the output root before
/// redundant ancestry replay. The checkpoint contains only that final receipt:
/// this API never consumes it to resume generation or reconstruct the oracle,
/// ancestry, or complete export. Checkpoint publication never replaces a
/// destination introduced after its empty-root preflight.
///
/// # Errors
///
/// Returns an error for any input, execution, proving, graph, receipt, encoding,
/// closed-tree, verification, or publication mismatch.
pub fn generate_recursive_candidate_export(
    output_root: &Path,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
    family: RecursiveFamily,
    calibration: &RecursiveCalibrationReport,
) -> Result<VerifiedRecursiveExport> {

    generate_recursive_candidate_export_with_recipe(output_root, elf, image_id, statement, family, calibration, RecursiveCalibrationRecipe::Fixed22)
}

/// Explicit-recipe counterpart; existing callers retain Fixed22 semantics.
pub fn generate_recursive_candidate_export_with_recipe(
    output_root: &Path,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
    family: RecursiveFamily,
    calibration: &RecursiveCalibrationReport,
    recipe: RecursiveCalibrationRecipe,
) -> Result<VerifiedRecursiveExport> {

    recipe.validate_family(family.as_str())?;
    require_empty_before_generation(output_root)?;
    validate_expected_method(elf, image_id)?;
    validate_ergo_statement_v1(statement, &image_id)?;

    let prover = LocalProver::new("eip-0045-pinned-local");
    authenticate_calibration(&prover, calibration, elf, image_id, statement, family, recipe)?;
    let oracle = generate_recursive_oracle_unreplayed(
        &prover,
        elf,
        image_id,
        statement,
        family,
        &calibration.segment_po2,
        calibration.segment_limit_po2,
        calibration.workload_iterations,
        calibration.assumption_workload_iterations,
    )?;
    let checkpoint_bytes =
        checkpoint_final_receipt(output_root, &oracle, image_id, statement, family.terminal())?;

    validate_recursive_oracle(&oracle, image_id, statement)?;
    validate_recursive_oracle_calibration_with_recipe(&oracle, calibration, recipe)?;

    let oracle_bytes = encode_recursive_oracle(&oracle)?;
    let decoded = decode_recursive_oracle(&oracle_bytes)
        .context("cannot decode freshly encoded recursive ancestry oracle")?;
    ensure!(
        encode_recursive_oracle(&decoded)? == oracle_bytes,
        "fresh recursive oracle is not exact canonical Borsh"
    );
    validate_recursive_oracle(&decoded, image_id, statement)?;

    let final_receipt = final_receipt(&oracle)?;
    let expected_claim = ReceiptClaim::ok(image_id, statement.to_vec()).digest();
    let raw_seal =
        validate_candidate_terminal_shape(final_receipt, family.terminal(), &expected_claim)?;
    let control_id = final_receipt.control_id;
    let profile_id = hex::encode(
        parse_ergo_statement_v1(statement)
            .context("cannot decode statement profile for ancestry projection")?
            .profile_id(),
    );
    let ancestry_bundle = build_projection_bundle(&oracle, image_id, statement, &profile_id)
        .context("cannot derive shared recursive ancestry projection")?;
    let ancestry_bytes = ancestry_bundle.jcs;
    let auxiliary_seals = ancestry_bundle.auxiliary_seals;
    let calibration_bytes = calibration.to_canonical_jcs_with_recipe(recipe)?;

    let base_artifacts: [(&str, &[u8]); 8] = [
        (ANCESTRY_FILE, &ancestry_bytes),
        (CLAIM_DIGEST_FILE, expected_claim.as_bytes()),
        (CONTROL_ID_FILE, control_id.as_bytes()),
        (IMAGE_ID_FILE, image_id.as_bytes()),
        (JOURNAL_FILE, statement),
        (RAW_SEAL_FILE, &raw_seal),
        (CALIBRATION_FILE, &calibration_bytes),
        (ORACLE_FILE, &oracle_bytes),
    ];
    let mut artifacts = Vec::with_capacity(base_artifacts.len() + auxiliary_seals.len());
    artifacts.extend(base_artifacts);
    artifacts.extend(
        auxiliary_seals
            .iter()
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice())),
    );
    let staging = stage_recursive_export(output_root, &artifacts, family)?;

    let staged =
        verify_recursive_candidate_export_bytes(&staging, statement, family, elf, image_id, recipe)?;
    publish_staging_export(output_root, &staging)?;
    let published = verify_recursive_candidate_export_bytes(
        &output_root.join(FINAL_EXPORT_DIRECTORY),
        statement,
        family,
        elf,
        image_id,
        recipe,
    )?;
    ensure!(
        staged == published,
        "published recursive export identity changed after rename"
    );
    verify_unchanged_checkpoint(
        output_root,
        &checkpoint_bytes,
        image_id,
        statement,
        family.terminal(),
    )?;
    require_completed_parent_layout(output_root)?;
    Ok(published)
}

fn stage_recursive_export(
    output_root: &Path,
    artifacts: &[(&str, &[u8])],
    family: RecursiveFamily,
) -> Result<PathBuf> {
    require_checkpoint_only(output_root)?;
    let expected_paths = expected_manifest_paths(family);
    ensure!(
        artifacts.len() == expected_paths.len(),
        "recursive artifact count differs from the closed family export"
    );
    for ((path, _), expected) in artifacts.iter().zip(&expected_paths) {
        ensure!(
            *path == expected,
            "recursive artifact sequence differs from the closed family export"
        );
    }

    let staging = output_root.join(STAGING_EXPORT_DIRECTORY);
    fs::create_dir(&staging).with_context(|| {
        format!(
            "cannot create recursive candidate staging directory {}",
            staging.display()
        )
    })?;
    let proof_output = staging.join(PROOF_OUTPUT_DIRECTORY);
    fs::create_dir(&proof_output).with_context(|| {
        format!(
            "cannot create recursive candidate output directory {}",
            proof_output.display()
        )
    })?;
    for (name, bytes) in artifacts {
        let artifact_path = proof_output.join(name);
        let parent = artifact_path
            .parent()
            .context("recursive artifact has no parent directory")?;
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "cannot create recursive candidate artifact directory {}",
                parent.display()
            )
        })?;
        write_new_file(&artifact_path, bytes)?;
    }
    let manifest = build_proof_output_manifest(&proof_output)?;
    ensure_manifest_paths(&manifest, family)?;
    let manifest_bytes = canonical_json_bytes(
        &serde_json::to_value(&manifest).context("cannot encode recursive output manifest")?,
    )
    .context("cannot canonicalize recursive output manifest")?;
    ensure!(
        manifest_bytes.len() <= MANIFEST_MAX_BYTES,
        "recursive output manifest exceeds its byte limit"
    );
    write_new_file(&staging.join(OUTPUT_MANIFEST_FILE), &manifest_bytes)?;
    Ok(staging)
}

/// Strictly re-read one recursive candidate export from disk.
///
/// The family, statement, ELF, and image ID are caller-owned expectations. No
/// export field is allowed to select a verifier parameter or candidate family.
///
/// # Errors
///
/// Returns an error for any unsafe node, extra path, noncanonical JSON, bounded
/// read, manifest, codec, ancestry, receipt, proof-shape, or identity mismatch.
pub fn verify_recursive_candidate_export(
    export_root: &Path,
    expected_statement_file: &Path,
    expected_family: RecursiveFamily,
    expected_elf: &[u8],
    expected_image_id: Digest,
) -> Result<VerifiedRecursiveExport> {

    verify_recursive_candidate_export_with_recipe(export_root, expected_statement_file, expected_family, expected_elf, expected_image_id, RecursiveCalibrationRecipe::Fixed22)
}

/// Explicit-recipe counterpart; existing callers retain Fixed22 semantics.
pub fn verify_recursive_candidate_export_with_recipe(
    export_root: &Path,
    expected_statement_file: &Path,
    expected_family: RecursiveFamily,
    expected_elf: &[u8],
    expected_image_id: Digest,
    recipe: RecursiveCalibrationRecipe,
) -> Result<VerifiedRecursiveExport> {

    recipe.validate_family(expected_family.as_str())?;
    let statement = read_regular_bounded(
        expected_statement_file,
        MAX_STATEMENT_BYTES,
        "expected statement",
    )?;
    verify_recursive_candidate_export_bytes(
        export_root,
        &statement,
        expected_family,
        expected_elf,
        expected_image_id,
        recipe,
    )
}

#[allow(clippy::too_many_lines)]
fn verify_recursive_candidate_export_bytes(
    export_root: &Path,
    statement: &[u8],
    expected_family: RecursiveFamily,
    expected_elf: &[u8],
    expected_image_id: Digest,
    recipe: RecursiveCalibrationRecipe,
) -> Result<VerifiedRecursiveExport> {
    recipe.validate_family(expected_family.as_str())?;
    validate_expected_method(expected_elf, expected_image_id)?;
    validate_ergo_statement_v1(statement, &expected_image_id)?;
    require_exact_export_layout(export_root, expected_family)?;

    let proof_output = export_root.join(PROOF_OUTPUT_DIRECTORY);
    let manifest_path = export_root.join(OUTPUT_MANIFEST_FILE);
    let manifest_source = read_regular_bounded(
        &manifest_path,
        MANIFEST_MAX_BYTES,
        "recursive output manifest",
    )?;
    let manifest_value = validate_canonical_json_source(&manifest_source)
        .context("recursive output manifest is not exact RFC 8785 JCS")?;
    let manifest: ProofOutputManifest = serde_json::from_value(manifest_value)
        .context("recursive output manifest has the wrong closed shape")?;
    validate_manifest_shape(&manifest)?;
    ensure_manifest_paths(&manifest, expected_family)?;
    validate_proof_output_manifest(&proof_output, &manifest)?;

    let ancestry_source = read_manifested(
        &proof_output,
        &manifest,
        ANCESTRY_FILE,
        RECURSIVE_ANCESTRY_MAX_BYTES,
    )?;
    let claim_bytes = read_fixed::<DIGEST_BYTES>(&proof_output, &manifest, CLAIM_DIGEST_FILE)?;
    let control_bytes = read_fixed::<DIGEST_BYTES>(&proof_output, &manifest, CONTROL_ID_FILE)?;
    let image_bytes = read_fixed::<DIGEST_BYTES>(&proof_output, &manifest, IMAGE_ID_FILE)?;
    let journal = read_manifested(&proof_output, &manifest, JOURNAL_FILE, MAX_STATEMENT_BYTES)?;
    let raw_seal = read_manifested(&proof_output, &manifest, RAW_SEAL_FILE, PROOF_BYTES)?;
    let calibration_source = read_manifested(
        &proof_output,
        &manifest,
        CALIBRATION_FILE,
        RECURSIVE_CALIBRATION_MAX_BYTES,
    )?;
    let oracle_source = read_manifested(
        &proof_output,
        &manifest,
        ORACLE_FILE,
        RECURSIVE_ORACLE_MAX_BYTES,
    )?;
    let physical_auxiliary_seals = read_auxiliary_seals(&proof_output, &manifest, expected_family)?;

    ensure!(
        journal == statement,
        "recursive candidate journal differs from expected statement"
    );
    ensure!(
        image_bytes == *expected_image_id.as_bytes(),
        "recursive image-ID artifact differs"
    );
    ensure!(
        raw_seal.len() == PROOF_BYTES,
        "recursive raw seal has the wrong byte length"
    );

    let calibration = RecursiveCalibrationReport::from_canonical_jcs_with_recipe(&calibration_source, recipe)
        .context("cannot parse exact recursive calibration artifact")?;
    let calibration_prover = LocalProver::new("eip-0045-pinned-local-export-replay");
    authenticate_calibration(
        &calibration_prover,
        &calibration,
        expected_elf,
        expected_image_id,
        statement,
        expected_family,
        recipe,
    )?;

    let oracle: RecursiveOracle = decode_recursive_oracle(&oracle_source)
        .context("cannot decode bounded recursive ancestry oracle")?;
    let roundtrip =
        encode_recursive_oracle(&oracle).context("cannot re-encode recursive ancestry oracle")?;
    ensure!(
        roundtrip == oracle_source,
        "recursive oracle is not the exact pinned Borsh encoding"
    );
    ensure!(
        oracle.family == expected_family,
        "recursive oracle family differs from caller expectation"
    );
    validate_recursive_oracle(&oracle, expected_image_id, statement)?;
    validate_recursive_oracle_calibration_with_recipe(&oracle, &calibration, recipe)?;

    let final_receipt = final_receipt(&oracle)?;
    let expected_claim = ReceiptClaim::ok(expected_image_id, statement.to_vec()).digest();
    ensure!(
        claim_bytes == *expected_claim.as_bytes(),
        "recursive claim-digest artifact differs"
    );
    ensure!(
        control_bytes == *final_receipt.control_id.as_bytes(),
        "recursive control-ID artifact differs"
    );
    let extracted_seal = validate_candidate_terminal_shape(
        final_receipt,
        expected_family.terminal(),
        &expected_claim,
    )?;
    ensure!(
        extracted_seal == raw_seal,
        "raw-seal artifact differs from final succinct receipt"
    );

    let profile_id = hex::encode(
        parse_ergo_statement_v1(statement)
            .context("cannot decode statement profile for ancestry replay")?
            .profile_id(),
    );
    let expected_ancestry =
        build_projection_bundle(&oracle, expected_image_id, statement, &profile_id)
            .context("cannot replay shared recursive ancestry projection")?;
    ensure!(
        ancestry_source == expected_ancestry.jcs,
        "recursive ancestry projection differs from the cryptographically replayed oracle"
    );
    ensure!(
        physical_auxiliary_seals == expected_ancestry.auxiliary_seals,
        "physical auxiliary seals differ from the cryptographically replayed oracle"
    );
    validate_projection_bundle(
        &ancestry_source,
        expected_family,
        expected_image_id,
        statement,
        &profile_id,
        &raw_seal,
        &physical_auxiliary_seals,
    )?;

    validate_proof_output_manifest(&proof_output, &manifest)?;
    ensure!(
        read_regular_bounded(
            &manifest_path,
            MANIFEST_MAX_BYTES,
            "recursive output manifest",
        )? == manifest_source,
        "recursive output manifest changed during verification"
    );
    require_exact_export_layout(export_root, expected_family)?;

    let InnerReceipt::Composite(source) = &oracle.source_receipt.inner else {
        bail!("validated recursive source receipt is no longer composite");
    };
    Ok(VerifiedRecursiveExport {
        family: expected_family,
        image_id: expected_image_id,
        claim_digest: expected_claim,
        control_id: final_receipt.control_id,
        source_segment_count: source.segments.len(),
        ancestry_step_count: oracle.steps.len(),
    })
}

fn validate_expected_method(elf: &[u8], image_id: Digest) -> Result<()> {
    let computed = compute_image_id(elf).context("cannot compute expected guest ELF image ID")?;
    ensure!(
        computed == image_id,
        "expected guest ELF differs from expected image ID"
    );
    Ok(())
}

fn final_receipt(oracle: &RecursiveOracle) -> Result<&risc0_zkvm::SuccinctReceipt<ReceiptClaim>> {
    oracle
        .steps
        .get(oracle.final_step as usize)
        .map(|step| &step.receipt)
        .context("recursive final-step index is out of range")
}

fn encode_checkpoint_receipt(receipt: &Receipt) -> Result<Vec<u8>> {
    let bytes = receipt_oracle_bincode_options()
        .serialize(receipt)
        .context("cannot encode final-receipt checkpoint")?;
    ensure!(
        bytes.len() <= CANDIDATE_RECEIPT_ORACLE_MAX_BYTES,
        "final-receipt checkpoint exceeds its byte limit"
    );
    let decoded = decode_checkpoint_receipt(&bytes)?;
    ensure!(
        decoded.journal.bytes == receipt.journal.bytes
            && decoded.claim()?.digest() == receipt.claim()?.digest(),
        "fresh final-receipt checkpoint changed receipt identity"
    );
    Ok(bytes)
}

fn checkpoint_final_receipt(
    output_root: &Path,
    oracle: &RecursiveOracle,
    image_id: Digest,
    statement: &[u8],
    terminal: CandidateTerminal,
) -> Result<Vec<u8>> {
    let receipt = Receipt::new(
        InnerReceipt::Succinct(final_receipt(oracle)?.clone()),
        statement.to_vec(),
    );
    validate_checkpoint_receipt(&receipt, image_id, statement, terminal)?;
    let bytes = encode_checkpoint_receipt(&receipt)?;
    write_atomic_checkpoint(output_root, &bytes)?;
    Ok(bytes)
}

fn decode_checkpoint_receipt(bytes: &[u8]) -> Result<Receipt> {
    decode_outer_receipt_oracle(bytes).context("cannot decode exact final-receipt checkpoint")
}

fn validate_checkpoint_receipt(
    receipt: &Receipt,
    image_id: Digest,
    statement: &[u8],
    terminal: CandidateTerminal,
) -> Result<()> {
    ensure!(
        receipt.journal.bytes == statement,
        "final-receipt checkpoint journal differs from expected statement"
    );
    let expected_claim = ReceiptClaim::ok(image_id, statement.to_vec()).digest();
    ensure!(
        receipt.claim()?.digest() == expected_claim,
        "final-receipt checkpoint claim is not exact OK"
    );
    let InnerReceipt::Succinct(inner) = &receipt.inner else {
        bail!("final-receipt checkpoint is not succinct");
    };
    validate_candidate_terminal_shape(inner, terminal, &expected_claim)?;
    let output = inner
        .claim
        .as_value()
        .context("final-receipt checkpoint claim is pruned")?
        .output
        .as_value()
        .context("final-receipt checkpoint output is pruned")?
        .as_ref()
        .context("final-receipt checkpoint has no output")?;
    ensure!(
        output.assumptions.is_empty(),
        "final-receipt checkpoint still has assumptions"
    );
    receipt
        .verify_with_context(&VerifierContext::default().with_dev_mode(false), image_id)
        .context("final-receipt checkpoint failed upstream verification")
}

fn verify_unchanged_checkpoint(
    output_root: &Path,
    expected_bytes: &[u8],
    image_id: Digest,
    statement: &[u8],
    terminal: CandidateTerminal,
) -> Result<()> {
    let bytes = read_regular_bounded(
        &output_root.join(CHECKPOINT_FILE),
        CANDIDATE_RECEIPT_ORACLE_MAX_BYTES,
        "recursive final-receipt checkpoint",
    )?;
    ensure!(
        bytes == expected_bytes,
        "recursive final-receipt checkpoint changed during publication"
    );
    validate_checkpoint_receipt(
        &decode_checkpoint_receipt(&bytes)?,
        image_id,
        statement,
        terminal,
    )
}

fn write_atomic_checkpoint(output_root: &Path, bytes: &[u8]) -> Result<()> {
    require_ordinary_directory(output_root, "recursive output root")?;
    ensure!(
        bounded_names(output_root, 1)?.is_empty(),
        "recursive output root changed after empty preflight"
    );
    let checkpoint = output_root.join(CHECKPOINT_FILE);
    create_atomic_candidate_file(
        &checkpoint,
        bytes,
        "recursive final-receipt salvage checkpoint",
    )?;
    require_checkpoint_only(output_root)
}

fn require_checkpoint_only(output_root: &Path) -> Result<()> {
    require_ordinary_directory(output_root, "recursive output root")?;
    ensure!(
        bounded_names(output_root, 1)? == [CHECKPOINT_FILE],
        "recursive output root changed after final-receipt checkpoint"
    );
    let checkpoint = output_root.join(CHECKPOINT_FILE);
    require_regular_file(&checkpoint, "recursive final-receipt checkpoint")?;
    require_single_hard_link(&checkpoint, "recursive final-receipt salvage checkpoint")
}

fn require_single_hard_link(path: &Path, label: &str) -> Result<()> {
    let file =
        File::open(path).with_context(|| format!("cannot open {label} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect open {label} {}", path.display()))?;
    #[cfg(unix)]
    let links = checkpoint_hard_link_count(&file, &metadata, path, label);
    #[cfg(windows)]
    let links = checkpoint_hard_link_count(&file, &metadata, path, label)?;
    ensure!(
        links == 1,
        "{label} must have exactly one hard link: {} has {links}",
        path.display()
    );
    Ok(())
}

#[cfg(unix)]
fn checkpoint_hard_link_count(
    _file: &File,
    metadata: &Metadata,
    _path: &Path,
    _label: &str,
) -> u64 {
    use std::os::unix::fs::MetadataExt as _;

    metadata.nlink()
}

#[cfg(windows)]
fn checkpoint_hard_link_count(
    file: &File,
    _metadata: &Metadata,
    path: &Path,
    label: &str,
) -> Result<u64> {
    Ok(winapi_util::file::information(file)
        .with_context(|| format!("cannot inspect {label} link count {}", path.display()))?
        .number_of_links())
}

fn require_completed_parent_layout(output_root: &Path) -> Result<()> {
    require_ordinary_directory(output_root, "recursive output root")?;
    ensure!(
        bounded_names(output_root, 2)? == [CHECKPOINT_FILE, FINAL_EXPORT_DIRECTORY],
        "completed recursive output-root path set differs"
    );
    let checkpoint = output_root.join(CHECKPOINT_FILE);
    require_regular_file(&checkpoint, "recursive final-receipt checkpoint")?;
    require_single_hard_link(&checkpoint, "recursive final-receipt salvage checkpoint")?;
    require_ordinary_directory(
        &output_root.join(FINAL_EXPORT_DIRECTORY),
        "recursive final export",
    )
}

fn authenticate_calibration(
    prover: &LocalProver,
    calibration: &RecursiveCalibrationReport,
    elf: &[u8],
    image_id: Digest,
    statement: &[u8],
    family: RecursiveFamily,
    recipe: RecursiveCalibrationRecipe,
) -> Result<()> {
    let mut image_id_bytes = [0_u8; DIGEST_BYTES];
    image_id_bytes.copy_from_slice(image_id.as_bytes());
    verify_recursive_calibration_with_recipe(
        calibration,
        elf,
        &image_id_bytes,
        statement,
        family.as_str(),
        recipe,
        |workload_iterations| {
            observe_recursive_calibration_shape(
                prover,
                elf,
                image_id,
                statement,
                family,
                recipe.segment_limit_po2(),
                workload_iterations,
            )
        },
    )
}

#[cfg(test)]
const fn terminal_label(terminal: CandidateTerminal) -> &'static str {
    match terminal {
        CandidateTerminal::Join => "join",
        CandidateTerminal::Resolve => "resolve",
        CandidateTerminal::Lift(_) => "lift",
    }
}

fn expected_manifest_paths(family: RecursiveFamily) -> Vec<String> {
    let mut paths = MANIFEST_PATHS.map(str::to_owned).to_vec();
    paths.extend(recursive_ancestry_expected_auxiliary_paths(project_family(
        family,
    )));
    paths.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    paths
}

fn ensure_manifest_paths(manifest: &[ManifestEntry], family: RecursiveFamily) -> Result<()> {
    let expected_paths = expected_manifest_paths(family);
    ensure!(
        manifest.len() == expected_paths.len(),
        "recursive output manifest entry count differs"
    );
    for (entry, expected) in manifest.iter().zip(expected_paths) {
        ensure!(
            entry.path == expected,
            "recursive output manifest path set differs"
        );
    }
    Ok(())
}

fn require_exact_export_layout(export_root: &Path, family: RecursiveFamily) -> Result<()> {
    require_ordinary_directory(export_root, "recursive export root")?;
    ensure!(
        bounded_names(export_root, 2)? == [OUTPUT_MANIFEST_FILE, PROOF_OUTPUT_DIRECTORY],
        "recursive export top-level path set differs"
    );
    let proof_output = export_root.join(PROOF_OUTPUT_DIRECTORY);
    require_ordinary_directory(&proof_output, "recursive proof-output")?;
    require_regular_file(
        &export_root.join(OUTPUT_MANIFEST_FILE),
        "recursive output manifest",
    )?;
    ensure!(
        collect_proof_output_directories(&proof_output, family)?
            == expected_proof_output_directories(family),
        "recursive proof-output directory set differs from the closed family export"
    );
    Ok(())
}

fn expected_proof_output_directories(family: RecursiveFamily) -> BTreeSet<String> {
    let mut directories = BTreeSet::new();
    for path in expected_manifest_paths(family) {
        let segments = path.split('/').collect::<Vec<_>>();
        for end in 1..segments.len() {
            directories.insert(segments[..end].join("/"));
        }
    }
    directories
}

fn collect_proof_output_directories(
    proof_output: &Path,
    family: RecursiveFamily,
) -> Result<BTreeSet<String>> {
    let maximum = expected_proof_output_directories(family).len();
    let mut directories = BTreeSet::new();
    let mut pending = vec![(proof_output.to_path_buf(), String::new())];
    while let Some((directory, prefix)) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("cannot enumerate directory {}", directory.display()))?
        {
            let entry = entry.context("cannot read recursive proof-output directory entry")?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("recursive proof-output has a non-UTF-8 path"))?;
            ensure!(
                !name.is_empty()
                    && name.is_ascii()
                    && name != "."
                    && name != ".."
                    && !name.contains(['/', '\\']),
                "recursive proof-output has an unsafe path segment"
            );
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).with_context(|| {
                format!(
                    "cannot inspect recursive proof-output entry {}",
                    path.display()
                )
            })?;
            ensure!(
                !metadata.file_type().is_symlink() && !is_reparse_point(&metadata),
                "recursive proof-output contains a link or reparse point"
            );
            if metadata.file_type().is_dir() {
                let relative = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                ensure!(
                    directories.len() < maximum,
                    "recursive proof-output contains too many directories"
                );
                ensure!(
                    directories.insert(relative.clone()),
                    "recursive proof-output contains a duplicate directory"
                );
                pending.push((path, relative));
            } else {
                ensure!(
                    metadata.file_type().is_file(),
                    "recursive proof-output entry is neither a directory nor a regular file"
                );
            }
        }
    }
    Ok(directories)
}

fn bounded_names(path: &Path, exact_count: usize) -> Result<Vec<String>> {
    let mut names = Vec::with_capacity(exact_count);
    for entry in fs::read_dir(path)
        .with_context(|| format!("cannot enumerate directory {}", path.display()))?
    {
        ensure!(
            names.len() < exact_count,
            "directory contains more than {exact_count} entries"
        );
        names.push(
            entry
                .context("cannot read directory entry")?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("directory contains a non-UTF-8 path"))?,
        );
    }
    names.sort();
    Ok(names)
}

fn read_manifested(
    root: &Path,
    manifest: &[ManifestEntry],
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>> {
    let entry = manifest
        .iter()
        .find(|entry| entry.path == name)
        .with_context(|| format!("recursive output manifest omits {name}"))?;
    let bytes = read_regular_bounded(&root.join(name), maximum, name)?;
    ensure!(
        entry.length == bytes.len().to_string(),
        "manifested length differs for {name}"
    );
    ensure!(
        entry.sha256 == sha256_hex(&bytes),
        "manifested SHA-256 differs for {name}"
    );
    Ok(bytes)
}

fn read_fixed<const N: usize>(
    root: &Path,
    manifest: &[ManifestEntry],
    name: &str,
) -> Result<[u8; N]> {
    let bytes = read_manifested(root, manifest, name, N)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow::anyhow!("{name} has {} bytes, expected {N}", bytes.len()))
}

fn read_auxiliary_seals(
    root: &Path,
    manifest: &[ManifestEntry],
    family: RecursiveFamily,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let paths = recursive_ancestry_expected_auxiliary_paths(project_family(family));
    let mut seals = BTreeMap::new();
    for path in paths {
        let bytes = read_manifested(root, manifest, &path, PROOF_BYTES)?;
        ensure!(
            bytes.len() == PROOF_BYTES,
            "auxiliary raw seal has the wrong byte length at {path}"
        );
        ensure!(
            seals.insert(path, bytes).is_none(),
            "duplicate auxiliary raw-seal path"
        );
    }
    Ok(seals)
}

fn read_regular_bounded(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>> {
    require_regular_file(path, label)?;
    let file =
        File::open(path).with_context(|| format!("cannot open {label} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect open {label}"))?;
    ensure!(
        metadata.file_type().is_file() && !is_reparse_point(&metadata),
        "opened {label} is not a regular non-link file"
    );
    ensure!(
        metadata.len() <= maximum as u64,
        "{label} exceeds its {maximum}-byte limit"
    );
    let capacity =
        usize::try_from(metadata.len()).context("recursive artifact length does not fit usize")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read bounded {label}"))?;
    ensure!(bytes.len() <= maximum, "{label} grew above its byte limit");
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "{label} changed length while being read"
    );
    Ok(bytes)
}

fn require_ordinary_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {label} {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir() && !is_reparse_point(&metadata),
        "{label} is not an ordinary non-link directory"
    );
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {label} {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && !is_reparse_point(&metadata),
        "{label} is not a regular non-link file"
    );
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "cannot create recursive candidate artifact {}",
                path.display()
            )
        })?;
    file.write_all(bytes).with_context(|| {
        format!(
            "cannot write recursive candidate artifact {}",
            path.display()
        )
    })?;
    file.sync_all().with_context(|| {
        format!(
            "cannot sync recursive candidate artifact {}",
            path.display()
        )
    })
}

fn publish_staging_export(output_root: &Path, staging: &Path) -> Result<()> {
    publish_staging_export_after_sync(output_root, staging, |_| Ok(()))
}

fn publish_staging_export_after_sync(
    output_root: &Path,
    staging: &Path,
    after_sync: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    ensure!(
        staging == output_root.join(STAGING_EXPORT_DIRECTORY),
        "recursive staging path is not reserved"
    );
    let destination = output_root.join(FINAL_EXPORT_DIRECTORY);
    sync_directory(&staging.join(PROOF_OUTPUT_DIRECTORY))?;
    sync_directory(staging)?;
    after_sync(&destination)?;
    renamore::rename_exclusive(staging, &destination).with_context(|| {
        format!(
            "cannot atomically publish recursive candidate without replacement {}",
            destination.display()
        )
    })?;
    sync_directory(output_root)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("cannot open directory for sync {}", path.display()))?
        .sync_all()
        .with_context(|| format!("cannot sync directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(windows)]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn is_reparse_point(_metadata: &Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_recipe_authentication_source(source: &str) {
        let file = syn::parse_file(source).unwrap();
        let function = |name: &str| {
            let matches: Vec<_> = file.items.iter().filter_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == name => Some(item),
                _ => None,
            }).collect();
            assert_eq!(matches.len(), 1, "unique function {name}");
            matches[0]
        };
        let expected: syn::Block = syn::parse_quote!({
            let mut image_id_bytes = [0_u8; DIGEST_BYTES];
            image_id_bytes.copy_from_slice(image_id.as_bytes());
            verify_recursive_calibration_with_recipe(
                calibration, elf, &image_id_bytes, statement, family.as_str(), recipe,
                |workload_iterations| {
                    observe_recursive_calibration_shape(prover, elf, image_id, statement,
                        family, recipe.segment_limit_po2(), workload_iterations,)
                },
            )
        });
        assert_eq!(*function("authenticate_calibration").block, expected);
        struct Calls(Vec<syn::ExprCall>);
        impl<'ast> syn::visit::Visit<'ast> for Calls {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("authenticate_calibration")) {
                    self.0.push(call.clone());
                }
                syn::visit::visit_expr_call(self, call);
            }
        }
        for (name, expected) in [
            ("generate_recursive_candidate_export_with_recipe", syn::parse_quote!(authenticate_calibration(&prover, calibration, elf, image_id, statement, family, recipe)?;)),
            ("verify_recursive_candidate_export_bytes", syn::parse_quote!(authenticate_calibration(&calibration_prover, &calibration, expected_elf, expected_image_id, statement, expected_family, recipe,)?;)),
        ] {
            let expected: syn::Stmt = expected;
            let body = &function(name).block;
            assert_eq!(body.stmts.iter().filter(|stmt| **stmt == expected).count(), 1, "direct propagated authentication {name}");
            let mut calls = Calls(Vec::new());
            syn::visit::Visit::visit_block(&mut calls, body);
            assert_eq!(calls.0.len(), 1, "no extra or decorative authenticator {name}");
            if name == "generate_recursive_candidate_export_with_recipe" {
                let generation: syn::Stmt = syn::parse_quote!(
                    let oracle = generate_recursive_oracle_unreplayed(
                        &prover, elf, image_id, statement, family, &calibration.segment_po2,
                        calibration.segment_limit_po2, calibration.workload_iterations,
                        calibration.assumption_workload_iterations,
                    )?;
                );
                let generation_positions: Vec<_> = body.stmts.iter().enumerate()
                    .filter_map(|(index, stmt)| (*stmt == generation).then_some(index)).collect();
                assert_eq!(generation_positions.len(), 1, "unique direct proof generation");
                let authentication_position = body.stmts.iter().position(|stmt| *stmt == expected).unwrap();
                assert!(authentication_position < generation_positions[0],
                    "calibration authentication must precede proof generation");
            }
        }
    }

    #[test]
    fn generation_and_export_verification_share_the_exact_recipe_executor_join() {
        let source = include_str!("recursive_export.rs").split("\n#[cfg(test)]\nmod tests").next().unwrap();
        assert_recipe_authentication_source(source);
        for (old, new) in [
            ("statement, family, recipe)?;", "statement, family, RecursiveCalibrationRecipe::Fixed22)?;"),
            ("        expected_family,\n        recipe,\n    )?;", "        expected_family,\n        RecursiveCalibrationRecipe::Fixed22,\n    )?;"),
            ("recipe.segment_limit_po2()", "22"),
            ("        family.as_str(),\n        recipe,", "        family.as_str(),\n        RecursiveCalibrationRecipe::Fixed22,"),
            ("observe_recursive_calibration_shape(", "unrelated_observer("),
            ("statement, family, recipe)?;", "statement, family, recipe).ok();"),
        ] {
            assert_recipe_authentication_source(source);
            assert_eq!(source.matches(old).count(), 1, "isolated mutation {old}");
            let mutant = source.replacen(old, new, 1);
            assert!(std::panic::catch_unwind(|| assert_recipe_authentication_source(&mutant)).is_err(), "{old}");
        }
        assert_recipe_authentication_source(source);
        let authentication = "    authenticate_calibration(&prover, calibration, elf, image_id, statement, family, recipe)?;\n";
        let generation = concat!(
            "    let oracle = generate_recursive_oracle_unreplayed(\n",
            "        &prover,\n        elf,\n        image_id,\n        statement,\n        family,\n",
            "        &calibration.segment_po2,\n        calibration.segment_limit_po2,\n",
            "        calibration.workload_iterations,\n        calibration.assumption_workload_iterations,\n    )?;\n"
        );
        assert_eq!(source.matches(authentication).count(), 1, "single authentication move source");
        assert_eq!(source.matches(generation).count(), 1, "single generation move target");
        let without_authentication = source.replacen(authentication, "", 1);
        let mutant = without_authentication.replacen(generation, &format!("{generation}{authentication}"), 1);
        assert_eq!(mutant.matches(authentication).count(), 1);
        assert_eq!(mutant.replacen(authentication, "", 1), without_authentication,
            "only the authentication position may change");
        let rejected = std::panic::catch_unwind(|| assert_recipe_authentication_source(&mutant))
            .expect_err("authentication after generation must fail the order guard");
        let message = rejected.downcast_ref::<&str>().copied()
            .or_else(|| rejected.downcast_ref::<String>().map(String::as_str));
        assert_eq!(message, Some("calibration authentication must precede proof generation"));
    }

    #[test]
    fn explicit_recipe_export_rejects_family_before_filesystem_or_execution() {
        let recipe = RecursiveCalibrationRecipe::Join21;
        let report = RecursiveCalibrationReport {
            schema: crate::recursive_calibration::RECURSIVE_CALIBRATION_SCHEMA.to_owned(),
            lifecycle: crate::recursive_calibration::RECURSIVE_CALIBRATION_LIFECYCLE.to_owned(),
            elf_sha256: "00".repeat(32), image_id: "00".repeat(32), statement_sha256: "00".repeat(32),
            family: "terminal-resolve".to_owned(), segment_limit_po2: 21,
            workload_iterations: 0, assumption_workload_iterations: 0, segment_po2: vec![21],
        };
        let error = generate_recursive_candidate_export_with_recipe(Path::new("missing-parent/out"), b"not-elf",
            Digest::ZERO, b"not-statement", RecursiveFamily::TerminalResolve, &report, recipe).unwrap_err();
        assert_eq!(error.to_string(), "Join21 permits only terminal-join and resolve-then-join");
        let error = verify_recursive_candidate_export_with_recipe(Path::new("missing-export"), Path::new("missing-statement"),
            RecursiveFamily::TerminalResolve, b"not-elf", Digest::ZERO, recipe).unwrap_err();
        assert_eq!(error.to_string(), "Join21 permits only terminal-join and resolve-then-join");
        let _: fn(&Path, &[u8], Digest, &[u8], RecursiveFamily, &RecursiveCalibrationReport) -> Result<VerifiedRecursiveExport> = generate_recursive_candidate_export;
        let _: fn(&Path, &Path, RecursiveFamily, &[u8], Digest) -> Result<VerifiedRecursiveExport> = verify_recursive_candidate_export;
    }

    #[test]
    fn recursive_manifest_paths_include_every_family_auxiliary_seal_in_order() {
        for family in [
            RecursiveFamily::TerminalJoin,
            RecursiveFamily::TerminalResolve,
            RecursiveFamily::ResolveThenJoin,
        ] {
            let paths = expected_manifest_paths(family);
            assert!(paths.windows(2).all(|pair| pair[0] < pair[1]));
            assert_eq!(
                paths.len(),
                MANIFEST_PATHS.len()
                    + eip_0045_reproduction::recursive_ancestry::
                        recursive_ancestry_expected_auxiliary_paths(project_family(family))
                        .len()
            );
            assert!(paths.iter().any(|path| path == CALIBRATION_FILE));
            assert!(eip_0045_reproduction::recursive_ancestry::
                recursive_ancestry_expected_auxiliary_paths(project_family(family))
                .iter()
                .all(|path| paths.contains(path)));
        }
    }

    #[test]
    fn recursive_manifest_rejects_missing_extra_or_substituted_auxiliary_seal() {
        let family = RecursiveFamily::TerminalResolve;
        let exact = expected_manifest_paths(family)
            .into_iter()
            .map(|path| ManifestEntry {
                path,
                length: "0".to_owned(),
                sha256: "00".repeat(32),
            })
            .collect::<Vec<_>>();
        ensure_manifest_paths(&exact, family).unwrap();

        let mut missing = exact.clone();
        missing.pop();
        assert!(ensure_manifest_paths(&missing, family).is_err());

        let mut extra = exact.clone();
        extra.push(ManifestEntry {
            path: "unexpected-auxiliary-seal.bin".to_owned(),
            length: "0".to_owned(),
            sha256: "00".repeat(32),
        });
        extra.sort_by(|left, right| left.path.cmp(&right.path));
        assert!(ensure_manifest_paths(&extra, family).is_err());

        let mut substituted = exact;
        substituted
            .iter_mut()
            .find(|entry| entry.path.ends_with("candidate-ancestry-step-00-raw-seal.bin"))
            .unwrap()
            .path = "reproduction/schema/b4-corpus-v1.candidate/positive/terminal-resolve-explicit-root/candidate-ancestry-step-99-raw-seal.bin".to_owned();
        substituted.sort_by(|left, right| left.path.cmp(&right.path));
        assert!(ensure_manifest_paths(&substituted, family).is_err());
    }

    #[test]
    fn staging_physically_exports_every_referenced_auxiliary_seal() {
        let family = RecursiveFamily::ResolveThenJoin;
        let root = unique_test_root("recursive-auxiliary-export");
        fs::create_dir(&root).unwrap();
        write_new_file(&root.join(CHECKPOINT_FILE), b"checkpoint").unwrap();

        let paths = expected_manifest_paths(family);
        let payloads = paths
            .iter()
            .enumerate()
            .map(|(index, _)| vec![u8::try_from(index).unwrap()])
            .collect::<Vec<_>>();
        let artifacts = paths
            .iter()
            .zip(&payloads)
            .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
            .collect::<Vec<_>>();

        let staging = stage_recursive_export(&root, &artifacts, family).unwrap();
        let manifest = build_proof_output_manifest(staging.join(PROOF_OUTPUT_DIRECTORY)).unwrap();
        ensure_manifest_paths(&manifest, family).unwrap();
        for ((path, expected), entry) in artifacts.iter().zip(&manifest) {
            assert_eq!(*path, entry.path);
            assert_eq!(
                fs::read(staging.join(PROOF_OUTPUT_DIRECTORY).join(path)).unwrap(),
                *expected
            );
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recursive_export_layout_rejects_an_extra_empty_directory() {
        let family = RecursiveFamily::TerminalJoin;
        let root = unique_test_root("recursive-empty-directory");
        let proof_output = root.join(PROOF_OUTPUT_DIRECTORY);
        fs::create_dir_all(&proof_output).unwrap();
        write_new_file(&root.join(OUTPUT_MANIFEST_FILE), b"manifest").unwrap();
        for path in expected_manifest_paths(family) {
            if let Some(parent) = Path::new(&path).parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(proof_output.join(parent)).unwrap();
            }
        }
        require_exact_export_layout(&root, family).unwrap();

        fs::create_dir(proof_output.join("unexpected-empty-directory")).unwrap();
        let error = require_exact_export_layout(&root, family)
            .unwrap_err()
            .to_string();
        assert!(error.contains("too many directories"));

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn final_export_publication_does_not_replace_a_raced_destination() {
        let root = unique_test_root("recursive-final-export-create-only-race");
        let staging = root.join(STAGING_EXPORT_DIRECTORY);
        let proof_output = staging.join(PROOF_OUTPUT_DIRECTORY);
        fs::create_dir_all(&proof_output).unwrap();
        write_new_file(&proof_output.join("staged-artifact"), b"staged").unwrap();

        let mut raced_identity = None;
        let result = publish_staging_export_after_sync(&root, &staging, |destination| {
            fs::create_dir(destination)?;
            raced_identity = Some(directory_identity(destination));
            Ok(())
        });

        assert!(
            result.is_err(),
            "create-only final export publication accepted a raced destination"
        );
        let destination = root.join(FINAL_EXPORT_DIRECTORY);
        assert_eq!(
            directory_identity(&destination),
            raced_identity.unwrap(),
            "final export publication replaced the raced destination identity"
        );
        assert!(
            fs::read_dir(&destination).unwrap().next().is_none(),
            "raced destination gained staged contents"
        );
        assert!(
            staging.is_dir(),
            "failed final export publication removed its staging source"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    fn directory_identity(path: &Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt as _;

        let metadata = fs::symlink_metadata(path).unwrap();
        (metadata.dev(), metadata.ino())
    }

    #[cfg(windows)]
    fn directory_identity(path: &Path) -> (u64, u64) {
        let handle = winapi_util::Handle::from_path_any(path).unwrap();
        let information = winapi_util::file::information(&handle).unwrap();
        (information.volume_serial_number(), information.file_index())
    }

    #[cfg(unix)]
    #[test]
    fn checkpoint_publication_does_not_replace_a_raced_destination() {
        let root = unique_test_root("recursive-checkpoint-create-only-race");
        fs::create_dir(&root).unwrap();
        let checkpoint = root.join(CHECKPOINT_FILE);
        let raced_bytes = b"raced-destination";
        let attacker_root = root.clone();
        let attacker_checkpoint = checkpoint.clone();
        let attacker = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while !fs::read_dir(&attacker_root).unwrap().any(|entry| {
                entry
                    .map(|entry| entry.file_name() != CHECKPOINT_FILE)
                    .unwrap_or(false)
            }) {
                assert!(
                    std::time::Instant::now() < deadline,
                    "checkpoint temporary file never appeared"
                );
                std::thread::yield_now();
            }
            write_new_file(&attacker_checkpoint, raced_bytes).unwrap();
        });

        // Keep the temporary file observable long enough for the racing writer
        // to publish after preflight and before final publication.
        let candidate_bytes = vec![0xA5; 64 * 1024 * 1024];
        let result = write_atomic_checkpoint(&root, &candidate_bytes);
        attacker.join().unwrap();

        assert!(
            result.is_err(),
            "create-only checkpoint publication accepted a raced destination"
        );
        assert_eq!(
            fs::read(&checkpoint).unwrap(),
            raced_bytes,
            "create-only checkpoint publication replaced the raced destination"
        );
        assert_eq!(
            bounded_names(&root, 1).unwrap(),
            [CHECKPOINT_FILE],
            "failed checkpoint publication left an entry beside the raced destination"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn checkpoint_success_is_create_only_and_leaves_one_final_link() {
        let root = unique_test_root("recursive-checkpoint-create-only-success");
        fs::create_dir(&root).unwrap();
        let checkpoint = root.join(CHECKPOINT_FILE);

        write_atomic_checkpoint(&root, b"first-checkpoint").unwrap();
        assert_eq!(fs::read(&checkpoint).unwrap(), b"first-checkpoint");
        assert_eq!(bounded_names(&root, 1).unwrap(), [CHECKPOINT_FILE]);
        require_single_hard_link(&checkpoint, "test checkpoint").unwrap();

        assert!(write_atomic_checkpoint(&root, b"replacement").is_err());
        assert_eq!(fs::read(&checkpoint).unwrap(), b"first-checkpoint");
        assert_eq!(bounded_names(&root, 1).unwrap(), [CHECKPOINT_FILE]);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn family_terminal_labels_are_exact() {
        assert_eq!(
            terminal_label(RecursiveFamily::TerminalJoin.terminal()),
            "join"
        );
        assert_eq!(
            terminal_label(RecursiveFamily::TerminalResolve.terminal()),
            "resolve"
        );
        assert_eq!(
            terminal_label(RecursiveFamily::ResolveThenJoin.terminal()),
            "join"
        );
    }

    fn unique_test_root(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{label}-{}-{nonce}", std::process::id()))
    }
}
