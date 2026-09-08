//! Command-line entry point for non-final candidate proof generation.

use std::{
    fs::{self, File, Metadata},
    io::Read as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use bincode::Options as _;
use clap::{Parser, Subcommand};
#[cfg(feature = "b4-terminal-fixture-generation")]
use eip_0045_candidate_generator::terminal_fixture_export::{
    generate_local_terminal_fixture_export, verify_local_terminal_fixture_export,
};
#[cfg(test)]
use eip_0045_candidate_generator::CANDIDATE_RECEIPT_ORACLE_MAX_BYTES;
use eip_0045_candidate_generator::{
    CANDIDATE_RECEIPT_ORACLE_MAX_BYTES_U64, EXECUTOR_SEGMENT_LIMIT_PO2,
    EXPECTED_INNER_CONTROL_ROOT_HEX, EXPECTED_OUTER_PO2, EXPECTED_VERIFIER_PARAMETERS_HEX,
    SegmentObservation, WORKLOAD_SEED,
    alternate_root_candidate::{
        FIXED_ALTERNATE_ROOT_CLAIM_DIGEST_PATH, FIXED_ALTERNATE_ROOT_CONTROL_ID_PATH,
        FIXED_ALTERNATE_ROOT_IMAGE_ID_PATH, FIXED_ALTERNATE_ROOT_JOURNAL_PATH,
        FIXED_ALTERNATE_ROOT_MANIFEST_PATH, FIXED_ALTERNATE_ROOT_METADATA_PATH,
        FIXED_ALTERNATE_ROOT_RAW_SEAL_PATH, FIXED_ALTERNATE_ROOT_RECEIPT_ORACLE_PATH,
        generate_fixed_alternate_root_proof_bundle,
    },
    expected_normal_lift_control_id,
    export::{verify_alternate_root_candidate_export, verify_candidate_export},
    profile_freeze::{PROFILE_ID_FILE, verify_profile_freeze_directory},
    receipt_oracle_bincode_options,
    recursive::{
        RecursiveFamily, inspect_explicit_root_cache_gate, inspect_recursive_shape,
        observe_recursive_calibration_shape,
    },
    recursive_calibration::{
        RECURSIVE_CALIBRATION_MAX_BYTES, RecursiveCalibrationRecipe,
        RecursiveCalibrationReport, create_atomic_candidate_file,
        create_recursive_calibration_file_with_recipe, derive_recursive_calibration_with_recipe,
        preflight_recursive_calibration_file,
    },
    recursive_export::{generate_recursive_candidate_export_with_recipe, verify_recursive_candidate_export_with_recipe},
    select_canonical_iterations,
    statement_bundle::{MAX_GUEST_ELF_BYTES, reference_contract_proposition_bytes},
    validate_candidate_succinct_shape, validate_ergo_statement_v1,
};
use eip_0045_methods::{EIP_0045_GUEST_ELF, EIP_0045_GUEST_ID, GuestInputHeader};
use eip_0045_reproduction::{
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
    constants::{
        MAX_APPLICATION_PAYLOAD_BYTES, MAX_STATEMENT_BYTES, PROOF_BYTES, PROOF_WORDS, RISC0_COMMIT,
        RISC0_REPOSITORY,
    },
    manifest::{build_proof_output_manifest, require_empty_before_generation},
    profile::{contract_id, ergo_statement_v1},
};
use risc0_zkvm::{
    Digest, Executor, ExecutorEnv, ExitCode, InnerReceipt, LocalProver, Prover, ProverOpts,
    Receipt, SessionInfo, SessionStats, VerifierContext, compute_image_id, sha::Digestible,
};
use sha2::{Digest as _, Sha256};

const PROOF_OUTPUT_DIRECTORY: &str = "proof-output";
const OUTPUT_MANIFEST_FILE: &str = FIXED_ALTERNATE_ROOT_MANIFEST_PATH;
const FINAL_EXPORT_DIRECTORY: &str = "candidate-proof-export";
const STAGING_EXPORT_DIRECTORY: &str = ".candidate-proof-export.staging";
const RAW_SEAL_FILE: &str = "candidate-raw-seal.bin";
const RECEIPT_ORACLE_FILE: &str = "candidate-receipt-oracle.bincode";
const JOURNAL_FILE: &str = "candidate-journal.bin";
const IMAGE_ID_FILE: &str = "candidate-image-id.bin";
const CLAIM_DIGEST_FILE: &str = "candidate-claim-digest.bin";
const CONTROL_ID_FILE: &str = "candidate-control-id.bin";
const METADATA_FILE: &str = "candidate-metadata.json";

#[derive(Debug, Parser)]
#[command(name = "eip-0045-candidate-generator")]
#[command(about = "Non-final EIP-0045 RISC Zero candidate generator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Args)]
struct LocalAlternateStatementFinalArgs {
    #[arg(long)]
    canonical_statement: PathBuf,
    #[arg(long)]
    case9_recursive_oracle: PathBuf,
    #[arg(long)]
    case9_assumption_raw_seal: PathBuf,
    #[arg(long)]
    case9_final_raw_seal: PathBuf,
    #[arg(long)]
    shared_checkpoint_root: PathBuf,
    #[arg(long)]
    calibration_file: PathBuf,
}
impl LocalAlternateStatementFinalArgs {
    fn paths(&self) -> [&Path; 4] {
        [&self.canonical_statement, &self.case9_recursive_oracle,
            &self.case9_assumption_raw_seal, &self.case9_final_raw_seal]
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Prove the local alternate-statement TerminalResolve/Fixed22 final.
    GenerateLocalAncestryAlternateStatementResolveFixed22 {
        #[command(flatten)]
        inputs: LocalAlternateStatementFinalArgs,
        #[arg(long)]
        output_root: PathBuf,
    },
    /// Replay the local alternate-statement TerminalResolve/Fixed22 final.
    VerifyLocalAncestryAlternateStatementResolveFixed22 {
        #[command(flatten)]
        inputs: LocalAlternateStatementFinalArgs,
        #[arg(long)]
        checkpoint_root: PathBuf,
    },
    /// Prove the local alternate-statement ResolveThenJoin/Join21 final.
    GenerateLocalAncestryAlternateStatementResolveThenJoinJoin21 {
        #[command(flatten)]
        inputs: LocalAlternateStatementFinalArgs,
        #[arg(long)]
        output_root: PathBuf,
    },
    /// Replay the local alternate-statement ResolveThenJoin/Join21 final.
    VerifyLocalAncestryAlternateStatementResolveThenJoinJoin21 {
        #[command(flatten)]
        inputs: LocalAlternateStatementFinalArgs,
        #[arg(long)]
        checkpoint_root: PathBuf,
    },
    /// Prove one local fixed duplicate-assumption Lift16 checkpoint.
    GenerateLocalAncestryDuplicateAssumption {
        #[arg(long)]
        canonical_statement: PathBuf,
        #[arg(long)]
        case9_recursive_oracle: PathBuf,
        #[arg(long)]
        case9_assumption_raw_seal: PathBuf,
        #[arg(long)]
        case9_final_raw_seal: PathBuf,
        #[arg(long)]
        output_root: PathBuf,
    },
    /// Reopen a duplicate-assumption checkpoint; never prove or write.
    VerifyLocalAncestryDuplicateAssumption {
        #[arg(long)]
        canonical_statement: PathBuf,
        #[arg(long)]
        case9_recursive_oracle: PathBuf,
        #[arg(long)]
        case9_assumption_raw_seal: PathBuf,
        #[arg(long)]
        case9_final_raw_seal: PathBuf,
        #[arg(long)]
        checkpoint_root: PathBuf,
    },
    /// Prove one local fixed locked-alternate-program Lift15 checkpoint.
    GenerateLocalAncestryAlternateProgram {
        #[arg(long)]
        canonical_statement: PathBuf,
        #[arg(long)]
        case9_recursive_oracle: PathBuf,
        #[arg(long)]
        case9_assumption_raw_seal: PathBuf,
        #[arg(long)]
        case9_final_raw_seal: PathBuf,
        #[arg(long)]
        output_root: PathBuf,
    },
    /// Reopen a locked-alternate-program checkpoint; never prove or write.
    VerifyLocalAncestryAlternateProgram {
        #[arg(long)]
        canonical_statement: PathBuf,
        #[arg(long)]
        case9_recursive_oracle: PathBuf,
        #[arg(long)]
        case9_assumption_raw_seal: PathBuf,
        #[arg(long)]
        case9_final_raw_seal: PathBuf,
        #[arg(long)]
        checkpoint_root: PathBuf,
    },
    /// Prove one local fixed alternate-statement Lift15 and retain its checkpoint.
    GenerateLocalAncestrySharedAssumption {
        #[arg(long)]
        canonical_statement: PathBuf,
        #[arg(long)]
        case9_recursive_oracle: PathBuf,
        #[arg(long)]
        case9_assumption_raw_seal: PathBuf,
        #[arg(long)]
        case9_final_raw_seal: PathBuf,
        /// Fresh directory; no existing destination is replaced.
        #[arg(long)]
        output_root: PathBuf,
    },
    /// Reopen and replay a local fixed Lift15 checkpoint against retained inputs.
    VerifyLocalAncestrySharedAssumption {
        #[arg(long)]
        canonical_statement: PathBuf,
        #[arg(long)]
        case9_recursive_oracle: PathBuf,
        #[arg(long)]
        case9_assumption_raw_seal: PathBuf,
        #[arg(long)]
        case9_final_raw_seal: PathBuf,
        #[arg(long)]
        checkpoint_root: PathBuf,
    },
    /// Generate the fixed nine terminal fixtures as a create-only local export.
    #[cfg(feature = "b4-terminal-fixture-generation")]
    LocalTerminalFixtureExport {
        /// Exact common statement for all five authenticated source inputs.
        #[arg(long)]
        statement_file: PathBuf,
        /// Exact outer direct Lift-15 receipt oracle.
        #[arg(long)]
        lift15_receipt_oracle: PathBuf,
        /// Exact terminal-join recursive oracle, including step-zero SystemSplit.
        #[arg(long)]
        terminal_join_recursive_oracle: PathBuf,
        /// Exact terminal-resolve recursive oracle.
        #[arg(long)]
        terminal_resolve_recursive_oracle: PathBuf,
        /// Existing physical empty directory; no existing entry is replaced.
        #[arg(long)]
        output_root: PathBuf,
    },
    /// Re-read all nineteen local terminal artifacts and replay their catalogue.
    #[cfg(feature = "b4-terminal-fixture-generation")]
    VerifyLocalTerminalFixtureExport {
        /// Published local-terminal-fixture-export directory.
        #[arg(long)]
        export_root: PathBuf,
        /// Exact expected statement, bound to the embedded guest.
        #[arg(long)]
        expected_statement: PathBuf,
    },
    /// Compute one image ID directly from a bounded ELF and write exact bytes.
    ArtifactIdentity {
        /// Exact guest ELF whose RISC Zero image ID is required.
        #[arg(long)]
        elf_file: PathBuf,
        /// New 32-byte output file; an existing entry is never replaced.
        #[arg(long)]
        output_file: PathBuf,
    },
    /// Build proposition and ErgoStatementV1 bytes for the current candidate ELF.
    CandidateStatement {
        /// Directory containing the exact verified B1/B2/B3 profile package.
        #[arg(long)]
        profile_dir: PathBuf,
        /// Exact 32-byte network chain-domain identifier.
        #[arg(long)]
        chain_domain_id_file: PathBuf,
        /// Application payload of at most 16,384 bytes.
        #[arg(long)]
        application_payload_file: PathBuf,
        /// Existing ordinary directory which must be empty.
        #[arg(long)]
        output_root: PathBuf,
    },
    /// Generate and fully validate one non-final candidate succinct receipt.
    CandidateProof {
        /// File containing the exact journal/statement bytes.
        #[arg(long)]
        statement_file: PathBuf,
        /// Exact single-segment trace exponent in the frozen range 15..=22.
        #[arg(long)]
        segment_po2: u32,
        /// Existing ordinary directory which must be empty.
        #[arg(long)]
        output_root: PathBuf,
    },
    /// Generate the fixed valid po2-15 witness with an alternate inner root.
    AlternateRootCandidateProof {
        /// File containing the exact journal/statement bytes.
        #[arg(long)]
        statement_file: PathBuf,
        /// Existing ordinary directory which must be empty.
        #[arg(long)]
        output_root: PathBuf,
    },
    /// Re-read and verify one complete non-final candidate export.
    VerifyCandidateExport {
        /// Published `candidate-proof-export` directory to verify.
        #[arg(long)]
        export_root: PathBuf,
        /// File containing the exact statement expected in the receipt journal.
        #[arg(long)]
        expected_statement: PathBuf,
        /// Exact expected single-segment exponent in the frozen range 15..=22.
        #[arg(long)]
        expected_segment_po2: u32,
    },
    /// Re-read and verify one fixed alternate-root po2-15 candidate export.
    VerifyAlternateRootCandidateExport {
        /// Published `candidate-proof-export` directory to verify.
        #[arg(long)]
        export_root: PathBuf,
        /// File containing the exact statement expected in the receipt journal.
        #[arg(long)]
        expected_statement: PathBuf,
    },
    /// Execute only and report whether one workload has the exact B4 family shape.
    RecursiveShape {
        /// File containing the exact journal/statement bytes.
        #[arg(long)]
        statement_file: PathBuf,
        /// Candidate family: terminal-join, terminal-resolve, or resolve-then-join.
        #[arg(long)]
        family: RecursiveFamily,
        /// Executor segment limit used to produce the one- or two-segment source.
        #[arg(long)]
        segment_limit_po2: u32,
        /// Deterministic guest workload iteration count.
        #[arg(long)]
        workload_iterations: u32,
    },
    /// Deterministically calibrate one recursive family without generating a proof.
    RecursiveCalibrate {
        /// Closed host calibration recipe; existing invocations remain fixed22.
        #[arg(long, default_value = "fixed22")]
        recipe: RecursiveCalibrationRecipe,
        /// File containing the exact journal/statement bytes.
        #[arg(long)]
        statement_file: PathBuf,
        /// Candidate family: terminal-join, terminal-resolve, or resolve-then-join.
        #[arg(long)]
        family: RecursiveFamily,
        /// New canonical JCS calibration file; an existing entry is never replaced.
        #[arg(long)]
        calibration_file: PathBuf,
    },
    /// Prove by execution that explicit-root mode rejects zero and wrong caches.
    RecursiveRootGate {
        /// File containing the exact journal/statement bytes.
        #[arg(long)]
        statement_file: PathBuf,
    },
    /// Generate and fully replay one non-final B4 recursive candidate export.
    RecursiveCandidateProof {
        /// Closed host calibration recipe; existing invocations remain fixed22.
        #[arg(long, default_value = "fixed22")]
        recipe: RecursiveCalibrationRecipe,
        /// File containing the exact journal/statement bytes.
        #[arg(long)]
        statement_file: PathBuf,
        /// Candidate family: terminal-join, terminal-resolve, or resolve-then-join.
        #[arg(long)]
        family: RecursiveFamily,
        /// Exact canonical calibration file, rederived before proving.
        #[arg(long)]
        calibration_file: PathBuf,
        /// Existing ordinary directory which must be empty.
        #[arg(long)]
        output_root: PathBuf,
    },
    /// Strictly verify and replay one complete B4 recursive candidate export.
    VerifyRecursiveCandidateExport {
        /// Closed host calibration recipe; existing invocations remain fixed22.
        #[arg(long, default_value = "fixed22")]
        recipe: RecursiveCalibrationRecipe,
        /// Published `candidate-recursive-proof-export` directory.
        #[arg(long)]
        export_root: PathBuf,
        /// File containing the exact statement expected in the final receipt.
        #[arg(long)]
        expected_statement: PathBuf,
        /// Caller-owned expected recursive family.
        #[arg(long)]
        expected_family: RecursiveFamily,
    },
}

struct CandidateProofResult {
    receipt: Receipt,
    stats: SessionStats,
    raw_seal: Vec<u8>,
    inner_control_root: String,
    verifier_parameters: String,
    receipt_kind: &'static str,
    verification_authority: &'static str,
    profile_owned_shape_verify: bool,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::GenerateLocalAncestryAlternateStatementResolveFixed22 { inputs, output_root } => {
            reject_runtime_overrides()?;
            eip_0045_candidate_generator::local_ancestry_alternate_statement_final::generate_resolve_fixed22(
                inputs.paths(), &inputs.shared_checkpoint_root, &inputs.calibration_file, &output_root)?;
            println!("localAlternateStatementFinal=candidate-replayed\nfamily=terminal-resolve\nrecipe=fixed22\nwitnessQualified=false\nofficialCampaign=false");
            Ok(())
        }
        Command::VerifyLocalAncestryAlternateStatementResolveFixed22 { inputs, checkpoint_root } => {
            reject_runtime_overrides()?;
            eip_0045_candidate_generator::local_ancestry_alternate_statement_final::verify_resolve_fixed22(
                inputs.paths(), &inputs.shared_checkpoint_root, &inputs.calibration_file, &checkpoint_root)?;
            println!("localAlternateStatementFinalReplay=candidate-replayed\nfamily=terminal-resolve\nrecipe=fixed22\nwitnessQualified=false\nofficialCampaign=false");
            Ok(())
        }
        Command::GenerateLocalAncestryAlternateStatementResolveThenJoinJoin21 { inputs, output_root } => {
            reject_runtime_overrides()?;
            eip_0045_candidate_generator::local_ancestry_alternate_statement_final::generate_resolve_then_join_join21(
                inputs.paths(), &inputs.shared_checkpoint_root, &inputs.calibration_file, &output_root)?;
            println!("localAlternateStatementFinal=candidate-replayed\nfamily=resolve-then-join\nrecipe=join21\nwitnessQualified=false\nofficialCampaign=false");
            Ok(())
        }
        Command::VerifyLocalAncestryAlternateStatementResolveThenJoinJoin21 { inputs, checkpoint_root } => {
            reject_runtime_overrides()?;
            eip_0045_candidate_generator::local_ancestry_alternate_statement_final::verify_resolve_then_join_join21(
                inputs.paths(), &inputs.shared_checkpoint_root, &inputs.calibration_file, &checkpoint_root)?;
            println!("localAlternateStatementFinalReplay=candidate-replayed\nfamily=resolve-then-join\nrecipe=join21\nwitnessQualified=false\nofficialCampaign=false");
            Ok(())
        }
        Command::GenerateLocalAncestryDuplicateAssumption { canonical_statement,
            case9_recursive_oracle, case9_assumption_raw_seal, case9_final_raw_seal, output_root } => {
            reject_runtime_overrides()?;
            eip_0045_candidate_generator::local_ancestry_duplicate_assumption::generate(
                [&canonical_statement, &case9_recursive_oracle, &case9_assumption_raw_seal, &case9_final_raw_seal],
                &output_root)?;
            println!("localDuplicateAssumption=verified\nterminal=lift16\nofficialCampaign=false");
            Ok(())
        }
        Command::VerifyLocalAncestryDuplicateAssumption { canonical_statement,
            case9_recursive_oracle, case9_assumption_raw_seal, case9_final_raw_seal, checkpoint_root } => {
            reject_runtime_overrides()?;
            eip_0045_candidate_generator::local_ancestry_duplicate_assumption::verify(
                [&canonical_statement, &case9_recursive_oracle, &case9_assumption_raw_seal, &case9_final_raw_seal],
                &checkpoint_root)?;
            println!("localDuplicateAssumptionReplay=verified\nterminal=lift16\nofficialCampaign=false");
            Ok(())
        }
        Command::GenerateLocalAncestryAlternateProgram { canonical_statement,
            case9_recursive_oracle, case9_assumption_raw_seal, case9_final_raw_seal, output_root } => {
            reject_runtime_overrides()?;
            eip_0045_candidate_generator::local_ancestry_alternate_program::generate(
                [&canonical_statement, &case9_recursive_oracle, &case9_assumption_raw_seal, &case9_final_raw_seal],
                &output_root)?;
            println!("localAlternateProgram=verified\nterminal=lift15\nofficialCampaign=false");
            Ok(())
        }
        Command::VerifyLocalAncestryAlternateProgram { canonical_statement,
            case9_recursive_oracle, case9_assumption_raw_seal, case9_final_raw_seal, checkpoint_root } => {
            reject_runtime_overrides()?;
            eip_0045_candidate_generator::local_ancestry_alternate_program::verify(
                [&canonical_statement, &case9_recursive_oracle, &case9_assumption_raw_seal, &case9_final_raw_seal],
                &checkpoint_root)?;
            println!("localAlternateProgramReplay=verified\nterminal=lift15\nofficialCampaign=false");
            Ok(())
        }
        Command::GenerateLocalAncestrySharedAssumption { canonical_statement,
            case9_recursive_oracle, case9_assumption_raw_seal, case9_final_raw_seal, output_root } => {
            reject_runtime_overrides()?;
            eip_0045_candidate_generator::local_ancestry_shared_assumption::generate(
                [&canonical_statement, &case9_recursive_oracle, &case9_assumption_raw_seal, &case9_final_raw_seal],
                &output_root)?;
            println!("localSharedAssumption=verified\nterminal=lift15\nofficialCampaign=false");
            Ok(())
        }
        Command::VerifyLocalAncestrySharedAssumption { canonical_statement,
            case9_recursive_oracle, case9_assumption_raw_seal, case9_final_raw_seal, checkpoint_root } => {
            reject_runtime_overrides()?;
            eip_0045_candidate_generator::local_ancestry_shared_assumption::verify(
                [&canonical_statement, &case9_recursive_oracle, &case9_assumption_raw_seal, &case9_final_raw_seal],
                &checkpoint_root)?;
            println!("localSharedAssumptionReplay=verified\nterminal=lift15\nofficialCampaign=false");
            Ok(())
        }
        #[cfg(feature = "b4-terminal-fixture-generation")]
        Command::LocalTerminalFixtureExport {
            statement_file,
            lift15_receipt_oracle,
            terminal_join_recursive_oracle,
            terminal_resolve_recursive_oracle,
            output_root,
        } => {
            reject_runtime_overrides()?;
            embedded_artifact_identity()?;
            generate_local_terminal_fixture_export(
                &output_root,
                EIP_0045_GUEST_ELF,
                &statement_file,
                &lift15_receipt_oracle,
                &terminal_join_recursive_oracle,
                &terminal_resolve_recursive_oracle,
            )?;
            println!("localTerminalFixtureExport=verified");
            println!("fixtureCount=9");
            println!("artifactCount=19");
            println!("officialCampaign=false");
            Ok(())
        }
        #[cfg(feature = "b4-terminal-fixture-generation")]
        Command::VerifyLocalTerminalFixtureExport {
            export_root,
            expected_statement,
        } => {
            verify_local_terminal_fixture_export(
                &export_root,
                EIP_0045_GUEST_ELF,
                &expected_statement,
            )?;
            println!("localTerminalFixtureReplay=verified");
            println!("officialCampaign=false");
            Ok(())
        }
        Command::ArtifactIdentity {
            elf_file,
            output_file,
        } => artifact_identity(&elf_file, &output_file),
        Command::CandidateStatement {
            profile_dir,
            chain_domain_id_file,
            application_payload_file,
            output_root,
        } => candidate_statement(
            &profile_dir,
            &chain_domain_id_file,
            &application_payload_file,
            &output_root,
        ),
        Command::CandidateProof {
            statement_file,
            segment_po2,
            output_root,
        } => candidate_proof(&statement_file, segment_po2, &output_root),
        Command::AlternateRootCandidateProof {
            statement_file,
            output_root,
        } => alternate_root_candidate_proof(&statement_file, &output_root),
        Command::VerifyCandidateExport {
            export_root,
            expected_statement,
            expected_segment_po2,
        } => {
            let verified = verify_candidate_export(
                &export_root,
                &expected_statement,
                expected_segment_po2,
                EIP_0045_GUEST_ELF,
                Digest::from(EIP_0045_GUEST_ID),
            )?;
            ensure!(
                verified.image_id.as_bytes().len() == 32
                    && verified.claim_digest.as_bytes().len() == 32
                    && verified.control_id.as_bytes().len() == 32
                    && verified.journal_digest.as_bytes().len() == 32,
                "verified candidate export returned a malformed digest observation"
            );
            println!(
                "EIP-0045 candidate receipt/proof/export binding: verified po2={}",
                verified.segment_po2
            );
            println!(
                "EIP-0045 local observations: shape checked only; calibration, execution, and verification-action metadata remain non-receipt-bound and are not authenticated as provenance by this verification"
            );
            Ok(())
        }
        Command::VerifyAlternateRootCandidateExport {
            export_root,
            expected_statement,
        } => {
            let verified = verify_alternate_root_candidate_export(
                &export_root,
                &expected_statement,
                EIP_0045_GUEST_ELF,
                Digest::from(EIP_0045_GUEST_ID),
            )?;
            ensure! {
                verified.image_id.as_bytes().len() == 32
                    && verified.claim_digest.as_bytes().len() == 32
                    && verified.control_id.as_bytes().len() == 32
                    && verified.journal_digest.as_bytes().len() == 32,
                "verified fixed alternate-root export returned a malformed digest observation"
            };
            println!(
                "EIP-0045 fixed alternate-root candidate receipt/proof/export binding: verified po2={}",
                verified.segment_po2
            );
            println!(
                "EIP-0045 verifier-parameter isolation: fixed alternate-root context accepted and stock context rejected at the verifier-parameters boundary"
            );
            Ok(())
        }
        Command::RecursiveShape {
            statement_file,
            family,
            segment_limit_po2,
            workload_iterations,
        } => {
            reject_runtime_overrides()?;
            let statement =
                read_regular_file_bounded(&statement_file, MAX_STATEMENT_BYTES, "statement file")?;
            let image_id = embedded_artifact_identity()?;
            let prover = LocalProver::new("eip-0045-pinned-local");
            let segment_po2 = inspect_recursive_shape(
                &prover,
                EIP_0045_GUEST_ELF,
                image_id,
                &statement,
                family,
                segment_limit_po2,
                workload_iterations,
            )?;
            println!("family={family}");
            println!(
                "assumptionRootSemantics={}",
                family.assumption_root_semantics()
            );
            println!("sourceSegmentCount={}", segment_po2.len());
            println!(
                "sourceSegmentPo2={}",
                segment_po2
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
            println!("shapeOnly=true");
            Ok(())
        }
        Command::RecursiveCalibrate {
            recipe,
            statement_file,
            family,
            calibration_file,
        } => {
            reject_runtime_overrides()?;
            recipe.validate_family(family.as_str())?;
            preflight_recursive_calibration_file(&calibration_file)?;
            let statement =
                read_regular_file_bounded(&statement_file, MAX_STATEMENT_BYTES, "statement file")?;
            let report = derive_embedded_recursive_calibration(&statement, family, recipe)?;
            create_recursive_calibration_file_with_recipe(&calibration_file, &report, recipe)?;
            println!("family={family}");
            println!("segmentLimitPo2={}", report.segment_limit_po2);
            println!("workloadIterations={}", report.workload_iterations);
            println!(
                "assumptionWorkloadIterations={}",
                report.assumption_workload_iterations
            );
            println!(
                "sourceSegmentPo2={}",
                report
                    .segment_po2
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
            println!("proofGeneration=false");
            Ok(())
        }
        Command::RecursiveRootGate { statement_file } => {
            reject_runtime_overrides()?;
            let statement =
                read_regular_file_bounded(&statement_file, MAX_STATEMENT_BYTES, "statement file")?;
            let image_id = embedded_artifact_identity()?;
            let prover = LocalProver::new("eip-0045-pinned-local");
            let observation = inspect_explicit_root_cache_gate(
                &prover,
                EIP_0045_GUEST_ELF,
                image_id,
                &statement,
                EXECUTOR_SEGMENT_LIMIT_PO2,
                0,
            )?;
            println!("imageId={}", hex::encode(observation.image_id.as_bytes()));
            println!("statementSha256={}", sha256_hex(&statement));
            println!(
                "requestedClaim={}",
                hex::encode(observation.requested_claim.as_bytes())
            );
            println!(
                "requestedRoot={}",
                hex::encode(observation.requested_root.as_bytes())
            );
            println!(
                "mutatedClaim={}",
                hex::encode(observation.mutated_claim.as_bytes())
            );
            println!(
                "mutatedRoot={}",
                hex::encode(observation.mutated_root.as_bytes())
            );
            println!(
                "acceptedSegmentPo2={}",
                observation
                    .accepted_segment_po2
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
            println!("correctExplicitRootCache=accepted");
            println!("zeroRootCache=rejected");
            println!("mutatedRootCache=rejected");
            println!("mutatedClaimCache=rejected");
            println!("segmentLimitPo2={EXECUTOR_SEGMENT_LIMIT_PO2}");
            println!("workloadIterations=0");
            println!("proofGeneration=false");
            Ok(())
        }
        Command::RecursiveCandidateProof {
            recipe,
            statement_file,
            family,
            calibration_file,
            output_root,
        } => {
            reject_runtime_overrides()?;
            recipe.validate_family(family.as_str())?;
            require_empty_before_generation(&output_root)?;
            let statement =
                read_regular_file_bounded(&statement_file, MAX_STATEMENT_BYTES, "statement file")?;
            let image_id = embedded_artifact_identity()?;
            let calibration_source = read_regular_file_bounded(
                &calibration_file,
                RECURSIVE_CALIBRATION_MAX_BYTES,
                "recursive calibration file",
            )?;
            let calibration = RecursiveCalibrationReport::from_canonical_jcs_with_recipe(&calibration_source, recipe)?;
            let verified = generate_recursive_candidate_export_with_recipe(
                &output_root,
                EIP_0045_GUEST_ELF,
                image_id,
                &statement,
                family,
                &calibration,
                recipe,
            )?;
            println!("family={}", verified.family);
            println!(
                "assumptionRootSemantics={}",
                verified.family.assumption_root_semantics()
            );
            println!("sourceSegmentCount={}", verified.source_segment_count);
            println!("ancestryStepCount={}", verified.ancestry_step_count);
            println!(
                "claimDigest={}",
                hex::encode(verified.claim_digest.as_bytes())
            );
            println!("controlId={}", hex::encode(verified.control_id.as_bytes()));
            println!("candidateOnly=true");
            println!("calibrationReceiptBound=false");
            println!("calibrationConsensusProvenance=false");
            println!("ancestryReceiptBound=false");
            println!("ancestryConsensusProvenance=false");
            Ok(())
        }
        Command::VerifyRecursiveCandidateExport {
            recipe,
            export_root,
            expected_statement,
            expected_family,
        } => {
            let verified = verify_recursive_candidate_export_with_recipe(
                &export_root,
                &expected_statement,
                expected_family,
                EIP_0045_GUEST_ELF,
                Digest::from(EIP_0045_GUEST_ID),
                recipe,
            )?;
            println!("family={}", verified.family);
            println!(
                "assumptionRootSemantics={}",
                verified.family.assumption_root_semantics()
            );
            println!("sourceSegmentCount={}", verified.source_segment_count);
            println!("ancestryStepCount={}", verified.ancestry_step_count);
            println!(
                "claimDigest={}",
                hex::encode(verified.claim_digest.as_bytes())
            );
            println!("controlId={}", hex::encode(verified.control_id.as_bytes()));
            println!("recursiveCandidateReplay=verified");
            println!("calibrationReceiptBound=false");
            println!("calibrationConsensusProvenance=false");
            println!("ancestryReceiptBound=false");
            println!("ancestryConsensusProvenance=false");
            Ok(())
        }
    }
}

fn derive_embedded_recursive_calibration(
    statement: &[u8],
    family: RecursiveFamily,
    recipe: RecursiveCalibrationRecipe,
) -> Result<RecursiveCalibrationReport> {
    recipe.validate_family(family.as_str())?;
    let image_id = embedded_artifact_identity()?;
    let image_id_bytes = digest_bytes(image_id);
    let prover = LocalProver::new("eip-0045-pinned-local-calibration");
    derive_recursive_calibration_with_recipe(
        EIP_0045_GUEST_ELF,
        &image_id_bytes,
        statement,
        family.as_str(),
        recipe,
        |workload_iterations| {
            observe_recursive_calibration_shape(
                &prover,
                EIP_0045_GUEST_ELF,
                image_id,
                statement,
                family,
                recipe.segment_limit_po2(),
                workload_iterations,
            )
        },
    )
}

fn artifact_identity(elf_file: &Path, output_file: &Path) -> Result<()> {
    let elf = read_regular_file_bounded(elf_file, MAX_GUEST_ELF_BYTES, "guest ELF")?;
    let image_id = compute_image_id(&elf).context("cannot compute guest ELF image ID")?;
    create_atomic_candidate_file(output_file, image_id.as_bytes(), "artifact identity")?;
    println!("imageId={}", hex::encode(image_id.as_bytes()));
    println!("elfBytes={}", elf.len());
    println!("elfSha256={}", sha256_hex(&elf));
    Ok(())
}

fn digest_bytes(digest: Digest) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(digest.as_bytes());
    bytes
}

fn candidate_statement(
    profile_dir: &Path,
    chain_domain_id_file: &Path,
    application_payload_file: &Path,
    output_root: &Path,
) -> Result<()> {
    const PROPOSITION_FILE: &str = "candidate-proposition.bin";
    const STATEMENT_FILE: &str = "candidate-statement.bin";
    const PROGRAM_ID_FILE: &str = "candidate-program-id.bin";
    const CONTRACT_ID_FILE: &str = "candidate-contract-id.bin";

    require_empty_before_generation(output_root)?;
    verify_profile_freeze_directory(profile_dir, profile_dir)
        .context("candidate statement profile package is not exact B1/B2/B3")?;
    let profile_id: [u8; 32] =
        read_regular_file_bounded(&profile_dir.join(PROFILE_ID_FILE), 32, "profile ID")?
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                anyhow::anyhow!("profile ID has {} bytes, expected 32", bytes.len())
            })?;
    let chain_domain_id: [u8; 32] =
        read_regular_file_bounded(chain_domain_id_file, 32, "chain-domain ID")?
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                anyhow::anyhow!("chain-domain ID has {} bytes, expected 32", bytes.len())
            })?;
    let payload = read_regular_file_bounded(
        application_payload_file,
        MAX_APPLICATION_PAYLOAD_BYTES,
        "application payload",
    )?;
    let image_id = embedded_artifact_identity()?;
    let program_id: [u8; 32] = image_id
        .as_bytes()
        .try_into()
        .context("embedded candidate image ID is not exactly 32 bytes")?;
    let proposition = reference_contract_proposition_bytes(&program_id, &profile_id)?;
    let contract = contract_id(&proposition);
    let statement = ergo_statement_v1(
        &chain_domain_id,
        &profile_id,
        &program_id,
        &proposition,
        &payload,
    )?;
    validate_ergo_statement_v1(&statement, &image_id)?;

    require_empty_before_generation(output_root)?;
    for (name, bytes) in [
        (CONTRACT_ID_FILE, contract.as_slice()),
        (PROGRAM_ID_FILE, program_id.as_slice()),
        (PROPOSITION_FILE, proposition.as_slice()),
        (STATEMENT_FILE, statement.as_slice()),
    ] {
        write_new_file(&output_root.join(name), bytes)?;
    }
    println!("programId={}", hex::encode(program_id));
    println!("contractId={}", hex::encode(contract));
    println!("statementBytes={}", statement.len());
    println!("candidateOnly=true");
    Ok(())
}

fn embedded_artifact_identity() -> Result<Digest> {
    checked_image_id(EIP_0045_GUEST_ELF)
}

fn checked_image_id(elf: &[u8]) -> Result<Digest> {
    let declared = Digest::from(EIP_0045_GUEST_ID);
    let computed = compute_image_id(elf).context("cannot compute the guest ELF image ID")?;
    ensure!(
        computed == declared,
        "computed guest ELF image ID differs from the generated methods constant"
    );
    Ok(computed)
}

// Keep generation, proof binding, and atomic publication in one visible order;
// splitting the pipeline would make its mutation boundary harder to audit.
#[allow(clippy::too_many_lines)]
fn candidate_proof(statement_file: &Path, segment_po2: u32, output_root: &Path) -> Result<()> {
    reject_runtime_overrides()?;
    require_empty_before_generation(output_root)?;

    let statement =
        read_regular_file_bounded(statement_file, MAX_STATEMENT_BYTES, "statement file")?;
    let image_id = embedded_artifact_identity()?;
    validate_ergo_statement_v1(&statement, &image_id)
        .context("statement file is not canonical ErgoStatementV1 for the pinned guest")?;

    let prover = LocalProver::new("eip-0045-pinned-local");
    let calibration = select_canonical_iterations(segment_po2, |iterations| {
        let session = execute_once(&prover, &statement, segment_po2, iterations)?;
        validate_execution(&session, &statement)?;
        segment_observation(&session)
    })?;

    let selected_session = execute_once(
        &prover,
        &statement,
        segment_po2,
        calibration.workload_iterations,
    )?;
    validate_execution(&selected_session, &statement)?;
    let selected_observation = segment_observation(&selected_session)?;
    ensure!(
        selected_observation == calibration.observation,
        "selected execution shape differs from calibrated execution shape"
    );
    let expected_claim = selected_session
        .receipt_claim
        .as_ref()
        .context("selected execution did not return a receipt claim")?;
    let expected_claim_digest = expected_claim.digest();
    let independent_claim = ok_receipt_claim_digests(image_id.as_bytes(), &statement)
        .context("independent byte-level receipt-claim derivation failed")?;
    ensure!(
        expected_claim_digest.as_bytes() == independent_claim.expected_claim,
        "preflight execution claim differs from the independent byte-level OK-claim derivation"
    );

    let verifier_context = VerifierContext::default().with_dev_mode(false);
    ensure!(
        !verifier_context.dev_mode(),
        "verifier context enabled dev mode"
    );
    let proof = prove_stock_candidate(
        &prover,
        &statement,
        image_id,
        segment_po2,
        calibration.workload_iterations,
        expected_claim_digest,
        &verifier_context,
    )?;
    let receipt = proof.receipt;
    ensure!(
        receipt.journal.bytes == statement,
        "receipt journal differs from statement"
    );
    ensure!(
        receipt.metadata.verifier_parameters == receipt.inner.verifier_parameters(),
        "receipt metadata verifier parameters differ from inner receipt"
    );
    let receipt_claim_digest = receipt.claim()?.digest();
    ensure!(
        receipt_claim_digest == expected_claim_digest,
        "proved receipt claim differs from preflight execution claim"
    );

    let receipt_oracle = serialize_receipt_oracle(&receipt)?;
    let journal_digest = receipt.journal.digest();
    ensure!(
        journal_digest.as_bytes() == independent_claim.journal_digest,
        "receipt journal digest differs from the independent SHA-256 derivation"
    );
    let control_id = expected_normal_lift_control_id(segment_po2)?;

    // Recheck immediately before the first mutation. This is accidental-race
    // detection, not a same-host malicious-process security boundary.
    require_empty_before_generation(output_root)?;
    let staging_export = create_staging_export(output_root)?;
    let proof_output = staging_export.join(PROOF_OUTPUT_DIRECTORY);
    fs::create_dir(&proof_output).with_context(|| {
        format!(
            "cannot create candidate proof-output directory {}",
            proof_output.display()
        )
    })?;

    let artifacts: [(&str, &[u8], &str); 6] = [
        (RAW_SEAL_FILE, &proof.raw_seal, "raw-succinct-seal"),
        (
            RECEIPT_ORACLE_FILE,
            &receipt_oracle,
            "upstream-bincode-receipt-oracle",
        ),
        (JOURNAL_FILE, &receipt.journal.bytes, "journal"),
        (IMAGE_ID_FILE, image_id.as_bytes(), "guest-image-id"),
        (
            CLAIM_DIGEST_FILE,
            expected_claim_digest.as_bytes(),
            "receipt-claim-digest",
        ),
        (
            CONTROL_ID_FILE,
            control_id.as_bytes(),
            "normal-lift-control-id",
        ),
    ];
    let mut file_metadata = Vec::with_capacity(artifacts.len());
    for (name, bytes, role) in artifacts {
        write_new_file(&proof_output.join(name), bytes)?;
        file_metadata.push(FileMetadata {
            path: name.to_owned(),
            length: bytes.len().to_string(),
            sha256: sha256_hex(bytes),
            role: role.to_owned(),
        });
    }

    let metadata = CandidateMetadata {
        candidate_status: "non-final-reproduction-candidate".to_owned(),
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
            statement_sha256: sha256_hex(&statement),
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
            segment_count: proof.stats.segments.to_string(),
            executor_segment_limit_po2: EXECUTOR_SEGMENT_LIMIT_PO2,
            segment_po2,
            user_cycles: proof.stats.user_cycles.to_string(),
            total_cycles: proof.stats.total_cycles.to_string(),
            paging_cycles: proof.stats.paging_cycles.to_string(),
            reserved_cycles: proof.stats.reserved_cycles.to_string(),
        },
        proof: ProofMetadata {
            receipt_kind: proof.receipt_kind.to_owned(),
            hash_function: "poseidon2".to_owned(),
            control_id: hex::encode(control_id.as_bytes()),
            inner_control_root: proof.inner_control_root,
            verifier_parameters: proof.verifier_parameters,
            outer_po2: EXPECTED_OUTER_PO2,
            raw_seal_words: PROOF_WORDS.to_string(),
            raw_seal_bytes: PROOF_BYTES.to_string(),
            claim_digest: hex::encode(expected_claim_digest.as_bytes()),
            journal_digest: hex::encode(journal_digest.as_bytes()),
        },
        verification: VerificationMetadata {
            receipt_bound: false,
            verification_authority: proof.verification_authority.to_owned(),
            explicit_local_prover: true,
            dev_mode: false,
            prove_guest_errors: false,
            work_receipt_present: false,
            upstream_receipt_verify: true,
            profile_owned_shape_verify: proof.profile_owned_shape_verify,
            receipt_oracle_is_consensus_encoding: false,
        },
        files: file_metadata,
    };
    let metadata_bytes = metadata
        .to_canonical_jcs()
        .context("cannot encode canonical candidate metadata")?;
    write_new_file(&proof_output.join(METADATA_FILE), &metadata_bytes)?;

    let manifest = build_proof_output_manifest(&proof_output)?;
    let manifest_value =
        serde_json::to_value(&manifest).context("cannot encode proof-output manifest")?;
    let manifest_bytes = canonical_json_bytes(&manifest_value)
        .context("cannot canonicalize proof-output manifest")?;
    write_new_file(&staging_export.join(OUTPUT_MANIFEST_FILE), &manifest_bytes)?;
    publish_staging_export(output_root, &staging_export)?;

    Ok(())
}

fn alternate_root_candidate_proof(statement_file: &Path, output_root: &Path) -> Result<()> {
    reject_runtime_overrides()?;
    require_empty_before_generation(output_root)?;
    let statement =
        read_regular_file_bounded(statement_file, MAX_STATEMENT_BYTES, "statement file")?;
    let bundle = generate_fixed_alternate_root_proof_bundle(&statement)?;

    // Recheck immediately before the first mutation. This is accidental-race
    // detection, not a same-host malicious-process security boundary.
    require_empty_before_generation(output_root)?;
    let staging_export = create_staging_export(output_root)?;
    let proof_output = staging_export.join(PROOF_OUTPUT_DIRECTORY);
    fs::create_dir(&proof_output).with_context(|| {
        format!(
            "cannot create candidate proof-output directory {}",
            proof_output.display()
        )
    })?;
    let claim_digest = bundle.claim_digest();
    let control_id = bundle.control_id();
    let image_id = bundle.image_id();
    let artifacts: [(&str, &[u8]); 7] = [
        (FIXED_ALTERNATE_ROOT_CLAIM_DIGEST_PATH, &claim_digest),
        (FIXED_ALTERNATE_ROOT_CONTROL_ID_PATH, &control_id),
        (FIXED_ALTERNATE_ROOT_IMAGE_ID_PATH, &image_id),
        (FIXED_ALTERNATE_ROOT_JOURNAL_PATH, bundle.journal()),
        (FIXED_ALTERNATE_ROOT_METADATA_PATH, bundle.metadata_jcs()),
        (FIXED_ALTERNATE_ROOT_RAW_SEAL_PATH, bundle.raw_seal()),
        (
            FIXED_ALTERNATE_ROOT_RECEIPT_ORACLE_PATH,
            bundle.receipt_oracle(),
        ),
    ];
    for (path, bytes) in artifacts {
        write_new_file(&proof_output.join(path), bytes)?;
    }
    let physical_manifest = build_proof_output_manifest(&proof_output)?;
    let physical_manifest_value =
        serde_json::to_value(&physical_manifest).context("cannot encode proof-output manifest")?;
    let physical_manifest_jcs = canonical_json_bytes(&physical_manifest_value)
        .context("cannot canonicalize proof-output manifest")?;
    ensure!(
        physical_manifest_jcs == bundle.manifest_jcs(),
        "published alternate-root files differ from the provider-owned manifest"
    );
    write_new_file(
        &staging_export.join(OUTPUT_MANIFEST_FILE),
        &physical_manifest_jcs,
    )?;
    publish_staging_export(output_root, &staging_export)
}

#[allow(clippy::too_many_arguments)]
fn prove_stock_candidate(
    prover: &LocalProver,
    statement: &[u8],
    image_id: Digest,
    segment_po2: u32,
    workload_iterations: u32,
    expected_claim_digest: Digest,
    stock_verifier_context: &VerifierContext,
) -> Result<CandidateProofResult> {
    let opts = closed_prover_opts(ProverOpts::succinct())?;
    let prove_info = prover
        .prove_with_ctx(
            build_env(statement, segment_po2, workload_iterations)?,
            stock_verifier_context,
            EIP_0045_GUEST_ELF,
            &opts,
        )
        .context("pinned local succinct proving failed")?;
    ensure!(
        prove_info.work_receipt.is_none(),
        "prover unexpectedly returned a work receipt"
    );
    ensure!(
        prove_info.stats.segments == 1,
        "prover reported {} segments, expected exactly one",
        prove_info.stats.segments
    );
    let receipt = prove_info.receipt;
    let InnerReceipt::Succinct(succinct) = &receipt.inner else {
        bail!("prover did not return a succinct receipt");
    };
    let raw_seal =
        validate_candidate_succinct_shape(succinct, segment_po2, &expected_claim_digest)?;
    receipt
        .verify_with_context(stock_verifier_context, image_id)
        .context("upstream stock receipt verification failed")?;
    Ok(CandidateProofResult {
        receipt,
        stats: prove_info.stats,
        raw_seal,
        inner_control_root: EXPECTED_INNER_CONTROL_ROOT_HEX.to_owned(),
        verifier_parameters: EXPECTED_VERIFIER_PARAMETERS_HEX.to_owned(),
        receipt_kind: "succinct-single-lift",
        verification_authority: "pinned-stock-verifier-context",
        profile_owned_shape_verify: true,
    })
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

fn build_env(
    statement: &[u8],
    segment_po2: u32,
    workload_iterations: u32,
) -> Result<ExecutorEnv<'static>> {
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
        segment_po2 < EXECUTOR_SEGMENT_LIMIT_PO2,
        "target segment po2 must remain below the executor segmentation ceiling"
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
    segment_po2: u32,
    workload_iterations: u32,
) -> Result<SessionInfo> {
    prover
        .execute(
            build_env(statement, segment_po2, workload_iterations)?,
            EIP_0045_GUEST_ELF,
        )
        .context("local candidate execution failed")
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

fn create_staging_export(output_root: &Path) -> Result<PathBuf> {
    let staging_export = output_root.join(STAGING_EXPORT_DIRECTORY);
    fs::create_dir(&staging_export).with_context(|| {
        format!(
            "cannot create non-final candidate export staging directory {}",
            staging_export.display()
        )
    })?;
    Ok(staging_export)
}

fn publish_staging_export(output_root: &Path, staging_export: &Path) -> Result<()> {
    let final_export = output_root.join(FINAL_EXPORT_DIRECTORY);
    ensure!(
        !final_export.exists(),
        "final candidate export path already exists: {}",
        final_export.display()
    );
    ensure!(
        staging_export == output_root.join(STAGING_EXPORT_DIRECTORY),
        "candidate export staging path is not the reserved staging directory"
    );

    let proof_output = staging_export.join(PROOF_OUTPUT_DIRECTORY);
    sync_directory(&proof_output)?;
    sync_directory(staging_export)?;
    fs::rename(staging_export, &final_export).with_context(|| {
        format!(
            "cannot atomically publish candidate export {} as {}",
            staging_export.display(),
            final_export.display()
        )
    })?;
    sync_directory(output_root)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)
        .with_context(|| format!("cannot open directory for sync {}", path.display()))?
        .sync_all()
        .with_context(|| format!("cannot sync directory {}", path.display()))
}

#[cfg(not(unix))]
fn sync_directory(path: &Path) -> Result<()> {
    let _ = path;
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("cannot create candidate artifact {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("cannot write candidate artifact {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("cannot sync candidate artifact {}", path.display()))?;
    Ok(())
}

fn read_regular_file_bounded(path: &Path, maximum: usize, label: &str) -> Result<Vec<u8>> {
    let maximum_u64 = u64::try_from(maximum).context("file-size cap does not fit u64")?;
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {label} {}", path.display()))?;
    ensure!(
        path_metadata.file_type().is_file() && !is_reparse_point(&path_metadata),
        "{label} is not a regular non-link file: {}",
        path.display()
    );

    let file =
        File::open(path).with_context(|| format!("cannot open {label} {}", path.display()))?;
    let opened_metadata = file
        .metadata()
        .with_context(|| format!("cannot inspect open {label} {}", path.display()))?;
    ensure!(
        opened_metadata.file_type().is_file() && !is_reparse_point(&opened_metadata),
        "opened {label} is not a regular non-link file: {}",
        path.display()
    );
    ensure!(
        opened_metadata.len() <= maximum_u64,
        "{label} {} has {} bytes, maximum is {maximum}",
        path.display(),
        opened_metadata.len()
    );

    let initial_capacity =
        usize::try_from(opened_metadata.len()).context("bounded file length does not fit usize")?;
    let mut bytes = Vec::with_capacity(initial_capacity);
    let read_limit = maximum_u64
        .checked_add(1)
        .context("file-size cap cannot be incremented for bounded reading")?;
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read bounded {label} {}", path.display()))?;
    ensure!(
        bytes.len() <= maximum,
        "{label} {} grew above {maximum} bytes while being read",
        path.display()
    );
    ensure!(
        u64::try_from(bytes.len()).context("observed file length does not fit u64")?
            == opened_metadata.len(),
        "{label} {} changed length while being read",
        path.display()
    );
    Ok(bytes)
}

fn serialize_receipt_oracle(receipt: &risc0_zkvm::Receipt) -> Result<Vec<u8>> {
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

#[cfg(windows)]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &Metadata) -> bool {
    false
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
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    #[test]
    fn local_ancestry_alternate_statement_final_cli_has_two_fixed_branches() {
        use clap::CommandFactory as _;
        let command = Cli::command();
        for branch in ["resolve-fixed22", "resolve-then-join-join21"] {
            for (action, destination) in [("generate", "output-root"), ("verify", "checkpoint-root")] {
                let route = format!("{action}-local-ancestry-alternate-statement-{branch}");
                let subcommand = command.find_subcommand(&route).unwrap();
                let expected = ["canonical-statement", "case9-recursive-oracle", "case9-assumption-raw-seal",
                    "case9-final-raw-seal", "shared-checkpoint-root", "calibration-file", destination];
                let actual = subcommand.get_arguments().filter_map(clap::Arg::get_long)
                    .filter(|name| *name != "help").collect::<std::collections::BTreeSet<_>>();
                assert_eq!(actual, expected.into_iter().collect());
                assert!(subcommand.get_arguments().filter(|arg| arg.get_long() != Some("help")).all(clap::Arg::is_required_set));
                let mut args = vec!["generator".to_owned(), route];
                for name in expected { args.extend([format!("--{name}"), "fixture".to_owned()]); }
                assert!(Cli::try_parse_from(&args).is_ok());
                for field in ["elf", "image-id", "family", "recipe", "workload-iterations", "segment-po2", "dev-mode",
                    "campaign", "alternate-statement", "expected-checkpoint-sha256", "expected-outer-sha256"] {
                    let mut changed = args.clone(); changed.extend([format!("--{field}"), "unowned".to_owned()]);
                    assert_eq!(Cli::try_parse_from(changed).unwrap_err().kind(), clap::error::ErrorKind::UnknownArgument);
                }
                for i in 0..7 {
                    let mut changed = args.clone(); changed.drain(2 + i * 2..4 + i * 2);
                    assert_eq!(Cli::try_parse_from(changed).unwrap_err().kind(), clap::error::ErrorKind::MissingRequiredArgument);
                }
            }
        }
    }

    #[test]
    fn local_ancestry_duplicate_assumption_cli_has_only_four_inputs_and_one_destination() {
        use clap::CommandFactory as _;
        let command = Cli::command();
        for (route, destination) in [("generate-local-ancestry-duplicate-assumption", "output-root"),
                                     ("verify-local-ancestry-duplicate-assumption", "checkpoint-root")] {
            let subcommand = command.find_subcommand(route).unwrap();
            let expected = ["canonical-statement", "case9-recursive-oracle", "case9-assumption-raw-seal", "case9-final-raw-seal", destination];
            let actual = subcommand.get_arguments().filter_map(clap::Arg::get_long)
                .filter(|name| *name != "help").collect::<std::collections::BTreeSet<_>>();
            assert_eq!(actual, expected.into_iter().collect());
            assert!(subcommand.get_arguments().filter(|arg| arg.get_long() != Some("help")).all(clap::Arg::is_required_set));
            let mut args = vec!["generator".to_owned(), route.to_owned()];
            for name in expected { args.extend([format!("--{name}"), "fixture".to_owned()]); }
            assert!(Cli::try_parse_from(&args).is_ok());
            for forbidden in ["elf", "image-id", "family", "role", "recipe", "workload-iterations", "segment-po2",
                              "root", "alternate-statement", "calibration-file", "campaign", "prover", "dev-mode"] {
                let mut changed = args.clone(); changed.extend([format!("--{forbidden}"), "unowned".to_owned()]);
                assert_eq!(Cli::try_parse_from(changed).unwrap_err().kind(), clap::error::ErrorKind::UnknownArgument);
            }
            for index in 0..5 {
                let mut missing = args.clone(); missing.drain(2 + index * 2..4 + index * 2);
                assert_eq!(Cli::try_parse_from(missing).unwrap_err().kind(), clap::error::ErrorKind::MissingRequiredArgument);
            }
        }
    }

    #[test]
    fn local_ancestry_alternate_program_cli_has_only_four_inputs_and_one_destination() {
        use clap::CommandFactory as _;
        let command = Cli::command();
        for (route, destination) in [("generate-local-ancestry-alternate-program", "output-root"),
                                     ("verify-local-ancestry-alternate-program", "checkpoint-root")] {
            let subcommand = command.find_subcommand(route).unwrap();
            let expected = ["canonical-statement", "case9-recursive-oracle", "case9-assumption-raw-seal", "case9-final-raw-seal", destination];
            let actual = subcommand.get_arguments().filter_map(clap::Arg::get_long)
                .filter(|name| *name != "help").collect::<std::collections::BTreeSet<_>>();
            assert_eq!(actual, expected.into_iter().collect());
            assert!(subcommand.get_arguments().filter(|arg| arg.get_long() != Some("help")).all(clap::Arg::is_required_set));
            let mut args = vec!["generator".to_owned(), route.to_owned()];
            for name in expected { args.extend([format!("--{name}"), "fixture".to_owned()]); }
            assert!(Cli::try_parse_from(&args).is_ok());
            for forbidden in ["elf", "image-id", "family", "role", "recipe", "workload-iterations", "segment-po2",
                              "root", "alternate-statement", "calibration-file", "campaign", "prover", "dev-mode"] {
                let mut changed = args.clone(); changed.extend([format!("--{forbidden}"), "unowned".to_owned()]);
                assert_eq!(Cli::try_parse_from(changed).unwrap_err().kind(), clap::error::ErrorKind::UnknownArgument);
            }
            for index in 0..5 {
                let mut missing = args.clone(); missing.drain(2 + index * 2..4 + index * 2);
                assert_eq!(Cli::try_parse_from(missing).unwrap_err().kind(), clap::error::ErrorKind::MissingRequiredArgument);
            }
        }
    }

    #[test]
    fn local_ancestry_shared_cli_has_only_four_inputs_and_one_destination() {
        use clap::CommandFactory as _;
        let command = Cli::command();
        assert!(Cli::try_parse_from(["generator"]).is_err());
        for (route, destination) in [("generate-local-ancestry-shared-assumption", "output-root"),
                                     ("verify-local-ancestry-shared-assumption", "checkpoint-root")] {
            let subcommand = command.find_subcommand(route).unwrap();
            let expected = ["canonical-statement", "case9-recursive-oracle", "case9-assumption-raw-seal", "case9-final-raw-seal", destination];
            let actual = subcommand.get_arguments().filter_map(clap::Arg::get_long)
                .filter(|name| *name != "help").collect::<std::collections::BTreeSet<_>>();
            assert_eq!(actual, expected.into_iter().collect());
            assert!(subcommand.get_arguments().filter(|arg| arg.get_long() != Some("help"))
                .all(clap::Arg::is_required_set));
            let mut args = vec!["generator".to_owned(), route.to_owned()];
            for name in expected { args.extend([format!("--{name}"), "fixture".to_owned()]); }
            assert!(Cli::try_parse_from(&args).is_ok());
            for forbidden in ["elf", "image-id", "role", "family", "segment-po2", "workload-iterations",
                              "root", "alternate-statement", "calibration-file", "recipe", "campaign", "prover", "dev-mode"] {
                let mut changed = args.clone(); changed.extend([format!("--{forbidden}"), "unowned".to_owned()]);
                assert_eq!(Cli::try_parse_from(changed).unwrap_err().kind(), clap::error::ErrorKind::UnknownArgument);
            }
            for index in 0..5 {
                let mut missing = args.clone(); missing.drain(2 + index * 2..4 + index * 2);
                assert_eq!(Cli::try_parse_from(missing).unwrap_err().kind(), clap::error::ErrorKind::MissingRequiredArgument);
            }
        }
    }

    #[cfg(feature = "b4-terminal-fixture-generation")]
    #[test]
    fn local_terminal_cli_has_only_fixed_sources_and_no_prover_controls() {
        use clap::CommandFactory as _;

        let command = Cli::command();
        for (name, expected) in [
            ("local-terminal-fixture-export", vec![
                "statement-file", "lift15-receipt-oracle", "terminal-join-recursive-oracle",
                "terminal-resolve-recursive-oracle", "output-root",
            ]),
            ("verify-local-terminal-fixture-export", vec!["export-root", "expected-statement"]),
        ] {
            let subcommand = command.find_subcommand(name).expect("feature-enabled command is present");
            let actual = subcommand.get_arguments().filter_map(|argument| argument.get_long())
                .filter(|name| *name != "help").collect::<std::collections::BTreeSet<_>>();
            assert_eq!(actual, expected.into_iter().collect());
            assert!(subcommand.get_arguments().filter(|argument| argument.get_long() != Some("help"))
                .all(clap::Arg::is_required_set));
        }
        let arguments = [
            "generator", "local-terminal-fixture-export", "--statement-file", "statement.bin",
            "--lift15-receipt-oracle", "lift.bincode", "--terminal-join-recursive-oracle", "join.borsh",
            "--terminal-resolve-recursive-oracle", "resolve.borsh", "--output-root", "output",
        ];
        assert!(matches!(Cli::try_parse_from(arguments).unwrap().command, Command::LocalTerminalFixtureExport { .. }));
        for flag in ["--guest-elf", "--family", "--dev-mode", "--prover", "--segment-po2"] {
            let mut altered = arguments.to_vec();
            altered.extend([flag, "unowned"]);
            assert_eq!(Cli::try_parse_from(altered).unwrap_err().kind(), clap::error::ErrorKind::UnknownArgument);
        }
        let verification_arguments = [
            "generator", "verify-local-terminal-fixture-export", "--export-root", "export",
            "--expected-statement", "statement.bin",
        ];
        assert!(matches!(Cli::try_parse_from(verification_arguments).unwrap().command,
            Command::VerifyLocalTerminalFixtureExport { .. }));
        for flag in ["--guest-elf", "--family", "--dev-mode", "--prover", "--segment-po2"] {
            let mut altered = verification_arguments.to_vec();
            altered.extend([flag, "unowned"]);
            assert_eq!(Cli::try_parse_from(altered).unwrap_err().kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }

    #[cfg(not(feature = "b4-terminal-fixture-generation"))]
    #[test]
    fn local_terminal_cli_is_absent_without_its_feature() {
        use clap::CommandFactory as _;

        let command = Cli::command();
        assert!(command.find_subcommand("local-terminal-fixture-export").is_none());
        assert!(command.find_subcommand("verify-local-terminal-fixture-export").is_none());
    }

    #[test]
    fn recursive_cli_exposes_only_fixed_calibration_and_root_gate_controls() {
        let identity = Cli::try_parse_from([
            "generator",
            "artifact-identity",
            "--elf-file",
            "guest.elf",
            "--output-file",
            "image-id.bin",
        ])
        .unwrap();
        assert!(matches!(identity.command, Command::ArtifactIdentity { .. }));
        let calibrated = Cli::try_parse_from([
            "generator",
            "recursive-calibrate",
            "--statement-file",
            "statement.bin",
            "--family",
            "terminal-join",
            "--calibration-file",
            "calibration.json",
        ])
        .unwrap();
        assert!(matches!(
            calibrated.command,
            Command::RecursiveCalibrate {
                family: RecursiveFamily::TerminalJoin,
                recipe: RecursiveCalibrationRecipe::Fixed22,
                ..
            }
        ));

        let proof = Cli::try_parse_from([
            "generator",
            "recursive-candidate-proof",
            "--statement-file",
            "statement.bin",
            "--family",
            "terminal-resolve",
            "--calibration-file",
            "calibration.json",
            "--output-root",
            "output",
        ])
        .unwrap();
        assert!(matches!(
            proof.command,
            Command::RecursiveCandidateProof {
                family: RecursiveFamily::TerminalResolve,
                recipe: RecursiveCalibrationRecipe::Fixed22,
                ..
            }
        ));

        assert!(
            Cli::try_parse_from([
                "generator",
                "recursive-root-gate",
                "--statement-file",
                "statement.bin",
                "--segment-limit-po2",
                "22",
            ])
            .is_err()
        );
        for forbidden in [
            "--segment-limit-po2",
            "--workload-iterations",
            "--assumption-workload-iterations",
            "--mode",
            "--guest-mode",
            "--assumption-count",
            "--assumption-copies",
            "--duplicate-count",
        ] {
            assert!(
                Cli::try_parse_from([
                    "generator",
                    "recursive-candidate-proof",
                    "--statement-file",
                    "statement.bin",
                    "--family",
                    "terminal-join",
                    "--calibration-file",
                    "calibration.json",
                    "--output-root",
                    "output",
                    forbidden,
                    "1",
                ])
                .is_err(),
                "legacy proof control {forbidden} remained accepted"
            );
        }
        assert!(
            Cli::try_parse_from([
                "generator",
                "recursive-root-gate",
                "--statement-file",
                "statement.bin",
                "--workload-iterations",
                "1",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "generator",
                "recursive-candidate-proof",
                "--statement-file",
                "statement.bin",
                "--family",
                "terminal-join",
                "--calibration-file",
                "calibration.json",
                "--output-root",
                "output",
                "--workload-iterations",
                "1",
            ])
            .is_err()
        );

        let alternate = Cli::try_parse_from([
            "generator",
            "alternate-root-candidate-proof",
            "--statement-file",
            "statement.bin",
            "--output-root",
            "output",
        ])
        .unwrap();
        assert!(matches!(
            alternate.command,
            Command::AlternateRootCandidateProof { .. }
        ));
        assert!(
            Cli::try_parse_from([
                "generator",
                "alternate-root-candidate-proof",
                "--statement-file",
                "statement.bin",
                "--output-root",
                "output",
                "--segment-po2",
                "16",
            ])
            .is_err(),
            "alternate-root witness exposed a caller-selected segment exponent"
        );
    }

    #[test]
    fn recursive_cli_recipe_selectors_are_closed_and_default_fixed22() {
        let cases = [
            vec!["generator", "recursive-calibrate", "--statement-file", "s", "--family", "terminal-join", "--calibration-file", "c"],
            vec!["generator", "recursive-candidate-proof", "--statement-file", "s", "--family", "terminal-join", "--calibration-file", "c", "--output-root", "o"],
            vec!["generator", "verify-recursive-candidate-export", "--expected-statement", "s", "--expected-family", "terminal-join", "--export-root", "o"],
        ];
        let selected = |command| match command {
            Command::RecursiveCalibrate { recipe, .. }
            | Command::RecursiveCandidateProof { recipe, .. }
            | Command::VerifyRecursiveCandidateExport { recipe, .. } => recipe,
            _ => panic!("wrong recursive command"),
        };
        for arguments in cases {
            assert_eq!(selected(Cli::try_parse_from(&arguments).unwrap().command), RecursiveCalibrationRecipe::Fixed22);
            for (label, recipe) in [("fixed22", RecursiveCalibrationRecipe::Fixed22), ("join21", RecursiveCalibrationRecipe::Join21)] {
                let mut explicit = arguments.clone();
                explicit.extend(["--recipe", label]);
                assert_eq!(selected(Cli::try_parse_from(explicit).unwrap().command), recipe);
            }
            for invalid in ["21", "22", "join20", "JOIN21", "", "fixed23"] {
                let mut altered = arguments.clone();
                altered.extend(["--recipe", invalid]);
                assert!(Cli::try_parse_from(altered).is_err());
            }
            let mut arbitrary = arguments.clone();
            arbitrary.extend(["--segment-limit-po2", "21"]);
            assert!(Cli::try_parse_from(arbitrary).is_err());
        }
        assert!(RecursiveCalibrationRecipe::Join21.validate_family("terminal-resolve").is_err());
    }

    #[test]
    fn alternate_root_export_verifier_has_one_explicit_closed_cli_path() {
        assert!(
            Cli::try_parse_from([
                "generator",
                "verify-alternate-root-candidate-export",
                "--export-root",
                "candidate-proof-export",
                "--expected-statement",
                "statement.bin",
            ])
            .is_ok(),
            "the fixed alternate-root export must have an explicit verifier command"
        );
        assert!(
            Cli::try_parse_from([
                "generator",
                "verify-alternate-root-candidate-export",
                "--export-root",
                "candidate-proof-export",
                "--expected-statement",
                "statement.bin",
                "--expected-segment-po2",
                "15",
            ])
            .is_err(),
            "the fixed alternate-root verifier must not expose a caller-selected mode scalar"
        );
    }

    #[test]
    fn alternate_root_cli_delegates_once_before_any_output_mutation() {
        let source = include_str!("main.rs");
        let function = source
            .split("fn alternate_root_candidate_proof")
            .nth(1)
            .and_then(|tail| tail.split("fn prove_stock_candidate").next())
            .expect("alternate-root CLI publication function must remain visible");
        assert_eq!(
            function
                .matches("generate_fixed_alternate_root_proof_bundle")
                .count(),
            1,
            "alternate-root CLI must invoke the closed in-memory provider exactly once"
        );
        let provider = function
            .find("generate_fixed_alternate_root_proof_bundle")
            .unwrap();
        let staging = function.find("create_staging_export").unwrap();
        let first_write = function.find("write_new_file").unwrap();
        assert!(provider < staging && staging < first_write);
        assert!(
            !function.contains("LocalProver")
                && !function.contains("ProverOpts")
                && !function.contains("RecursionProver"),
            "alternate-root CLI must not retain an independent proving path"
        );
    }

    static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn metadata_fixture() -> CandidateMetadata {
        CandidateMetadata {
            candidate_status: "non-final-reproduction-candidate".to_owned(),
            format_version: 1,
            upstream: UpstreamMetadata {
                repository: "https://example.invalid/risc0".to_owned(),
                commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                risc0_zkvm_version: "3.0.5".to_owned(),
                receipt_oracle_codec: "bincode-1.3.3-upstream-host-serialization".to_owned(),
            },
            method: MethodMetadata {
                image_id: "11".repeat(32),
                elf_length: "123".to_owned(),
                elf_sha256: "22".repeat(32),
            },
            proof_bound: ProofBoundMetadata {
                receipt_bound: true,
                statement_length: "3".to_owned(),
                statement_sha256: "33".repeat(32),
                journal_digest: "44".repeat(32),
                claim_digest: "55".repeat(32),
            },
            private_calibration: PrivateCalibrationMetadata {
                receipt_bound: false,
                candidate_scope: "local-reproduction-provenance-only".to_owned(),
                selection_rule: "canonical-monotone-ranking-v1-not-global-minimum".to_owned(),
                selected_observation_is_exact: true,
                workload_iterations: "37".to_owned(),
                workload_seed_hex: "4549503030343501".to_owned(),
            },
            local_execution_observation: LocalExecutionObservation {
                receipt_bound: false,
                candidate_scope: "local-reproduction-provenance-only".to_owned(),
                segment_count: "1".to_owned(),
                executor_segment_limit_po2: EXECUTOR_SEGMENT_LIMIT_PO2,
                segment_po2: 18,
                user_cycles: "100".to_owned(),
                total_cycles: "110".to_owned(),
                paging_cycles: "5".to_owned(),
                reserved_cycles: "5".to_owned(),
            },
            proof: ProofMetadata {
                receipt_kind: "succinct-single-lift".to_owned(),
                hash_function: "poseidon2".to_owned(),
                control_id: "66".repeat(32),
                inner_control_root: EXPECTED_INNER_CONTROL_ROOT_HEX.to_owned(),
                verifier_parameters: EXPECTED_VERIFIER_PARAMETERS_HEX.to_owned(),
                outer_po2: EXPECTED_OUTER_PO2,
                raw_seal_words: PROOF_WORDS.to_string(),
                raw_seal_bytes: PROOF_BYTES.to_string(),
                claim_digest: "55".repeat(32),
                journal_digest: "44".repeat(32),
            },
            verification: VerificationMetadata {
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
            files: vec![],
        }
    }

    fn fresh_test_root(label: &str) -> PathBuf {
        let counter = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "eip0045-generator-{label}-{}-{nanos}-{counter}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create unique test root");
        root
    }

    fn statement_fixture(payload: &[u8]) -> Vec<u8> {
        let image_id = embedded_artifact_identity().unwrap();
        let payload_length = u32::try_from(payload.len()).unwrap();
        let mut statement = Vec::with_capacity(
            eip_0045_reproduction::constants::STATEMENT_PREFIX_BYTES + payload.len(),
        );
        statement.extend_from_slice(eip_0045_reproduction::constants::ERGO_STATEMENT_DOMAIN);
        statement.push(0x01);
        statement.extend_from_slice(&[0x11; 32]);
        statement.extend_from_slice(&[0x22; 32]);
        statement.extend_from_slice(image_id.as_bytes());
        statement.extend_from_slice(&[0x33; 32]);
        statement.extend_from_slice(&payload_length.to_le_bytes());
        statement.extend_from_slice(payload);
        statement
    }

    #[test]
    fn metadata_serialization_marks_the_receipt_boundary() {
        let value = serde_json::to_value(metadata_fixture()).unwrap();

        assert_eq!(value["proofBound"]["receiptBound"], true);
        assert_eq!(value["privateCalibration"]["receiptBound"], false);
        assert_eq!(value["verification"]["receiptBound"], false);
        assert_eq!(
            value["verification"]["verificationAuthority"],
            "pinned-stock-verifier-context"
        );
        assert_eq!(
            value["privateCalibration"]["candidateScope"],
            "local-reproduction-provenance-only"
        );
        assert_eq!(value["localExecutionObservation"]["receiptBound"], false);
        assert_eq!(
            value["localExecutionObservation"]["candidateScope"],
            "local-reproduction-provenance-only"
        );
    }

    #[test]
    fn current_producer_shape_is_accepted_by_the_shared_metadata_consumer() {
        let produced = metadata_fixture();
        let source = produced.to_canonical_jcs().unwrap();
        let consumed = CandidateMetadata::from_canonical_jcs(&source).unwrap();

        assert_eq!(consumed, produced);
        assert_eq!(
            consumed.verification.verification_authority,
            "pinned-stock-verifier-context"
        );
    }

    #[test]
    fn metadata_tampering_stays_outside_the_receipt_bound_section() {
        let original = serde_json::to_value(metadata_fixture()).unwrap();
        let mut tampered = original.clone();
        tampered["privateCalibration"]["workloadIterations"] = serde_json::json!("999");
        tampered["localExecutionObservation"]["totalCycles"] = serde_json::json!("9999");

        assert_ne!(original, tampered);
        assert_eq!(original["proofBound"], tampered["proofBound"]);
        assert_eq!(tampered["privateCalibration"]["receiptBound"], false);
        assert_eq!(tampered["localExecutionObservation"]["receiptBound"], false);
    }

    #[test]
    fn bounded_file_reader_accepts_the_cap_and_rejects_oversize_and_directories() {
        let root = fresh_test_root("bounded-reader");
        let at_limit = root.join("at-limit.bin");
        let oversized = root.join("oversized.bin");
        fs::write(&at_limit, [0x5au8; 32]).unwrap();
        fs::write(&oversized, [0x5au8; 33]).unwrap();

        assert_eq!(
            read_regular_file_bounded(&at_limit, 32, "test input").unwrap(),
            [0x5a; 32]
        );
        assert!(read_regular_file_bounded(&oversized, 32, "test input").is_err());
        assert!(read_regular_file_bounded(&root, 32, "test input").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn artifact_identity_publication_is_exact_create_only_and_cleanup_complete() {
        let root = fresh_test_root("artifact-identity");
        let elf = root.join("guest.elf");
        let output = root.join("image-id.bin");
        fs::write(&elf, EIP_0045_GUEST_ELF).unwrap();

        artifact_identity(&elf, &output).unwrap();
        let expected = compute_image_id(EIP_0045_GUEST_ELF).unwrap();
        assert_eq!(fs::read(&output).unwrap(), expected.as_bytes());
        assert!(artifact_identity(&elf, &output).is_err());
        let names = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"guest.elf".to_owned()));
        assert!(names.contains(&"image-id.bin".to_owned()));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn bounded_file_reader_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let root = fresh_test_root("bounded-reader-symlink");
        let target = root.join("target.bin");
        let alias = root.join("alias.bin");
        fs::write(&target, b"bounded").unwrap();
        symlink(&target, &alias).unwrap();

        assert!(read_regular_file_bounded(&alias, 7, "test input").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn receipt_oracle_codec_is_fixed_little_endian_strict_and_bounded() {
        let fixture = (0x0102_0304_u32, vec![5_u8, 6, 7]);
        let encoded = receipt_oracle_bincode_options()
            .serialize(&fixture)
            .unwrap();
        assert_eq!(
            encoded,
            [
                0x04, 0x03, 0x02, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x06,
                0x07,
            ]
        );
        assert_eq!(encoded, bincode::serialize(&fixture).unwrap());
        assert_eq!(
            receipt_oracle_bincode_options()
                .deserialize::<(u32, Vec<u8>)>(&encoded)
                .unwrap(),
            fixture
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert!(
            receipt_oracle_bincode_options()
                .deserialize::<(u32, Vec<u8>)>(&trailing)
                .is_err()
        );

        let maximum = CANDIDATE_RECEIPT_ORACLE_MAX_BYTES;
        assert_eq!(
            u64::try_from(maximum).unwrap(),
            CANDIDATE_RECEIPT_ORACLE_MAX_BYTES_U64
        );
        let at_limit = vec![0u8; maximum - 8];
        let at_limit_encoding = receipt_oracle_bincode_options()
            .serialize(&at_limit)
            .unwrap();
        assert_eq!(at_limit_encoding.len(), maximum);
        drop(at_limit);
        drop(at_limit_encoding);

        let oversized = vec![0u8; maximum - 7];
        assert!(
            receipt_oracle_bincode_options()
                .serialize(&oversized)
                .is_err()
        );
    }

    #[test]
    fn shipping_guest_preserves_chunk_boundaries_and_maximum_journal_exactly() {
        let prover = LocalProver::new("eip-0045-integration-test");
        for statement_length in [
            255,
            256,
            257,
            eip_0045_reproduction::constants::MAX_STATEMENT_BYTES,
        ] {
            let payload_length =
                statement_length - eip_0045_reproduction::constants::STATEMENT_PREFIX_BYTES;
            let statement = statement_fixture(&vec![0x5a; payload_length]);
            assert_eq!(statement.len(), statement_length);

            let session = execute_once(&prover, &statement, 15, 0).unwrap();
            validate_execution(&session, &statement).unwrap();
            assert_eq!(session.journal.bytes, statement);
        }
    }

    #[test]
    fn shipping_guest_plain_zero_workload_reaches_the_minimum_profile_po2() {
        let statement = statement_fixture(&[]);
        let session = execute_once(
            &LocalProver::new("eip-0045-integration-test"),
            &statement,
            u32::from(eip_0045_reproduction::constants::MIN_SEGMENT_PO2),
            0,
        )
        .unwrap();
        validate_execution(&session, &statement).unwrap();
        assert_eq!(
            segment_observation(&session).unwrap(),
            SegmentObservation::new(1, Some(15)).unwrap()
        );
    }

    #[test]
    fn shipping_guest_rejects_bad_workload_before_any_journal_commit() {
        let statement = statement_fixture(&[0x5a; 32]);
        let header = GuestInputHeader::new(statement.len(), 0, WORKLOAD_SEED).unwrap();
        let mut input = header.encode().to_vec();
        input[16] ^= 1;
        input.extend_from_slice(&statement);

        let mut builder = ExecutorEnv::builder();
        builder
            .segment_limit_po2(EXECUTOR_SEGMENT_LIMIT_PO2)
            .write_slice(&input);
        let session = LocalProver::new("eip-0045-integration-test")
            .execute(builder.build().unwrap(), EIP_0045_GUEST_ELF)
            .unwrap();

        assert_ne!(session.exit_code, ExitCode::Halted(0));
        assert!(session.journal.bytes.is_empty());
    }

    #[test]
    fn shipping_guest_rejects_oversized_statement_before_read_or_commit() {
        let mut input = [0u8; eip_0045_methods::GUEST_INPUT_HEADER_BYTES];
        input[..4].copy_from_slice(
            &u32::try_from(eip_0045_reproduction::constants::MAX_STATEMENT_BYTES + 1)
                .unwrap()
                .to_le_bytes(),
        );

        let mut builder = ExecutorEnv::builder();
        builder
            .segment_limit_po2(EXECUTOR_SEGMENT_LIMIT_PO2)
            .write_slice(&input);
        let session = LocalProver::new("eip-0045-integration-test")
            .execute(builder.build().unwrap(), EIP_0045_GUEST_ELF)
            .unwrap();

        assert_ne!(session.exit_code, ExitCode::Halted(0));
        assert!(session.journal.bytes.is_empty());
    }

    #[test]
    fn staging_is_not_a_final_export_before_the_single_publish_rename() {
        let root = fresh_test_root("atomic-publish");
        let staging = create_staging_export(&root).unwrap();
        let proof_output = staging.join(PROOF_OUTPUT_DIRECTORY);
        fs::create_dir(&proof_output).unwrap();
        write_new_file(&proof_output.join("seal.bin"), b"candidate").unwrap();
        write_new_file(&staging.join(OUTPUT_MANIFEST_FILE), b"[]").unwrap();

        assert!(!root.join(FINAL_EXPORT_DIRECTORY).exists());
        assert!(staging.exists());

        publish_staging_export(&root, &staging).unwrap();

        assert!(!staging.exists());
        assert_eq!(
            fs::read(
                root.join(FINAL_EXPORT_DIRECTORY)
                    .join(PROOF_OUTPUT_DIRECTORY)
                    .join("seal.bin")
            )
            .unwrap(),
            b"candidate"
        );
        assert!(
            root.join(FINAL_EXPORT_DIRECTORY)
                .join(OUTPUT_MANIFEST_FILE)
                .exists()
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn abandoned_staging_never_creates_a_final_export() {
        let root = fresh_test_root("abandoned-staging");
        let staging = create_staging_export(&root).unwrap();
        let proof_output = staging.join(PROOF_OUTPUT_DIRECTORY);
        fs::create_dir(&proof_output).unwrap();
        write_new_file(&proof_output.join("partial.bin"), b"partial").unwrap();

        assert!(staging.exists());
        assert!(!root.join(FINAL_EXPORT_DIRECTORY).exists());
        fs::remove_dir_all(root).unwrap();
    }
}
