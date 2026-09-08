// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Deterministic B3 profile and statement-bundle generator and verifier.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use eip_0045_candidate_generator::profile_freeze::{
    install_profile_freeze_bundle, verified_summary, write_profile_freeze_bundle,
};
use eip_0045_candidate_generator::statement_bundle::{
    verified_statement_summary, write_reference_statement_bundle,
};

#[derive(Parser)]
#[command(about = "Generate or strictly verify EIP-0045 profile artifacts")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate derived B3 files into one new staging directory.
    Generate {
        /// Directory containing exact algorithm.txt and constants.bin inputs.
        #[arg(long)]
        profile_dir: PathBuf,
        /// New, non-existing directory that will receive the six B3 outputs.
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Install reviewed B3 bytes next to B1/B2, refusing every overwrite.
    Install {
        /// Directory containing exact B1/B2 and no pre-existing B3 outputs.
        #[arg(long)]
        profile_dir: PathBuf,
    },
    /// Verify existing B3 files against exact B1 and B2 inputs.
    Verify {
        /// Directory containing exact algorithm.txt and constants.bin inputs.
        #[arg(long)]
        profile_dir: PathBuf,
        /// Directory containing the six generated B3 outputs.
        #[arg(long)]
        bundle_dir: PathBuf,
    },
    /// Generate a self-contained statement bundle into one new directory.
    Statement {
        /// Directory containing the exact verified B1/B2/B3 package.
        #[arg(long)]
        profile_dir: PathBuf,
        /// Exact bounded guest ELF from which the program ID is derived.
        #[arg(long)]
        guest_elf: PathBuf,
        /// New, non-existing directory that will receive the statement bundle.
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Strictly verify a self-contained statement bundle.
    VerifyStatement {
        /// Directory containing the exact verified B1/B2/B3 package.
        #[arg(long)]
        profile_dir: PathBuf,
        /// Directory containing the complete statement bundle.
        #[arg(long)]
        bundle_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Generate {
            profile_dir,
            output_dir,
        } => {
            let bundle = write_profile_freeze_bundle(&profile_dir, &output_dir)?;
            println!("manifest.bin bytes={}", bundle.manifest().len());
            println!("profile-id.bin bytes={}", bundle.profile_id().len());
            println!("staged B3 outputs written");
        }
        Command::Install { profile_dir } => {
            let bundle = install_profile_freeze_bundle(&profile_dir)?;
            println!("manifest.bin bytes={}", bundle.manifest().len());
            println!("profileId={}", hex::encode(bundle.profile_id()));
            println!("installed B3 outputs written");
        }
        Command::Verify {
            profile_dir,
            bundle_dir,
        } => {
            let summary = verified_summary(&profile_dir, &bundle_dir)?;
            println!("manifest sha256={}", summary.manifest_sha256);
            println!("profileId={}", summary.profile_id_hex);
        }
        Command::Statement {
            profile_dir,
            guest_elf,
            output_dir,
        } => {
            let bundle = write_reference_statement_bundle(&profile_dir, &guest_elf, &output_dir)?;
            println!("statement.bin bytes={}", bundle.statement().len());
            println!("contractId={}", hex::encode(bundle.contract_id()));
            println!("reference statement outputs written");
        }
        Command::VerifyStatement {
            profile_dir,
            bundle_dir,
        } => {
            let summary = verified_statement_summary(&profile_dir, &bundle_dir)?;
            println!("statement.bin bytes={}", summary.statement_bytes);
            println!("statement sha256={}", summary.statement_sha256);
            println!("contractId={}", summary.contract_id_hex);
            println!("journalDigest={}", summary.journal_digest_hex);
            println!("claimDigest={}", summary.claim_digest_hex);
        }
    }
    Ok(())
}
