// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Primary source-locked generator and strict verifier for the B2 artifact.

#[path = "../constants_artifact.rs"]
mod constants_artifact;

use std::{fs, path::PathBuf};

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use sha2::{Digest as _, Sha256};

#[derive(Parser)]
#[command(about = "Generate or strictly verify the EIP-0045 B2 constants artifact")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Generate {
        #[arg(long)]
        risc0_root: PathBuf,
        #[arg(long)]
        output_bin: PathBuf,
        #[arg(long)]
        output_json: PathBuf,
    },
    Verify {
        #[arg(long)]
        input_bin: PathBuf,
    },
    ValidateGrammar {
        #[arg(long)]
        input_bin: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Generate {
            risc0_root,
            output_bin,
            output_json,
        } => {
            let (binary_sha256, json_sha256) =
                constants_artifact::write_outputs(&risc0_root, &output_bin, &output_json)?;
            println!(
                "constants.bin bytes={} sha256={binary_sha256}",
                constants_artifact::ARTIFACT_BYTES
            );
            println!("constants.json sha256={json_sha256}");
        }
        Command::Verify { input_bin } => {
            let bytes = fs::read(&input_bin)
                .with_context(|| format!("cannot read {}", input_bin.display()))?;
            constants_artifact::verify_canonical(&bytes)?;
            println!(
                "constants.bin bytes={} sha256={}",
                bytes.len(),
                hex::encode(Sha256::digest(&bytes))
            );
        }
        Command::ValidateGrammar { input_bin } => {
            let bytes = fs::read(&input_bin)
                .with_context(|| format!("cannot read {}", input_bin.display()))?;
            let decoded = constants_artifact::decode(&bytes)?;
            ensure!(
                constants_artifact::encode(&decoded)? == bytes,
                "B2 decode/re-encode mismatch"
            );
            println!(
                "B2 grammar valid bytes={} sha256={}",
                bytes.len(),
                hex::encode(Sha256::digest(&bytes))
            );
        }
    }
    Ok(())
}
