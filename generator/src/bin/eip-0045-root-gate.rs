// Copyright 2026 A. Shannon
// SPDX-License-Identifier: Apache-2.0

//! Execute-only explicit-root conformance gate for an external guest ELF.

use std::{
    fs::{self, File, Metadata},
    io::Read as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use eip_0045_candidate_generator::recursive::inspect_explicit_root_cache_gate;
use eip_0045_reproduction::constants::MAX_STATEMENT_BYTES;
use risc0_zkvm::{LocalProver, compute_image_id};
use sha2::{Digest as _, Sha256};

const MAX_GUEST_ELF_BYTES: usize = 4 * 1024 * 1024;
const SEGMENT_LIMIT_PO2: u32 = 23;
const WORKLOAD_ITERATIONS: u32 = 0;

#[derive(Parser)]
#[command(about = "Run the EIP-0045 explicit-root gate on one external guest ELF")]
struct Cli {
    /// Exact guest ELF whose image ID is derived locally.
    #[arg(long)]
    guest_elf: PathBuf,
    /// Exact `ErgoStatementV1` expected to name the derived image ID.
    #[arg(long)]
    statement_file: PathBuf,
}

fn main() -> Result<()> {
    reject_runtime_overrides()?;
    let args = Cli::parse();
    let elf = read_regular_file_bounded(&args.guest_elf, MAX_GUEST_ELF_BYTES, "guest ELF")?;
    ensure!(!elf.is_empty(), "guest ELF is empty");
    let statement =
        read_regular_file_bounded(&args.statement_file, MAX_STATEMENT_BYTES, "statement file")?;
    let image_id = compute_image_id(&elf).context("cannot compute guest ELF image ID")?;
    let prover = LocalProver::new("eip-0045-external-root-gate");
    let observation = inspect_explicit_root_cache_gate(
        &prover,
        &elf,
        image_id,
        &statement,
        SEGMENT_LIMIT_PO2,
        WORKLOAD_ITERATIONS,
    )?;

    println!("guestElfBytes={}", elf.len());
    println!("guestElfSha256={}", hex::encode(Sha256::digest(&elf)));
    println!("imageId={}", hex::encode(observation.image_id.as_bytes()));
    println!("statementBytes={}", statement.len());
    println!(
        "statementSha256={}",
        hex::encode(Sha256::digest(&statement))
    );
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
    println!("segmentLimitPo2={SEGMENT_LIMIT_PO2}");
    println!("workloadIterations={WORKLOAD_ITERATIONS}");
    println!("correctExplicitRootCache=accepted");
    println!("zeroRootCache=rejected");
    println!("mutatedRootCache=rejected");
    println!("mutatedClaimCache=rejected");
    println!("proofGeneration=false");
    Ok(())
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
            bail!("external root gate forbids runtime environment override {name}");
        }
    }
    for (name, _) in std::env::vars_os() {
        let name = name.to_string_lossy();
        if name.starts_with("BONSAI_") {
            bail!("external root gate forbids runtime environment override {name}");
        }
    }
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
