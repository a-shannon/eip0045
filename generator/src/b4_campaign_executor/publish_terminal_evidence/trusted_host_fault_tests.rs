//! Physical transaction faults for the trusted-host terminal publication route.

use std::{cell::Cell, fs, os::fd::BorrowedFd, path::PathBuf};

use anyhow::{Context as _, Result};

use super::super::{
    TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FILE,
    execute::{
        NoopPublishTerminalEvidenceTransitionObserver, ProjectedPublishLeaves,
        coordinate_publish_terminal_evidence_mutation,
    },
    project_publish_terminal_evidence_layout,
};
use crate::b4_campaign_executor::typestate::ExecutorPreflightContext;
use eip_0045_reproduction::b4_terminal_evidence_packet::reopen_b4_terminal_evidence_packet_from_directory_descriptor;

const PACKET: &str = "terminal-evidence-packet";

#[derive(Clone, Copy)]
enum Fault {
    HealthyTransaction,
    ReceiptCreation,
    PostcommitPacketReopen,
}

struct FaultOutcome {
    _temporary_campaign: tempfile::TempDir,
    final_path: PathBuf,
    staging_path: PathBuf,
    result: Result<()>,
    reached_receipt_create: bool,
    reached_postcommit: bool,
    reached_packet_reopen: bool,
    emitted_completion_witness: bool,
}

fn write_minimal_descriptor_packet(root: BorrowedFd<'_>, name: &str) -> Result<()> {
    use rustix::fs::{Mode, OFlags, ResolveFlags};

    rustix::fs::mkdirat(root, name, Mode::RWXU)?;
    let packet = rustix::fs::openat2(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )?;
    rustix::fs::fchmod(&packet, Mode::RWXU)?;
    Ok(())
}

fn run_physical_fault(fault: Fault) -> FaultOutcome {
    let temporary_campaign = tempfile::tempdir().unwrap();
    let campaign = temporary_campaign.path().join("campaign");
    let prior = campaign.join("prior");
    let runs = campaign.join("runs");
    let final_path = runs.join("run-001");
    fs::create_dir_all(&prior).unwrap();
    fs::create_dir_all(&runs).unwrap();
    fs::write(prior.join("stable.bin"), b"immutable prior source").unwrap();
    let executable = fs::read_link("/proc/self/exe").unwrap();
    let projected =
        project_publish_terminal_evidence_layout(&campaign, [&prior], &final_path).unwrap();
    let staging_path = projected.outer_staging_root().to_path_buf();
    let preflight = ExecutorPreflightContext::capture(&executable, projected).unwrap();
    let reached_receipt_create = Cell::new(false);
    let reached_postcommit = Cell::new(false);
    let reached_packet_reopen = Cell::new(false);
    let emitted_completion_witness = Cell::new(false);

    let result = preflight.execute(|execute| {
        execute.with_mutation(|capability| {
            let leaves = ProjectedPublishLeaves::from_layout(capability.projected_layout())?;
            assert_eq!(leaves.packet_relative, PACKET);
            assert_eq!(
                leaves.receipt_relative,
                TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FILE
            );
            let packet_relative = leaves.packet_relative.clone();
            let receipt_relative = leaves.receipt_relative.clone();
            let reserved_relative = leaves.reserved_inner_relative.clone();
            let mut observer = NoopPublishTerminalEvidenceTransitionObserver;
            coordinate_publish_terminal_evidence_mutation(
                &mut observer,
                (),
                || capability.begin_create_only_directory(),
                |transaction, ()| {
                    transaction.publish_and_adopt_directory_tree(&packet_relative, |root| {
                        write_minimal_descriptor_packet(root, &packet_relative)
                    })
                },
                |transaction, &()| {
                    reached_receipt_create.set(true);
                    let maximum = if matches!(fault, Fault::ReceiptCreation) {
                        0
                    } else {
                        64
                    };
                    transaction
                        .create_file(&receipt_relative, b"{}", maximum)
                        .context("fault harness receipt create_file boundary")
                },
                |transaction, (), ()| {
                    transaction.commit_with_postcommit_validation(|committed| {
                        reached_postcommit.set(true);
                        leaves.revalidate_published_projection()?;
                        committed.require_projected_reserved_staging_absent(
                            &packet_relative,
                            &reserved_relative,
                        )?;
                        let packet = committed.directory_descriptor(&packet_relative)?;
                        if matches!(fault, Fault::PostcommitPacketReopen) {
                            reached_packet_reopen.set(true);
                            let _verified =
                                reopen_b4_terminal_evidence_packet_from_directory_descriptor(
                                    packet,
                                )
                                .context("fault harness semantic packet reopen boundary")?;
                        } else {
                            assert_eq!(committed.read_file(&receipt_relative, 64)?, b"{}");
                        }
                        emitted_completion_witness.set(true);
                        Ok(())
                    })
                },
            )
        })
    });

    FaultOutcome {
        _temporary_campaign: temporary_campaign,
        final_path,
        staging_path,
        result,
        reached_receipt_create: reached_receipt_create.get(),
        reached_postcommit: reached_postcommit.get(),
        reached_packet_reopen: reached_packet_reopen.get(),
        emitted_completion_witness: emitted_completion_witness.get(),
    }
}

#[test]
fn receipt_creation_failure_retains_staging_hold_without_committed_authority() {
    let outcome = run_physical_fault(Fault::ReceiptCreation);
    let error = outcome.result.as_ref().unwrap_err();
    let cause = format!("{error:#}");
    assert!(cause.contains("fault harness receipt create_file boundary"));
    assert!(cause.contains("exceeds its caller-supplied byte bound"));
    assert!(outcome.reached_receipt_create);
    assert!(!outcome.reached_postcommit);
    assert!(!outcome.reached_packet_reopen);
    assert!(!outcome.emitted_completion_witness);
    assert!(!outcome.final_path.exists());
    assert!(outcome.staging_path.join(PACKET).is_dir());
    assert!(
        !outcome
            .staging_path
            .join(TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FILE)
            .exists()
    );
}

#[test]
fn postcommit_reopen_failure_retains_committed_hold_without_authority() {
    let outcome = run_physical_fault(Fault::PostcommitPacketReopen);
    let error = outcome.result.as_ref().unwrap_err();
    let cause = format!("{error:#}");
    assert!(cause.contains("fault harness semantic packet reopen boundary"));
    assert!(cause.contains("cannot pin terminal evidence directory"));
    assert!(outcome.reached_receipt_create);
    assert!(outcome.reached_postcommit);
    assert!(outcome.reached_packet_reopen);
    assert!(!outcome.emitted_completion_witness);
    assert!(outcome.final_path.join(PACKET).is_dir());
    assert!(
        outcome
            .final_path
            .join(TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FILE)
            .is_file()
    );
    assert!(!outcome.staging_path.exists());
}

#[test]
fn physical_transaction_control_commits_and_reopens_its_receipt() {
    let outcome = run_physical_fault(Fault::HealthyTransaction);
    assert!(
        outcome.result.is_ok(),
        "{:?}",
        outcome.result.as_ref().err()
    );
    assert!(outcome.reached_receipt_create);
    assert!(outcome.reached_postcommit);
    assert!(!outcome.reached_packet_reopen);
    assert!(outcome.emitted_completion_witness);
    assert!(outcome.final_path.join(PACKET).is_dir());
    assert!(
        outcome
            .final_path
            .join(TERMINAL_EVIDENCE_CAMPAIGN_RECEIPT_FILE)
            .is_file()
    );
    assert!(!outcome.staging_path.exists());
}
