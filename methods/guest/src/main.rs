#![no_main]
#![no_std]

use core::hint::black_box;

use eip_0045_methods::{
    next_statement_chunk_length, workload_result, GuestInputHeader, GuestMode,
    GUEST_INPUT_HEADER_BYTES, GUEST_STATEMENT_CHUNK_BYTES, MAX_STATEMENT_BYTES,
};
use risc0_circuit_recursion::control_id::ALLOWED_CONTROL_ROOT;
use risc0_zkvm::{guest::env, sha::Digestible, Digest, MaybePruned, ReceiptClaim};

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut header_bytes = [0u8; GUEST_INPUT_HEADER_BYTES];
    env::read_slice(&mut header_bytes);
    let header = match GuestInputHeader::decode(&header_bytes) {
        Ok(header) => header,
        Err(_) => env::exit(1),
    };

    match header.mode() {
        GuestMode::Plain => run_plain(header),
        GuestMode::VerifyAssumptionZeroRoot
        | GuestMode::VerifyAssumptionExplicitRoot
        | GuestMode::VerifyAssumptionExplicitRootTwice => run_assumption(header),
    }
}

// Keeping the plain path in a separate, non-inlined frame prevents the
// assumption-only 16 KiB buffer from raising the minimum plain execution above
// po2=15. The workload still gates every journal commit. Once it succeeds, the
// statement is read and committed in exact 256-byte-or-smaller chunks.
#[inline(never)]
fn run_plain(header: GuestInputHeader) {
    require_workload(header);

    let mut statement_chunk = [0u8; GUEST_STATEMENT_CHUNK_BYTES];
    let mut remaining = header.statement_length() as usize;
    while remaining != 0 {
        let chunk_length = next_statement_chunk_length(remaining);
        env::read_slice(&mut statement_chunk[..chunk_length]);
        env::commit_slice(&statement_chunk[..chunk_length]);
        remaining -= chunk_length;
    }
}

// Assumption mode must hash the exact statement for env::verify, so this
// isolated frame retains the bounded statement until verification, workload
// validation, and journal commitment are complete. The same ELF is still used
// by all eleven positive candidate families and the dedicated duplicate-head
// negative witness; only this private mode differs.
#[inline(never)]
fn run_assumption(header: GuestInputHeader) {
    let statement_length = header.statement_length() as usize;
    let mut statement = [0u8; MAX_STATEMENT_BYTES];
    let mut remaining = statement_length;
    let mut offset = 0;
    while remaining != 0 {
        let chunk_length = next_statement_chunk_length(remaining);
        env::read_slice(&mut statement[offset..offset + chunk_length]);
        offset += chunk_length;
        remaining -= chunk_length;
    }

    match header.mode() {
        GuestMode::Plain => env::exit(1),
        GuestMode::VerifyAssumptionZeroRoot => {
            env::verify(
                Digest::from(header.assumption_image_id()),
                &statement[..statement_length],
            )
            .unwrap();
        }
        GuestMode::VerifyAssumptionExplicitRoot
        | GuestMode::VerifyAssumptionExplicitRootTwice => {
            let journal_digest = statement[..statement_length].digest();
            let claim = ReceiptClaim::ok(
                Digest::from(header.assumption_image_id()),
                MaybePruned::Pruned(journal_digest),
            );
            let claim_digest = claim.digest();
            env::verify_assumption(claim_digest, ALLOWED_CONTROL_ROOT).unwrap();
            if header.mode() == GuestMode::VerifyAssumptionExplicitRootTwice {
                env::verify_assumption(claim_digest, ALLOWED_CONTROL_ROOT).unwrap();
            }
        }
    }

    require_workload(header);

    let mut committed = 0;
    while committed != statement_length {
        let chunk_length = next_statement_chunk_length(statement_length - committed);
        env::commit_slice(&statement[committed..committed + chunk_length]);
        committed += chunk_length;
    }
}

// Dynamic optimization barriers keep the calibration loop present in the
// shipping guest ELF. The comparison is the sole gate before either path can
// commit journal bytes.
#[inline(always)]
fn require_workload(header: GuestInputHeader) {
    let actual_workload_result = workload_result(
        black_box(header.workload_seed()),
        black_box(header.workload_iterations()),
    );
    if black_box(actual_workload_result) != header.expected_workload_result() {
        env::exit(1);
    }
}
