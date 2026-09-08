#![no_main]
#![no_std]

use core::hint::black_box;

use eip_0045_methods::{
    next_statement_chunk_length, workload_result, GuestInputHeader, GuestMode,
    GUEST_INPUT_HEADER_BYTES, GUEST_STATEMENT_CHUNK_BYTES,
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    let mut header_bytes = [0u8; GUEST_INPUT_HEADER_BYTES];
    env::read_slice(&mut header_bytes);
    let header = match GuestInputHeader::decode(&header_bytes) {
        Ok(header) => header,
        Err(_) => env::exit(1),
    };
    if header.mode() != GuestMode::Plain {
        env::exit(1);
    }

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
