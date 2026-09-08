# EIP-0045 reproduction companion

Rust source, profile artifacts and candidate-proof tooling for
[EIP-0045: native STARK verification](https://github.com/ergoplatform/eips/pull/103).
The ErgoScript opcode and JVM verifier are developed separately in
[SigmaState PR #1116](https://github.com/ergoplatform/sigmastate-interpreter/pull/1116).

## September 2026 milestone

The generator now exposes local checkpoint workflows for a shared assumption,
an alternate program, a duplicate assumption, and alternate-statement
Resolve/Join finals. Each workflow has a separate verification command.
The two alternate-statement finals reuse the same retained assumption receipt;
a newly generated receipt for an equivalent claim is not interchangeable.

These workflows are building blocks for the negative-ancestry test corpus.
They keep candidate generation separate from campaign qualification.
The source also includes the pinned profile package, receipt and ancestry
validators, fixture schemas, and their direct tests.

The accepted embedded-generator build passed 52 focused tests; nine
environment-gated tests remained ignored. That result covers the reviewed
local-checkpoint build, not every feature combination or the complete B4
campaign. Proof generation and subsequent replay are separate validation steps.

## Source layout

| Directory | Purpose |
| --- | --- |
| `profiles/risc0-v3-succinct/` | Fixed profile inputs and derived identity |
| `reproduction/` | Validation, schemas, fixtures and reproduction contracts |
| `generator/` | Candidate generation, calibration and checkpoint replay |
| `methods/` | Guest input ABI and locked guest-build contract |
| `appliance/h0-tmpfs-provider/crates/` | Dependencies of the optional campaign tooling |
| `docs/specs/` | Verifier and execution-boundary specifications |

Rust 1.89.0 and dependency lockfiles are pinned. The generator is a separate
Cargo workspace. Its default `embedded-method` feature builds the guest and
requires the exact environment checked by `methods/build.rs` and
`methods/build_contract.rs`; it is not a portable, unrestricted
`cargo run` entry point. Running it requires a separately provisioned locked
guest environment; the commands below cover only non-proving checks.

The older B4 build documents describe the fuller campaign environment. Its
Docker image definition and complete provisioning are not included in this
source milestone.

Ordinary library checks can be run without generating proofs:

```sh
cargo test --manifest-path methods/Cargo.toml --no-default-features --locked
cargo test --manifest-path reproduction/Cargo.toml --no-default-features --features profile --lib --tests --locked
cargo test --manifest-path generator/Cargo.toml --locked --no-default-features --lib
```

These commands do not exercise the embedded checkpoint routes. Their focused
tests and genuine proof runs require the locked guest environment and the
specific authenticated input receipts.

## Remaining work

The complete B4 corpus, Rust/JVM differential results and final archive remain
open. So do measured consensus costs, the authenticated activation transition,
independent reproduction, and node/admission integration. This repository
does not activate a profile on Ergo and is not a production release.

Licensed under Apache-2.0. Attribution for adapted profile material accompanies
the profile package.
