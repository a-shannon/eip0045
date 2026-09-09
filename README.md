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

The follow-up adds a non-proving ancestry codec, extraction of the retained
Case-9 receipt encodings, and the `eip-0045-ancestry-pair` command. The command
compares complete retained assumption bytes from Resolve/Join oracles against
supplied length and SHA-256 pins; it does not verify proofs or authenticate
provenance. The validator also exercises 15 retained-receipt negative-ancestry
cases through its local Linux test path.

Focused validation passed those 15 cases, 56 consumer tests and 21 targeted
minimal-generator, CLI and integration tests. The default embedded-generator
build produced the library and five binaries, and its 37 selected ordinary
recursive tests passed. These are scoped checks, not the full default test
harness or every feature combination. Source changes and execution evidence
received independent review.

These workflows are building blocks for the negative-ancestry test corpus.
Candidate generation, retained-byte comparison, cryptographic replay and
campaign qualification remain separate steps. The source also includes the
pinned profile package, receipt and ancestry validators, fixture schemas and
their direct tests.

## Source layout

| Directory | Purpose |
| --- | --- |
| `profiles/risc0-v3-succinct/` | Fixed profile inputs and derived identity |
| `reproduction/` | Validation, schemas, fixtures and reproduction contracts |
| `generator/` | Candidate generation, calibration and checkpoint replay |
| `methods/` | Guest input ABI and locked guest-build contract |
| `appliance/h0-tmpfs-provider/crates/` | Dependencies of the optional campaign tooling |
| `docs/specs/` | Verifier and execution-boundary specifications |

Host Rust 1.89.0 and dependency lockfiles are pinned. The generator is a separate
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
