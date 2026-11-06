# EIP-0045 local developer preview

This preview runs the EIP-0045 checks already in the public repository. It
covers the guest input ABI, reproduction and profile contracts, and the
non-proving generator library. The quickstart follows the library job in
the [public CI workflow](../.github/workflows/non-proving.yml), which uses
Ubuntu 24.04 and Rust 1.89.0.

## Run the preview

From a Linux shell:

```sh
git clone https://github.com/a-shannon/eip0045.git
cd eip0045
rustup toolchain install 1.89.0 --profile minimal
export CARGO_TARGET_DIR="$PWD/../eip0045-preview-target"
cargo +1.89.0 fetch --manifest-path methods/guest/Cargo.toml --locked
cargo +1.89.0 test --manifest-path methods/Cargo.toml --no-default-features --locked
cargo +1.89.0 test --manifest-path reproduction/Cargo.toml --no-default-features --features profile --lib --tests --locked
cargo +1.89.0 test --manifest-path generator/Cargo.toml --no-default-features --lib --locked
```

These tests exercise public source without generating a STARK proof or
activating a verifier profile. The [6 November progress report](progress/2026-11-06.md)
also records a newer *local* result: a pinned test binary listed 1,658 tests,
including all 26 expected selectors, and its Root result passed the strict
metadata contract. The native sources used for that listing have not yet been
published, so this quickstart does not reproduce that particular run.

## What remains for a full release

- Complete B4's eleven ordered positive cases, 254 independently reconstructed
  negative materialization identities and 508 paired Rust/JVM results. Formal
  campaign credit is currently 0/508.
- Finish measured consensus costs, authenticated activation and node admission
  work under B5–B8, then obtain a fresh independent reproduction of the
  complete package.
- Publish and validate the native sources and build inputs needed for others
  to reproduce the bounded test listing and the later campaign.
- Obtain upstream maintainer acceptance and a merge, then complete the
  separate release process. This fork preview does not provide those steps.

No EIP-0045 profile is activated on Ergo by this preview.
