#!/usr/bin/env bash
# Build the Rust verifier and the RISC Zero ProgramBinary used by this demo.
set -euo pipefail
src=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
: "${GUEST_TOOLCHAIN:?Point GUEST_TOOLCHAIN at the extracted RISC Zero r0.1.97.0 rust-toolchain directory}"
: "${CARGO_TARGET_DIR:?Select an absolute build directory}"
case "$CARGO_TARGET_DIR" in /*) ;; *) echo 'CARGO_TARGET_DIR must be absolute' >&2; exit 2;; esac
out=${1:?Specify a new output program file}
case "$out" in /*) ;; *) out="$PWD/$out";; esac
host_cargo=${HOST_CARGO:-cargo}
"$host_cargo" build --manifest-path "$src/host/Cargo.toml" --release --locked --jobs "${CARGO_BUILD_JOBS:-2}"
# Cargo includes path-package identities in symbols. Remapping debug strings
# alone does not make the linked guest reproducible in different checkouts.
# Create an exclusively owned, fixed guest workspace. Preserve it with this
# build's target outputs for diagnostics after the compile (success or fail).
fixed=/tmp/eip0045-guest-310-v1
guest_archive="$CARGO_TARGET_DIR/guest-generation"
if [[ -e "$guest_archive" || -L "$guest_archive" ]]; then
    echo 'Select a fresh CARGO_TARGET_DIR for this generation.' >&2
    exit 2
fi
mkdir -m 700 -- "$fixed"
trap 'mv -T -- "$fixed" "$guest_archive"' EXIT
mkdir -p -- "$fixed/source" "$fixed/cargo/registry"
cp -R -- "$src/guest" "$src/abi" "$fixed/source/"
ln -s -- "$GUEST_TOOLCHAIN" "$fixed/toolchain"
# The source and extraction paths stay canonical. The optional local cache
# supplies only Cargo's checksummed crate archives and index in offline mode.
if [[ "${CARGO_NET_OFFLINE:-false}" == true ]]; then
    cache_root=${CARGO_HOME:-$HOME/.cargo}
    for name in index cache; do
        ln -s -- "$cache_root/registry/$name" "$fixed/cargo/registry/$name"
    done
fi
(
    cd "$fixed/source/guest"
    export PATH="$fixed/toolchain/bin:$PATH" RUSTC="$fixed/toolchain/bin/rustc"
    export CARGO_HOME="$fixed/cargo" CARGO_TARGET_DIR="$fixed/target"
    sep=$'\x1f'
    flags=(-C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings -C panic=abort --cfg 'getrandom_backend="custom"'
        "--remap-path-prefix=$fixed/source=/src" "--remap-path-prefix=$fixed/cargo=/cargo" "--remap-path-prefix=$fixed/target=/target")
    printf -v encoded "%s$sep" "${flags[@]}"
    export CARGO_ENCODED_RUSTFLAGS="${encoded%$sep}"
    "$fixed/toolchain/bin/cargo" build --release --locked --jobs "${CARGO_BUILD_JOBS:-2}" --target riscv32im-risc0-zkvm-elf
)
"$CARGO_TARGET_DIR/release/ergo310-receipt" pack "$fixed/target/riscv32im-risc0-zkvm-elf/release/ergo310-guest" "$out"
