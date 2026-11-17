# One Ergo receipt, two verifiers

This demo checks a RISC Zero 3.1.0 succinct proof of the EIP-0045 reference guest. The guest reads the public statement and commits it to its journal. The proof terminates in a single normal RV32IM lift with segment exponent 15.

| Expected application payload (UTF-8) | Stock Rust verifier | Scala/JVM verifier |
|---|---|---|
| `Ergo EIP-0045 local demo v3.1.0` | Accept | Accept |
| `Ergo EIP-0045 local demo v3.1.1` | Reject: claim digest mismatch | Reject: claim mismatch |

The proof bytes stay fixed. The second row flips the low bit of the last payload byte. Rust authenticates the archived receipt, matches its extracted raw seal against the shared seal file, and checks the expected journal against the same inner receipt. The JVM independently constructs the expected Ergo claim from the chain domain, profile, guest image, reference contract and payload. It checks the raw seal and derives the terminal control from the proof.

## Replay from a checkout

Use x86-64 Linux with Python 3.9+, a JDK 17+ `java` on PATH and Rust installed through rustup (host toolchain 1.97.1). The pinned RISC Zero compiler below also builds the host verifier. From this directory:

```sh
python3 verify.py
```

The first invocation builds the locked Rust verifier and fetches three hash-pinned Scala 2.13.18 jars. Allow network access for those dependencies or prepopulate the Cargo and Scala caches. Expected verifier output:

```text
Rust: ACCEPT lift-po2-15
Rust: REJECT claim-digest-mismatch
ACCEPT lift-po2-15
REJECT raw-seal-claim-mismatch
```

The vector contains a 223,606-byte stock receipt and its 222,668-byte raw seal. The seal SHA-256 is `5617ac97be387733a4edb767190fee0f1cbb64e05b63360f52f5f44fa9d04430`. The [vector metadata](vector/vector.json) pins the receipt, guest image, statement and candidate profile. [Profile reconstruction](profile/README.md) describes the algorithm and constants.

## Rebuild the guest and produce another proof

For an exact compiler setup on x86-64 Linux, run the following in Bash from this directory. Choose an empty output directory on a volume with space for the compiler and build.

```sh
set -euo pipefail
work=$(mktemp -d)
export GUEST_TOOLCHAIN="$work/toolchain" CARGO_TARGET_DIR="$work/target" CARGO_BUILD_JOBS=2
mkdir "$GUEST_TOOLCHAIN" "$work/tools"
curl -fLsS --retry 2 https://github.com/risc0/rust/releases/download/r0.1.97.0/rust-toolchain-x86_64-unknown-linux-gnu.tar.gz -o "$work/rust.tgz"
echo "100b597d605b706bec94e1d32bfaaf5851df8d75173f986d4b56a3e90916be53  $work/rust.tgz" | sha256sum -c -
tar -xzf "$work/rust.tgz" -C "$GUEST_TOOLCHAIN"
export PATH="$GUEST_TOOLCHAIN/bin:$PATH" HOST_CARGO="$GUEST_TOOLCHAIN/bin/cargo"

bash prover/build-program.sh "$work/program.bin"
image=b574db28719df2261c18b5c5f0a52ad5ad96a290679df3223c1c3acacd0fca9c
profile=5649af920f3119ca06e8566d836d3c89de81af52ef3d140a0ad7012ca364d35c
python3 statement.py "$image" "$profile" "$work/input"

curl -fLsS --retry 2 https://github.com/risc0/risc0/releases/download/v3.1.0/cargo-risczero-x86_64-unknown-linux-gnu.tgz -o "$work/prover.tgz"
echo "415ca205d4408f5d768b9e4d623f2aac6b869329a6cf965f0c57a88a6dbb5871  $work/prover.tgz" | sha256sum -c -
tar -xzf "$work/prover.tgz" -C "$work/tools"
r0vm=$(find "$work/tools" -type f -name r0vm -print -quit)
test "$("$r0vm" --elf "$work/program.bin" --id)" = "$image"
host="$CARGO_TARGET_DIR/release/ergo310-receipt"
"$host" guest-input "$work/input/statement.bin" "$work/guest-input.bin" 0
RISC0_DEV_MODE=0 RAYON_NUM_THREADS=2 "$r0vm" --elf "$work/program.bin" \
    --initial-input "$work/guest-input.bin" --receipt-kind succinct --hashfn poseidon2 \
    --receipt "$work/receipt.bin"
"$host" extract "$work/receipt.bin" "$work/raw-seal.bin" "$image"
"$host" verify "$work/receipt.bin" "$work/raw-seal.bin" "$image" "$work/input/statement.bin"
rc=0
"$host" verify "$work/receipt.bin" "$work/raw-seal.bin" "$image" "$work/input/changed-statement.bin" || rc=$?
test "$rc" = 1
python3 jvm/verify.py profile/bundle "$work/raw-seal.bin" "$image" \
    'Ergo EIP-0045 local demo v3.1.0' --changed-payload 'Ergo EIP-0045 local demo v3.1.1'
```

Fresh zero-knowledge proofs may have different seal hashes. The reproducible result for a fresh proof is the terminal and the four verdicts. The archived vector also supports byte-for-byte replay.

The build script uses an exclusive temporary directory with a fixed name for the Rust guest. Cargo includes local crate identities in symbol names, which can change the guest image when the checkout moves. At exit the script moves the guest workspace into the chosen target directory. Use a fresh target for a new guest build.

## Scope

This is one offline interoperability case using the corrected [3.1.0 circuits](https://github.com/risc0/risc0/releases/tag/v3.1.0) and a demo profile. The earlier developer preview used 3.0.5. The complete corpus, consensus costing, node integration and network activation remain open. The demo guest commits an application statement. Applications define and enforce their own spending rules.
