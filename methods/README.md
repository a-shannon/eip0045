# Methods

This directory contains two source-built RISC Zero v3.0.5 guests. The consumer
guest remains the one guest used by all eleven positive B4 candidate families:
the eight normal lifts (`po2=15..22`), terminal join, terminal resolve, and
resolve ancestry followed by terminal join. The private alternate-program guest
exists only for the closed negative-ancestry rows that require a different
program ID. The build admits source only through the pinned toolchain and exact
dependency closure; no prebuilt ELF is trusted by filename or provenance claim
alone.

## Path-sensitive build identity

The pinned RISC Zero dependency source paths are present in the guest ELF's
`.rodata` and therefore affect both the ELF bytes and image ID even when the
executable instructions are unchanged. An `embed-methods` build consequently
fails closed unless `HOME` is exactly `/home/ergo/eip0045`, `CARGO_HOME` is
exactly `/home/ergo/eip0045/.cargo`, `CARGO_TARGET_DIR` is exactly `/target`,
`CARGO_MANIFEST_DIR` is exactly `/workspace/methods`, all four are physical
canonical directories, and
`/home/ergo/eip0045/.cargo/config.toml` is a physical regular file equal
byte-for-byte to `reproduction/cargo-offline-config.toml`. The build contract
tests reject superseded build-home roots, `/root`, source or target-directory
path drift, and any config mutation or extension.

The HOME, Cargo-home, and config conditions pin the lexical dependency checkout
root actually supplied to the guest build; those loadable path bytes are
image-identity inputs, not cosmetic host preferences. The manifest and target
directory conditions additionally pin the whole-ELF evidence identity:
non-loadable metadata can change an ELF digest without changing its computed
image ID. A fresh campaign must therefore compare both the resulting guest ELF and computed
image ID with a second fresh build under the same canonical path before any B4
candidate can be promoted.

## Private input ABI

The guest reads one exact 60-byte little-endian header followed by the declared
statement bytes:

```text
mode:u32le ||
statementLength:u32le ||
workloadIterations:u32le ||
workloadSeed:u64le ||
expectedWorkloadResult:u64le ||
assumptionImageId[32] ||
statementBytes[statementLength]
```

The canonical producer serialization ends immediately after
`statementBytes` and the checked-in builders assert that its total length is
exactly `60 + statementLength` bytes. The guest consumes that declared prefix;
it does not separately test exhaustion of private stdin. Consequently, EOF is
a producer-side framing requirement, not a guest rejection property. Any
external producer that accepts preassembled private-input bytes must reject a
total length different from the header's `encoded_input_length()` before
execution.

Exactly four modes exist:

- `mode=0` requires `assumptionImageId` to be all zero and makes no receipt
  assumption.
- `mode=1` requires a nonzero image ID and calls
  `env::verify(assumptionImageId, statementBytes)` exactly once, recording the
  zero control root used for self-composition.
- `mode=2` requires a nonzero image ID, derives the exact digest of
  `ReceiptClaim::ok(assumptionImageId, SHA-256(statementBytes))`, and calls
  `env::verify_assumption(claimDigest, ALLOWED_CONTROL_ROOT)` exactly once. The
  root comes from the pinned RISC Zero dependency and is not an input.
- `mode=3` uses the same nonzero image ID, claim digest, and pinned explicit
  root as `mode=2`, but calls `env::verify_assumption` exactly twice with that
  identical tuple. It exists only for the closed duplicate-inventory negative
  witness; it is not a fourth positive candidate family or a caller-selected
  repetition count.

The header decoder rejects every other mode, a non-exact header length, a
statement above 16,543 bytes, and either noncanonical mode/image-ID pairing.
The deterministic workload runs after the optional assumption verification and
must produce the header's expected result before the guest commits any journal
bytes. This ordering lets one private calibration value fill a final source
segment while every family continues to use the same guest ELF.

All four modes commit exactly `statementBytes` and nothing from the private header.
The assumption image ID is the same guest's image ID, and the assumed journal
is the same `ErgoStatementV1`. This makes the conditional receipt suitable for
stock `resolve` while keeping the final successful claim identical across all
eleven cases. The terminal-resolve case uses the explicit root; the
resolve-then-join ancestry case uses the zero-root branch.

Plain mode validates the workload first, then streams the statement directly
from input to the journal in at most 256-byte pieces. Assumption modes retain
the statement in one fixed 16,543-byte guest buffer because `env::verify`
needs the entire journal slice; they preserve the order
`read -> verify assumption -> workload -> commit`. Chunking is not a
serialization layer and does not change the journal. The two paths are
non-inlined frames in the same guest so the assumption-only buffer does not
raise the minimum plain execution above `po2=15`. No heap allocation or
zkVM-specific proof selection is exposed to the consumer guest.

The alternate-program guest uses the same exact 60-byte header and statement
framing, but accepts only `mode=0`. It rejects every assumption mode before the
workload or journal commitment, validates the same deterministic workload, and
then streams exactly the declared statement to the journal. It has no
assumption API, caller-selected mode extension, environment, argument, or path
input. Its generated ELF and image ID are independently recomputed and must be
distinct from the consumer guest before negative-ancestry evidence can use it.

Changing any ABI field, mode rule, workload implementation, or guest source
changes the ELF and therefore the image ID. A B4 campaign must consequently
regenerate all eight lift candidates and all three recursive candidates from
the same newly built ELF; historical one-lift receipts cannot be mixed into
that corpus.
