# EIP-0045 StarkProfileManifestV1

Status: pre-activation construction specification. The exact B1/B2 package in
this directory deterministically derives the B3 bytes and profile ID reported
below; this does not assign network finality. The 65,119-byte B2 artifact
remains fixed.

## Authority and artifacts

`manifest.bin` is the sole byte-level authority for Manifest V1 fields. Its
exact 458 bytes are authenticated by `profileId`. It commits exactly two
normative external artifacts:

1. kind 1: `algorithm.txt`, the self-contained normative verifier algorithm;
2. kind 2: `constants.bin`, the normative verifier data.

`binary-format.md`, `constants.json`, `manifest.json`, and the Python tools are
derived documentation or verification aids. They are not additional normative
artifacts and are absent from the `profileId` commitment graph.

The generated raw files are:

- `manifest.bin`: the 458-byte manifest;
- `manifest.json`: the RFC 8785 canonical derived view;
- `algorithm-artifact-preimage.bin`: the exact kind-1 digest preimage;
- `binary-data-artifact-preimage.bin`: the exact kind-2 digest preimage;
- `profile-id-preimage.bin`: the exact 485-byte profile-ID preimage;
- `profile-id.bin`: the resulting raw 32-byte profile ID.

Former 382-byte B3 files describe the superseded single-lift candidate. They
are not valid inputs to this 458-byte grammar. `formatVersion` remains 1; exact
length, the typed ten-entry layout, and the resulting profile identity
distinguish the corrected pre-activation construction.

## Integer and digest conventions

All integers are unsigned. Multibyte integers are little-endian. All digests
occupy exactly 32 raw bytes. `BLAKE2b-256` means BLAKE2b configured with a
32-byte output, not a truncation of BLAKE2b-512.

For artifact kind `K` and exact artifact bytes `A`, define:

```text
artifactPreimage =
    ASCII("Ergo.StarkProfileArtifact.v1") ||
    0x00 ||
    u16le(K) ||
    u32le(length(A)) ||
    A

artifactDigest = BLAKE2b-256(artifactPreimage)
```

The fixed B2 input has 65,119 bytes, raw SHA-256
`8c4a92b7d354890481eefdef233d4ca43f6bcd9f7cb00e4dd9e709da47789ef3`,
and domain-separated artifact digest
`dd8528a8621edc8dd24aadeed7bd7a2f0c1afd88dd563c5ec8f51cc7f75df0b1`.
Its authenticated data fixes, among other values, the 50-query STARK profile
and 28 BabyBear reverse roots. Those roots are B2 data, not terminal controls.

## Exact 458-byte layout

| Offset | Bytes | Field | Encoding |
| ---: | ---: | --- | --- |
| 0 | 1 | `formatVersion` | exactly `0x01` |
| 1 | 4 | `exactProofBytes` | `u32le`, initial value 222,668 |
| 5 | 4 | `maxApplicationPayloadBytes` | `u32le`, initial value 16,384 |
| 9 | 1 | `outerPo2` | initial value 18 |
| 10 | 32 | `innerControlRoot` | raw digest |
| 42 | 340 | ten terminal-control entries | each `controlKind || parameter || controlId` |
| 382 | 38 | algorithm reference | `u16le(kind) || u32le(length) || digest` |
| 420 | 38 | binary-data reference | same encoding |
| 458 | 0 | strict EOF | no trailing bytes |

Each terminal-control entry is exactly 34 bytes:

```text
controlKind:u8 || parameter:u8 || controlId[32]
```

The manifest contains exactly these entries in table order:

| Index | Kind | Parameter | Meaning | Control ID |
| ---: | ---: | ---: | --- | --- |
| 0 | 1 | 15 | normal lift | `1ca3ca03030719064ba61b3125bdd326fc57f74e799ef860bdea6f3227381e16` |
| 1 | 1 | 16 | normal lift | `c32b3627d2b3d60c64adf523a98bd16c0ff607471f3d6630d1f26d5e9406d841` |
| 2 | 1 | 17 | normal lift | `c9b08054994f542a6310b00d9b6fc6528ed7bb6f4ca5476a686847127cdfdc5b` |
| 3 | 1 | 18 | normal lift | `e7934a23ddce1423b425cf32aa23be29f48cd40e0b6ff9376dce6f3bf9d0bc35` |
| 4 | 1 | 19 | normal lift | `8c2fdd36ede09a4b9d316a43c51f1160cbd8876659c5f35810c3a119c60d3843` |
| 5 | 1 | 20 | normal lift | `34530b42028fb631c90e1226bb0e750d4b9b593840d45216f75dca449dac7734` |
| 6 | 1 | 21 | normal lift | `fd84d83092a1e1244d423a26d89c892ab098b467c6d82229912deb26e37d2562` |
| 7 | 1 | 22 | normal lift | `9d9dbf33535ab11f52a93839dfd23b352b7626009e81d9459fd04e488898ec6a` |
| 8 | 2 | 0 | join | `7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e` |
| 9 | 3 | 0 | resolve | `53a7b23d07f99e5d5685e85874f5181e8486aa267a0ae607ffe9ba47c8bdda4a` |

Kind 1 requires parameter 15 through 22 at its fixed position. Kind 2 and kind
3 require the reserved parameter zero. No other kind or parameter is defined
by Manifest V1. Position does not authorize an alternate kind or parameter.
All ten control IDs must be pairwise distinct.

The first artifact reference must have kind 1 and the second kind 2. Both
lengths must be nonzero, and each declared length and digest must match the
exact supplied artifact bytes. A decoder validates exactly 458 bytes before
field access and must reach byte 458 exactly.

The approved proof ABI uses exactly four chunks of 65,535, 65,535, 65,535,
and 26,063 bytes. Their sum is the manifest-owned 222,668-byte raw seal. The
chunk partition is an opcode/collection ABI invariant, not another Manifest V1
field.

## Outermost-only terminal policy

The terminal table constrains only the reconstructed **outermost** code root.
It does not expose or constrain child controls carried privately as witnesses.
Consequently:

- an allowed terminal `join` may contain children produced by any recursion
  control, including controls absent from this terminal table;
- an allowed terminal `resolve` may discharge an assumption with any explicit
  guest-committed control root; zero denotes self-composition under the
  conditional receipt root; and
- the pinned inner root check does not turn the ten-entry table into an
  ancestry proof.

These are RISC Zero typed-claim semantics, not permission to trust an arbitrary
root silently. The application guest bound by `programId` owns the assumption
policy and provenance checks. The EIP verifier separately requires the pinned
decoded inner root, exact invocation-bound image ID, exact final OK claim with
empty assumptions, and strict proof EOF.

The canonical `manifest.json` view names this ordered array
`terminalControls`. Each object contains exactly the semantic fields
`controlId`, `controlKind`, and `parameter`; JSON key sorting is canonical and
does not change array order.

## Profile identity

For exact 458-byte `manifest.bin` bytes `M`, define:

```text
profileIdPreimage =
    ASCII("Ergo.StarkProfileId.v1") ||
    0x00 ||
    u32le(458) ||
    M

profileId = BLAKE2b-256(profileIdPreimage)
```

For the exact B1/B2 package in this directory, `manifest.bin` has SHA-256
`deffb2cb231f98a348cbd166d5f1c43315661ccd8bd212099f16f238d0fe8946`
and the resulting raw `profileId` is
`23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383`.

The preimage is exactly 485 bytes. Runtime code must first decode and validate
all 458 manifest bytes, authenticate the expected `profileId`, and validate
both artifact envelopes. Once a network transition activates that identity,
the authenticated manifest fields are runtime authority; a duplicated
pre-activation constants table is not.

## Reproducible freeze procedure

Run the independent in-memory test without writing B3:

```text
python profiles/risc0-v3-succinct/verify_profile.py self-test \
  --profile-dir profiles/risc0-v3-succinct
```

After B1 and B2 are frozen, generate into a new empty staging directory. The
generator refuses to overwrite an existing output directory:

```text
cargo run --locked --manifest-path generator/Cargo.toml \
  --no-default-features --bin eip-0045-profile -- generate \
  --profile-dir profiles/risc0-v3-succinct \
  --output-dir <new-staging-directory>
```

Run the Rust verifier and the independent standard-library Python verifier on
the same staging directory. Repeat generation into a second new directory and
require byte equality for all six files before installation.

```text
cargo run --locked --manifest-path generator/Cargo.toml \
  --no-default-features --bin eip-0045-profile -- verify \
  --profile-dir profiles/risc0-v3-succinct \
  --bundle-dir <new-staging-directory>

python profiles/risc0-v3-succinct/verify_profile.py verify \
  --profile-dir profiles/risc0-v3-succinct \
  --bundle-dir <new-staging-directory>
```

After both staging runs and both verifiers agree, install the independently
re-derived outputs. This command preflights all six destinations and refuses
every overwrite:

```text
cargo run --locked --manifest-path generator/Cargo.toml \
  --no-default-features --bin eip-0045-profile -- install \
  --profile-dir profiles/risc0-v3-succinct
```

Neither implementation assigns finality. The network activation artifact must
pin the separately reviewed 32-byte `profileId`.
