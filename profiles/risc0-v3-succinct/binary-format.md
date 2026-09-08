# RISC Zero v3 succinct binary verifier data

`constants.bin` is the normative B2 verifier-data artifact. The complete
normative decoder grammar is embedded in the content-addressed B1
`algorithm.txt`; this file is a derived, non-normative review view and cannot
reinterpret B1. Its displayed length is 65,119 bytes. All integers are unsigned
little-endian. The grammar has no magic, version, padding, reserved fields,
alignment gaps, or trailing bytes. The enclosing profile manifest identifies
the artifact as kind 2 and binds its length and digest.

The artifact owns numeric verifier tables, dimensions, indices, and the two
16-byte protocol-information preimages absorbed by the verifier. It does not
contain proof sizes, payload limits, the recursion control root, typed terminal
control entries, `outerPo2`, a cost schedule, or a `profileId`. Those values are
owned by the manifest, host rules, or activation record.

## Fixed header

| Offset | Size | Field | Required value |
| ---: | ---: | --- | ---: |
| 0 | 4 | BabyBear modulus | 2,013,265,921 |
| 4 | 1 | extension degree | 4 |
| 5 | 4 | extension polynomial beta for `x^4 + beta` | 11 |
| 9 | 1 | maximum root exponent | 27 |
| 10 | 1 | Poseidon2 state cells | 24 |
| 11 | 1 | Poseidon2 rate cells | 16 |
| 12 | 1 | Poseidon2 output cells | 8 |
| 13 | 1 | Poseidon2 half-full rounds | 4 |
| 14 | 1 | Poseidon2 partial rounds | 21 |
| 15 | 1 | Poseidon2 S-box degree | 7 |
| 16 | 2 | stored Poseidon2 round constants | 213 |
| 18 | 1 | Poseidon2 internal diagonal constants | 24 |
| 19 | 1 | STARK queries | 50 |
| 20 | 1 | inverse Reed-Solomon rate | 4 |
| 21 | 1 | FRI fold | 16 |
| 22 | 1 | FRI fold exponent | 4 |
| 23 | 2 | FRI minimum degree | 256 |
| 25 | 1 | recursion output size | 32 |
| 26 | 1 | recursion mix size | 20 |
| 27 | 1 | check size | 16 |
| 28 | 2 | tap count | 643 |
| 30 | 1 | register-group count | 3 |
| 31 | 3 | group sizes, ordered accum/code/data | 12, 23, 128 |
| 34 | 1 | combination count | 5 |
| 35 | 1 | total combination backs | 20 |
| 36 | 2 | PolyExt instruction count | 12,359 |
| 38 | 2 | PolyExt field-variable count | 11,130 |
| 40 | 2 | PolyExt mix-variable count | 1,229 |
| 42 | 2 | returned mix-variable index | 1,228 |
| 44 | 4 | extension coefficient remap | 0, 2, 1, 3 |
| 48 | 3 | register-group identifiers | 0, 1, 2 |
| 51 | 1 | proof-system info length | 16 |
| 52 | 1 | circuit info length | 16 |
| 53 | 1 | tap-record width | 5 |
| 54 | 1 | extension challenge scale | 3 |
| 55 | 16 | proof-system info bytes | ASCII `RISC0_STARK:v1__` |
| 71 | 16 | circuit info bytes | ASCII `RECURSION:rev1v1` |

The header ends at offset 87.

## Numeric tables

| Offset | Size | Encoding |
| ---: | ---: | --- |
| 87 | 112 | 28 BabyBear reverse roots of unity as `u32le` |
| 199 | 852 | 213 canonical Poseidon2 round constants as `u32le` |
| 1,051 | 96 | 24 Poseidon2 internal-diagonal constants as `u32le` |
| 1,147 | 3,215 | 643 packed tap records |
| 4,362 | 60,757 | 12,359 ordered PolyExt instructions |
| 65,119 | 0 | strict EOF |

Every BabyBear value in these tables must be less than the modulus.

The 213 Poseidon2 round constants are the values actually read by the
permutation, in round order. Store all 24 constants for full rounds 0 through
3, only cell 0 for partial rounds 4 through 24, and all 24 constants for full
rounds 25 through 28. The omitted 483 expanded slots must be zero in the pinned
upstream source. A decoder reconstructs the expanded 29 by 24 table by filling
those omitted partial-round slots with zero.

## Tap records

Each tap record is exactly five bytes in this order:

```text
group:u8 || offset:u8 || back:u8 || combo:u8 || skip:u8
```

The 643 records preserve upstream order. `group` must be in `[0, 3)`, `offset`
must be less than the selected group size, `combo` must be in `[0, 5)`, and
`skip` must be nonzero. Starting at record zero, each `skip`-sized run is one
register and must keep one identical `(group, offset, combo, skip)` tuple. The
registers must enumerate exactly one `(group, offset)` for every column in
lexicographic group/offset order: accum 0 through 11, code 0 through 22, then
data 0 through 127. Backs within one register must be unique and strictly
increasing. All registers assigned to one combo must have the same back list;
all five combos must occur, their five lists must be pairwise distinct, and
their concatenated length must be 20. The algorithm reconstructs the derived
TapSet combination indexes from these ordered records; they are not duplicated
here.

## PolyExt instruction stream

An instruction starts with a one-byte tag. Operands use the fixed width shown
below, so instruction width varies only by tag.

| Tag | Instruction | Operands | Width | Count |
| ---: | --- | --- | ---: | ---: |
| 0 | `Const` | `value:u32le` | 5 | 284 |
| 1 | `ConstExt` | four `u32le` values | 17 | 0 |
| 2 | `Get` | `tap:u16le` | 3 | 669 |
| 3 | `GetGlobal` | `arg:u16le, offset:u16le` | 5 | 52 |
| 4 | `Add` | `left:u16le, right:u16le` | 5 | 4,061 |
| 5 | `Sub` | `left:u16le, right:u16le` | 5 | 1,385 |
| 6 | `Mul` | `left:u16le, right:u16le` | 5 | 4,679 |
| 7 | `True` | none | 1 | 1 |
| 8 | `AndEqz` | `chain:u16le, inner:u16le` | 5 | 1,076 |
| 9 | `AndCond` | `chain:u16le, cond:u16le, inner:u16le` | 7 | 152 |

`Const`, `ConstExt`, `Get`, `GetGlobal`, `Add`, `Sub`, and `Mul` append one
field variable. `True`, `AndEqz`, and `AndCond` append one mix variable. Field
and mix indices are separate zero-based spaces. Every `Add`, `Sub`, or `Mul`
operand must reference an earlier field variable. `AndEqz` references an
earlier mix chain and an earlier field variable. `AndCond` references an
earlier mix chain, an earlier field condition, and an earlier mix value. A
`Get` tap index must be less than 643. `GetGlobal` admits only argument 0 with
offset below 32 or argument 1 with offset below 20.

The last instruction must leave exactly 11,130 field variables and 1,229 mix
variables. Returned mix index 1,228 is the final mix variable, not an
instruction index. Algebraically equivalent instruction reordering or DAG
rewriting is not conformant.

## Reproduction

The primary generator reads ten exact source files from RISC Zero commit
`8eb06ab020a92dc5b63ba6dd0836d432aba6d890`. It checks a SHA-256 lock for every
source before extracting data. The locked hash is over the canonical Git-blob
text: a physical CRLF checkout is converted byte-for-byte to LF first, while a
UTF-8 BOM, NUL, or lone CR is rejected. No other normalization is permitted.
It also proves the expanded Poseidon2 partial-round slots are zero, validates
the TapSet and PolyExt censuses and backward references, and refuses to
overwrite an output.

From `generator/`, with the pinned source checkout already available:

```text
cargo run --locked --offline --no-default-features --bin eip-0045-constants -- generate --risc0-root <PINNED_RISC0_CHECKOUT> --output-bin ../profiles/risc0-v3-succinct/constants.bin --output-json ../profiles/risc0-v3-succinct/constants.json
cargo run --locked --offline --no-default-features --bin eip-0045-constants -- verify --input-bin ../profiles/risc0-v3-succinct/constants.bin
python ../profiles/risc0-v3-succinct/verify_constants.py ../profiles/risc0-v3-succinct/constants.bin
```

Both `verify` commands require the exact canonical SHA-256 below in addition to
strict grammar and decode/re-encode identity. For development of a later B2
revision, the Rust `validate-grammar` subcommand and Python `--grammar-only`
option expose structural validation without claiming the current canonical
identity. `constants.json` is a non-normative, complete decoded view for human
and cross-implementation review; only `constants.bin` supplies B2 bytes.

Current artifact SHA-256:

```text
8c4a92b7d354890481eefdef233d4ca43f6bcd9f7cb00e4dd9e709da47789ef3
```
