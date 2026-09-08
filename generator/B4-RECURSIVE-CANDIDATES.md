# B4 recursive candidate procedure

This procedure closes the three receipt shapes missing from the eight normal
lift candidates. It is deliberately candidate-only: successful generation or
replay does not promote bytes into B7, a LOCK, a final KAT corpus, or an
activation package.

## Closed scope

One guest ELF and one image ID must produce all eleven cases:

1. normal lift at each segment exponent `15..22`;
2. a genuine two-segment receipt whose outermost recursion program is stock
   Poseidon2 `join`;
3. a genuine assumption-bearing one-segment receipt whose outermost recursion
   program is stock Poseidon2 `resolve` and whose final claim has no remaining
   assumptions; and
4. a genuine two-segment ancestry in which the second segment is resolved
   before stock `join` becomes the outermost program.

The three recursive graphs are fixed at their smallest genuine cardinality:

| Family | Source | Canonical ancestry | Final terminal |
| --- | --- | --- | --- |
| `terminal-join` | two unconditional segments | `lift(s0)`, `lift(s1)`, `join(0,1)` | `join` |
| `terminal-resolve` | one explicit-root conditional segment plus one independent same-program assumption receipt | `lift(s0)`, `resolve(0,A)` | `resolve` |
| `resolve-then-join` | two-segment zero-root conditional execution plus assumption `A` | `lift(s0)`, `lift(s1)`, `resolve(1,A)`, `join(0,2)` | `join` |

Canonical case 8, `terminal-join`, is the only family whose source execution
receives a PoVW job. The private deterministic job is bound to the case-8
domain, image ID, and statement digest; its nonzero job number is the
little-endian first eight bytes of that SHA-256 derivation, with zero normalized
to one. Both execute-only observation and composite proving use this same
policy. The two authenticated source receipts must have indices `0` and `1`
and decode to the default zero work log, the derived job, and consecutive
segment nonces `0` and `1`. The ancestry remains the normal
`lift(s0)`, `lift(s1)`, `join(0,1)` graph.

This identity is fixture-local and non-accounting: it represents neither
operational PoVW work credit nor a coverage/readiness advance. It makes the
existing case-8 segments composable by the later stock terminal PoVW DAG.
Case-8-dependent bytes must be regenerated under this policy before source
freeze. The other recursive families retain the ordinary no-PoVW source
environment.

`A` is a real, independently proved, single-lift receipt for the same image ID
and exact statement journal. `terminal-resolve` constructs the exact OK claim
digest and calls `env::verify_assumption` once with the pinned explicit
`ALLOWED_CONTROL_ROOT`. `resolve-then-join` calls `env::verify` once and records
the zero root used for self-composition. Neither root is a generator or
transaction input. The source composite therefore contains one real assumption
receipt. The final `resolve` output and final `join` output are both required to
have an empty assumption list and the exact successful
`ReceiptClaim::ok(imageId, statement)` digest.

Only pinned upstream `lift`, `join`, and `resolve` prover-server calls are used.
There is no identity receipt, union receipt, PoVW recursion wrapper, Groth16
wrapping, receipt unwrapping, development mode, or alternate terminal.

## Build the current candidate statement

The optional assumption mode changes the guest ELF, so the historical B3
reference program ID is not reused. Build the direct-contract proposition and
statement against the current embedded ELF without changing any B1, B2, or B3
bytes:

The embedded-method build must run with exact `HOME=/home/ergo/eip0045`, exact
`CARGO_HOME=/home/ergo/eip0045/.cargo`, and the pinned Cargo config at that physical
path. RISC Zero dependency source paths enter the guest ELF's `.rodata`, so a
different home can change the ELF and image ID without changing executable
instructions. The build script rejects such path drift before producing a new
embedded artifact. Promotion also requires two fresh same-path builds to agree
on the ELF and image ID. The current-head ELF and every identity derived from it
remain pending until that dual-build agreement is recorded.

```text
eip-0045-candidate-generator candidate-statement \
  --profile-dir ../profiles/risc0-v3-succinct \
  --chain-domain-id-file chain-domain-id.bin \
  --application-payload-file application-payload.bin \
  --output-root empty-candidate-input-root
```

Use `candidate-statement.bin` for all eleven cases and deploy or inspect
`candidate-proposition.bin` for the direct Ergo transaction path. The command
also writes the derived contract ID and current program ID. Every destination
is create-only.

## Deterministic recursive calibration

Create one canonical calibration report before authorizing proof generation:

```text
eip-0045-candidate-generator recursive-calibrate \
  --statement-file candidate-statement.bin \
  --family terminal-join \
  --calibration-file terminal-join.calibration.json
```

Repeat for `terminal-resolve` and `resolve-then-join`. The default `fixed22`
recipe fixes the segment ceiling at `22` and the independent assumption
workload at `0`. Neither accepts an arbitrary numeric override. Starting at
workload `0`, calibration applies the documented
exponential-bracketing and binary-ranking convention, rejects a jump beyond the
family's exact cardinality, and requires the ranking execution plus one replay
of the selected workload to yield the same exact profile-valid
segment-exponent sequence. During ranking only, an undersized final segment is
classified below the first valid sequence; an overlarge segment or an
undersized non-final segment is rejected. The selected sequence and its replay
must contain only exponents `15..=22`. The convention does not claim a global
minimum.

The create-only canonical JCS report binds the ELF SHA-256, computed image ID,
statement SHA-256, family, fixed constants, selected workload, and exact source
segment sequence. It contains no timestamp, path, CPU time, or machine label.
The proof command rederives the complete report and then requires the later
source preflight and every lifted source segment to match that sequence exactly.

`recursive-shape` remains a diagnostic command only. Manually supplied shape or
workload values cannot authorize a B4 proof.

### Explicit Join21 recipe

`--recipe join21` selects a separate closed recipe for `terminal-join` and
`resolve-then-join` only. Supply it explicitly to all three commands:

```text
eip-0045-candidate-generator recursive-calibrate \
  --statement-file candidate-statement.bin --family terminal-join \
  --recipe join21 --calibration-file terminal-join21.calibration.json
eip-0045-candidate-generator recursive-candidate-proof \
  --statement-file candidate-statement.bin --family terminal-join \
  --recipe join21 --calibration-file terminal-join21.calibration.json \
  --output-root terminal-join21-output
eip-0045-candidate-generator verify-recursive-candidate-export \
  --export-root terminal-join21-output/candidate-recursive-proof-export \
  --expected-statement candidate-statement.bin --expected-family terminal-join \
  --recipe join21
```

Use a fresh calibration file and output directory. For `resolve-then-join`,
derive its own report with that family and require the same family at verification.
Join21 retains the same full ranking, selected-workload replay, and complete
rederivation before proving and when verifying the export. Every observation,
including intermediate ranking executions, must stay at or below `21`; the
selected and replayed sequences must also satisfy the unchanged lower bound
and exact family cardinality. Assumption workload remains `0`.

The report keeps the V1 schema and fields, with `segmentLimitPo2` bound to `21`.
Its declared ceiling never selects the recipe implicitly. The legacy APIs and
commands without `--recipe` remain Fixed22 and reject a Join21 report. The
explicit recipe APIs require the same recipe through generation and export
verification. Historical Fixed22 report bytes remain unchanged.

This is a host-side execution recipe, not a guest, image-ID, statement, or
verification-profile change. It does not replace the separately required
Lift22 fixture or qualify a B4 campaign.

Before proving either assumption-bearing family, exercise the explicit-root
cache gate against the same embedded ELF and statement:

```text
eip-0045-candidate-generator recursive-root-gate \
  --statement-file candidate-statement.bin
```

The embedded root gate fixes the executor ceiling and workload internally at
`23` and `0`, respectively.

CI and fresh-process replay use the non-embedded equivalent so the reviewed
ELF itself remains the only program-identity authority:

```text
eip-0045-root-gate \
  --guest-elf guest.elf \
  --statement-file statement.bin
```

The external command derives the image ID from `guest.elf` and fixes both the
segment ceiling and workload internally; neither can be supplied as an
identity or calibration override.

This performs four otherwise identical executor runs and generates no STARK
proof. The exact claim and pinned `ALLOWED_CONTROL_ROOT` cache must succeed; a
zero-root cache, a deterministic one-bit mutation of the pinned root, and a
deterministic one-bit mutation of the claim must all fail in the pinned
upstream assumption matcher. Each rejection diagnostic must name the exact
claim and root requested by the guest. The command prints the image ID,
statement digest, requested and mutated claims and roots, accepted segment
exponents, and all four verdicts. Retain that transcript with the guest and
statement digests; it is an execute-only integration gate, not a B4 receipt.

## Generate and replay

After the execute-only result is reviewed, generate one family into a distinct
existing empty root:

```text
eip-0045-candidate-generator recursive-candidate-proof \
  --statement-file candidate-statement.bin \
  --family resolve-then-join \
  --calibration-file resolve-then-join.calibration.json \
  --output-root empty-family-output-root
```

Generation first rejects an occupied output root, strictly parses and rederives
the calibration inside the generation API itself, repeats the exact
source-sequence inspection, proves and
verifies every source receipt, and compares every lifted source segment with
the calibrated sequence. It then executes the canonical stock recursion graph,
checks every operation's claim semantics, requires the exact final OK claim
with no assumptions, applies the profile-owned terminal/control/root/seal gate,
and atomically retains the costly final receipt in a create-only local salvage
checkpoint before redundant archive replay or serialization. Finally it
serializes a bounded oracle, strictly projects the shared V2 ancestry document,
physically stages every referenced assumption and non-final-step raw seal at
its exact repository-relative path, strictly replays the staged export,
publishes it with an atomic no-replace directory rename, and replays the
published export again. Publication fails closed if the destination already
exists or the host filesystem cannot provide atomic exclusive rename
semantics; there is no check-then-rename fallback.

The final-receipt salvage checkpoint remains at
`.candidate-recursive-final-receipt.checkpoint.bincode` beside the final export.
It is a local create-only diagnostic/salvage artifact, not part of the closed
shareable export and not consensus evidence. It contains only the verified
final receipt. Neither generation nor replay consumes it as resume input, and
it cannot reconstruct the source receipt, intermediate receipts, oracle,
ancestry, auxiliary seals, or complete export. If a later replay or publication
check fails, the final receipt remains available for diagnosis or explicit
manual salvage, while no partial export is presented as complete. A fresh
generation still requires the original inputs and performs the full proving
route again.

A fresh process can repeat the full check without trusting export metadata:

```text
eip-0045-candidate-generator verify-recursive-candidate-export \
  --export-root empty-family-output-root/candidate-recursive-proof-export \
  --expected-statement candidate-statement.bin \
  --expected-family resolve-then-join
```

The caller supplies the expected family, statement, ELF, and image ID. The
checker requires the exact canonical calibration artifact from the closed
manifest, freshly rederives it with execute-only runs against those caller-owned
inputs, and then requires its exact constants, workload, and segment sequence
to agree with the retained source and lifts. No value inside the export selects
a verifier parameter, receipt family, or free proving control.

## Export contract

`candidate-recursive-proof-export/` has exactly two top-level entries: a
canonical proof-output manifest and `proof-output/`. The latter has exactly:

- the final raw succinct seal;
- exact journal, image ID, claim digest, and terminal control ID;
- the exact canonical JCS calibration report;
- the canonical V2 ancestry projection, including the source assumption
  inventory and role-specific path, length, and SHA-256 reference for every
  receipt seal;
- a bounded Borsh oracle containing the source composite, optional assumption
  receipt, and every intermediate succinct receipt; and
- every assumption and non-final-step raw seal referenced by that projection,
  stored under its exact repository-relative reference path.

The canonical manifest is the strict unsigned-ASCII ordering of the eight base
artifacts followed by the family-specific auxiliary paths. Terminal join and
terminal resolve each contain two auxiliary seals and therefore ten manifested
files; resolve-then-join contains four auxiliary seals and therefore twelve.
Missing, extra, reordered, or substituted paths are invalid.

The checker validates the closed physical tree twice, uses the upstream-
supported deterministic Borsh representation with a 32-MiB cap, exact end of
input, and exact re-encoding for the oracle, verifies every retained receipt
with development mode disabled, reconstructs every lift/join/resolve claim
edge, and regenerates the shared V2 projection from the replayed oracle. It
reads every auxiliary seal back from its manifested path and requires the
physical bytes to equal the authenticated oracle bytes. The projection binds
each seal's graph role to its path, length, and digest; the manifest binds that
same path, length, and digest to the closed physical tree.

The final receipt cryptographically authenticates its claim and outer proof. It
does **not** authenticate the calibration workload or historical route by which
that receipt was produced. Both calibration and ancestry evidence are therefore
marked `receiptBound: false` and `consensusProvenance: false`; they become useful
candidate evidence only because a fresh checker independently re-executes the
calibration and replays the ancestry. This agreement does not turn either one
into consensus provenance. The Borsh oracle is pinned reproduction tooling,
never a consensus or untrusted-network encoding.

## Resource authorization

No recursive proof should be started merely to discover its execution shape.
Use the execute-only gate first. On a CPU-only host, each stock recursion step
is a substantial STARK proof. The minimal graphs imply:

- terminal join: two base segment proofs, two lifts, and one join;
- terminal resolve: one base assumption proof plus its lift, one conditional
  base proof plus its lift, and one resolve; and
- resolve then join: the assumption pair, two conditional-program base segment
  proofs, two lifts, one resolve, and one join.

Plan for substantial peak memory and minutes to tens of minutes per family on
a modern workstation; the complete eleven-case campaign can take hours. Do not
treat 12 GiB, or any other provisional host limit, as an authorized envelope.
The completed 12, 20, and 24 GiB trials used one exact debug-profile generator
and ended in cgroup OOM; they characterize only that debug artifact and do not
measure the release artifact required by the B4 build contract.

Freeze and reproduce the exact release generator first, then measure that same
binary under the pinned Linux host, network isolation, an explicit no-swap
policy, recorded thread controls, and a machine-local Cargo target. Bind every
resource observation to the binary digest, build profile, input identities,
cgroup limits, peak usage, and terminal result before choosing the campaign
envelope. Host resource limits are operational evidence, not verifier-cost
calibration, consensus parameters, or protocol constants.

## Promotion exclusions

Before B4 closure, all eleven final receipts must be regenerated from the same
reviewed ELF and statement, accepted by the independent verifier path, and
included in a closed corpus with the negative mutations required by the
profile. B7 is separate: it later reproduces the archived results and generates
fresh challenge-bound randomized receipts. Until those gates close, keep the
exports visibly candidate-only and do not update normative corpus identities.
