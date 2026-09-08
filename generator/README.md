# Candidate proof generator

This crate executes and proves the pinned RISC Zero v3.0.5 guest with the
in-process local prover. Its outputs are explicitly non-final reproduction
candidates. They are not a final profile, LOCK, KAT, evidence record, or
activation package.

The current B4 work adds candidate-only construction and strict replay for the
three stock recursive families. See
[`B4-RECURSIVE-CANDIDATES.md`](B4-RECURSIVE-CANDIDATES.md) for the closed graphs,
commands, output contract, resource envelope, and promotion exclusions.

Canonical case 8 (`terminal-join`) alone receives a private deterministic,
nonzero PoVW source job bound to the case-8 domain, guest image ID, and statement
digest. Execute-only shape observation and composite proving apply the same
policy, and authentication requires source receipt indices `0` and `1` with
the default zero work log, the derived job, and consecutive segment nonces
`0` and `1`. Its recursive ancestry remains normal Lift/Lift/Join. This
fixture-local identity carries no operational work credit and does not advance
coverage or readiness; it permits later reuse of those exact source segments
by the stock terminal PoVW DAG. Case-8-dependent bytes must be regenerated
under the corrected policy before source freeze.

Its `recursive-root-gate` command is the cheap integration check for the
explicit-root guest branch. It executes the real embedded guest once with the
exact pinned claim/root tuple and requires upstream rejection of zero-root,
one-bit-mutated-root, and one-bit-mutated-claim caches. Every rejection must
name the exact tuple requested by the guest. It invokes execution only, not
proof generation, and produces no receipt. Its segment ceiling and workload
are fixed internally at `23` and `0`.

`recursive-calibrate` is the only authorizing calibration path for the three
recursive candidate families. It fixes the family ceiling at `22`, fixes the
assumption workload at `0`, selects a workload by the closed ranking convention,
classifies only an undersized final segment as below the first profile-valid
sequence, rejects overlarge and undersized non-final segments, requires two
identical selected observations entirely within `15..=22`, and writes a
create-only canonical JCS report bound to the exact guest, image, statement,
family, constants, and source segment sequence. `recursive-candidate-proof`
accepts that report instead of caller-supplied workload or ceiling values. The
public generation API itself authenticates and freshly rederives the report
before proving, so direct library callers have no free-control bypass. The exact
canonical report is then included in the closed export manifest.

Fresh export replay parses that exact canonical report, binds it to the
caller-owned ELF-derived image ID, statement, and family, reruns the complete
execute-only calibration, and requires the retained source and lifts to match
the calibrated sequence. The closed manifest also contains every assumption
and non-final-step raw seal referenced by the shared V2 ancestry projection,
under the exact referenced repository-relative path. Replay reads those
physical files, checks their manifested length and SHA-256, and requires their
bytes and graph roles to match the authenticated Borsh oracle. Calibration and
ancestry remain explicitly
`receiptBound: false` and `consensusProvenance: false`: the final receipt proves
its claim, not the historical workload or route used to obtain it.

For CI and independent replay, `eip-0045-root-gate` performs the same four-run
gate on caller-supplied ELF and statement files. It derives the image ID from
the ELF itself, accepts no image-ID or assumption-root override, fixes the
execute-only workload to zero, and refuses RISC Zero runtime overrides.

The reference 191-byte statement bundle is likewise derived from the reviewed
ELF rather than an independently supplied image ID or proposition:

```text
eip-0045-profile statement \
  --profile-dir ../profiles/risc0-v3-succinct \
  --guest-elf guest.elf \
  --output-dir empty-statement-bundle
```

This fixes the Ergo mainnet chain domain, derives the B3 profile ID and direct
contract proposition, and uses the transparent 32-byte sequence `00..1f` as a
conformance KAT payload. That payload has no application authorization meaning.
The builder computes the image ID from the bounded ELF; callers cannot
substitute a separate image ID or proposition. Its checked-in exact-reference
constants still describe the historical pre-current-HEAD guest and remain
quarantined until two fresh hermetic builds of the final source agree and the
derived identities are updated. This path is not a B4 identity source before
that update.

## Historical pre-current-HEAD identity record

Generation followed by a fresh-process strict replay of the earlier guest
yielded these identities. They are not identities of the current source and
MUST NOT be used by B4:

```text
guest ELF bytes       = 128280
guest ELF SHA-256     = 936fe43714111a4479a6a890c2d733e5bbd132bfdb0345665023641616587afb
program ID            = 9490a07414919c7eca0176d4ff9614523beecc8746ae7ffd4916f29b2edb9fe5
profile ID            = 23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383
proposition SHA-256   = a3df052fa7d25dfd9eed6370d9f60db6aee7ef5cc8124c59f52fc171ed16ddd0
contract ID           = f3582418f41ba6920c83758e56ac4475bf6084a039f91a762388e774258a6c61
statement bytes       = 191
statement SHA-256     = fc8064e54129958bcbdfa292b90251c1536d7cd8ce5e641a326e7cbd78b452ef
expected claim digest = 2ea54a883cfb8b2252937074a3b9d453264cf3e87ae6760afc3680c1da6fc92d
manifest bytes        = 2552
manifest SHA-256      = 83a2c75473d4d048cdf66d922a4f9ab6909d46025ce94c3a3793e1348c388123
```

`candidate-statement` builds the direct-contract proposition and exact
`ErgoStatementV1` for the ELF embedded in this generator. It verifies the B1,
B2, and B3 package before reading its profile ID and refuses every overwrite:

```text
eip-0045-candidate-generator candidate-statement \
  --profile-dir ../profiles/risc0-v3-succinct \
  --chain-domain-id-file chain-domain-id.bin \
  --application-payload-file application-payload.bin \
  --output-root empty-candidate-input-root
```

The output contains the program ID derived from the freshly reproduced
embedded ELF, direct-contract proposition, derived contract ID, and statement.
Before dual-build agreement these values are provisional and cannot enter B4.
Because the shared guest has distinct zero-root and pinned explicit-root
assumption modes, the statement derived after that agreement must be used when
regenerating all eleven B4 candidates. The frozen B3 profile identity remains
authoritative and independent of the guest rebuild; an older candidate
statement is historical and is not rewritten or promoted.

The `candidate-proof` command retains the one-lift producer shape. Historical
exports from the earlier guest are superseded; a new B4 campaign must rebuild
the generator and use this command to regenerate all eight lifts against the
current shared image and statement. It accepts one canonical statement, selects a
deterministic workload through its documented canonical ranking procedure,
requires an exact one-segment result at the requested `po2`, produces one
succinct lift receipt, validates that candidate's complete outer shape, and
only then stages artifacts. That command does not generate join or resolve
receipts; the separate `recursive-candidate-proof` path does. Its outputs MUST
NOT be mixed across guest image IDs, and no individual lift export may be promoted
as a complete KAT corpus for the current
`risc0-v3-succinct` profile. The procedure does not claim a global minimum
workload iteration count. The supplied output root must already exist and be
empty.

The requested `--segment-po2` is the actual final segment exponent proved by
the receipt. It is intentionally distinct from the host-only executor
segmentation ceiling, fixed at `23`. That one-bit headroom above the profile
maximum `22` prevents RISC Zero's instruction-reservation threshold from
splitting an otherwise valid smaller final segment. The ceiling is recorded as
local, non-receipt-bound metadata; it is not a statement field or proof word.

Before any calibration or proving, the command requires an ordinary non-link
statement file, reads it through a 16,543-byte input cap, and parses it as exact
`ErgoStatementV1` bytes:

The non-link, file-type, and before/after length checks are filesystem-hygiene
controls for the sealed reproduction host. They are not an atomic no-follow
boundary against another same-host process replacing a pathname concurrently;
such a process is outside the candidate generator's threat model.

```text
"Ergo.VerifyStark.Statement" || 0x01 ||
chainDomainId[32] || profileId[32] || programId[32] || contractId[32] ||
payloadLength:u32le || applicationPayload[payloadLength] || EOF
```

The fixed prefix is 159 bytes, `payloadLength` is at most 16,384, and no
trailing bytes are accepted. `programId` must equal the pinned
`EIP_0045_GUEST_ID`; `chainDomainId`, `profileId`, and `contractId` remain the
opaque bytes supplied by the statement producer. Validation does not rewrite
the statement, guest input ABI, or receipt journal.

```text
eip-0045-candidate-generator candidate-proof \
  --statement-file statement.bin \
  --segment-po2 18 \
  --output-root empty-output-root
```

Use a minimal 159-byte statement for the first real `po2=15` boundary smoke
test, then the 191-byte, 32-byte-payload conformance statement.
The protocol-level 16,384-byte payload limit does not imply that the largest
statement must fit the smallest supported execution segment.

The command first writes a non-final staging directory, then atomically renames
it to `candidate-proof-export/`. That final directory contains `proof-output/`
and `candidate-proof-output-manifest.json`; the latter inventories every
regular file under `proof-output/` and is excluded from its own inventory by
construction. `candidate-receipt-oracle.bincode` is upstream host
serialization retained only as a reproduction oracle. Generation uses explicit
fixed-integer little-endian bincode options with a one-MiB serialization limit
and refuses to write an encoding above that limit. Producer and checker call
the same codec-and-cap primitive so these settings cannot drift independently.
The raw seal is exported solely through `SuccinctReceipt::get_seal_bytes()`.

`candidate-metadata.json` separates `proofBound` values from
`privateCalibration`, `localExecutionObservation`, and `verification`. Those
three sections are explicitly `receiptBound: false`: they report candidate
local provenance or actions performed by this generator/checker, not facts
authenticated by the receipt journal or claim. In particular,
`explicitLocalProver`, `workReceiptPresent`, and the two verification-result
flags are observations of this run rather than proof statements.

For the two alternate-root-gated negative executions, the generator exposes one
non-configurable witness command:

```text
eip-0045-candidate-generator alternate-root-candidate-proof \
  --statement-file statement.bin \
  --output-root empty-output-root
```

It always proves the `po2=15` lift against a fixed 26-entry control set formed
by omitting the final stock `unwrap_povw` leaf. The resulting root and verifier
parameter digest are exact constants in the generator. Before publication, the
receipt must verify under that fixed alternate authority and must fail under
the stock verifier context specifically because the verifier-parameter digest
differs. Its metadata records
`verificationAuthority: fixed-alternate-control-root-verifier-context`.
This artifact is a valid negative witness only for the two fixed B4 consumers
described below; it is not an initial-profile receipt. The stock
`verify-candidate-export` command deliberately does not admit it. For execution
108, the B4 raw-seal consumer independently verifies its STARK and requires the
late initial-profile root mismatch.

The finalizer authenticates this fixed proof once and reuses it only at
canonical zero-based execution indices 108 and 146. Index 108,
`terminal-inner-root-mismatch--inner-control-root`, selects it as the complete
negative fixture. Index 146,
`resolve-explicit-field-sweep--assumption-receipt-root`, remains a mutation of
case 9 ancestry, not `FixtureSelection`: the authenticated seal replaces only
the assumption-receipt producer. The ancestry consumer may retain the seal's
actual inner root only after independent STARK verification, claim binding, and
terminal binding, and explicit resolve compares that authenticated root to its
requested root. Zero-root self-composition is a distinct conditional rule and
must not be reduced to naive root equality. Physical materialization and
Rust/JVM replay of both executions remain pending.

The closed terminal-fixture producer preserves the historical
`lift-po2-14` ID/path as corpus ABI, but that real slot is stock Poseidon2
Identity over the authenticated case-0 Lift15 receipt. The unchanged guest
cannot produce a successful single-segment Lift14: Lift15 is its minimum and a
forced Lift14 continues, so no real Lift14 KAT is claimed. The unchanged exact
17-control synthetic sweep still covers the excluded Lift14 control.
`allowed-terminal-non-ok` reuses authenticated case-8 ancestry step 0, an exact
`SystemSplit`/no-output continuation rather than a guest error.

Only canonical case 8 carries the private deterministic case-8-domain,
program/statement-bound PoVW job. Its authenticated nonces are exactly 0 and 1
under that job; this is fixture-local conformance identity, not work credit.
The producer authenticates case-0/8/9 semantics, performs no second normal
case-8 Lift, and returns an in-memory derive-first set. Official-campaign
lineage remains a later positive-authority integration gate. This capability
does not close coverage or B4, establish B5/readiness/activation, integrate a
node or mempool, or provide target-runtime evidence.

The `verify-candidate-export` command re-reads a completed export in a fresh
process. It requires the exact expected statement and segment exponent rather
than selecting either from candidate metadata:

```text
eip-0045-candidate-generator verify-candidate-export \
  --export-root output-root/candidate-proof-export \
  --expected-statement statement.bin \
  --expected-segment-po2 18
```

The command requires closed top-level and proof-output file sets, validates the
canonical manifest and metadata against the physical tree, and decodes the
receipt oracle with an explicit one-MiB limit, fixed-integer little-endian
bincode options, strict end of input, and exact re-encoding. It reconstructs the
successful receipt claim both through the pinned upstream types and through a
separate byte-level SHA-256/tagged-struct implementation, requires both paths
to agree, compares every exported identity and raw-seal byte string, applies
the profile-owned shape gate, runs the pinned upstream verifier with development
mode disabled, and snapshots the tree again before returning.

Success reports the verified receipt/proof/export binding separately from all
non-receipt-bound metadata. For the calibration, local-execution, and
verification-observation sections, the command checks only their closed shape
and internal candidate consistency. Their values are not authenticated as
execution provenance by export verification.

This is candidate-export checking only. The bincode receipt is a pinned
upstream reproduction oracle, not a consensus encoding or an input format for
untrusted node traffic. A successful command does not create final KAT,
activation, independence, or freshness evidence.

The cycle fields preserve the pinned upstream `SessionStats` names. For this
runtime, `reservedCycles = totalCycles - userCycles - pagingCycles`; it includes
the fixed 4,113 control rows and power-of-two padding, rather than a separate
receipt-bound workload. Consequently these observations describe one local
execution and must not be copied into the consensus cost schedule as if they
were verifier measurements.
