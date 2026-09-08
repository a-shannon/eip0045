# Reproduction validator

This crate implements format and derivation checks that can be settled before
the final EIP-0045 profile artifacts exist. Its outputs are deterministic; it
does not generate proofs, sign evidence, anchor transactions, or declare a
candidate profile final.

The immutable lock, final expanded corpus-registry and top-level lock artifacts,
exact RISC Zero build, KAT generation, JVM differential verifier, and measured
cost calibration are later gates. Until those gates close, files whose names
contain `.candidate` are non-normative.

The `profile_manifest` module supplies a strict 458-byte Manifest V1 codec. Its
ten typed terminal entries are encoded as
`controlKind:u8 || parameter:u8 || controlId[32]`: eight lift entries for
parameters 15 through 22, followed by join and resolve entries whose reserved
parameter is zero. It deliberately separates generic V1 grammar, pre-B3
conformance to the selected initial RISC Zero target, domain-separated
artifact-envelope checks, and activated-style package validation by an
externally authorized `profileId`. The latter never calls the pre-B3
target-table checker: once a transition authorizes an identity, the retained
raw manifest bytes and their artifact commitments are the runtime authority.
The terminal allowlist authenticates only the outermost code root and is not a
recursive ancestry grammar.

`schema/b4-corpus-v1.candidate.json` is the closed B4 registry skeleton. It
fixes the ordered eleven-case positive inventory, including explicit-root
terminal resolve and zero-root resolve-before-join, and the finite nine-class
negative inventory. Post-B3 identities remain exact empty `pending` slots
until the rebuilt guest, statement bundle, source lock, generator, both
verifiers, canonical negative plan, detached-subject catalogue, and terminal
fixture catalogue exist. The canonical plan contains exactly 63 ordered groups
and 254 concrete executions, including 36 distinct authoritative parser cut
positions. A populated registry must switch atomically to `expanded`, bind
every slot, provide the complete per-case artifact roles, and map every
negative row byte-for-byte to exactly four fields: `executionId`,
`baseSelectorId`, `materializationDomain`, and `materialization`. The
materialization is either one closed mutation recipe or selection of a
separately authenticated terminal fixture. Exactly ten plan executions use
that fixture-selection path rather than mutation. Byte edits carry an
authenticated pre-edit witness and
concrete offset or truncation boundary. Sequence insertion and replacement
carry the complete new element (`elementId`, `bytesHex`, and `sha256`);
omission and movement authenticate both the exact existing ID and digest. A
sequence move removes `fromIndex` first and inserts the element at `toIndex`
in the shortened sequence, making `toIndex` the final index. A left-to-right
boundary shift prepends the exact suffix of the left chunk to the right chunk;
a right-to-left shift appends the exact prefix of the right chunk to the left.
Reconstruction requires `byteCount > 0`, keeps the donor nonempty, and
preserves both chunk count and concatenated proof bytes.

V1 admits exactly five catalogue-derived detached sequence targets:
`registry-positive-cases`, `registry-negative-cases`,
`registry-negative-classes`, `profile-package-files`, and `proof-chunks`.
Two additional targets, `registry-negative-bindings` and
`abstract-tree-probe`, are synthetic validator-only subjects and are not
catalogue entries. Each catalogue-derived base is an exact
`Eip0045B4SequenceSubjectV1` RFC 8785 envelope containing the target and its
ordered elements. Registry and profile element bytes must themselves be exact
RFC 8785 JCS; proof-chunk elements decode to the raw chunk bytes. Element IDs
are bounded canonical lower-kebab ASCII and unique within the base,
hexadecimal is lowercase and bounded, and every element digest is recomputed.
The live-derived `Eip0045B4SubjectCatalogV1` contains exactly 15 detached
subjects: the positive and negative registry projections, the negative-class
projection, the profile-package projection, and one proof-chunk projection
for each of the eleven positives. Each plan execution binds its exact
`baseSelectorId`; catalogue-backed sequence executions select one of those
subject IDs. The materialization identity repeats that selector so a detached
witness cannot silently move between subjects. The envelope and its hash do
not establish source provenance by themselves. Before `expanded` can
activate, the global semantic gate must deterministically project each
catalogue-derived subject from the owning registry, profile package, or
positive export and byte-compare that projection with the catalogued base.
The two synthetic validator-only subjects must likewise be reconstructed from
their independently defined validator baselines.

`b4_mutation` applies every byte or sequence operation from exact base bytes,
authenticates all witnesses and ranges, and returns the complete result (raw
bytes for byte edits, canonical subject JCS for sequence edits). The canonical
`Eip0045B4MaterializationIdentityV1` binds the canonical plan, exact
four-field registry row, canonical materialization recipe, materialization
domain, and exact base and output lengths and SHA-256 digests. Identity
verification replays the recipe through the domain adapter and compares the
complete output bytes. For the ten fixture-selection executions, terminal
bytes must first pass
`Eip0045B4TerminalFixtureCatalogV1::validate_raw_seal_artifacts`; only then are
the selected bytes passed to `B4FixtureSelectionReplayAdapterV1` for binding
and replay. The adapter does not authenticate fixture provenance by itself.
The catalogue-less API remains fail-closed and never fabricates bytes.

`Eip0045B4ValidationResultV1` separately binds one implementation's typed
validation result to the materialization identity and the plan-owned
validation surface and QA result. The materialization identity and validation
result contain no paths, hosts, timestamps, raw error strings, or archive of
the materialized output.

`Eip0045B4NegativeMaterializationSetV1` is the public projection of the
feature-gated negative-materialization closure. The historical authority
constructor requires five inputs: the campaign, positive-generation, and
ancestry opaque authorities, the ancestry-publication root, and external
inputs. It remains exact at `218/254`. A separate Linux descriptor-rooted
constructor additionally requires the opaque terminal-evidence import
authority and an ancestry directory descriptor. Its terminal-aware dispatcher
adds exactly rows `11..=13`, `110..=112`, and `131..=139`, reaching `233/254`.
Rows `108` and `140..=159` remain unavailable, so neither constructor can emit
the authority. The handoff owns the bytes returned by authenticated reopened
reads of the 24-file publication set. Public V1 exposes ten pathless
commitments plus the required path-aware ancestry-catalogue identity. Final
publication revalidation occurs only after private assembly of all 254 rows
and is point-in-time: it provides no post-return freshness or snapshot
guarantee and no durability, runtime-readiness, proof, or archive evidence.

`Eip0045B4SemanticReportV1` is currently a structural format: callers can
serialize and parse its closed local shape, but that value confers no campaign
authority. Its former caller-supplied adapter rebuild path is test-only. A
production authority/finalizer constructor remains unavailable until it can
consume the opaque campaign-precommit, positive-generation,
negative-materialization-set, and 508 physical-run authorities.

The same fail-closed boundary applies to terminal-lock creation: lock values
can be parsed structurally, but the legacy raw-report create/rebind helpers are
test-only until an authoritative semantic report exists.

No-op edits, impossible ranges, open mutation selectors, surrogate sequence
targets, wildcards, templates, unknown nested fields, unknown classes,
missing or reordered positives, family/mode/root drift, final vector or lock
paths, self-inclusion, duplicate paths, path-redirection links, and unbounded
files reject. Non-redirecting Windows cloud/recall metadata is not treated as
a link. Mutated verifier inputs are reconstructed deterministically in memory;
the corpus archives the canonical materialization identity and each
implementation's separate typed validation result, not a second
unauthenticated copy of the resulting input. This revision deliberately
rejects the `expanded` lifecycle even when its structural fields are
populated: that transition stays fail-closed until the global Rust/JVM
semantic validator reconstructs every materialization and checks every B3,
statement, claim, positive, and isolated-negative binding. B7 run evidence is
outside this grammar.

Validate the canonical registry and every currently bound physical artifact
from the repository root with:

```text
cargo run --manifest-path reproduction/Cargo.toml --locked -- \
  b4-corpus-check --repo-root .
```

The pinned Dockerfile is an inspectable base-image commitment, not proof that
the image is locally available or that a hermetic build has completed.

## B4 positive-acceptance contract

The positive phase is specified by nine closed RFC 8785 JCS formats:

- `finalizer-schema/b4-positive-input-set-v1.schema.json`;
- `finalizer-schema/b4-positive-generation-set-v1.schema.json`;
- `finalizer-schema/b4-validator-build-descriptor-v1.schema.json`;
- `finalizer-schema/b4-jvm-copy-only-inclusion-manifest-v1.schema.json`;
- `finalizer-schema/b4-positive-oci-runner-profile-v1.schema.json`;
- `finalizer-schema/b4-positive-seccomp-v1.schema.json`;
- `finalizer-schema/b4-positive-verifier-input-v1.schema.json`;
- `finalizer-schema/b4-positive-observation-v1.schema.json`; and
- `finalizer-schema/b4-positive-acceptance-v1.schema.json`.

`docs/specs/b4-verifier-cli-v2.md` defines their authority boundaries and the
fixed verifier CLI. The exact B4-only OCI/seccomp and JVM/JAR subsets are in
`docs/specs/b4-oci-execution-policy-v1.md` and
`docs/specs/b4-jvm-artifact-policy-v1.md`. In particular, the finalizer owns
four runner profiles; validator descriptors commit to those profiles but
cannot select or override
their image, runtime, seccomp, namespace, mount, Java, or resource policy. A
verifier receives only the six cryptographic file identities and never receives
the input-set identity, case plan, expected terminal, implementation identity,
or acceptance record.

The Rust descriptor retains one reproducible build step. The JVM descriptor has
two phase-major steps: two fresh application-intermediate builds must first
agree with the bound `applicationInput`, then two further fresh COPY-ONLY
packaging runs consume only a newly staged, read-only `/phase-input` tree. The
packager executable and its seven ordered arguments are exact descriptor and
toolchain bindings; the packaging phase receives no source-tree or broad
dependency mount. See the two policy documents above for the canonical staging
layout, fresh-instance rules, and output equalities.

The proof generator is bound differently because it produces candidates rather
than an acceptance decision. The input set carries a closed projection derived
from an authoritatively checked dual-build archive and a fixed fresh-process,
network-disabled generation/replay policy. It has no opaque build descriptor or
machine-specific resource schedule; every generated proof remains untrusted
until physical replay, generation-set binding, and both verifier runs succeed.

`b4_positive_gate` is the executable schema and cross-document semantic layer.
Its `PositiveGateBindings::validate_and_bind_jcs` entry point parses exact
canonical bytes and validates every document against its embedded Draft
2020-12 schema. It then checks commitments, fixed role order,
descriptor/profile/seccomp references, OCI and JAR cross-field relations,
bounded and ordered inventories, the fixed build environment, implementation
non-alias metadata, and the absence of provenance authority in the verifier
input.

The input set is pre-proof. After the generator has produced and strictly
replay-verified all eleven physical exports, `bind_generation_set` consumes the
post-proof generation set plus the exact proof-generator and exported artifact
bytes. It reconstructs every proof-output manifest, binds the three recursive
calibrations, and rejects case drift or any reused manifest or raw seal. No run
can be semantically admitted before that phase succeeds.

The next closed phase reconstructs all 254 negative materializations and
publishes their exact ordered set create-only. No qualifying negative launch is
admitted before that complete set binds the precommit, positive generation
authority, source documents, neutral inputs, contexts, and roots. This keeps
receipt-independent cases from becoming an alternate early execution path.

`validate_run` then binds one finalizer-selected case and implementation to
caller-supplied physical measurements, the launched artifact and, for JVM runs,
the exact Java binary plus its exact `release` file. It requires the archived
observation to equal the independently derived semantic observation
byte-for-byte. The differential
gate requires Rust and JVM to use identical verifier-input and observation
bytes while retaining distinct implementation attribution. The eleven-case
suite preserves all twenty-two exact acceptance SHA-256 values in fixed order
and rejects any reuse.

This module is not a generator-replay attestor or finalizer executor. Its output
tokens prove schema conformance and only the semantic relationships checked in
the module; caller-supplied measurements remain trusted inputs. The finalizer
remains responsible for invoking the strict generator replay paths, safe
bounded OCI/JAR/ELF/Git parsing, fresh filesystem materialization, static
`runc` launch, namespace/seccomp/cgroup enforcement, process-tree supervision,
create-only publication, and trustworthy no-follow physical measurements.
Until that executor and the complete positive and negative evidence are
implemented and independently reviewed, the gate is an executable contract
component rather than B4 completion evidence.

## B4 build-archive validation

`b4-build-check` validates the archive properties that can be recomputed from
the final bytes: closed paths and hashes, equality of the two run trees,
within-run before/after/final snapshots, canonical candidate source locks,
materialized-source agreement, Cargo metadata/closure policy, the complete
build identity record, image-ID representations, and the downstream statement
identity chain.

Invocation without either an explicit inspection flag or the complete external
anchor set is rejected. Inspection-only validation is requested explicitly:

```text
cargo run --manifest-path reproduction/Cargo.toml --locked -- \
  b4-build-check --root <archive> --allow-unanchored-inspection
```

It reports `providedDigestMatched=not-provided`, `sourceBinding=unbound`, and
`runnerClaims=unattested`; every unparsed artifact is classified as
`opaque-hash-bound`. A final archive cannot by itself prove that two commands
ran, that their paths and seeds were fresh or disjoint, that the recorded
container controls were used, that tests executed, or that publication was
historically create-only.

Authoritative validation is Unix-only and requires all three caller-owned
anchors together. Windows supports explicit unanchored inspection only because
the standard library does not expose the stable device/inode/link-count binding
used by this checker:

```text
cargo run --manifest-path reproduction/Cargo.toml --locked -- \
  b4-build-check --root <archive> \
  --expected-source-commit <40-lowercase-hex> \
  --expected-source-tree <40-lowercase-hex> \
  --expected-evidence-root <64-lowercase-hex>
```

The evidence root is computed as:

```text
SHA256(
  "EIP0045-B4-EVIDENCE-ROOT-V1\0" ||
  SHA256(B4-COMPLETE) ||
  SHA256(evidence-manifest.txt)
)
```

The expected root must be retained outside the archive. A non-circular
publication freezes the builder commit first, creates the archive from that
commit, and records the resulting root in a later signed or otherwise
independently retained commitment. Anchoring prevents later archive rebinding;
it does not attest the runner's execution history.

`preflight-proof-output` requires a physically empty export root immediately
before generation. `manifest-proof-output` then hashes the post-generation tree
twice and rejects inconsistent snapshots. For real B7 evidence the generator
must have exited and the export tree must be sealed against writers; these
checks detect accidental races but do not defend against a malicious process
coordinating path substitutions on the same host.
