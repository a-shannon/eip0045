# EIP-0045 B4 verifier CLI V2

**Status:** Candidate specification

**Interface:** `eip0045-b4-verifier-cli-v2`

**Format family:** `Eip0045B4Positive*V1`,
`Eip0045B4Negative*V1`, and the bound COPY-ONLY JVM packaging manifest

## Purpose and formats

This contract gives the reference Rust verifier and the JVM-lineage verifier
candidate (wire identifier `independent-jvm`) one authority-minimal interface
for both the eleven B4 positive cases and the 254 isolated negative
materializations. It separates pre-proof provenance, cryptographic and
structural validation, process outcomes, and trusted attribution so that no
verifier can attest its own identity or receive an expected claim, terminal,
QA result, verdict, rejection class, or rejection stage.

The positive contract retains these nine closed JSON formats:

- `Eip0045B4PositiveInputSetV1`, specified by
  `reproduction/finalizer-schema/b4-positive-input-set-v1.schema.json`;
- `Eip0045B4PositiveGenerationSetV1`, specified by
  `reproduction/finalizer-schema/b4-positive-generation-set-v1.schema.json`;
- `Eip0045B4ValidatorBuildDescriptorV1`, specified by
  `reproduction/finalizer-schema/b4-validator-build-descriptor-v1.schema.json`;
- `Eip0045B4JvmCopyOnlyInclusionManifestV1`, specified by
  `reproduction/finalizer-schema/b4-jvm-copy-only-inclusion-manifest-v1.schema.json`;
- `Eip0045B4PositiveOciRunnerProfileV1`, specified by
  `reproduction/finalizer-schema/b4-positive-oci-runner-profile-v1.schema.json`;
- `Eip0045B4PositiveSeccompV1`, specified by
  `reproduction/finalizer-schema/b4-positive-seccomp-v1.schema.json`;
- `Eip0045B4PositiveVerifierInputV1`, specified by
  `reproduction/finalizer-schema/b4-positive-verifier-input-v1.schema.json`;
- `Eip0045B4PositiveObservationV1`, specified by
  `reproduction/finalizer-schema/b4-positive-observation-v1.schema.json`; and
- `Eip0045B4PositiveAcceptanceV1`, specified by
  `reproduction/finalizer-schema/b4-positive-acceptance-v1.schema.json`.

Every instance is UTF-8 RFC 8785 JCS without a byte-order mark. Unknown fields,
duplicate keys, noncanonical encodings, and trailing bytes are invalid.
The closed OCI and JVM artifact subsets are specified separately by
`docs/specs/b4-oci-execution-policy-v1.md` and
`docs/specs/b4-jvm-artifact-policy-v1.md`.

The negative and campaign formats are specified by their exact schemas under
`reproduction/finalizer-schema/`. Their verifier-visible subset consists only
of `Eip0045B4NegativeVerifierInputV1` and
`Eip0045B4NegativeObservationV1`. The negative plan, expectation set,
materialization identity, attributed result, semantic report, verifier
contract, campaign-executor contract, and campaign precommit remain
finalizer-side authorities and are never mounted into a validator root.

## Authority separation

The finalizer maintains four disjoint surfaces:

1. The provenance root contains the pre-proof input set, the post-proof
   generation set, four finalizer-owned
   OCI runner profiles, generator material, validator descriptors and binaries,
   reviewed source trees, build closures, calibrations, ancestry, metadata, and
   receipt oracles. A verifier never receives this root.
2. One fresh positive-verifier root contains only the seven regular files
   listed below.
   It contains no case plan, expected terminal, calibration, ancestry, metadata,
   oracle, receipt wrapper, build descriptor, source tree, validator identity,
   acceptance record, or resolvable provenance path.
3. One fresh negative-verifier root contains only `negative-input.json` and the
   exact subject and context files named by that input. It contains no negative
   plan, expectation set, materialization identity, QA code, implementation
   identity, attributed result, or resolvable provenance path.
4. The create-only acceptance and negative-result archives are written by the
   finalizer after process and semantic validation. A verifier cannot write
   into either archive.

The positive verifier input carries only the exact identities of the six
cryptographic input files. It does not carry the input-set identity. The
finalizer alone maps those identities to the pre-proof document outside the
verifier root and later binds independent, pathless commitments to both the
input set and generation set in each acceptance record. The negative verifier
input likewise carries only neutral dispatch and physical identities. Thus
neither validator can select or attest the provenance root.

## Pre-proof input set

One `Eip0045B4PositiveInputSetV1` is created after the deterministic guest,
complete B3 profile, statement, generator, CLI contract, four runner profiles,
validator descriptors, reviewed builds, source lock, and recursive calibrations
are fixed, and before any of the eleven receipts is proved.

The input set binds exactly two validator descriptors in canonical order: one
Rust reference implementation and one independent Scala/JVM implementation. It
also binds exactly four runner-profile documents in canonical order:
`rust-validator-build`, `jvm-validator-build`, `rust-validator`, and
`jvm-validator`, at indices zero through three respectively. A runner
profile is selected by this input-set order and finalizer policy, never by
untrusted descriptor contents alone. The input set contains exactly the eleven
case declarations in canonical order. It contains
no raw-seal identity, proof digest, verifier input, observation, verdict, or
acceptance record.

The case `artifactRoles` arrays prescribe the future proof-export inventory.
They are ordered labels only and contain no artifact path, length, digest,
bytes, or result:

- each lift prescribes `claim-digest`, `control-id`, `image-id`, `journal`,
  `metadata`, `raw-seal`, and `receipt-oracle`;
- each recursive case prescribes `ancestry`, `calibration`, `claim-digest`,
  `control-id`, `image-id`, `journal`, `raw-seal`, and `receipt-oracle`.

Lift `metadata` is a post-execution audit view. Recursive `calibration` is a
pre-proof input and must be freshly rederived before proving and archive replay.
`ancestry` is non-consensus provenance. None is cryptographic verifier input or
authority for a claim, terminal, or control ID.

## Proof-generator build and execution boundary

The proof generator has no opaque build-descriptor escape hatch. Its input-set
binding contains the exact executable plus a closed
`eip0045-b4-qualifying-build-binding-v1` projection. Before creating the input
set, the finalizer runs the strict B4 build checker in authoritative mode on the
complete dual-build archive, with the externally retained evidence root,
source commit, and source tree. Unix file-identity binding is mandatory. The
finalizer derives, rather than trusts, the projection's evidence root, source
commit/tree, source-lock digest, generator Cargo-closure digest,
proof-generation-test digest, and generator artifact length and digest. The
projected source-lock digest must equal the input set's source-lock identity,
and the projected generator identity must equal the physically copied
executable. Both qualifying build runs must contain that same executable.

The adjacent `eip0045-b4-proof-generation-executor-v1` policy fixes case order,
disables network and inherited environment, forbids generator or replay process
reuse, requires a pre-existing read-only input set, gives each generation a
fresh empty create-only output root, mounts each replay export read-only, and
publishes nothing after a failed case. Generation and strict replay are
separate fresh processes.

The generator is deliberately not granted a fifth validator runner profile.
It produces untrusted candidate bytes; those bytes become admissible only after
strict physical replay, generation-set binding, and agreement of the two
separately attributed cryptographic verifier implementations. Generator CPU,
memory, and wall-time
ceilings are therefore local operational controls rather than portable corpus
authority. This avoids freezing machine-specific proving resources into the
verification contract while keeping the security-relevant isolation and
provenance fixed.

## Post-proof generation set

The finalizer publishes the input set with create-new semantics before invoking
the proof generator. It then generates each of the eleven exports in case order
and replays the complete physical export with the generator's strict
`verify_candidate_export` or `verify_recursive_candidate_export` path. The
expected lift exponent or recursive family comes from the already frozen input
set; export metadata never selects it.

Only after all eleven replays pass does the finalizer create one
`Eip0045B4PositiveGenerationSetV1`. It commits pathlessly to the exact input-set
bytes and proof-generator artifact, then records for each case the exact
proof-output manifest, ordered physical artifacts, statement journal, image ID,
claim, terminal control, calibration identity where applicable, and raw seal.
The finalizer reconstructs every proof-output manifest from the physical bytes,
requires exactly the planned role/filename layout, and requires all eleven
manifest digests and all eleven raw-seal digests to be distinct.

No validator run or acceptance is admitted before this generation set is bound.
Every later acceptance commits to its exact bytes. Internal commitments prove
consistency, not chronology: the pre-proof ordering is established by the
finalizer's create-only custody and, for qualifying B7 evidence, an externally
retained pre-generation input-set anchor. A coordinated after-the-fact rewrite
without that custody evidence is not qualifying execution history.

## Validator build descriptors

Each validator is bound by one
`Eip0045B4ValidatorBuildDescriptorV1`. The closed descriptor binds:

- implementation identity and language;
- an implementation-lineage declaration;
- the reviewed source repository, commit, Git tree, and source archive;
- canonical dependency and toolchain closures;
- an offline, fresh-output, byte-reproducible build recipe;
- the exact native executable or executable-JAR identity and closed inspection
  record;
- the fixed dual-surface verifier interface and direct positive entrypoint; and
- exact commitments to the finalizer-owned build and execution runner profiles.

The finalizer first hashes and parses the four profiles named by the input set.
It then hashes and parses the descriptor named by each validator entry, requires
the entry's index, implementation, and language to match the descriptor, and
requires each descriptor profile reference to equal the corresponding input-set
artifact identity exactly. A descriptor cannot supply or override the OCI
image, OCI runtime, seccomp policy, namespaces, mounts, resource limits, Java
runtime, or fixed process environment. Its environment projection is empty; it
can add only the closed build recipe. Every referenced identity is validated
below the provenance root before use.

The Rust and JVM descriptors must differ in descriptor SHA-256, launched
artifact SHA-256, reviewed source `(repository, commit, tree)` tuple, source
archive SHA-256, lineage SHA-256, implementation language, and entrypoint kind.
Equality in any one of those independence fields rejects the pair. Shared
schemas, wire-format fixtures, and the CLI contract are allowed; shared
verifier implementation lineage is not.

Distinct hashes and the lineage declaration are necessary bindings, not a
mathematical proof of independent authorship. The required independent final
review must compare both materialized source inventories and delegation
surfaces. The Rust validator must be a static ELF without a program interpreter.
The JVM artifact is launched in `jar-only` classpath mode and must pass the
versioned JAR policy. That inspection rejects native-library payloads, native or
process-launch symbolic references, malformed class files, nested executable
formats, executable scripts, agent-launch manifest attributes, signed-JAR
surfaces, and unscanned non-class entries. It establishes complete archive
structure plus direct symbolic-reference and byte-signature coverage. It does
not establish absence of reflective, generated-bytecode, encoded/assembled, or
resource-driven delegation; those remain explicit source-review obligations.
The complete image/rootfs and every traversed executable path are independently
bound by the runner profile. No claim is made that the image or Java runtime is
minimal, or that image identity alone proves implementation lineage.

The descriptor's artifact path is the launched file. The Rust build recipe
contains one exact, hash-bound executable/argv step and runs it twice in fresh
containers and output roots. Here and below, "direct" means that the finalizer
inserts no shell or wrapper; executable semantics are not inferred from the
path basename. The JVM recipe instead contains the two ordered direct phases
`application-intermediate` and `copy-only-packaging`. The finalizer completes
and compares both fresh application-phase repetitions against
`packaging.applicationInput` before launching either of the two further fresh
packaging repetitions. The latter receive only the exact read-only
`/phase-input` layout and exact seven-argument packager vector defined by
`b4-jvm-artifact-policy-v1.md`; their outputs must equal both the inclusion
manifest output and descriptor artifact identities. No `runc exec`, supervisor,
shell, container, output root, or packaging input root survives or is reused
between applicable repetitions. Timeout, cgroup, capture, and output quotas
apply independently to every invocation. Both implementations adapt to the same
verifier CLI; neither may use a wrapper to satisfy it.

## Positive-verifier root and input

For each positive case, the finalizer creates a new empty root and copies
exactly these seven regular, non-linked files with create-new semantics:

```text
verifier-input.json
profile-manifest.bin
profile-algorithm.txt
profile-constants.bin
guest.elf
statement.bin
raw-seal.bin
```

There are no directories or additional entries. Before launch and after process
exit, the finalizer enumerates the root, rejects missing or extra names, and
rechecks every byte length and SHA-256. It rejects symbolic links, reparse
points, hard-link aliases, non-regular files, path replacement, and any file
whose identity changes during execution.

The execution platform is fixed to Linux amd64. The host verifier root is
allocated below a neutral finalizer-owned staging root; every run-specific path
component is opaque and contains no case ID, index, family, terminal, or
provenance label. It is mounted read-only at `/input`, so the fixed in-container
argument vector contains only `/input` and `verifier-input.json`. Environment
inheritance is disabled; the runner profile supplies exactly
`LANG=C.UTF-8`, `LC_ALL=C.UTF-8`, and `TZ=UTC`. No argv,
environment value, filename, or verifier-readable file discloses a case label,
expected terminal, or expected profile, image, program, statement, or claim
value beyond the identities and bytes of the six actual cryptographic inputs.

`Eip0045B4PositiveVerifierInputV1` contains only the exact identities of the six
cryptographic files. Its filenames are fixed by schema.
It contains no case ID or index, expected verdict, profile ID, program ID, claim
digest, terminal, control ID, validator identity, build descriptor, or external
path. The finalizer may invoke the same canonical verifier-input bytes with
both validators.

## Negative-verifier root and input

For each negative execution and implementation, the finalizer creates a fresh
empty root. It copies `negative-input.json`, exactly one `subject.bin`, and an
exact positional prefix of zero to 64 context files:
`context/00.bin`, `context/01.bin`, ..., `context/63.bin`. The `context`
directory exists only when the prefix is nonempty. No other filename or
directory is admitted. Every declared file is a regular non-linked file
created without replacement; no undeclared file, directory, link, reparse
point, device, socket, or alias is admitted.

Before launch and after process exit, the finalizer recursively enumerates the
root, rejects any missing or extra path, and remeasures the length and SHA-256
of `negative-input.json`, the subject, and every context file. It opens files
without following links, retains the validated handles through import, and
rejects path replacement, hard-link aliases, cross-root aliases, or byte drift.
The two implementations receive separately staged roots whose canonical input
and declared file bytes are byte-identical.

`Eip0045B4NegativeVerifierInputV1` contains only the materialization domain,
validation surface, and positional physical identities. The subject role and
path are exactly `subject` and `subject.bin`. Context position `i` has exactly
role `context-i` padded to two decimal digits and path
`context/i.bin` with the same padding. Every declared file uses the
non-semantic `raw-bytes` encoding. These fixed positions eliminate arbitrary
role and path channels; the parser additionally rejects duplicate paths,
`negative-input.json` or any descendant of it, and every
ancestor/descendant relationship between declared file paths. The input
contains no execution or case ID, implementation role, plan or registry
identity, materialization recipe or identity, QA result code, expected verdict,
expected rejection, validator descriptor, or external path.

Only the twenty domain/surface pairs present in the canonical negative plan
are admitted: eight verifier-input surfaces, eleven artifact-validator
surfaces, and tree-validator/corpus-closure. The zero-to-64 prefix is only the neutral
format bound. Before the verifier contract or campaign precommit can be
closed, the reviewed Rust and JVM handlers must freeze one exact context
cardinality for each of all twenty pairs. The pre-proof authority constructor
fails closed while that table is incomplete, duplicated, out of range, or
does not match the selected pair.

The validator parses and validates `negative-input.json` before reading any
declared file. It then independently remeasures each file and refuses a
missing, extra, aliased, changed, incorrectly encoded, or incorrectly ordered
input before invoking the selected closed validation surface. No subject or
context file may select a validation surface or provide an expectation.

## Complete B3 envelope validation

The verifier must validate the complete closed profile envelope, not only the
manifest:

- `profile-algorithm.txt`: exactly 29,773 bytes, SHA-256
  `90a884da420a09f2c1108d7388c2ac74db8dbdb195de704206e2bf8ec1ad0bee`;
- `profile-constants.bin`: exactly 65,119 bytes, SHA-256
  `8c4a92b7d354890481eefdef233d4ca43f6bcd9f7cb00e4dd9e709da47789ef3`;
- `profile-manifest.bin`: exactly 458 bytes, SHA-256
  `deffb2cb231f98a348cbd166d5f1c43315661ccd8bd212099f16f238d0fe8946`;
  and
- profile ID
  `23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383`.

The verifier authenticates the exact B1 bytes by their fixed length, SHA-256,
ASCII/LF form, and manifest binding; parses and re-encodes the B2 constants and
Manifest V1 envelope; checks all manifest lengths, hashes, typed controls,
roots, and cross-references against the supplied B1/B2 bytes; constructs the
exact 485-byte profile-ID preimage; derives its BLAKE2b-256 profile ID; and
requires that value in the statement. An absent, extra, substituted, partially
checked, or internally inconsistent profile artifact rejects before proof
acceptance.

The verifier then derives the program ID from the bounded ELF, validates the
exact statement, derives the successful empty-assumption claim, consumes the
222,668-byte seal through EOF, recovers the verified terminal control ID, maps
it to exactly one typed profile terminal, and completes cryptographic
verification. No case label or provenance artifact selects those values.

## Exact launch

The finalizer resolves input-set, profile, and descriptor paths only below the
provenance root. Every
path is lowercase normalized ASCII and must reject a trailing slash, a trailing
dot in any segment, empty segments, `.` or `..` segments, and the Windows
device basenames `con`, `prn`, `aux`, `nul`, `com1` through `com9`, and `lpt1`
through `lpt9`, with or without an extension. Absolute paths, links, reparse
points, hard-link aliases, non-regular files, and escapes from the provenance
root reject.

Before any build or verification, the finalizer validates all cross-document
semantics that JSON Schema cannot express:

- the four runner profiles occur exactly once in their fixed role/index order;
- every descriptor profile commitment equals the corresponding input-set
  artifact identity, and the acceptance profile commitment equals both;
- lineage paths, dependency keys, toolchain keys, and artifact paths are
  strictly ordered and unique under their canonical key;
- descriptor build environments contain no variables, and every role uses only
  the fixed three-variable runner environment;
- the Rust build output path equals its descriptor artifact path; the JVM
  application and packaging phase outputs respectively bind
  `packaging.applicationInput` and the descriptor artifact, and the packaging
  input layout and argument vector equal the closed runner and JAR policies;
- each closure digest is rederived from its canonical inventory; and
- each reviewed Git bundle contains the declared commit, that commit resolves
  to the declared tree, and the materialized source inventory matches it.

Materialized source and dependency roots reject symlinks, hard-link aliases,
gitlinks/submodules, special nodes, nested mounts, unbound files, and archive
escapes. A toolchain or Java image path may traverse only an image-internal
symlink chain whose every hop remains in the already bound rootfs; the final
target must be one regular file and its bytes must match the declared identity.
The finalizer hashes the resolved target, never a link's textual payload.

Git-tree source paths are portable ASCII but remain case-sensitive, so normal
Scala/Java class filenames are preserved. Finalizer-created archive paths remain
lowercase. The finalizer applies the dot, parent, trailing-dot, and
case-insensitive Windows-device checks to both path classes.

Each profile binds one archive under the B4-specific OCI image-layout ustar
policy, the selected manifest/config/platform, ordered compressed-layer and
DiffID tuples, the rederived post-changeset rootfs inventory, one static amd64
ELF `runc`, and one separately hashed canonical seccomp document. The exact
Image Specification 1.1.1 and Runtime Specification 1.3.0 commit pins, archive,
gzip, layer, whiteout, symlink, ownership, mount-target, rootfs, and seccomp
rules are normative in `docs/specs/b4-oci-execution-policy-v1.md`. This is a
closed B4 importer, not a generic OCI compatibility claim.

The finalizer parses, hashes, inflates, applies, and remeasures the complete
archive before launch. It requires the runner's seccomp syscall projection to
equal the separately supplied wrapper exactly and inserts only that wrapper's
`linuxSeccomp` member into the runtime configuration. A missing parser,
unsupported syscall, unavailable kernel control, digest/DiffID mismatch, or
isolation failure refuses the run; it never widens or repairs the profile.

The finalizer constructs the OCI configuration and command; no
descriptor-provided command string, shell, script, launcher, shim, or wrapper
is accepted:

```text
/validator/validator verify-positive --root /input --input verifier-input.json
/runtime/bin/java <bound-jvm-options...> -jar /validator/validator.jar verify-positive --root /input --input verifier-input.json

/validator/validator verify-negative --root /input --input negative-input.json
/runtime/bin/java <bound-jvm-options...> -jar /validator/validator.jar verify-negative --root /input --input negative-input.json
```

Both subcommands must be implemented by the same exact artifact named by one
build descriptor. The descriptor's direct `verify-positive` entrypoint anchors
positive acceptance; its `eip0045-b4-verifier-cli-v2` interface and the bound
verifier-contract manifest make `verify-negative` mandatory. The negative
input supplies only neutral domain/surface dispatch and exact subject/context
identities. It contains no plan execution ID, implementation role, QA code, or
expected rejection.

The finalizer ignores ambient OCI defaults and uses the profile's read-only
rootfs, non-root UID/GID, private mount/PID/IPC/UTS/user namespaces,
`private-empty-loopback-down-no-address-no-route` network policy,
no capabilities, `no_new_privs`, closed stdin, bounded stdout/stderr, one fresh
bounded `/tmp`, a private `/proc`, a private empty network namespace with
loopback down and no interface or route, and only the prescribed mounts.
`/dev` contains only exact bind mounts of the host `null`, `zero`, `full`,
`random`, and `urandom` pseudodevices; no other host device is passed through.
The user namespace maps only container UID/GID 65,532 to the finalizer's own
effective UID/GID after denying supplementary groups. If any isolation,
seccomp, cgroup v2,
resource-limit, or post-destroy inspection primitive is unavailable, the run is
refused rather than weakened.

Immediately before launch and after exit, the finalizer rehashes the OCI
archive, `runc`, seccomp document, mounted Rust executable or JVM JAR, and all
verifier inputs. For the JVM profile it also hashes `/runtime/bin/java` in the
staged rootfs, derives and matches its vendor and version, and supplies the
exact nine-option vector. Options that inject Java or native agents, change a
boot or application class path, or select another entrypoint are forbidden.
Hash drift, path drift, a wrapper, a different Java runtime, a policy mismatch,
or an option mismatch rejects at attribution before any acceptance record is
created. After the run, the container, cgroup, bundle, rootfs, and tmpfs are
destroyed and their absence is checked.

Before a JAR can be launched, the finalizer applies
`docs/specs/b4-jvm-artifact-policy-v1.md` to the exact physically measured JAR
bytes and compares every derived archive, manifest, class-file, non-class, and
analysis-boundary field with the descriptor. The policy performs bounded
streaming decompression and full local-header/central-directory/CRC/size/EOF
checks, parses every class file through EOF under Java SE 21, and scans every
non-class regular entry. Extraction is unnecessary for attribution. The
finalizer likewise parses the Rust ELF and requires amd64, static linkage, and
no program interpreter.

## File and field bounds

An input set, generation set, runner profile, seccomp document, or validator
build descriptor is at most 1,048,576 bytes. A positive verifier input,
positive observation, or acceptance record is at most 65,536 bytes. A negative
verifier input is at most 65,536 bytes; a negative observation is at most 4,096
bytes; it names one subject, at most 64 context files, and no file larger than
536,870,912 bytes. One inventoried source file is at most 16,777,216 bytes, and
one dependency/lock artifact is at most 268,435,456 bytes. A reviewed Git
bundle, validator artifact, `runc` binary, or Java binary is at most
1,073,741,824 bytes. An OCI
image-layout archive is at most 17,179,869,184 bytes and may
materialize at most 34,359,738,368 rootfs bytes, 1,000,000 entries, and 128
layers. The guest ELF
is at most 4,194,304 bytes, the statement is 159 through 16,543 bytes, and the
raw seal is exactly 222,668 bytes. Paths are at most 240 ASCII bytes, Java
vendor/version fields are at most 128 bytes, and the JVM option vector is the
exact nine-entry sequence fixed by schema.

The finalizer additionally enforces derived aggregate ceilings before mounting:
at most 536,870,912 source-inventory bytes, 8,589,934,592 dependency-closure
bytes, and 8,589,934,592 toolchain-inventory bytes. A JAR has at most 65,534
entries and 1,073,741,824 total uncompressed bytes; each entry is also bounded
by 1,073,741,824 uncompressed bytes. These are finalizer limits, not
self-declared allocation authority; all declared totals are rederived before
use.

The finalizer checks declared length before allocation, performs bounded reads,
requires EOF, computes SHA-256 while reading, and rejects a file that grows,
shrinks, aliases another identity, or changes between validation and use.

## Successful verifier process

A successful verifier emits a cryptographic observation, never an acceptance
record or implementation attribution:

- exit code is zero;
- stdout is exactly one canonical `Eip0045B4PositiveObservationV1` object;
- stdout starts with `{`, ends with `}`, and reaches EOF immediately after the
  final `}`: no BOM, newline, prefix, second value, or trailing byte;
- stderr is empty; and
- the observation reports `accept`, status `ok`, zero final assumptions, and
  only verifier-derived profile, program, statement, claim, terminal, and
  control values.

The finalizer parses and canonicalizes that observation, hashes its exact stdout
bytes, and constructs a new `Eip0045B4PositiveAcceptanceV1` from authoritative
data. It does not deserialize or copy an acceptance record from verifier output.
It independently supplies the case ID/index, input-set commitment,
generation-set commitment, verifier-input commitment, observation commitment,
reviewed descriptor, launched artifact, source, lineage, and JVM runtime
binding. It recomputes every such non-cryptographic field and embeds only the
validated observation.

## Runner limits and private outcomes

The two build profiles fix a one-hour wall timeout, 12-GiB `memory.max`, zero
`memory.swap.max`, an eight-CPU cgroup quota, 512 PIDs, 1,024 open file
descriptors, disabled core dumps, 1-MiB stdout/stderr caps, and a separately
enforced 32-GiB/1,000,000-entry output-filesystem quota. The two
verification profiles fix:

- wall timeout: 300,000 milliseconds;
- cgroup v2 `memory.max`: 4,294,967,296 bytes;
- cgroup v2 `memory.swap.max`: zero;
- CPU quota: 400,000 microseconds per 100,000-microsecond period;
- PIDs: 256;
- open file descriptors: 256;
- core dumps: disabled;
- captured stdout: 65,536 bytes; and
- captured stderr: 65,536 bytes.

The finalizer applies every cgroup and rlimit before exec, verifies their active
kernel values, enforces wall time on the complete cgroup, kills and waits for
the complete process tree on failure, and stops capture at the byte bounds.
`memorySwapBytes` denotes the cgroup v2 swap-only limit, not Docker's combined
memory-plus-swap flag. If the selected platform cannot enforce any bound,
launch is refused.

For `verify-positive`, exit code `10` denotes cryptographic rejection and exit
code `11` denotes an input, profile, parse, or binding rejection. Both require
empty stdout. Other nonzero exits are runtime failures. The runner classifies
only private, non-accepting outcomes: `launch-failure`, `timeout`,
`signal-or-oom`, `output-limit`, `parse-or-binding-failure`,
`cryptographic-rejection`, and `runtime-failure`. Diagnostics may exist only
on bounded stderr for a failing process. No private outcome is an acceptance
document, corpus result, or substitute for one.

For `verify-negative`, an observed subject rejection is the requested evidence
outcome rather than a process failure. It therefore exits zero, keeps stderr
empty, and emits exactly one canonical
`Eip0045B4NegativeObservationV1`. That observation binds the domain, surface,
negative-input digest, subject identity, `reject` verdict, and first stable
`(class, stage)` boundary derived by the implementation. It carries no
implementation identity or external expectation.

An unexpectedly accepted negative subject, malformed campaign framing,
timeout, signal, OOM, output overflow, noncanonical observation, nonempty
stderr, or any other runtime failure is a private non-result. The finalizer
alone compares a successful observation with the pre-proof expectation set and
constructs `Eip0045B4ValidationResultV1`; it never promotes a private failure
or an earlier incidental rejection into corpus evidence.

## Differential acceptance gate

The positive phase contains eleven canonical verifier inputs, twenty-two
validator executions, twenty-two observation commitments, and exactly eleven
Rust plus eleven JVM acceptance records. For each case, the finalizer requires:

- the raw seal and proof-output manifest are the unique physical artifacts
  already bound for that case by the generation set;
- both validators receive the same canonical verifier-input bytes and physical
  profile, ELF, statement, and raw seal bytes;
- each validator executes under the one finalizer-owned profile fixed for its
  role, with no descriptor-selected policy;
- the two independently derived observations agree byte-for-byte on profile,
  program, statement, claim, status, assumption count, terminal kind,
  terminal parameter, and control ID;
- the observation terminal equals the case plan held outside the verifier root;
- each acceptance binds its distinct reviewed implementation and exact launched
  runtime; and
- a fresh finalizer-executor repeats both launches, freshly rederived from the
  same exact runner profiles and bound artifact bytes; the semantic gate then
  validates the new observations and finalizer-created acceptances against the
  archived bytes.

The semantic checker derives the expected program, profile, statement, claim,
and case terminal independently of the generator and validators. It is a
binding and semantic checker, not a third STARK implementation.

The final suite preserves the SHA-256 of all twenty-two exact acceptance byte
strings in `(case-0 Rust, case-0 JVM, ..., case-10 Rust, case-10 JVM)` order and
rejects any reused acceptance digest.

The executable cross-document reference gate is
`reproduction/src/b4_positive_gate.rs`. Its public entry point parses exact
canonical JCS, validates every document against the corresponding embedded
Draft 2020-12 schema, and enforces the cross-document semantic commitments and
differential byte-equality requirements in this specification. Its run API
consumes trusted physical measurements supplied by the finalizer. It does not
implement generator replay, OCI/JAR/ELF/Git parsing, sandbox creation, process
supervision, filesystem custody, or create-only publication; those remain
separate finalizer-executor obligations and must be tested independently. Its
outputs attest only the schema and semantic relations it actually checks, not
that an execution or historical ordering occurred.

## Differential rejection gate

The negative phase contains exactly 254 canonical plan executions, 254
independently reconstructed materialization identities, 508 validator
executions, 508 observations, and 508 finalizer-authored validation results.
The finalizer flattens the canonical plan once and processes every position as
`(execution-index, rust-reference)` followed by
`(execution-index, independent-jvm)`.

During materialization the precommitted executor invokes the bound generator's
fixed `alternate-root-candidate-proof` command once with the exact
`lift-po2-15` statement. The command exposes no caller-selected root, control
set, exponent, or terminal position. Its export must verify under the frozen
alternate context and is authenticated once for exactly two canonical
executions.

At zero-based index 108,
`terminal-inner-root-mismatch--inner-control-root` selects the
independently generated proof as its fixture. Both negative validators must
accept its STARK and terminal before reporting exactly the late initial-profile
inner-root mismatch. At index 146,
`resolve-explicit-field-sweep--assumption-receipt-root` remains a mutation of
case 9 ancestry, not a `FixtureSelection`: the same authenticated proof supplies
the replaced assumption-receipt producer. The ancestry consumer retains that
seal's actual inner root only after independent STARK verification, claim
binding, and terminal binding, then compares it to the explicit resolve's
requested root. The case 10 zero-root branch is conditional self-composition
and must not use naive requested-root equality. The shared proof is not a
twelfth positive case and cannot enter the positive generation set.

For each execution, the finalizer requires:

- one and only one registry row and materialization identity matching the
  exact plan position, execution ID, domain, surface, base selector, recipe,
  reconstructed subject length, and reconstructed subject SHA-256;
- one canonical neutral negative input derived from that materialization and
  the independently selected context, with the same exact input and declared
  file bytes supplied to both implementations;
- each successful observation to bind that input digest, subject identity,
  domain, surface, `reject` verdict, and its implementation's independently
  frozen first `(class, stage)` boundary;
- the observed boundary to equal the corresponding pre-proof expectation slot,
  never merely any earlier rejection from the same run;
- each result to be constructed by the finalizer from the exact plan,
  materialization identity, observation, measured validator artifact,
  independently validated descriptor, and implementation role; and
- a fresh finalizer process to rebuild the same bindings from the closed
  physical archive.

The global semantic gate rejects a missing, extra, duplicate, reordered,
relabelled, swapped, reused, or cross-bound plan row, registry row,
materialization, input, observation, artifact, descriptor, expectation, or
result. It independently rederives the domain totals
`131 + 102 + 21 = 254` and the implementation total `254 × 2 = 508`; declared
counts are not evidence. Identical observation bytes are permitted only when
their independently bound input, subject, surface, and expected boundary are
genuinely identical. A launch failure, timeout, signal, OOM, output-limit
failure, malformed framing, unexpected acceptance, or other private non-result
can never occupy a report slot.

For planning provenance, the original reviewed producer-work partition was
`254 = 134 closed/frozen + 106 fixture-gated + 4 instrumentation-gated + 2
alternate-root-gated + 8 new-proof/no-producer`. It is a historical schedule,
not the current coverage assertion. The historical five-input closure remains
exact at `218/254`. The descriptor-rooted terminal-aware dispatcher reaches
`233/254` in its projection-only producer seam, with rows `108` and
`140..=159` still unavailable. This is not evidence of a successful physical
terminal import, all 254 materializations, or any of the 508 executions.

## Create-only lifecycle

The input set, campaign precommit, runner profiles, seccomp documents,
descriptors, generation set, verifier roots, verifier inputs, observations,
acceptance records, materialization identities, validation results, semantic
report, manifest, lock, completion markers, and published phase roots are
create-only:

1. every destination must be absent;
2. each verifier root and the archive are built under absent sibling staging
   roots with fail-if-exists writes;
3. the input set and campaign precommit are durably closed before qualifying
   proof generation;
4. the generation set is durably closed after all eleven strict export replays;
5. all 254 negative subjects, contexts, neutral inputs, and roots are
   reconstructed and bound by one create-only negative materialization set
   before any negative-verifier run;
6. positive verification may begin after generation-set closure; positive and
   negative verification may run concurrently only after materialization-set
   closure;
7. all positive and negative bounded runs plus their independent semantic
   checks complete before the final manifest and lock are generated;
8. each applicable completion marker is written last;
9. publication is atomic and never replaces an existing destination; and
10. a fresh process rechecks every published root and final binding.

### Negative-materialization-set publication root

`prepare-negative-materialization-set` publishes a phase root with exactly one
top-level directory, `reproduction/`. That directory contains exactly one
regular file, `negative-materialization-set.json`. This phase has no separate
completion marker.

The no-replace publication of the complete phase root is its completion
boundary. After the atomic commit, the handler reopens
`reproduction/negative-materialization-set.json`, requires byte-for-byte
equality with the authenticated materialization-set authority and repeats the
semantic validation before returning success. An extra entry, a missing file
or a different path is invalid.

Failure never merges with, repairs, or overwrites a published root. Positive
completion is not a B4 lock or activation-readiness claim; the 254 negative
materializations, 508 rejection records, semantic report, final tree manifest,
and `LOCK.json` remain separate later gates.

### Pre-proof input-set publication root

`prepare-input-set` publishes to a campaign-selected phase root. The executor
must authenticate that absolute root as a strict descendant of its retained
campaign root and as a component-wise antichain with every retained prior root
and the reserved create-only staging sibling. The phase-root spelling is not a
portable contract value. Its campaign-global relative path is derived from the
retained final root; it is never taken from the current directory, the staging
path, or a caller-supplied artifact locator.

One opaque, non-serializable path projection is derived from that retained
final root and fixes both campaign-global sibling paths. The semantic
publication binding must require the positive gate's pathful input-set identity
to equal the projected input path, require the gate-derived completion sibling
to equal the projected completion path, and reject any exact or
ancestor/descendant conflict between the completion path and positive
provenance. Neither the pure path projection nor this semantic binding
authenticates a filesystem object or grants mutation authority. Pure preflight
stores the projection in the projected layout. The H0 handler must obtain that
projection only through a non-clonable transaction guard which borrows the exact
descriptor-rooted mutation capability and retained layout, then create and
consume the semantic binding inside that same guard. No CLI or caller may
supply a detached projection or binding to the handler. Postcommit or import
authority exists only after a descriptor-rooted reopen reauthenticates the
exact published two-file closure.

The H0 phase root contains exactly two direct regular files and no directory:

```text
positive-input-set.json
positive-input-set-completion.json
```

The canonical input set is written and sealed first. The completion file is
written and sealed last, with no intervening or later entry creation, before
the outer directory is durably committed and published without replacement.
The projected required-entry inventory establishes set closure only; the H0
handler's transition types must enforce the `input set -> completion -> commit`
chronology.
The next `prepare-campaign-precommit` phase uses a distinct create-only root;
it never extends or repairs this published root.

`positive-input-set-completion.json` is exact RFC 8785 JCS with format
`Eip0045B4PositiveInputSetCompletionV1`, `formatVersion` 1, and one `inputSet`
object containing exactly the pathful positive-input-set identity fields
`path`, `byteLength`, `sha256`, and `encoding`. `path` is the campaign-global
final path ending in `positive-input-set.json`; `encoding` is
`rfc8785-jcs`. The marker is derived only after the semantic positive gate has
retained that exact identity.

The completion file is a closure witness, not an authority. It is excluded
from the positive input set and its provenance closure. A later phase must
independently reconstruct the positive gate from the authoritative external
inputs, rederive the marker, and compare the exact retained bytes. A marker,
even together with an input-set document, cannot authorize proof generation or
campaign-precommit construction by itself.
