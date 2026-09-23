# JVM archive tooling

`canonical_zip.py` implements the archive layer of the
[B4 JVM artifact policy](../../docs/specs/b4-jvm-artifact-policy-v1.md).
It checks classic ZIP structure and every decompressed payload before exposing
entries. Its writer emits deterministic STORED entries and reports the output
length, SHA-256, entry count and entry metadata aggregate.

The reader rejects ambiguous or unsupported archive forms, including duplicate
and ASCII-case-colliding names, traversal, overlapping records, CRC mismatch,
truncated DEFLATE streams and unconsumed compressed bytes. This is a closed
artifact format: an ordinary valid ZIP need not satisfy the policy.

## Run the checks

Python 3.12 and its standard library are sufficient. From the repository root:

```sh
output=$(mktemp -d)
python3 -B reproduction/jvm-artifact/test_canonical_zip.py \
  reproduction/jvm-artifact/canonical_zip.py \
  ed0d57c5fc507b4283f317838ff524e2aa05c8364f578f317cdccfb7c87e9f66 \
  "$output/grammar"
python3 -B reproduction/jvm-artifact/test_canonical_zip.py \
  reproduction/jvm-artifact/canonical_zip.py \
  ed0d57c5fc507b4283f317838ff524e2aa05c8364f578f317cdccfb7c87e9f66 \
  "$output/mutants" mutants
```

Each output directory must be absent before its command runs. The harness checks
the codec digest before importing it and writes `comparison.json` plus generated
fixtures into the selected directory. The grammar suite checks 88 cases. Four
mutants separately remove CRC checking, case-fold uniqueness, DEFLATE EOF
checking and the policy's CRC all-ones exclusion; each must accept its negative
witness while the original codec rejects it, and retain a passing control.

The same checks run in the `jvm-archive` CI job. They do not generate proofs or
execute candidate JVM classes.

## API and boundaries

- `inspect_archive(raw, canonical=False)` validates source-profile ZIP bytes;
  `canonical=True` also requires the canonical output profile.
- The returned archive exposes immutable entry records and
  `iter_entry_chunks(entry)` for bounded payload iteration.
- `write_canonical(output, entries)` accepts ordered `(name, bytes)` pairs.
  Put `META-INF/MANIFEST.MF` first, then sort other names by unsigned ASCII.
  The caller must open the output stream exclusively, for example with `xb`.

Fixtures compare canonical bytes against an independent ZIP constructor and
read them back with Python's ZIP reader. Cumulative-size rejection is exercised
with a reduced bound; actual decompression at the native 1 GiB limit and
worst-case resource behavior remain untested.

This module does not inspect class files or executable manifest contents,
approve dependency selection, validate a COPY-ONLY inclusion manifest, launch
Java, or establish runtime isolation. Those checks are required separately for
the full B4 artifact. B4 remains open.
