# Trusted-host campaign handlers

The `trusted-host-v1` realization connects input preparation, campaign precommit
and generation-set finalization. These handlers consume retained artifacts and
produce canonical documents without generating proofs. The full B4 campaign
remains incomplete.

## Trust and scope

This realization trusts the host operating system, its administrator and any
hypervisor. It retains the input identities, schema checks, executable binding
and authenticated build expectations used by the campaign. H0 custody tokens
remain confined to the separate H0 entry points.

Three commands are implemented by this source slice:

| Command | Prior roots | Result |
| --- | --- | --- |
| `prepare-input-set` | 1–2 | Positive input set and trusted-host completion |
| `prepare-campaign-precommit` | 1–2 | Trusted-host envelope around the positive precommit |
| `finalize-generation-set` | 1–16 | Canonical generation set from the eleven declared case exports |

The eleven-command executor contract remains unchanged. The other commands are
rejected by this realization. These handlers alone do not qualify an executor
binary or establish the physical B4 corpus, OCI execution, Rust/JVM agreement
or independent reproduction.

## Invocation contract

The campaign façade accepts flags once, in the following order. A trailing
`--preflight-only` selects validation without publication.

```text
b4-campaign COMMAND
  --realization trusted-host-v1
  --request REQUEST
  --request-bytes LENGTH
  --request-sha256 SHA256
  --expected-source-commit COMMIT
  --expected-source-tree TREE
  --expected-build-evidence-root SHA256
```

`REQUEST` names a normalized absolute path to one regular file. Its externally
pinned length is at most 65536 bytes. The caller supplies the expected source
commit, source tree and build-evidence digest separately. The request is held
open, checked against its length and digest, and rechecked after the command.
Symlinks, special files and a replaced request path are rejected.

The request uses RFC 8785 canonical JSON and the
[request schema](../../reproduction/finalizer-schema/b4-trusted-host-request-v1.schema.json).
It names the campaign root, prior roots, fresh output root, configured executor
and artifact locators. Each command has a closed set of locator roles. Unknown
fields, missing roles and out-of-range root indices are rejected.

## Binding the next command

The input-set completion binds the input document, its preparing request,
build-evidence digest and executor artifact. The precommit constructor checks
the completion bytes it consumes against that validated identity, including
the path, encoding, length and digest. Equal-length replacement bytes cannot
reuse a completion token.

Finalization retains the preceding request and precommit envelope, replays the
precommit derivation from the selected roots, and checks the current executable
and authenticated build. Root indices may change between commands; each prior
root must still be present by its exact path. The retained input and completion
must agree with the envelope before the shared generation-set validator runs.
Publication rechecks these bindings and creates a fresh output.

The
[completion schema](../../reproduction/finalizer-schema/b4-trusted-host-input-set-completion-v1.schema.json)
and
[precommit schema](../../reproduction/finalizer-schema/b4-trusted-host-campaign-precommit-v1.schema.json)
describe the envelopes. They do not confer physical provenance by themselves.

## Non-proving checks

Focused library tests use Rust 1.89.0. The generator's campaign features depend
on the H0 Linux ABI and therefore select `x86_64-unknown-linux-musl`; the target
and linker must already be provisioned.

```sh
cargo test --manifest-path reproduction/Cargo.toml --no-default-features --features positive-gate --locked --lib trusted_host
cargo test --manifest-path generator/Cargo.toml --target x86_64-unknown-linux-musl --no-default-features --features b4-prepare-input-set-kernel,b4-finalize-generation-set-handler --locked --lib trusted_host
```

The default generator binary also requires `embedded-method` and its locked
guest environment. These library commands do not build a qualified campaign
executable. Physical publication and reopening, all eleven executor commands,
the final corpus and its reproduction remain separate delivery gates.
