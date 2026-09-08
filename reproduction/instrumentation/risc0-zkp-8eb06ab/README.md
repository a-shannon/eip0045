# RISC Zero checkpoint patch contract

This directory binds a minimal observational patch for `risc0-zkp` 3.0.4 at
commit `8eb06ab020a92dc5b63ba6dd0836d432aba6d890`.

The patch adds typed notifications immediately before four existing
`InvalidProof` returns. The stock `verify` entrypoint delegates to the
instrumented entrypoint with a no-op callback, so the computation and returned
verdict remain unchanged.

The two patches apply only to:

- `risc0/zkp/src/verify/mod.rs`
- `risc0/zkp/src/verify/fri.rs`

`contract.json` binds the upstream source hashes, patch hashes, patched source
hashes, checkpoint order, and unresolved build authority.

The contract is not an executable verifier dependency. Cargo cannot apply a
source patch to the pinned Git dependency directly. The crypto-depth handler
therefore remains unavailable until a reviewed patched RISC Zero commit, or an
accepted upstream equivalent, is pinned in `Cargo.lock` and proves
stock/instrumented agreement on the four exact mutated real seals.
