# RISC Zero v3 succinct profile

This directory defines the candidate initial EIP-0045 profile for RISC Zero
v3.0.5 succinct receipts, the fixed statement grammar, and direct transaction
carriage. It is a pre-activation construction package, not an activated Ergo
consensus feature.

The manifest admits exactly ten typed **outermost** terminal controls, in one
fixed order:

1. normal RV32IM lifts with segment `po2` values 15 through 22;
2. the stock succinct `join`; and
3. the stock assumption-discharge `resolve`.

The terminal allowlist is not a recursion-ancestry allowlist. The verifier
matches only the reconstructed outermost code root. A terminal `join` may have
private children produced by controls that are not valid terminals for this
profile, including `po2 = 14`, identity, proof-of-verifiable-work, unwrap, or
`resolve`. A terminal `resolve` may discharge an assumption carrying any
explicit control root selected and committed by the guest; a zero root denotes
self-composition under the conditional receipt root. The application guest,
bound by `programId`, owns the safety and provenance policy for such
assumptions. EIP-0045 still requires the pinned decoded inner root and the exact
final OK claim with empty assumptions.

The broader upstream inner control root commits to 27 recursion programs. Root
membership alone therefore never authorizes a terminal. Identity, union,
unwrap, proof-of-verifiable-work, and every other non-allowlisted outermost
terminal are rejected.

Non-normative integration note: an application may aggregate another proof
system and verify its root inside the RISC Zero guest. That inner proof system,
the guest cycle count, and the number of execution segments are not profile or
cost parameters. Stock multi-segment succinct receipts terminate through the
allowlisted `join`; the node meters verification of the resulting receipt, not
guest proving or the work performed inside the guest. When the guest verifies
an inner or aggregate proof, application policy MUST cryptographically bind
that proof's externally relevant public statement, or a canonically encoded,
authenticated root commitment to that statement, to the
`ErgoStatementV1.applicationPayload`. Validity of an opaque inner proof or inner
root alone does not establish application facts such as amounts, destinations,
or nullifiers.

Manifest V1 is 458 bytes. Its ten entries use
`controlKind:u8 || parameter:u8 || controlId[32]`, and its complete profile-ID
preimage is 485 bytes. `manifest-format.md` specifies every byte and the
independent reproduction procedure.

Only `algorithm.txt` and `constants.bin` are normative external artifacts.
`manifest.json`, raw preimage files, and verification tools are derived
evidence. Any retained 382-byte manifest package and its profile ID belong to
the superseded single-lift candidate and must not be treated as this profile's
B3 identity. For the exact B1 and B2 bytes in this directory, the independently
reproduced 458-byte manifest has SHA-256
`deffb2cb231f98a348cbd166d5f1c43315661ccd8bd212099f16f238d0fe8946`
and derives profile ID
`23c4a123ffb33a1c8db89436fe0e7972bd8e4e289459ee5fd71be5440607d383`.
These values record package identity, not network activation or readiness.

The B2 `constants.bin` artifact remains byte-for-byte fixed at 65,119 bytes,
with SHA-256
`8c4a92b7d354890481eefdef233d4ca43f6bcd9f7cb00e4dd9e709da47789ef3`.
Identity fixation is not network activation. The guest ELF and image ID,
upstream verifier-parameters digest, final KAT corpus, cost schedule, and
lifecycle transition remain downstream evidence or activation artifacts, not
inputs to `profileId`.
