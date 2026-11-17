# Verify a RISC Zero 3.1.0 lift on the JVM

This verifier checks a raw Poseidon2 succinct seal against an Ergo statement.
The command takes the expected guest image ID and application payload from
the caller. It derives the reference contract proposition and claim inside
the JVM, loads the pinned profile, checks the proof transcript, and requires
the terminal control to be the normal RV32IM lift with segment exponent 15.

Run with Python 3.8+ and JDK 17 or later:

```sh
python3 verify.py PROFILE_DIR RAW_SEAL PROGRAM_ID_HEX 'Ergo EIP-0045 local demo v3.1.0' \
  --changed-payload 'Ergo EIP-0045 local demo v3.1.1'
```

The script pins Scala 2.13.18 compiler, library, and reflection jars by
SHA-256. It caches the jars locally and compiles the source once per invocation.
Set `EIP0045_SCALA_CACHE` to use a different cache directory or to provision
the three pinned jars offline. Each payload is checked in a separate JVM.
With the paired invocation, success requires `ACCEPT lift-po2-15` followed by
`REJECT raw-seal-claim-mismatch` for the same seal. A single invocation without
`--changed-payload` exits 0 for acceptance and 1 for verifier rejection.

The interpreter code and license notices come from
[SigmaState at 58023777](https://github.com/a-shannon/sigmastate-interpreter/tree/5802377788589cb2cd94c98a29e5f383671c63a3/core/shared/src/main/scala/sigma/stark).
The original source provenance is recorded in
[the upstream source map](docs/eip-0045-risc0-source-map.json).
The port updates the profile loader and constraint interpreter's expected
circuit dimensions for [RISC Zero 3.1.0](https://github.com/risc0/risc0/tree/22c5fb90522cb4d9427d4af6c05e747d20be2b7f).
The binary profile package binds the corrected constraint operations,
tap table and authorized terminal controls. See `LICENSE`, `LICENSE-APACHE`
and `NOTICE` for attribution.
