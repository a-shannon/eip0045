# Replay three recursive Ergo receipts

Run this command from the repository root on x86-64 Linux with Python 3.9+, rustup and a JDK 17+ on your PATH. The first run needs network access for the locked Rust dependencies and the hash-pinned Scala compiler jars.

```sh
python3 demos/risc0-3.1.0/recursive/verify.py
```

The replay uses the proofs included in this directory. It checks the three cases in order. For each case Rust reads the source composite, segment receipts and intermediate proofs, verifies them and reconstructs the claims along the recorded graph. Rust and the independent Scala/JVM verifier then check the final seal against the same Ergo statement. Both must accept the original payload and reject the same seal when the expected payload changes from `Ergo EIP-0045 local demo v3.1.0` to `Ergo EIP-0045 local demo v3.1.1`.

| B4 case | Source segment exponents | Operations the replay checks | Final raw seal SHA-256 |
|---|---|---|---|
| 8 | 16, 16 | Lift each segment, then join the two in execution order | `5406e5a959dea65298ccceb6a35493ff56eb3031e9001891f893e37c6bb9f6fe` |
| 9 | 16 | Lift a conditional segment, then discharge its assumption under the explicit 3.1.0 control root | `d387b501e43ce5ae0550adca2fd5279dea06e8a03b3dd12030845c790d253709` |
| 10 | 16, 15 | Lift both segments, discharge the second lift's zero-root assumption, then join the result with the first lift | `9345f511c6b2aabdbf87b715cd9d0a3900b346825cfeed99dad2544e0ef4c5f5` |

Cases 9 and 10 use the [published unconditional lift-15 receipt](../vector/vector.json) to discharge a claim for the same guest and journal. Case 9 commits the explicit root `e6feef13db7aed4a731c7b0852de1f5c89b137726073f625d05333184d3a551d`. Case 10 commits the zero root used for self-composition. The JVM derives the final terminal from each seal. Cases 8 and 10 both end in a join, so the intermediate receipts are what let a reader check their different construction paths.

Each final seal is 222,668 bytes and all three prove the same successful claim with empty assumptions. These are three off-chain interoperability cases on the 3.1.0 demo profile. Closing the full B4 corpus also requires the remaining positive cases, independent negative materializations and paired verifier results in one immutable archive.
