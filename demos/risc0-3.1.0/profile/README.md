# Rebuild the 3.1.0 demo profile

The offline verifier uses four files from `bundle/`. The manifest binds the algorithm, circuit constants, accepted terminal controls and exact transport size. Its domain-separated BLAKE2b-256 identity is `5649af920f3119ca06e8566d836d3c89de81af52ef3d140a0ad7012ca364d35c`. This profile is a developer demo.

With Python 3.9 or later, run the following from this directory. Supply a checkout of the public [historical EIP-0045 profile](https://github.com/a-shannon/eip0045/tree/e51b7c7a6a084a23628c7b1e19d5b5fb40753315/profiles/risc0-v3-succinct) and a checkout of [RISC Zero 3.1.0](https://github.com/risc0/risc0/tree/22c5fb90522cb4d9427d4af6c05e747d20be2b7f). The command compares the derived bytes with the supplied bundle.

```sh
python3 generate_profile.py "$EIP0045/profiles/risc0-v3-succinct" \
    "$RISC0/risc0/circuit/recursion/src" bundle --check
```

To create the same artifacts in a new directory, replace `bundle --check` with the new directory name. Inputs are pinned by SHA-256. The historical artifact supplies the unchanged field, Poseidon2 and tap tables. The generator replaces the ordered constraint program from the 3.1.0 recursion circuit. It adjusts the algorithm's corresponding data grammar and derives the manifest's eight lift IDs, join ID, resolve ID and inner root from the released control set.

For a recursion height of 18 the succinct verifier opens four base trees and three FRI layers. The Merkle cap and commitment reads, queries, output and final polynomial consume exactly 55,667 little-endian words. The normative artifacts and derived manifest have these SHA-256 digests.

| File | SHA-256 |
| --- | --- |
| algorithm.txt | `bb8b9685ff3b554246ce47ef9ff629f62aa3ea90231e109ce68cfe3545dcde41` |
| constants.bin | `b46670acf8a9abfc77403e56f9c017ff41accac1e015c54f614e12e191739084` |
| manifest.bin | `e52019540961bf1bd17f5354838c877f9539972421df2be9df7bb865a08976ec` |
| profile-id.bin | `ae9088baf49f05fd9bf58aaa21a0513f547ffff81b4c29ca05a1df40934dfa66` |
