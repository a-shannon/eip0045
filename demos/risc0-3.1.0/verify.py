"""Replay the published lift-15 proof in the stock Rust and Scala/JVM verifiers."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from statement import statement_bundle


ROOT = Path(__file__).resolve().parent
VECTOR = ROOT / "vector"


def require_hash(path, expected):
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError(f"{path.name}: expected SHA-256 {expected}, got {actual}")


def run():
    metadata = json.loads((VECTOR / "vector.json").read_bytes())
    program = metadata["programId"]
    profile = (ROOT / "profile/bundle/profile-id.bin").read_bytes()
    if profile.hex() != metadata["profileId"]:
        raise ValueError("vector and profile have different profile IDs")

    inputs = statement_bundle(bytes.fromhex(program), profile)
    if hashlib.sha256(inputs["statement.bin"]).hexdigest() != metadata["statementSha256"]:
        raise ValueError("the expected statement differs from the published vector")
    receipt, seal = VECTOR / "receipt.bin", VECTOR / "raw-seal.bin"

    def check_vector():
        require_hash(receipt, metadata["receiptSha256"])
        require_hash(seal, metadata["sealSha256"])

    check_vector()
    env = os.environ.copy()
    cache = Path(env.get("EIP0045_DEMO_CACHE", Path.home() / ".cache" / "ergo-eip0045-demo"))
    target = Path(env.get("CARGO_TARGET_DIR", cache / "rust-target")).resolve()
    env["CARGO_TARGET_DIR"] = str(target)
    manifest = ROOT / "prover/host/Cargo.toml"
    subprocess.run(["cargo", "build", "--release", "--locked", "--manifest-path", str(manifest),
                    "--bin", "ergo310-receipt"], env=env, check=True)
    executable = target / "release" / ("ergo310-receipt.exe" if os.name == "nt" else "ergo310-receipt")
    with tempfile.TemporaryDirectory() as folder:
        cases = [("statement.bin", 0, "ACCEPT lift-po2-15"),
                 ("changed-statement.bin", 1, "REJECT claim-digest-mismatch")]
        for name, expected_code, verdict in cases:
            expected = Path(folder) / name
            expected.write_bytes(inputs[name])
            result = subprocess.run([str(executable), "verify", str(receipt), str(seal),
                                     program, str(expected)], stdout=subprocess.PIPE, text=True)
            if result.returncode != expected_code or result.stdout.strip() != verdict:
                raise ValueError(f"Rust {name}: exit {result.returncode}; output {result.stdout!r}")
            print(f"Rust: {verdict}", flush=True)
            check_vector()

    subprocess.run([sys.executable, str(ROOT / "jvm/verify.py"), str(ROOT / "profile/bundle"),
                    str(seal), program, inputs["application-payload.bin"].decode("utf-8"),
                    "--changed-payload", inputs["changed-payload.bin"].decode("utf-8")],
                   check=True)
    check_vector()
    print(f"Verified lift-po2-15 in Rust and on the JVM. Seal SHA-256 {metadata['sealSha256']}")


if __name__ == "__main__":
    try:
        run()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(f"Demo failed: {error}")
