"""Replay the three recursive receipt fixtures using Rust and the JVM."""

import hashlib
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
DEMO = ROOT.parent
VECTORS = ROOT / "vectors"
SHA256SUMS = "d916b84f8e560ed9beb2c4a919af28864ed3aa07f53d4818c3551f2d9a60951f"
IMAGE = "b574db28719df2261c18b5c5f0a52ad5ad96a290679df3223c1c3acacd0fca9c"
PROFILE = "5649af920f3119ca06e8566d836d3c89de81af52ef3d140a0ad7012ca364d35c"


def verify_files():
    manifest = (VECTORS / "SHA256SUMS").read_bytes()
    if hashlib.sha256(manifest).hexdigest() != SHA256SUMS:
        raise ValueError("incorrect recursive vector manifest")
    digests = {}
    for line in manifest.decode("ascii").splitlines():
        expected, filename = line.split("  ", 1)
        path = VECTORS / filename
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"incorrect SHA-256 for {filename}")
        digests[filename] = expected
    return digests


def rust_command():
    cache = Path(os.environ.get("EIP0045_DEMO_CACHE", Path.home() / ".cache" / "ergo-eip0045-demo"))
    target = Path(os.environ.get("CARGO_TARGET_DIR", cache / "recursive-rust-target")).resolve()
    executable = "eip0045-recursive-replay" + (".exe" if os.name == "nt" else "")
    subprocess.run(["cargo", "build", "--release", "--locked", "--manifest-path", ROOT / "rust/Cargo.toml",
                    "--target-dir", target], cwd=ROOT, check=True)
    return target / "release" / executable


def compile_scala(classes):
    # Share the published lift verifier's compiler, Maven digests and download cache.
    jvm = runpy.run_path(str(DEMO / "jvm/verify.py"))
    default = Path.home() / ".cache" / "ergo-eip0045-demo" / "scala" / jvm["VERSION"]
    cache = Path(os.environ.get("EIP0045_SCALA_CACHE", default)).resolve()
    cache.mkdir(parents=True, exist_ok=True)
    jars = {name: jvm["verified_jar"](cache, name, digest) for name, digest in jvm["JARS"].items()}
    classes.mkdir()
    sources = sorted(jvm["SOURCE"].rglob("*.scala")) + [ROOT / "Recursive310.scala"]
    subprocess.run(jvm["JAVA"] + ["-cp", os.pathsep.join(jars.values()), "scala.tools.nsc.Main",
                   "-encoding", "UTF-8", "-classpath", jars["scala-library"],
                   "-d", classes, *sources], check=True)
    cp = os.pathsep.join([str(classes), jars["scala-library"]])
    return jvm["JAVA"] + ["-cp", cp, "sigma.stark.profile.Recursive310"]


def main():
    digests = verify_files()
    rust = rust_command()
    profile = DEMO / "profile/bundle"
    inputs = runpy.run_path(str(DEMO / "statement.py"))["statement_bundle"](
        bytes.fromhex(IMAGE), bytes.fromhex(PROFILE))
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        statement = work / "statement.bin"
        changed = work / "changed-statement.bin"
        statement.write_bytes(inputs["statement.bin"])
        changed.write_bytes(inputs["changed-statement.bin"])
        java = compile_scala(work / "classes")
        for case in ["8", "9", "10"]:
            folder = VECTORS / case
            print(f"Verifying case {case}", flush=True)
            subprocess.run([rust, case, folder, DEMO / "vector/receipt.bin", statement,
                            profile / "manifest.bin", changed], check=True)
            subprocess.run(java + [case, profile, folder / "raw-seal.bin",
                           digests[f"{case}/raw-seal.bin"]], check=True)
    verify_files()
    print("Rust and the JVM accepted all three recursive cases and rejected the changed payload for each.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f"Recursive replay failed: {error}")
