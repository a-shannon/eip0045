"""Compile and run the independent Scala/JVM verifier for the lift-15 demo."""

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path


VERSION = "2.13.18"
JARS = {
    "scala-compiler": "2f15891fcae7aad30a3892194fb2abb6224cf7ce5d2bd90fba7f1c48682fca21",
    "scala-library": "4e85d96ff7bc7dc627985523c3541b9917aaa08e956391380c42db21a2c4e5a0",
    "scala-reflect": "6935ff1982b2ac93d695f15aa66921be2f602921277afe002f018fd8c7d6e29b",
}
MAIN = "sigma.stark.profile.Lift15Demo"
JAVA = ["java", "-Xmx512m", "-XX:ActiveProcessorCount=1"]
SOURCE = Path(__file__).resolve().parent / "src" / "main" / "scala"


def verified_jar(cache, artifact, digest):
    name = f"{artifact}-{VERSION}.jar"
    jar = cache / name
    if jar.exists():
        if hashlib.sha256(jar.read_bytes()).hexdigest() != digest:
            raise ValueError(f"cached Scala artifact failed SHA-256: {name}")
        return str(jar)
    url = f"https://repo.maven.apache.org/maven2/org/scala-lang/{artifact}/{VERSION}/{name}"
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(32 * 1024 * 1024 + 1)
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"Scala dependency failed SHA-256: {name}")
    with tempfile.NamedTemporaryFile(dir=cache, delete=False) as pending:
        pending.write(data)
    os.replace(pending.name, jar)
    return str(jar)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile_dir")
    parser.add_argument("raw_seal")
    parser.add_argument("program_id")
    parser.add_argument("payload", help="expected payload as UTF-8 text")
    parser.add_argument("--changed-payload", help="also require a claim mismatch on the same seal")
    args = parser.parse_args()
    if args.changed_payload is not None and args.changed_payload == args.payload:
        parser.error("the changed payload must differ")
    default_cache = Path.home() / ".cache" / "ergo-eip0045-demo" / "scala" / VERSION
    cache = Path(os.environ.get("EIP0045_SCALA_CACHE", default_cache)).resolve()
    cache.mkdir(parents=True, exist_ok=True)
    jars = {name: verified_jar(cache, name, digest) for name, digest in JARS.items()}
    with tempfile.TemporaryDirectory(dir=cache, prefix="classes-") as classes:
        sources = sorted(str(p) for p in SOURCE.rglob("*.scala"))
        compiler = JAVA + ["-cp", os.pathsep.join(jars.values()), "scala.tools.nsc.Main"]
        build = subprocess.run(compiler + ["-encoding", "UTF-8", "-classpath",
                               jars["scala-library"], "-d", classes, *sources], check=False)
        if build.returncode:
            raise ValueError("Scala compilation failed")
        classpath = os.pathsep.join([classes, jars["scala-library"]])
        verify = JAVA + ["-cp", classpath, MAIN, args.profile_dir, args.raw_seal, args.program_id]
        first = subprocess.run(verify + [args.payload], check=False)
        if args.changed_payload is None or first.returncode != 0:
            return first.returncode
        second = subprocess.run(verify + [args.changed_payload], capture_output=True, text=True)
        sys.stdout.write(second.stdout)
        sys.stderr.write(second.stderr)
        if second.returncode != 1 or second.stdout.strip() != "REJECT raw-seal-claim-mismatch":
            raise ValueError("expected the JVM verifier to reject the changed payload at claim comparison")
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(error, file=sys.stderr)
        sys.exit(2)
