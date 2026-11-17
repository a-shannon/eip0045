"""Build the EIP-0045 3.1.0 demo profile from pinned public sources.

Inputs are the historical risc0-v3-succinct profile in the companion repo and
the upstream RISC Zero recursion/src directory at commit 22c5fb90522cb4d9427d4af6c05e747d20be2b7f.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct


OPCODES = ("Const", "ConstExt", "Get", "GetGlobal", "Add", "Sub", "Mul",
           "True", "AndEqz", "AndCond")
# Operands use disjoint index spaces for field and mix variables.
KINDS = ("v", "vvvv", "t", "go", "ff", "ff", "ff", "", "mf", "mfm")


def check(condition, message):
    if not condition:
        raise ValueError(message)


def pinned(path, digest, text=False):
    data = path.read_bytes()
    if text:
        data = data.replace(b"\r\n", b"\n")
    check(hashlib.sha256(data).hexdigest() == digest, f"input hash mismatch: {path.name}")
    return data


def polyext(source):
    block = source.split("block: &[", 1)[1]
    lines, remaining = block.split("],", 1)
    # Lines have numeric arguments and a trailing source-location comment.
    result = bytearray()
    counts = Counter()
    fields = mixes = 0
    for line in lines.splitlines():
        instruction = line.split("//", 1)[0].strip()
        if not instruction:
            continue
        match = re.fullmatch(r"PolyExtStep::(\w+)(?:\(([0-9, ]+)\))?,", instruction)
        check(match is not None, f"unknown instruction {instruction}")
        name, raw_args = match.groups()
        tag = OPCODES.index(name)
        operands = [int(s) for s in raw_args.split(",")] if raw_args else []
        check(len(operands) == len(KINDS[tag]), "invalid arity")
        result.append(tag)
        for kind, arg in zip(KINDS[tag], operands):
            limits = {"v": 2013265921, "f": fields, "m": mixes, "t": 643,
                      "g": 2, "o": 32 if operands[0] == 0 else 20}
            check(0 <= arg < limits[kind], f"invalid {name} operand {arg}")
            result.extend(struct.pack("<I" if kind == "v" else "<H", arg))
        if tag >= 7:
            mixes += 1
        else:
            fields += 1
        counts[name] += 1
    ret = int(re.match(r"\s*ret: (\d+),", remaining).group(1))
    check(ret == mixes - 1, "invalid circuit result")
    return result, counts, fields, mixes, ret


def seal_length():
    # RAW header, 4 base trees, coefficient vector, FRI commit/open rounds.
    degree = 1 << 18
    domain = 4 * degree
    trees = [(domain, w) for w in (23, 128, 12, 16)]
    while degree > 256:
        domain //= 16
        degree //= 16
        trees.append((domain, 16 * 4))
    queries = 50
    words = 32 + 1 + 4 * (643 + 16) + 4 * degree
    for rows, width in trees:
        top_depth = min(queries.bit_length() - 1, rows.bit_length() - 2)
        words += (1 << top_depth) * 8
        words += queries * (width + 8 * (rows.bit_length() - 1 - top_depth))
    return 4 * words


def digest(data):
    return hashlib.blake2b(data, digest_size=32).digest()


def build(legacy, source):
    algorithm = pinned(legacy / "algorithm.txt",
        "90a884da420a09f2c1108d7388c2ac74db8dbdb195de704206e2bf8ec1ad0bee", True)
    old = pinned(legacy / "constants.bin",
        "8c4a92b7d354890481eefdef233d4ca43f6bcd9f7cb00e4dd9e709da47789ef3")
    program = pinned(source / "poly_ext.rs",
        "4a7ef3cf97adc458c74f8023c934107614ea0d9653853ac723be024637d0112a", True)
    controls = pinned(source / "control_id.rs",
        "6f107740923acd80b7a2776154806285f8447dfe0270290de9eb7513326233dc", True).decode()
    # Identical recursion taps and identical inner proof geometry.
    pinned(source / "taps.rs", "d32cbf5350d6f724cf3582ef92fb6c392f993b51ee89c5384f7ad79bab43ce83", True)
    pinned(source / "info.rs", "41aa4085673846ac3efa19898c5cc12599882ed88f95b35fb936dc63eb4bd541", True)
    ops, census, fields, mixes, ret = polyext(program.decode())
    binary = bytearray(old[:4362])
    struct.pack_into("<4H", binary, 36, sum(census.values()), fields, mixes, ret)
    binary.extend(ops)
    b1 = algorithm.decode("ascii")
    updates = dict(zip((65119, 12359, 11130, 1229, 1228, 4061, 1385, 4679, 1076),
                       (len(binary), sum(census.values()), fields, mixes, ret,
                        census["Add"], census["Sub"], census["Mul"], census["AndEqz"])))
    for previous, new in updates.items():
        b1, n = re.subn(rf"\b{previous}\b", str(new), b1)
        check(n > 0, "old B1 did not match derived dimensions")
    allowed = controls.split("pub const ALLOWED_CONTROL_IDS:", 1)[1].split("];", 1)[0]
    roots = {n: bytes.fromhex(h) for h, n in re.findall(
        r'digest!\("([0-9a-f]{64})"\), // recursion (\w+)\.zkr', allowed)}
    check(len(roots) == len(set(roots.values())) == 27, "unexpected allowed control ids")
    root = bytes.fromhex(re.search(
        r'pub const ALLOWED_CONTROL_ROOT: Digest =\s*digest!\("([0-9a-f]{64})"\);', controls)[1])
    controls = [(1, n, roots[f"lift_rv32im_v2_{n}"]) for n in range(15, 23)]
    controls += [(2, 0, roots["join"]), (3, 0, roots["resolve"])]
    manifest = bytearray(struct.pack("<BIIB", 1, seal_length(), 16384, 18) + root)
    for kind, parameter, cid in controls:
        manifest.extend(bytes([kind, parameter]) + cid)
    algorithm = b1.encode("ascii")
    for kind, material in ((1, algorithm), (2, binary)):
        header = struct.pack("<HI", kind, len(material))
        manifest.extend(header + digest(b"Ergo.StarkProfileArtifact.v1\x00" + header + material))
    check(len(manifest) == 458, "wrong manifest length")
    profile = digest(b"Ergo.StarkProfileId.v1\x00" + struct.pack("<I", len(manifest)) + manifest)
    return {"algorithm.txt": algorithm, "constants.bin": binary,
            "manifest.bin": manifest, "profile-id.bin": profile}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("legacy", "source", "bundle"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--check", action="store_true",
                        help="compare the four existing artifacts instead of writing")
    args = parser.parse_args()
    material = build(args.legacy, args.source)
    if not args.check:
        args.bundle.mkdir(parents=True, exist_ok=False)
    for name, content in material.items():
        path = args.bundle / name
        if args.check:
            check(path.read_bytes() == content, f"artifact differs: {name}")
        else:
            with path.open("xb") as output:
                output.write(content)
    print(json.dumps({"profileId": material["profile-id.bin"].hex(), "proofBytes": seal_length(),
                      "files": {n: hashlib.sha256(c).hexdigest() for n, c in material.items()}}, indent=2))
