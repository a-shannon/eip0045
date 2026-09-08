#!/usr/bin/env python3
# Copyright 2026 A. Shannon
# SPDX-License-Identifier: Apache-2.0

"""Strict, independent decoder for the EIP-0045 B2 constants artifact."""

from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
import sys
from typing import Dict, List, Sequence, Tuple


ARTIFACT_BYTES = 65_119
CANONICAL_SHA256 = "8c4a92b7d354890481eefdef233d4ca43f6bcd9f7cb00e4dd9e709da47789ef3"
HEADER_BYTES = 87
MODULUS = 2_013_265_921
ROOT_COUNT = 28
ROUND_CONSTANT_COUNT = 213
DIAGONAL_COUNT = 24
TAP_COUNT = 643
GROUP_SIZES = (12, 23, 128)
COMBO_COUNT = 5
TOTAL_COMBO_BACKS = 20
OP_COUNT = 12_359
FIELD_VARS = 11_130
MIX_VARS = 1_229
RET_MIX_VAR = 1_228

EXPECTED_HISTOGRAM = {
    "Const": 284,
    "ConstExt": 0,
    "Get": 669,
    "GetGlobal": 52,
    "Add": 4_061,
    "Sub": 1_385,
    "Mul": 4_679,
    "True": 1,
    "AndEqz": 1_076,
    "AndCond": 152,
}

OP_NAMES = (
    "Const",
    "ConstExt",
    "Get",
    "GetGlobal",
    "Add",
    "Sub",
    "Mul",
    "True",
    "AndEqz",
    "AndCond",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


class Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, size: int, label: str) -> bytes:
        end = self.offset + size
        require(end <= len(self.data), "unexpected EOF while reading " + label)
        value = self.data[self.offset:end]
        self.offset = end
        return value

    def u8(self, label: str) -> int:
        return self.take(1, label)[0]

    def u16(self, label: str) -> int:
        return struct.unpack("<H", self.take(2, label))[0]

    def u32(self, label: str) -> int:
        return struct.unpack("<I", self.take(4, label))[0]


Tap = Tuple[int, int, int, int, int]
Operation = Tuple[int, Tuple[int, ...]]


@dataclass(frozen=True)
class Artifact:
    reverse_roots: Tuple[int, ...]
    round_constants: Tuple[int, ...]
    internal_diagonal: Tuple[int, ...]
    taps: Tuple[Tap, ...]
    operations: Tuple[Operation, ...]
    histogram: Dict[str, int]
    register_count: int
    combo_back_count: int


def fixed(actual: int, expected: int, label: str) -> None:
    require(actual == expected, "%s is %d, expected %d" % (label, actual, expected))


def read_fixed_header(reader: Reader) -> None:
    fixed(reader.u32("BabyBear modulus"), MODULUS, "BabyBear modulus")
    fixed(reader.u8("extension degree"), 4, "extension degree")
    fixed(reader.u32("extension beta"), 11, "extension beta")
    fixed(reader.u8("maximum root exponent"), 27, "maximum root exponent")
    fixed(reader.u8("Poseidon2 cells"), 24, "Poseidon2 cells")
    fixed(reader.u8("Poseidon2 rate"), 16, "Poseidon2 rate")
    fixed(reader.u8("Poseidon2 output cells"), 8, "Poseidon2 output cells")
    fixed(reader.u8("Poseidon2 half-full rounds"), 4, "Poseidon2 half-full rounds")
    fixed(reader.u8("Poseidon2 partial rounds"), 21, "Poseidon2 partial rounds")
    fixed(reader.u8("Poseidon2 S-box degree"), 7, "Poseidon2 S-box degree")
    fixed(reader.u16("Poseidon2 round-constant count"), ROUND_CONSTANT_COUNT,
          "Poseidon2 round-constant count")
    fixed(reader.u8("Poseidon2 diagonal count"), DIAGONAL_COUNT,
          "Poseidon2 diagonal count")
    fixed(reader.u8("STARK query count"), 50, "STARK query count")
    fixed(reader.u8("inverse Reed-Solomon rate"), 4,
          "inverse Reed-Solomon rate")
    fixed(reader.u8("FRI fold"), 16, "FRI fold")
    fixed(reader.u8("FRI fold exponent"), 4, "FRI fold exponent")
    fixed(reader.u16("FRI minimum degree"), 256, "FRI minimum degree")
    fixed(reader.u8("recursion output size"), 32, "recursion output size")
    fixed(reader.u8("recursion mix size"), 20, "recursion mix size")
    fixed(reader.u8("check size"), 16, "check size")
    fixed(reader.u16("tap count"), TAP_COUNT, "tap count")
    fixed(reader.u8("register-group count"), 3, "register-group count")
    for index, expected in enumerate(GROUP_SIZES):
        fixed(reader.u8("group size"), expected, "group size %d" % index)
    fixed(reader.u8("combination count"), COMBO_COUNT, "combination count")
    fixed(reader.u8("total combination backs"), TOTAL_COMBO_BACKS,
          "total combination backs")
    fixed(reader.u16("PolyExt instruction count"), OP_COUNT,
          "PolyExt instruction count")
    fixed(reader.u16("PolyExt field-variable count"), FIELD_VARS,
          "PolyExt field-variable count")
    fixed(reader.u16("PolyExt mix-variable count"), MIX_VARS,
          "PolyExt mix-variable count")
    fixed(reader.u16("returned mix-variable index"), RET_MIX_VAR,
          "returned mix-variable index")

    remap = tuple(reader.u8("extension coefficient remap") for _ in range(4))
    require(remap == (0, 2, 1, 3), "extension coefficient remap is not [0,2,1,3]")
    group_ids = tuple(reader.u8("register-group identifier") for _ in range(3))
    require(group_ids == (0, 1, 2), "register-group identifiers are not [0,1,2]")
    fixed(reader.u8("proof-system info length"), 16,
          "proof-system info length")
    fixed(reader.u8("circuit info length"), 16, "circuit info length")
    fixed(reader.u8("tap-record width"), 5, "tap-record width")
    fixed(reader.u8("extension challenge scale"), 3,
          "extension challenge scale")
    require(reader.take(16, "proof-system info") == b"RISC0_STARK:v1__",
            "proof-system info preimage differs")
    require(reader.take(16, "circuit info") == b"RECURSION:rev1v1",
            "circuit info preimage differs")
    fixed(reader.offset, HEADER_BYTES, "header end offset")


def read_field_values(reader: Reader, count: int, label: str) -> Tuple[int, ...]:
    values = tuple(reader.u32(label) for _ in range(count))
    for index, value in enumerate(values):
        require(value < MODULUS,
                "%s value %d is not reduced modulo BabyBear" % (label, index))
    return values


def validate_taps(taps: Sequence[Tap]) -> Tuple[int, int]:
    require(len(taps) == TAP_COUNT, "tap record census differs")
    for index, (group, offset, _back, combo, skip) in enumerate(taps):
        require(group < len(GROUP_SIZES), "tap %d group is out of range" % index)
        require(offset < GROUP_SIZES[group], "tap %d offset is out of range" % index)
        require(combo < COMBO_COUNT, "tap %d combo is out of range" % index)
        require(skip > 0, "tap %d skip is zero" % index)

    cursor = 0
    registers: List[Tuple[int, int]] = []
    combo_shapes: Dict[int, Tuple[int, ...]] = {}
    while cursor < len(taps):
        group, offset, _back, combo, skip = taps[cursor]
        end = cursor + skip
        require(end <= len(taps), "tap register overruns the record table")
        run = taps[cursor:end]
        for record in run:
            require(record[0] == group and record[1] == offset,
                    "tap register changes group or offset inside its skip run")
            require(record[3] == combo and record[4] == skip,
                    "tap register changes combo or skip inside its skip run")
        backs = tuple(record[2] for record in run)
        require(tuple(sorted(set(backs))) == backs,
                "tap register backs are not unique and increasing")
        if combo in combo_shapes:
            require(combo_shapes[combo] == backs,
                    "tap registers disagree on the back list for one combo")
        else:
            combo_shapes[combo] = backs
        registers.append((group, offset))
        cursor = end

    expected_registers = tuple(
        (group, offset)
        for group, size in enumerate(GROUP_SIZES)
        for offset in range(size)
    )
    require(tuple(registers) == expected_registers,
            "tap register order or register census differs")
    require(set(combo_shapes) == set(range(COMBO_COUNT)),
            "tap combo census differs")
    require(len(set(combo_shapes.values())) == COMBO_COUNT,
            "two tap combos have the same back list")
    combo_back_count = sum(len(backs) for backs in combo_shapes.values())
    fixed(combo_back_count, TOTAL_COMBO_BACKS, "derived combo-back census")
    return len(registers), combo_back_count


def field_ref(value: int, field_count: int, label: str) -> None:
    require(value < field_count,
            "%s field reference %d is not backward from %d" %
            (label, value, field_count))


def mix_ref(value: int, mix_count: int, label: str) -> None:
    require(value < mix_count,
            "%s mix reference %d is not backward from %d" %
            (label, value, mix_count))


def read_operations(reader: Reader) -> Tuple[Tuple[Operation, ...], Dict[str, int]]:
    operations: List[Operation] = []
    histogram: Counter[str] = Counter()
    field_count = 0
    mix_count = 0

    for op_index in range(OP_COUNT):
        tag = reader.u8("PolyExt tag")
        require(tag < len(OP_NAMES), "unknown PolyExt tag %d" % tag)
        name = OP_NAMES[tag]

        if tag == 0:
            operands = (reader.u32("Const value"),)
            require(operands[0] < MODULUS,
                    "Const at operation %d is not reduced modulo BabyBear" % op_index)
        elif tag == 1:
            operands = tuple(reader.u32("ConstExt value") for _ in range(4))
            require(all(value < MODULUS for value in operands),
                    "ConstExt at operation %d is not reduced modulo BabyBear" % op_index)
        elif tag == 2:
            operands = (reader.u16("Get tap"),)
            require(operands[0] < TAP_COUNT,
                    "Get at operation %d has an out-of-range tap" % op_index)
        elif tag == 3:
            operands = (reader.u16("GetGlobal argument"),
                        reader.u16("GetGlobal offset"))
            argument, offset = operands
            require(argument in (0, 1),
                    "GetGlobal at operation %d has an invalid argument" % op_index)
            bound = 32 if argument == 0 else 20
            require(offset < bound,
                    "GetGlobal at operation %d has an out-of-range offset" % op_index)
        elif tag in (4, 5, 6):
            operands = (reader.u16(name + " left"), reader.u16(name + " right"))
            field_ref(operands[0], field_count, name)
            field_ref(operands[1], field_count, name)
        elif tag == 7:
            operands = ()
        elif tag == 8:
            operands = (reader.u16("AndEqz chain"), reader.u16("AndEqz inner"))
            mix_ref(operands[0], mix_count, name)
            field_ref(operands[1], field_count, name)
        else:
            operands = (reader.u16("AndCond chain"),
                        reader.u16("AndCond condition"),
                        reader.u16("AndCond inner"))
            mix_ref(operands[0], mix_count, name)
            field_ref(operands[1], field_count, name)
            mix_ref(operands[2], mix_count, name)

        operations.append((tag, operands))
        histogram[name] += 1
        if tag in (7, 8, 9):
            mix_count += 1
        else:
            field_count += 1

    fixed(field_count, FIELD_VARS, "derived PolyExt field-variable census")
    fixed(mix_count, MIX_VARS, "derived PolyExt mix-variable census")
    fixed(RET_MIX_VAR, mix_count - 1, "returned final mix-variable index")
    actual_histogram = {name: histogram[name] for name in OP_NAMES}
    require(actual_histogram == EXPECTED_HISTOGRAM,
            "PolyExt opcode histogram differs")
    return tuple(operations), actual_histogram


def decode(data: bytes) -> Artifact:
    fixed(len(data), ARTIFACT_BYTES, "artifact length")
    reader = Reader(data)
    read_fixed_header(reader)
    reverse_roots = read_field_values(reader, ROOT_COUNT, "reverse root")
    round_constants = read_field_values(reader, ROUND_CONSTANT_COUNT,
                                        "Poseidon2 round constant")
    internal_diagonal = read_field_values(reader, DIAGONAL_COUNT,
                                          "Poseidon2 diagonal constant")

    taps = tuple(
        tuple(reader.u8("tap record") for _ in range(5))
        for _ in range(TAP_COUNT)
    )
    register_count, combo_back_count = validate_taps(taps)
    operations, histogram = read_operations(reader)
    fixed(reader.offset, len(data), "strict EOF offset")

    return Artifact(
        reverse_roots=reverse_roots,
        round_constants=round_constants,
        internal_diagonal=internal_diagonal,
        taps=taps,
        operations=operations,
        histogram=histogram,
        register_count=register_count,
        combo_back_count=combo_back_count,
    )


def put_u16(output: bytearray, value: int) -> None:
    output.extend(struct.pack("<H", value))


def put_u32(output: bytearray, value: int) -> None:
    output.extend(struct.pack("<I", value))


def encode(artifact: Artifact) -> bytes:
    output = bytearray()
    put_u32(output, MODULUS)
    output.append(4)
    put_u32(output, 11)
    output.extend((27, 24, 16, 8, 4, 21, 7))
    put_u16(output, ROUND_CONSTANT_COUNT)
    output.extend((DIAGONAL_COUNT, 50, 4, 16, 4))
    put_u16(output, 256)
    output.extend((32, 20, 16))
    put_u16(output, TAP_COUNT)
    output.append(3)
    output.extend(GROUP_SIZES)
    output.extend((COMBO_COUNT, TOTAL_COMBO_BACKS))
    put_u16(output, OP_COUNT)
    put_u16(output, FIELD_VARS)
    put_u16(output, MIX_VARS)
    put_u16(output, RET_MIX_VAR)
    output.extend((0, 2, 1, 3, 0, 1, 2, 16, 16, 5, 3))
    output.extend(b"RISC0_STARK:v1__")
    output.extend(b"RECURSION:rev1v1")
    fixed(len(output), HEADER_BYTES, "re-encoded header length")

    for table in (artifact.reverse_roots, artifact.round_constants,
                  artifact.internal_diagonal):
        for value in table:
            put_u32(output, value)
    for tap in artifact.taps:
        output.extend(tap)
    for tag, operands in artifact.operations:
        output.append(tag)
        if tag in (0, 1):
            for value in operands:
                put_u32(output, value)
        else:
            for value in operands:
                put_u16(output, value)

    fixed(len(output), ARTIFACT_BYTES, "re-encoded artifact length")
    return bytes(output)


def verify(data: bytes, canonical: bool = True) -> Artifact:
    artifact = decode(data)
    require(encode(artifact) == data, "decode/re-encode is not byte-identical")
    if canonical:
        actual = hashlib.sha256(data).hexdigest()
        require(actual == CANONICAL_SHA256,
                "canonical SHA-256 mismatch: expected %s, got %s" %
                (CANONICAL_SHA256, actual))
    return artifact


def main(argv: Sequence[str]) -> int:
    arguments = list(argv)
    canonical = True
    if arguments and arguments[0] == "--grammar-only":
        canonical = False
        arguments.pop(0)
    require(len(arguments) <= 1,
            "usage: verify_constants.py [--grammar-only] [constants.bin]")
    path = (Path(arguments[0]) if arguments
            else Path(__file__).with_name("constants.bin"))
    data = path.read_bytes()
    artifact = verify(data, canonical=canonical)
    digest = hashlib.sha256(data).hexdigest()
    histogram = ", ".join(
        "%s=%d" % (name, artifact.histogram[name]) for name in OP_NAMES
    )
    print("B2 constants: %s" % ("canonical" if canonical else "grammar valid"))
    print("length: %d" % len(data))
    print("sha256: %s" % digest)
    print("taps: %d records, %d registers, %d combos, %d combo backs" %
          (len(artifact.taps), artifact.register_count, COMBO_COUNT,
           artifact.combo_back_count))
    print("polyext: %d ops, %d field vars, %d mix vars, ret %d" %
          (len(artifact.operations), FIELD_VARS, MIX_VARS, RET_MIX_VAR))
    print("histogram: " + histogram)
    print("reencode: byte-identical")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError) as error:
        print("B2 verification failed: %s" % error, file=sys.stderr)
        sys.exit(1)
