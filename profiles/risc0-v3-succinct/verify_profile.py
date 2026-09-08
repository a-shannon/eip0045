#!/usr/bin/env python3
# Copyright 2026 A. Shannon
# SPDX-License-Identifier: Apache-2.0
"""Independent B3 manifest/package verifier using only the Python stdlib."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
from pathlib import Path
from typing import Any

MANIFEST_BYTES = 458
PROFILE_ID_PREIMAGE_BYTES = 485
DIGEST_BYTES = 32
EXACT_PROOF_BYTES = 222_668
MAX_APPLICATION_PAYLOAD_BYTES = 16_384
OUTER_PO2 = 18
ALGORITHM_KIND = 1
BINARY_DATA_KIND = 2
NORMAL_LIFT_CONTROL_KIND = 1
JOIN_CONTROL_KIND = 2
RESOLVE_CONTROL_KIND = 3
ARTIFACT_DOMAIN = b"Ergo.StarkProfileArtifact.v1"
PROFILE_ID_DOMAIN = b"Ergo.StarkProfileId.v1"
INNER_CONTROL_ROOT = bytes.fromhex(
    "a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56"
)
NORMAL_LIFT_CONTROL_IDS = tuple(
    bytes.fromhex(value)
    for value in (
        "1ca3ca03030719064ba61b3125bdd326fc57f74e799ef860bdea6f3227381e16",
        "c32b3627d2b3d60c64adf523a98bd16c0ff607471f3d6630d1f26d5e9406d841",
        "c9b08054994f542a6310b00d9b6fc6528ed7bb6f4ca5476a686847127cdfdc5b",
        "e7934a23ddce1423b425cf32aa23be29f48cd40e0b6ff9376dce6f3bf9d0bc35",
        "8c2fdd36ede09a4b9d316a43c51f1160cbd8876659c5f35810c3a119c60d3843",
        "34530b42028fb631c90e1226bb0e750d4b9b593840d45216f75dca449dac7734",
        "fd84d83092a1e1244d423a26d89c892ab098b467c6d82229912deb26e37d2562",
        "9d9dbf33535ab11f52a93839dfd23b352b7626009e81d9459fd04e488898ec6a",
    )
)
JOIN_CONTROL_ID = bytes.fromhex(
    "7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e"
)
RESOLVE_CONTROL_ID = bytes.fromhex(
    "53a7b23d07f99e5d5685e85874f5181e8486aa267a0ae607ffe9ba47c8bdda4a"
)
SUPPORTED_SEGMENT_PO2 = tuple(range(15, 23))
TERMINAL_CONTROLS = tuple(
    (NORMAL_LIFT_CONTROL_KIND, segment_po2, control_id)
    for segment_po2, control_id in zip(
        SUPPORTED_SEGMENT_PO2, NORMAL_LIFT_CONTROL_IDS, strict=True
    )
) + (
    (JOIN_CONTROL_KIND, 0, JOIN_CONTROL_ID),
    (RESOLVE_CONTROL_KIND, 0, RESOLVE_CONTROL_ID),
)
B2_SHA256 = "8c4a92b7d354890481eefdef233d4ca43f6bcd9f7cb00e4dd9e709da47789ef3"
B2_ARTIFACT_DIGEST = (
    "dd8528a8621edc8dd24aadeed7bd7a2f0c1afd88dd563c5ec8f51cc7f75df0b1"
)
MAX_ALGORITHM_BYTES = 1024 * 1024

ALGORITHM_FILE = "algorithm.txt"
BINARY_DATA_FILE = "constants.bin"
MANIFEST_FILE = "manifest.bin"
MANIFEST_JSON_FILE = "manifest.json"
ALGORITHM_PREIMAGE_FILE = "algorithm-artifact-preimage.bin"
BINARY_DATA_PREIMAGE_FILE = "binary-data-artifact-preimage.bin"
PROFILE_ID_PREIMAGE_FILE = "profile-id-preimage.bin"
PROFILE_ID_FILE = "profile-id.bin"


class VerificationError(ValueError):
    """One exact B3 invariant failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def blake2b256(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=DIGEST_BYTES).digest()


def artifact_preimage(kind: int, data: bytes) -> bytes:
    require(0 <= kind <= 0xFFFF, "artifact kind exceeds u16")
    require(len(data) <= 0xFFFFFFFF, "artifact length exceeds u32")
    return ARTIFACT_DOMAIN + b"\x00" + struct.pack("<HI", kind, len(data)) + data


def profile_id_preimage(manifest: bytes) -> bytes:
    require(len(manifest) == MANIFEST_BYTES, "manifest length is not 458")
    result = PROFILE_ID_DOMAIN + b"\x00" + struct.pack("<I", len(manifest)) + manifest
    require(len(result) == PROFILE_ID_PREIMAGE_BYTES, "profile-ID preimage length mismatch")
    return result


def validate_algorithm(data: bytes) -> None:
    require(0 < len(data) <= MAX_ALGORITHM_BYTES, "B1 length is outside 1..=1 MiB")
    require(not data.startswith(b"\xef\xbb\xbf"), "B1 has a UTF-8 BOM")
    require(b"\x00" not in data, "B1 contains NUL")
    require(b"\r" not in data, "B1 contains CR")
    require(data.isascii(), "B1 is not exact ASCII")
    require(data.endswith(b"\n"), "B1 does not end in LF")
    require(not data.endswith(b"\n\n"), "B1 has more than one final LF")


def validate_binary_data(data: bytes) -> None:
    require(len(data) == 65_119, "B2 length is not 65,119")
    require(sha256(data) == B2_SHA256, "B2 SHA-256 mismatch")
    require(data[19] == 50, "B2 query count is not 50")
    require(
        blake2b256(artifact_preimage(BINARY_DATA_KIND, data)).hex()
        == B2_ARTIFACT_DIGEST,
        "B2 domain-separated artifact digest mismatch",
    )


def artifact_reference(kind: int, data: bytes) -> bytes:
    return struct.pack("<HI", kind, len(data)) + blake2b256(artifact_preimage(kind, data))


def build_manifest(algorithm: bytes, binary_data: bytes) -> bytes:
    validate_algorithm(algorithm)
    validate_binary_data(binary_data)
    result = bytearray()
    result.append(1)
    result += struct.pack("<II", EXACT_PROOF_BYTES, MAX_APPLICATION_PAYLOAD_BYTES)
    result.append(OUTER_PO2)
    result += INNER_CONTROL_ROOT
    for control_kind, parameter, control_id in TERMINAL_CONTROLS:
        result.append(control_kind)
        result.append(parameter)
        result += control_id
    result += artifact_reference(ALGORITHM_KIND, algorithm)
    result += artifact_reference(BINARY_DATA_KIND, binary_data)
    require(len(result) == MANIFEST_BYTES, "constructed manifest length mismatch")
    return bytes(result)


def parse_manifest(data: bytes) -> dict[str, Any]:
    require(len(data) == MANIFEST_BYTES, "manifest length is not 458")
    offset = 0

    def take(count: int) -> bytes:
        nonlocal offset
        end = offset + count
        require(end <= len(data), f"unexpected manifest EOF at {offset}")
        value = data[offset:end]
        offset = end
        return value

    version = take(1)[0]
    require(version == 1, "manifest version is not 1")
    exact_proof_bytes, max_payload = struct.unpack("<II", take(8))
    require(exact_proof_bytes > 0, "manifest proof length is zero")
    outer_po2 = take(1)[0]
    inner_control_root = take(32)
    terminal_controls: list[dict[str, Any]] = []
    seen_control_ids: set[bytes] = set()
    for index, (expected_kind, expected_parameter, _) in enumerate(
        TERMINAL_CONTROLS
    ):
        control_kind = take(1)[0]
        parameter = take(1)[0]
        control_id = take(32)
        require(
            control_kind == expected_kind,
            f"terminal control kind mismatch at {index}",
        )
        require(
            parameter == expected_parameter,
            f"terminal control parameter mismatch at {index}",
        )
        require(
            control_id not in seen_control_ids,
            f"duplicate control ID at {index}",
        )
        seen_control_ids.add(control_id)
        terminal_controls.append(
            {
                "controlKind": control_kind,
                "parameter": parameter,
                "controlId": control_id.hex(),
                "controlIdBytes": control_id,
            }
        )

    artifacts: list[dict[str, Any]] = []
    for index, expected_kind in enumerate((ALGORITHM_KIND, BINARY_DATA_KIND)):
        kind, length = struct.unpack("<HI", take(6))
        digest = take(32)
        require(kind == expected_kind, f"artifact kind mismatch at {index}")
        require(length > 0, f"artifact length is zero at {index}")
        artifacts.append({"kind": kind, "length": length, "digest": digest})
    require(offset == MANIFEST_BYTES, "manifest decoder did not reach exact EOF")

    require(exact_proof_bytes == EXACT_PROOF_BYTES, "initial exactProofBytes mismatch")
    require(max_payload == MAX_APPLICATION_PAYLOAD_BYTES, "initial payload limit mismatch")
    require(outer_po2 == OUTER_PO2, "initial outerPo2 mismatch")
    require(inner_control_root == INNER_CONTROL_ROOT, "initial inner control root mismatch")
    decoded_terminal_controls = tuple(
        (item["controlKind"], item["parameter"], item["controlIdBytes"])
        for item in terminal_controls
    )
    require(
        decoded_terminal_controls == TERMINAL_CONTROLS,
        "initial terminal-control table mismatch",
    )

    encoded = bytearray([version])
    encoded += struct.pack("<II", exact_proof_bytes, max_payload)
    encoded.append(outer_po2)
    encoded += inner_control_root
    for item in terminal_controls:
        encoded.append(item["controlKind"])
        encoded.append(item["parameter"])
        encoded += item["controlIdBytes"]
    for item in artifacts:
        encoded += struct.pack("<HI", item["kind"], item["length"])
        encoded += item["digest"]
    require(bytes(encoded) == data, "manifest decode/re-encode mismatch")
    return {
        "version": version,
        "exactProofBytes": exact_proof_bytes,
        "maxApplicationPayloadBytes": max_payload,
        "outerPo2": outer_po2,
        "innerControlRoot": inner_control_root,
        "terminalControls": terminal_controls,
        "artifacts": artifacts,
    }


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def build_material(algorithm: bytes, binary_data: bytes) -> dict[str, bytes]:
    manifest = build_manifest(algorithm, binary_data)
    parsed = parse_manifest(manifest)
    algorithm_preimage = artifact_preimage(ALGORITHM_KIND, algorithm)
    binary_preimage = artifact_preimage(BINARY_DATA_KIND, binary_data)
    id_preimage = profile_id_preimage(manifest)
    profile_id = blake2b256(id_preimage)
    artifacts = parsed["artifacts"]
    terminal_controls = parsed["terminalControls"]
    view = {
        "artifacts": [
            {
                "artifactDigest": artifacts[0]["digest"].hex(),
                "artifactKind": ALGORITHM_KIND,
                "artifactLength": len(algorithm),
                "artifactPreimageFile": ALGORITHM_PREIMAGE_FILE,
                "artifactPreimageSha256": sha256(algorithm_preimage),
                "file": ALGORITHM_FILE,
                "role": "normative-algorithm",
            },
            {
                "artifactDigest": artifacts[1]["digest"].hex(),
                "artifactKind": BINARY_DATA_KIND,
                "artifactLength": len(binary_data),
                "artifactPreimageFile": BINARY_DATA_PREIMAGE_FILE,
                "artifactPreimageSha256": sha256(binary_preimage),
                "file": BINARY_DATA_FILE,
                "role": "normative-binary-data",
            },
        ],
        "terminalControls": [
            {
                "controlId": item["controlId"],
                "controlKind": item["controlKind"],
                "parameter": item["parameter"],
            }
            for item in terminal_controls
        ],
        "exactProofBytes": EXACT_PROOF_BYTES,
        "format": "StarkProfileManifestV1",
        "formatVersion": 1,
        "innerControlRoot": INNER_CONTROL_ROOT.hex(),
        "manifestBytes": MANIFEST_BYTES,
        "manifestSha256": sha256(manifest),
        "maxApplicationPayloadBytes": MAX_APPLICATION_PAYLOAD_BYTES,
        "outerPo2": OUTER_PO2,
        "profileId": profile_id.hex(),
        "profileIdFile": PROFILE_ID_FILE,
        "profileIdPreimageBytes": PROFILE_ID_PREIMAGE_BYTES,
        "profileIdPreimageFile": PROFILE_ID_PREIMAGE_FILE,
        "profileIdPreimageSha256": sha256(id_preimage),
    }
    return {
        MANIFEST_FILE: manifest,
        MANIFEST_JSON_FILE: canonical_json(view),
        ALGORITHM_PREIMAGE_FILE: algorithm_preimage,
        BINARY_DATA_PREIMAGE_FILE: binary_preimage,
        PROFILE_ID_PREIMAGE_FILE: id_preimage,
        PROFILE_ID_FILE: profile_id,
    }


def read_regular(path: Path, minimum: int, maximum: int) -> bytes:
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode), f"not a regular non-link file: {path}")
    require(minimum <= metadata.st_size <= maximum, f"invalid byte length for {path}")
    data = path.read_bytes()
    require(len(data) == metadata.st_size, f"file changed while being read: {path}")
    return data


def read_artifacts(profile_dir: Path) -> tuple[bytes, bytes]:
    algorithm = read_regular(profile_dir / ALGORITHM_FILE, 1, MAX_ALGORITHM_BYTES)
    binary_data = read_regular(profile_dir / BINARY_DATA_FILE, 65_119, 65_119)
    return algorithm, binary_data


def read_material(bundle_dir: Path) -> dict[str, bytes]:
    limits = {
        MANIFEST_FILE: (MANIFEST_BYTES, MANIFEST_BYTES),
        MANIFEST_JSON_FILE: (1, 64 * 1024),
        ALGORITHM_PREIMAGE_FILE: (1, MAX_ALGORITHM_BYTES + 64),
        BINARY_DATA_PREIMAGE_FILE: (1, 65_119 + 64),
        PROFILE_ID_PREIMAGE_FILE: (
            PROFILE_ID_PREIMAGE_BYTES,
            PROFILE_ID_PREIMAGE_BYTES,
        ),
        PROFILE_ID_FILE: (DIGEST_BYTES, DIGEST_BYTES),
    }
    return {
        name: read_regular(bundle_dir / name, minimum, maximum)
        for name, (minimum, maximum) in limits.items()
    }


def verify_material(
    algorithm: bytes, binary_data: bytes, supplied: dict[str, bytes]
) -> dict[str, bytes]:
    expected = build_material(algorithm, binary_data)
    require(set(supplied) == set(expected), "derived B3 output set mismatch")
    for name, expected_bytes in expected.items():
        require(supplied[name] == expected_bytes, f"{name} mismatch")
    parsed_json = json.loads(supplied[MANIFEST_JSON_FILE])
    require(
        canonical_json(parsed_json) == supplied[MANIFEST_JSON_FILE],
        "manifest.json is not canonical",
    )
    parsed = parse_manifest(supplied[MANIFEST_FILE])
    require(
        parsed["artifacts"][0]["length"] == len(algorithm),
        "B1 length reference mismatch",
    )
    require(
        parsed["artifacts"][1]["length"] == len(binary_data),
        "B2 length reference mismatch",
    )
    return expected


def verify_directory(profile_dir: Path, bundle_dir: Path) -> dict[str, bytes]:
    algorithm, binary_data = read_artifacts(profile_dir)
    return verify_material(algorithm, binary_data, read_material(bundle_dir))


def self_test(profile_dir: Path) -> None:
    require(MANIFEST_BYTES == 458, "Manifest V1 target length is not 458")
    require(
        PROFILE_ID_PREIMAGE_BYTES == 485,
        "profile-ID preimage target length is not 485",
    )
    require(
        len(TERMINAL_CONTROLS) == 10,
        "terminal-control target count is not ten",
    )
    require(
        tuple((kind, parameter) for kind, parameter, _ in TERMINAL_CONTROLS)
        == tuple((NORMAL_LIFT_CONTROL_KIND, po2) for po2 in range(15, 23))
        + ((JOIN_CONTROL_KIND, 0), (RESOLVE_CONTROL_KIND, 0)),
        "terminal-control kind/parameter order is not canonical",
    )

    algorithm, binary_data = read_artifacts(profile_dir)
    expected = build_material(algorithm, binary_data)
    verify_material(algorithm, binary_data, expected)

    for name in expected:
        changed = dict(expected)
        value = bytearray(changed[name])
        value[0] ^= 1
        changed[name] = bytes(value)
        try:
            verify_material(algorithm, binary_data, changed)
        except VerificationError:
            pass
        else:
            raise VerificationError(f"negative mutation escaped for {name}")

    changed_b2 = bytearray(binary_data)
    changed_b2[100] ^= 1
    try:
        build_material(algorithm, bytes(changed_b2))
    except VerificationError:
        pass
    else:
        raise VerificationError("mutated B2 escaped authentication")

    try:
        parse_manifest(expected[MANIFEST_FILE][:-1])
    except VerificationError:
        pass
    else:
        raise VerificationError("short manifest escaped exact-length gate")

    try:
        parse_manifest(expected[MANIFEST_FILE] + b"\x00")
    except VerificationError:
        pass
    else:
        raise VerificationError("long manifest escaped exact-length gate")

    first_terminal_offset = 42
    wrong_kind = bytearray(expected[MANIFEST_FILE])
    wrong_kind[first_terminal_offset] = JOIN_CONTROL_KIND
    try:
        parse_manifest(bytes(wrong_kind))
    except VerificationError:
        pass
    else:
        raise VerificationError("wrong terminal kind escaped fixed-position gate")

    wrong_parameter = bytearray(expected[MANIFEST_FILE])
    wrong_parameter[first_terminal_offset + 1] = 14
    try:
        parse_manifest(bytes(wrong_parameter))
    except VerificationError:
        pass
    else:
        raise VerificationError("wrong terminal parameter escaped canonical gate")

    duplicate_id = bytearray(expected[MANIFEST_FILE])
    first_id_offset = first_terminal_offset + 2
    second_id_offset = first_terminal_offset + 34 + 2
    duplicate_id[second_id_offset : second_id_offset + DIGEST_BYTES] = duplicate_id[
        first_id_offset : first_id_offset + DIGEST_BYTES
    ]
    try:
        parse_manifest(bytes(duplicate_id))
    except VerificationError:
        pass
    else:
        raise VerificationError("duplicate terminal ID escaped uniqueness gate")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify", help="verify six existing B3 outputs")
    verify.add_argument("--profile-dir", type=Path, required=True)
    verify.add_argument("--bundle-dir", type=Path, required=True)
    test = subparsers.add_parser(
        "self-test", help="derive in memory and run negative tests without writing B3"
    )
    test.add_argument("--profile-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "verify":
            material = verify_directory(args.profile_dir, args.bundle_dir)
            print(f"manifest sha256={sha256(material[MANIFEST_FILE])}")
            print(f"profileId={material[PROFILE_ID_FILE].hex()}")
        else:
            self_test(args.profile_dir)
            print("B3 independent self-test passed; no files written")
    except (OSError, VerificationError, UnicodeError, json.JSONDecodeError) as error:
        print(f"B3 verification failed: {error}", file=os.sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
