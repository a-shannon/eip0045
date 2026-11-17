"""Build the public inputs for the EIP-0045 lift-15 demonstration."""

import argparse
import hashlib
from pathlib import Path


CHAIN_DOMAIN = bytes.fromhex(
    "b0244dfc267baca974a4caee06120321562784303a8a688976ae56170e4d175b"
)
PAYLOAD = b"Ergo EIP-0045 local demo v3.1.0"
DOMAIN = b"Ergo.VerifyStark.Statement"


def statement_bundle(program_id: bytes, profile_id: bytes) -> dict[str, bytes]:
    if len(program_id) != 32 or len(profile_id) != 32:
        raise ValueError("program and profile IDs must each be 32 bytes")
    # Canonical reference ErgoTree with program and profile constants in wire order.
    proposition = (
        bytes.fromhex("1c53020e20") + program_id
        + bytes.fromhex("0e20") + profile_id
        + bytes.fromhex("d1b9e4e3001ae4e3010e73007301")
    )
    contract_id = hashlib.blake2b(proposition, digest_size=32).digest()
    prefix = DOMAIN + b"\x01" + CHAIN_DOMAIN + profile_id + program_id + contract_id
    changed = PAYLOAD[:-1] + b"1"
    return {
        "program-id.bin": program_id,
        "profile-id.bin": profile_id,
        "chain-domain-id.bin": CHAIN_DOMAIN,
        "proposition.bin": proposition,
        "contract-id.bin": contract_id,
        "application-payload.bin": PAYLOAD,
        "changed-payload.bin": changed,
        "statement.bin": prefix + len(PAYLOAD).to_bytes(4, "little") + PAYLOAD,
        "changed-statement.bin": prefix + len(changed).to_bytes(4, "little") + changed,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program_id", help="32-byte guest image ID in hex")
    parser.add_argument("profile_id", help="32-byte EIP profile ID in hex")
    parser.add_argument("out", type=Path, help="new directory for the fixture inputs")
    args = parser.parse_args()
    files = statement_bundle(bytes.fromhex(args.program_id), bytes.fromhex(args.profile_id))
    args.out.mkdir(parents=True, exist_ok=False)
    for name, data in files.items():
        (args.out / name).write_bytes(data)


if __name__ == "__main__":
    main()
