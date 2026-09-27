# B4 AMD64 startup-dependency closure V2: glibc relocation records

Policy ID: `eip0045-b4-elf64-amd64-startup-dependency-closure-v2`.

This policy extends the static startup-dependency closure in
`b4-oci-execution-policy-v1.md` for ELF64 AMD64 glibc DSOs. The V1 policy ID,
its accepted bytes, and its rejection behavior remain unchanged. V2 is a
separate policy choice. Until the physical rootfs reader, closure receipt,
positive gate, and profile schema select this ID together, a V2 parser result
is diagnostic only and cannot admit a B4 campaign.

The executable launcher and compiler continue to use the V1 runtime ELF
policy. A V2 DSO uses the V1 structural, dynamic-string, `DT_NEEDED`,
`DT_RUNPATH`, flag-mask, and resource bounds, except for the two explicit
extensions below. Every other unlisted dynamic tag still rejects, including
`DT_RPATH` and loader-directed audit, filter, and configuration tags.

## Closed glibc relocation records

V2 adds only these six `Elf64_Dyn` tag identities to the DSO parser:

| Triplet | Address tag | Byte-size tag | Entry-size tag |
| --- | --- | --- | --- |
| Relative relocations | `DT_RELR` (`0x24`) | `DT_RELRSZ` (`0x23`) | `DT_RELRENT` (`0x25`) |
| AMD64 PLT | `DT_X86_64_PLT` (`0x70000000`) | `DT_X86_64_PLTSZ` (`0x70000001`) | `DT_X86_64_PLTENT` (`0x70000003`) |

Each triplet is either wholly absent or present exactly once per tag. An
incomplete or repeated triplet rejects. Present triplets require a nonzero
byte size, a byte size divisible by the entry size, and an entry size of 8
bytes for RELR or 16 bytes for the AMD64 PLT. Their address and byte size
must map without overflow to one file-backed `PT_LOAD` range. The six raw
`(d_tag, d_un)` pairs and their distinct typed identities remain in dynamic
array order through the first `DT_NULL`. These checks bound the metadata and
preserve its identity; they do not prove relocation execution semantics.

## `PT_INTERP` on libc

The V1 rule excluding `PT_INTERP` from every DSO remains the default. V2
permits one `PT_INTERP` only when the DSO's sole `DT_SONAME` is exactly
`libc.so.6` and its canonical, NUL-terminated interpreter path is byte-equal
to the launcher interpreter path supplied by the closure. A different DSO,
malformed payload, duplicate interpreter segment, or unequal path rejects.
This exception does not make the DSO a new launcher or change closure
traversal. Selection of that path inside a descriptor-rooted rootfs and its
comparison with the exact launcher remain physical-consumer work.

The same independent runtime and loader gate described by the V1 policy is
still required before any H0 source or completion. A parser success alone
does not attest an OCI image, mount namespace, process mapping, or B4 result.
