# B4 OCI execution policy V1

This document defines the closed container-image and seccomp subset used by the
EIP-0045 B4 reproduction. It is normative for B4. It is deliberately narrower
than a general OCI image importer and must not be presented as one.

The machine-readable document shapes are:

- `Eip0045B4PositiveOciRunnerProfileV1`; and
- `Eip0045B4PositiveSeccompV1`.

JSON Schema validates their local shape. The finalizer-executor is responsible
for the byte, archive, graph, filesystem, kernel, and cross-document checks
below. Schema validation alone never authorizes extraction or execution.

## Pinned authority

B4 uses these exact upstream specifications:

- [OCI Image Specification 1.1.1, commit
  `147f9c13cedb47a0c4d9a11a222961073d585877`](https://github.com/opencontainers/image-spec/tree/147f9c13cedb47a0c4d9a11a222961073d585877);
- [OCI Runtime Specification 1.3.0, commit
  `92249139eea7161e13745abd4cb6d0ea02a3227a`](https://github.com/opencontainers/runtime-spec/tree/92249139eea7161e13745abd4cb6d0ea02a3227a);
- OCI image-layout marker version `1.0.0`; and
- Linux amd64 only.

Those pins identify the upstream vocabulary. The additional exclusions and
canonical encodings below are B4 rules.

## Image identity carried by a runner profile

`image.policy` is `eip0045-b4-oci-image-v1`. The profile binds the complete
archive bytes, the pinned Image Specification, layout version, the selected
manifest descriptor, its config descriptor, every ordered compressed layer
descriptor, every corresponding uncompressed DiffID, and the post-changeset
rootfs counts.

`image.retainedHostRootfsMetadataPolicy` is
`eip0045-b4-retained-host-rootfs-metadata-obligations-v1`. It binds the closed
retained-host metadata vocabulary below to the same runner role. The profile
member and its gate projection are inert expectations: neither is an
observation, a filesystem-support claim, or authority to launch, mount, mint
H0, complete B4, or report readiness.

Each `image.layers[i]` is one ordered tuple:

```text
(mediaType, compressed digest, compressed size,
 uncompressed tar byte length, uncompressed DiffID)
```

The tuple avoids an ambiguous zip between independently declared layer and
DiffID arrays. The finalizer requires the manifest layer at position `i` to
match the compressed descriptor and the config `rootfs.diff_ids[i]` to match
the tuple's DiffID. Repeated compressed digests or DiffIDs reject.

`postChangesetRootfs` describes the state after all layers have been applied.
`entryCount` excludes the root itself and equals the sum of regular-file,
directory, and symbolic-link counts. `regularFileBytes` is the sum of the exact
payload lengths of regular files in that final state; directory metadata and
symbolic-link target text contribute zero bytes. The finalizer rederives all
five values rather than trusting them as allocation authority.
A separate self-declared rootfs digest is unnecessary: the bound archive plus
the deterministic changeset rules derive the rootfs, while these counts provide
independent bounded-consumption checks.

## Closed outer archive

`image.archive.encoding` is
`eip0045-b4-oci-image-layout-ustar-v1`. The archive is an uncompressed POSIX
ustar subset with all of these properties:

1. Every entry is a regular file. There are no directory, link, device, FIFO,
   socket, sparse, PAX, GNU-extension, or concatenated-archive records.
2. Entry names are ASCII, have no leading `./` or slash, fit entirely in the
   100-byte ustar name field, and have an empty prefix field.
3. Names are strictly increasing by unsigned ASCII byte order and are exactly
   `oci-layout`, `index.json`, and `blobs/sha256/<64-lowercase-hex>` for every
   and only the blobs reachable from the selected manifest. There are no
   unreferenced blobs or additional files. Consequently, all `blobs/...`
   records precede `index.json`, which precedes `oci-layout`.
4. Header mode is `0644`, numeric UID and GID are zero, mtime is zero, uname and
   gname are empty, linkname is empty, and device-major and device-minor are
   zero. The typeflag is ASCII `0`. Magic is the six bytes `ustar` followed by
   NUL and version is `00`.
5. Header checksum, declared size, payload, and zero padding are checked before
   advancing. The archive ends with exactly two 512-byte zero blocks followed
   immediately by EOF. Prefixes, suffixes, nonzero padding, and further members
   reject.

The profile's `archive.byteLength` is the exact length implied by this closed
member set, not merely an independent upper bound. For a payload of `n` bytes,
one member occupies `512 + ceil(n / 512) * 512` bytes. The final length is 1,024
terminator bytes plus that extent for the fixed `oci-layout` payload, the RFC
8785 `index.json` derived from the profile's manifest descriptor and platform,
the manifest blob, the config blob, and every ordered layer blob. All additions
and 512-byte roundings use checked unsigned arithmetic. A single descriptor or
an aggregate blob set that cannot fit the declared archive therefore rejects
before the archive is opened.

For both this archive and the layer ustar streams, mode, UID, GID, device-major,
and device-minor fields are exactly seven zero-padded octal digits plus NUL;
size and mtime are exactly eleven zero-padded octal digits plus NUL. Base-256,
space-terminated, negative, overflowed, and other alternatives reject. The
checksum field is exactly six zero-padded octal digits, NUL, and space; its
value is the unsigned sum of the complete header with all eight checksum bytes
treated as ASCII spaces. Unused string bytes and payload padding are NUL.
Because an eleven-digit octal size field represents at most octal
`77777777777`, one ustar member payload is at most 8,589,934,591 bytes. A
declared size of 8,589,934,592 bytes, any twelfth digit, or a non-octal
representation rejects before payload allocation. The larger bound on the
complete outer archive is only an aggregate bound over multiple members; it
does not enlarge this per-member limit.

The exact `oci-layout` payload is the UTF-8 byte sequence:

```json
{"imageLayoutVersion":"1.0.0"}
```

`index.json`, the manifest blob, and the config blob are RFC 8785 canonical
JSON, contain no duplicate keys, and have these closed semantic forms:

- `index.json` has exactly `schemaVersion: 2`, media type
  `application/vnd.oci.image.index.v1+json`, and one manifest descriptor. That
  descriptor has exactly media type, digest, size, and platform; platform is
  exactly Linux amd64.
- The selected manifest has exactly `schemaVersion: 2`, media type
  `application/vnd.oci.image.manifest.v1+json`, one config descriptor, and the
  nonempty ordered layer-descriptor array. There is no nested index, URL,
  annotation, data field, artifact type, or subject.
- The config has exactly `architecture: amd64`, `os: linux`, and
  `rootfs: {type: "layers", diff_ids: [...]}`. Entrypoint, command,
  environment, user, working directory, history, creation time, and author are
  absent; the finalizer supplies execution state independently.
- Config and layer descriptors use exactly the media types fixed by schema.
  Every digest is `sha256:<64-lowercase-hex>`. Each descriptor size equals the
  referenced blob length, and its digest equals SHA-256 of those exact bytes.

The profile's `manifest` fields `(mediaType, digest, size)` must equal those
three fields in the sole index descriptor, and `image.platform` must equal that
descriptor's `platform`. The profile's `config` descriptor must equal the
manifest's config descriptor. These are member-wise comparisons of the parsed
RFC 8785 values; the index descriptor additionally contains `platform`, whereas
the profile keeps platform as a separate field. The finalizer hashes each blob
while reading it through a declared-size bound and requires EOF.

## Layer stream and changeset policy

Every layer media type is
`application/vnd.oci.image.layer.v1.tar+gzip`. Its blob is exactly one RFC 1952
gzip member using an RFC 1951 deflate stream. Its ten-byte header is exact:
ID1/ID2 are `1f 8b`, CM is `08`, FLG is `00`, MTIME is four zero bytes, XFL is
`00`, and OS is `ff`. Therefore no FEXTRA, FNAME, FCOMMENT, FHCRC, reserved
flag, implementation timestamp, or platform-dependent header byte is accepted.
A second member and trailing bytes reject. The finalizer checks the header,
bounded inflate, CRC32, ISIZE equal to `uncompressedBytes mod 2^32`, immediate
EOF, declared `uncompressedBytes`, and SHA-256 of the complete uncompressed tar
stream. That SHA-256 is the DiffID. The compressed blob is also one outer-ustar
member and is therefore at most 8,589,934,591 bytes. The sum of all declared
uncompressed layer lengths is at most 34,359,738,368 bytes.

The uncompressed stream is itself a restricted ustar changeset:

- entry paths are valid UTF-8, at most 240 bytes, NUL-free, relative, and
  canonical after removing the one required trailing slash on a directory;
  empty, `.`, `..`, repeated-slash, and above-root paths reject;
- the ustar typeflag is ASCII `0`, `5`, or `2` for a regular file, directory,
  or symbolic link respectively; a path of at most 100 bytes uses the name
  field and an empty prefix, while a longer path is split at the rightmost slash
  before a nonempty final component that leaves a prefix of at most 155 bytes
  and a name of at most 100 bytes; a directory's terminal slash remains in the
  name field, and any other encoding of the same path rejects;
- normalized paths are strictly increasing by unsigned UTF-8 byte order and
  unique within the layer;
- only regular files, directories, and symbolic links are accepted; hard
  links, devices, sockets, FIFOs, sparse data, xattrs, PAX, GNU extensions, and
  special permission bits reject;
- numeric UID and GID are exactly 65,532, uname and gname are empty, mtime is
  zero, regular-file mode is `0444` or `0555`, directory mode is `0555`, and
  symbolic-link mode is `0777`; directories and symbolic links have zero
  payload size, and a symbolic-link target is at most 100 UTF-8 bytes and is
  carried only in linkname;
- payload size, header checksum, padding, two-block terminator, and immediate
  EOF are checked exactly as for the outer archive; and
- one regular-file payload is at most 1,073,741,824 bytes, and the aggregate
  across all layers is at most 1,000,000 tar entries and the declared
  34,359,738,368 uncompressed bytes; those bounds are checked while streaming,
  before materialization can exceed them.

A whiteout is the sole exception to the regular-file mode rule: it is a
zero-length, mode-`0000` regular entry named `.wh.<basename>` or
`.wh..wh..opq`. Before applying any non-whiteout entry, the executor validates
the complete layer and takes the already materialized lower-rootfs state as the
whiteout reference snapshot. For `d/.wh.<basename>`, the target is exactly
`d/<basename>` in that snapshot; it must exist and is removed with its complete
subtree when it is a directory. For `d/.wh..wh..opq`, `d` itself must be an
existing lower-layer directory and every lower-layer descendant of `d` is
removed, while `d` remains. At the archive root, `.wh..wh..opq` applies the
same rule to the root directory. All whiteouts are applied as one first phase;
the remaining entries are then applied in their validated archive order. A
same-layer entry may recreate a path removed from the lower snapshot, including
below an opaque directory, but a whiteout cannot target an entry that exists
only in its own layer. A missing or wrong-type snapshot target, conflicting
whiteouts, malformed `.wh.` name, materialized marker, or marker remaining in
the final rootfs rejects.

Conflict detection uses an affected subtree, not merely the set of descendants
that happen to exist. The affected subtree of `d/.wh.<basename>` is its target
path and every possible descendant. The affected subtree of
`d/.wh..wh..opq` is the subject directory `d` itself and every possible
descendant; the root marker's affected subtree is the complete root. Two
whiteouts conflict exactly when those affected subtrees intersect, equivalently
when either subtree root is equal to or an ancestor of the other. This remains
true when the opaque directory is empty. It consequently rejects deleting a
directory while making that directory opaque, nested opaque markers, and a root
opaque marker combined with any other whiteout. Disjoint sibling subtrees do
not conflict.

Changesets are applied in manifest order under an absent staging root with
descriptor-relative, no-follow filesystem operations. No archive entry may
cause a write through a symbolic link. When a non-directory replaces an
existing entry, the prior entry is removed before creation; when a directory
replaces a directory, its attributes are replaced. Type conflicts, aliases,
and inconsistent parent state reject rather than being repaired.

A symbolic-link target is interpreted only in the container-root namespace.
Absolute targets are anchored at that root; relative targets are resolved from
the link's parent. Lexical resolution may not step above the root. A dangling
link is allowed when no bound execution path traverses it. Every traversed
bound path, including `/runtime/bin/java`, must resolve through at most 40
symbolic-link hops in a cycle-free, root-contained chain to one regular file
whose bytes match the declared identity. Resolution of hop 41, repeated inode
identity, repeated normalized path, an above-root step, or a non-regular final
target rejects. This permits harmless image links such as an untraversed
`/etc/mtab` link without permitting host traversal.

The final rootfs has only the three declared entry types, every entry retains
container-visible UID/GID 65,532, and the recomputed post-changeset counts equal
the runner profile. A count, type, ownership, mode, layer digest, DiffID, or
bound-path mismatch refuses the run.

The staging root is created with an implicit root directory that is not counted
in `postChangesetRootfs`; its final metadata is mode `0555`, UID/GID 65,532,
and mtime zero. Every materialized entry also has mtime zero. After all payloads
and whiteouts are applied, the finalizer reapplies directory metadata from
deepest directory to root so host-side child creation cannot alter a directory
mtime.

The retained-host extended-metadata obligation is closed rather than an
open-ended ban on “other metadata”. For the staging root and every materialized
entry, version 1 prohibits exactly these eleven atomic classes:

1. `xattr-name-set`: any extended-attribute name visible to the complete
   observer context below;
2. `posix-access-acl`: the POSIX access-ACL representation
   `system.posix_acl_access`;
3. `posix-default-acl`: the POSIX default-ACL representation
   `system.posix_acl_default`;
4. `linux-file-capability`: the Linux file-capability representation
   `security.capability`;
5. `immutable`: immutable inode state;
6. `append-only`: append-only inode state;
7. `encrypted`: encrypted inode state;
8. `verity`: verity inode state;
9. `casefold`: casefold inode state;
10. `nonzero-project-id`: a nonzero project identifier; and
11. `project-inherit`: project-inherit state.

The two ACL and file-capability representations are classified independently
from the aggregate extended-attribute name set, so one result cannot mask
another class.

A filesystem that can represent an ACL outside the two named POSIX forms is
`unsupported` for version 1; the policy does not infer cross-filesystem ACL
equivalence.

Each prohibited class for each retained inode has exactly one future outcome:
`absent`, `present`, `unsupported`, `inaccessible`, `oversize`, or `unstable`.
Only `absent` satisfies the policy. These lower-case spellings are exhaustive
and case-sensitive; no synonym, missing result, partial result, or acquisition
error means absence. `unsupported` includes a kernel, filesystem, or safe-API
surface that cannot decide the class. `inaccessible` includes any credential,
namespace, capability, or LSM context that can hide it. `oversize` includes a
source or aggregate result above the bound fixed by a separately versioned
producer contract. `unstable` includes identity, observer-context, size, or
result drift after the retry count fixed by that producer contract. This policy
does not select those numerical bounds or that retry count and cannot classify
an outcome without the future producer.

A later producer may emit `absent` only for a fresh, controlled, non-overlay
filesystem and mount whose metadata vocabulary is closed, and only after it
binds the observer's user namespace, effective UID/GID, filesystem UID/GID
(`fsuid`/`fsgid`), supplementary groups, capabilities, and LSM context.
One non-binding candidate elaboration of that future producer's
fresh-filesystem custody problem is
[`eip0045-b4-fresh-filesystem-custody-v1`](b4-fresh-filesystem-custody-v1.md).
The current profile, schema, and gate do not bind that identifier. It is not an
observation, does not select a production backend, and cannot mint `absent`,
H0, or B4 completion. A later live affine capability cannot be replaced by a
serialized receipt.
Acquisition is bounded,
descriptor-rooted, and no-follow for the root and every entry, including the
symbolic link itself, with inode custody and observer context revalidated before
and after the complete result. An empty `listxattr` result alone is
insufficient because names inaccessible to the observer may be omitted. No
errno or unsupported operation is absence. The producer may not add, remove,
or repair metadata or acquire extra privilege to manufacture an accepted
outcome. Until that producer backend and its safe symbolic-link ABI are
selected, pinned, and implemented, the gate projects only the inert policy
expectation and full metadata closure remains blocked.

Version 1 deliberately excludes atime, ctime, btime, allocation block counts,
block size, extent layout or count, compression, DAX, NODUMP, atomic-write
hints, automount and mount-root topology, and filesystem-specific storage or
quota facts other than the project fields named above. Inode, device, and mount
identities may support affine custody but are not profile equality fields.
Effective LSM labels, process capabilities,
container-visible UID/GID mapping, readonly-mount state, overlay lower or
copy-up state, and the later runtime mount view are separate contracts and are
not established here. Adding any excluded member to acceptance requires a new
policy identifier; version 1 may not be reinterpreted in place.

Every prescribed mount target and parent already exists in that bound rootfs
with the required type. A bind-file target is a zero-length regular placeholder;
a bind-directory or virtual-filesystem target is a directory. Neither the
finalizer nor `runc` may create, replace, or repair a missing target. Runtime
mounts overlay these counted placeholders without changing the underlying
post-changeset inventory.

The underlying `/dev` is a mode-`0555` directory and has exactly five
zero-length regular placeholders below it: `/dev/full`, `/dev/null`,
`/dev/random`, `/dev/urandom`, and `/dev/zero`; it has no other descendant.
At launch those files are overlaid by host character devices whose measured
major/minor pairs are respectively `1:7`, `1:3`, `1:8`, `1:9`, and `1:5`.
Device type, target, major, minor, and no-alias identity are checked before and
after `runc create`. `/proc`, `/tmp`, every role mount target, and all their
parents likewise pre-exist with the types prescribed by the profile.

## Common ELF64 inspection policy

Every native executable identity used by this reproduction is parsed from its
exact measured bytes before launch; matching a magic prefix is insufficient.
The common policy `eip0045-b4-elf64-amd64-structural-v1` applies to the bound
`runc`, the native Rust validator described by its build descriptor, and the
Java launcher. It accepts only this closed structural subset:

1. `e_ident` is ELF magic, class ELFCLASS64, data ELFDATA2LSB, version
   EV_CURRENT, OS ABI ELFOSABI_SYSV or ELFOSABI_LINUX, ABI version zero, and
   seven zero padding bytes. `e_type` is ET_EXEC or ET_DYN, `e_machine` is
   EM_X86_64, `e_version` is EV_CURRENT, and `e_ehsize` is 64.
2. There are 1 through 65,534 program headers, `e_phentsize` is 56, and the
   complete table is in the file under checked unsigned arithmetic. PN_XNUM and
   every other extended-numbering escape are rejected. A section table may be
   absent only as the exact tuple `(e_shoff, e_shentsize, e_shnum,
   e_shstrndx) = (0, 0, 0, 0)`. When present, it has 1 through 65,279 directly
   encoded entries, `e_shentsize` is 64, the complete nonempty table is in the
   file, entry zero is the exact all-zero SHT_NULL header, `e_shstrndx` is
   SHN_UNDEF or a valid ordinary index, and SHN_XINDEX is rejected.
3. Every program-header file range is bounds-checked. Each PT_LOAD has
   `p_filesz <= p_memsz`; `p_align` is zero, one, or a power of two; and, when
   greater than one, `p_vaddr mod p_align == p_offset mod p_align`. At least one
   PT_LOAD is readable, the entry point lies in an executable PT_LOAD, no
   PT_LOAD is both writable and executable, and no two PT_LOAD file ranges
   overlap except for a shared zero-length boundary.
4. There is at most one PT_INTERP, one PT_DYNAMIC, and one PT_GNU_STACK.
   PT_GNU_STACK is required and is not executable. PT_SHLIB is rejected.
   Program-header types not named here remain accepted only as inert structural
   metadata whose file range has passed the common bounds; they do not relax
   any load-segment rule.
5. If section headers exist, every non-NOBITS section range is bounds-checked,
   every `sh_link` or `sh_info` that is an index for that section type is
   validated, and the selected section-name string table is parsed through its
   declared end. Section names do not decide runtime identity or linkage.

The policy uses no section name, tool output, or host `file` command as a
substitute for these checks. It does not claim source provenance or native-code
correctness; those remain build, source-review, and differential obligations.

Each identity carries a rederived `elf` projection: common policy, ELF type,
OS ABI, program-header count, section-header count, load count, executable-load
count, entry-point containment, interpreter/dynamic/GNU-stack counts, and the
zero counts for writable-executable loads, executable stacks, overlapping load
ranges, extended numbering, and structural parse failures. A runtime-linked
identity additionally records the interpreter path, dynamic-entry count, and
DT_NEEDED count. The finalizer recomputes these values from the same bytes whose
length and SHA-256 are bound. It also requires executable-load count not to
exceed load count and every categorized segment count not to exceed the total
program-header count.

The `runc` binary and native validator additionally use
`eip0045-b4-elf64-amd64-static-v1`: PT_INTERP and PT_DYNAMIC are both absent.
This is the exact meaning of `static-no-interpreter`; a dynamically linked or
static-PIE binary with a dynamic segment is outside V1.

The Java launcher uses `eip0045-b4-elf64-amd64-runtime-v1`. It has exactly one
PT_INTERP and one PT_DYNAMIC. The interpreter payload is 2 through 241 bytes,
ends in exactly one NUL, and the preceding bytes are a canonical printable-
ASCII absolute path of at most 240 bytes with no empty, `.`, or `..` segment.
It resolves under the staged container root, using the same 40-hop rule, to a
regular mode-`0555` file already bound by the image. The dynamic array consists
of complete 16-byte Elf64_Dyn records. Inspection stops at the first DT_NULL,
which is included in `dynamicEntryCount`; that count is 1 through 65,534.
Complete records after the first DT_NULL are inert padding and are not counted.
Before that first terminator there is at most one DT_STRTAB and at most one
DT_STRSZ. `neededLibraryCount` is at most 4,096. `DT_RPATH` rejects before its
value is dereferenced. Any accepted dynamic string-table range that is
dereferenced, including every DT_NEEDED, DT_SONAME, or DT_RUNPATH value, is
mapped through exactly one file-backed PT_LOAD range and is NUL-terminated
within the declared table. V1 rejects DT_CONFIG,
DT_DEPAUDIT, DT_AUDIT, DT_AUXILIARY, and DT_FILTER rather than allowing those
tags to alter loader or dependency selection. The launcher receives no `LD_*`
environment variable, and the static algorithm below never searches host
libraries or loader caches. This statement does not classify later explicit
mounts or application-directed loads as part of that static algorithm.

### Closed static ELF startup-dependency closure

Each `buildJdk` and `javaRuntime` object requires
`startupDependencyPolicy` equal to
`eip0045-b4-elf64-amd64-startup-dependency-closure-v1`. Rust profiles omit this
field. Before `runc create`, the finalizer derives the policy result from the
same descriptor-rooted staged rootfs; the profile never declares a graph,
library name, selected path, or digest.

This result is a **static startup-dependency closure**, not evidence that an
arbitrary `PT_INTERP` implementation will perform the same search at runtime.
It is a prerequisite for, and remains strictly weaker than, the later gate that
binds the exact source-reviewed loader implementation, created mount namespace,
runtime configuration, smoke execution, and observed process mappings. It does
not cover `dlopen`, `dlmopen`, JNI, JVM agents, NSS, iconv/gconv, generated
objects, plugins, the vDSO, or any other application- or kernel-directed load.
No H0 source or completion may be minted from this static closure alone.

The JVM build role derives two independent closures, launcher first and compiler
second; the JVM verifier derives only the launcher closure. Each closure models
one future process and has its own loaded-SONAME table and numerical bounds.
The executable is inserted first and its exact resolved `PT_INTERP` second. A
FIFO work queue then processes each object's `DT_NEEDED` entries in dynamic-
array order. A newly selected object is appended when first discovered. A
SONAME-reused object keeps its first-discovery position, while every repeated
edge is retained. The ordered vector of closures and each closure's traversal
order are part of the result identity; Java and javac never share a loaded-
object table.
The executable and interpreter have depth zero and initialize the FIFO in that
order. A newly selected dependency of a depth-`d` node has depth `d + 1` and is
enqueued at the tail; a loaded-SONAME reuse edge is never enqueued. First-
discovery depth is retained if a later edge reaches the same node. The depth
bound is checked before selection or enqueue.

Every node records its canonical container path, complete symbolic-link chain,
final resolved rootfs path, byte length, SHA-256, ELF projection, optional
`DT_SONAME`, ordered accepted dynamic tags, ordered `DT_NEEDED` strings, exact
`DT_RUNPATH`, and ordered outgoing edges. Every edge records the requesting
node, dynamic-array ordinal, requested string, resolution kind (`loaded-soname`
or `rootfs-search`), and selected node identity. Local descriptor identities
remain custody checks and are not serialized as portable evidence.

The dynamic-array ordinal is the zero-based index of the `Elf64_Dyn` record in
`PT_DYNAMIC`. For every node, the ordered dynamic record projection retains the
exact signed `d_tag` and raw unsigned `d_un` pair for every record from ordinal
zero through and including the first `DT_NULL`; records after that terminator
are excluded. A dependency edge uses the ordinal of its `DT_NEEDED` record.
Decoded strings remain separate, typed fields and do not replace these raw
records.

The launcher and compiler retain `eip0045-b4-elf64-amd64-runtime-v1` and must
not carry `DT_SONAME`; they never enter the loaded-SONAME table. The interpreter
and every selected dependency use
`eip0045-b4-elf64-amd64-dso-v1`: ELF64 amd64, `ET_DYN`, no `PT_INTERP`, exactly
one `PT_DYNAMIC`, all common PT_LOAD/overlap/W^X/non-executable-stack rules, and
an entry point that is either zero or lies in an executable PT_LOAD. Each
interpreter or dependency has exactly one printable-ASCII `DT_SONAME`, 1 through
240 bytes, containing one basename with no slash or backslash. Its SONAME equals
the basename by which it was first selected. No two distinct closure nodes may
carry the same SONAME.

The accepted dynamic-tag set is closed. The policy interprets `DT_NULL`,
`DT_NEEDED`, `DT_STRTAB`, `DT_STRSZ`, `DT_SONAME`, `DT_RUNPATH`, `DT_FLAGS`, and
`DT_FLAGS_1`; it retains as dependency-selection-inert only `DT_PLTRELSZ`,
`DT_PLTGOT`, `DT_HASH`, `DT_SYMTAB`, `DT_RELA`, `DT_RELASZ`, `DT_RELAENT`,
`DT_REL`, `DT_RELSZ`, `DT_RELENT`, `DT_SYMENT`, `DT_INIT`, `DT_FINI`,
`DT_PLTREL`, `DT_DEBUG`, `DT_JMPREL`, `DT_BIND_NOW`, `DT_INIT_ARRAY`,
`DT_FINI_ARRAY`, `DT_INIT_ARRAYSZ`, `DT_FINI_ARRAYSZ`, `DT_PREINIT_ARRAY`,
`DT_PREINIT_ARRAYSZ`, `DT_SYMTAB_SHNDX`, `DT_GNU_HASH`, `DT_VERSYM`,
`DT_RELACOUNT`, `DT_RELCOUNT`, `DT_VERDEF`, `DT_VERDEFNUM`, `DT_VERNEED`, and
`DT_VERNEEDNUM`. `DT_RPATH`, `DT_SYMBOLIC`, `DT_TEXTREL`, `DT_CONFIG`,
`DT_DEPAUDIT`, `DT_AUDIT`, `DT_AUXILIARY`, `DT_FILTER`, GNU prelink/liblist/
conflict tags, and every unlisted tag reject. `DT_FLAGS` permits only
`DF_BIND_NOW`, `DF_ORIGIN`, and `DF_STATIC_TLS`; `DT_FLAGS_1` permits only
`DF_1_NOW`, `DF_1_NODELETE`, `DF_1_INITFIRST`, `DF_1_NOOPEN`, `DF_1_ORIGIN`,
`DF_1_NODUMP`, and `DF_1_PIE`. Every other or unknown flag bit, including
`DF_1_NODEFLIB`, rejects.

A `DT_NEEDED` value is 1 through 240 printable-ASCII bytes, is one basename
with no slash or backslash, and is unique within its requesting object. The
loaded-SONAME table is seeded by the interpreters in seed order. If a requested
name already identifies one loaded node, the edge reuses that node without a
filesystem search. Otherwise the finalizer performs the search below; the
selected object's sole SONAME must equal the requested name before it enters
the loaded table.

V1 rejects every `DT_RPATH` and permits at most one `DT_RUNPATH` per object. A
RUNPATH contains at most 16 colon-separated components with no empty component;
each component is 1 through 240 bytes and has exactly one of these forms:

- a non-root canonical absolute container path with at least one segment and no
  empty, `.`, or `..` segment; or
- exactly `$ORIGIN` or `${ORIGIN}`, optionally followed by `/` and nonempty
  printable-ASCII path segments. The suffix may contain `..`, but not `.`, and
  its lexical normalization must not escape the container root.

The origin token cannot be embedded, repeated, or combined with another token.
`$LIB`, `${LIB}`, `$PLATFORM`, `${PLATFORM}`, every other dollar expansion, a
backslash, and a literal semicolon reject. `$ORIGIN` expands to the canonical
parent of the requesting object's final resolved path. An object whose path
traversed a symbolic link may not use `$ORIGIN`. The final normalized component
must be a non-root absolute directory; normalization to `/` rejects.

For one filesystem search, the finalizer checks the requesting object's
expanded RUNPATH directories in textual order and then exactly these default
directories in this order:

```text
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu
/lib64
/usr/lib64
/lib
/usr/lib
```

RUNPATH applies only to direct dependencies of its owning object. Each search
directory is resolved descriptor-relative with manual no-follow component
opens and the same 40-hop symbolic-link bound as every other bound path. The
requested basename occurs as exactly one directory entry anywhere in the
complete rootfs, and that entry is a direct child of one search directory. Its
final target is one regular mode-`0444` or mode-`0555` file. Missing candidates,
duplicate entries even when they resolve to the same file, candidates outside
the closed directories, or candidates reached through more than 40 links
reject.

For each `rootfs-search` edge, the finalizer first constructs the ordered list
of textual directories: the requester's expanded RUNPATH followed by the six
default directories above. Every textual directory must exist and resolve from
the retained rootfs descriptor to a sealed directory. A missing component,
dangling target, final non-directory, cycle, root escape, or hop 41 rejects;
directories are never silently skipped. The finalizer then counts every live
journal entry whose byte-exact basename equals the `DT_NEEDED` value,
irrespective of entry type, and requires exactly one. Let `E` be that entry and
`P` the canonical path of its actual parent in the journal. `E` is eligible for
a textual directory `D` exactly when `P` equals the final resolved path of `D`.
If several textual aliases resolve to the same `P`, the earliest directory in
search order wins. The selected node's canonical path is `D + "/" +
DT_NEEDED`; its final path and complete link chain come from resolving that
canonical path.

Each complete path resolution starts one symbolic-link counter at zero on the
rootfs descriptor. Every followed link in any component, including links in a
search directory and in the candidate, increments that same counter. Resolving
`D` separately does not reset the counter for the complete `D/name` lookup,
which rejects at hop 41. Each root, interpreter, or newly selected dependency
has its own complete-resolution counter.

Every root, interpreter path, RUNPATH/default directory, symbolic-link hop, and
selected object is an antichain with every role-specific runtime mount target:
neither path may equal, contain, or be contained by the other. The finalizer
rechecks that antichain against the actual created mount namespace before
`runc start`; a mount or symlink overlay refuses start. The rootfs also contains
no `/etc/ld.so.cache`, `/etc/ld.so.preload`, or directory named
`glibc-hwcaps`. No host cache, preload, hardware-capability directory, or
implementation-defined directory participates.

During descriptor traversal, every normalized path actually looked up rejects
when a runtime mount target equals that path or is its ancestor. A mount target
strictly below an ordinary intermediate directory but outside the final path is
not an overlap; for example, `/runtime/other` does not conflict with the walk to
`/runtime/bin/java`. The symmetric antichain above still applies to each
complete canonical path, symbolic-link path and normalized target, and final
resolved path.

Absence of `/etc/ld.so.cache` and `/etc/ld.so.preload` is established by a
descriptor-rooted lookup of those canonical paths. Any live leaf entry,
including a dangling symlink, or any entry reached through a symlinked parent
rejects; absence is accepted only when a missing component is proven inside
the retained rootfs. No live entry of any type may have the exact basename
`glibc-hwcaps`.

Each per-process closure is limited to 512 distinct ELF objects, 4,096
dependency edges, depth 64, and 4,294,967,296 aggregate bytes read across
distinct objects. All additions are checked before opening or reading the next
object; integer overflow rejects. Only loaded-SONAME reuse terminates recursive
selection; V1 has no independent physical-path alias rule.

The static closure requires the configured real, effective, and saved process
UID and GID to be 65,532 and rejects special permission bits or file
capabilities on every executable node. These are static preconditions, not
proof of `AT_SECURE=0`. The current `runc create`/`runc start` lifecycle has no
stop-after-exec boundary: a later runtime gate may record the exact auxiliary
vector after start, but a nonzero `AT_SECURE` invalidates the smoke and triggers
bounded kill/delete/absence cleanup rather than serving as a pre-exec safety
gate. No readiness claim may treat an absent or late observation as proof that
`AT_SECURE` was zero.

The finalizer retains the static closure under the same private rootfs custody.
The later runtime gate rederives every node and edge before `runc start` and
after process exit but before unmount or deletion, and requires the same paths,
lengths, SHA-256 values, ELF projections, tags, SONAME table, edges, and order.
Host `ldd`, the host loader, ambient paths, basename-only matching, process
output, or cleanup followed by rematerialization are never evidence for this
closure or for runtime equivalence.

## Runtime and seccomp handoff

The runner profile binds a static amd64 `runc` ELF and its implementation
version. `runtime.binary.inspectionPolicy` is
`eip0045-b4-elf64-amd64-static-v1`, and
`runtime.configurationPolicy` is
`eip0045-b4-oci-runtime-config-projection-v1`.
`runtime.version` is exactly `1.3.0`.
`runtime.runtimeSpec` is exactly Runtime Specification 1.3.0 at the commit
above. The finalizer constructs a new runtime bundle with
`ociVersion: "1.3.0"`; image config defaults never flow into it.

The expected `runc state` codec is separately bound to runc tag `v1.3.0` at
commit `4ca628d1d4c974f92d24daccb901aa078aad748e`. The measured binary identity
does not prove that the binary was built from that source commit; the source
pin fixes only the codec accepted by the pure parser below.

The portable authority is the runner profile plus the physically remeasured
artifacts, not byte equality of a transient `config.json`. Bundle paths,
container IDs, bind-source paths, and the host side of the single-ID user
mapping are necessarily local. Every launch therefore rederives those fields
from the same exact profile, validates the resulting semantic projection, and
destroys the bundle afterward. A normalized configuration record may be
retained for diagnostics, but neither it nor the presence of a runtime bundle
is an execution attestation.

### Closed runtime-configuration projection

The semantic projection is closed. Any unlisted OCI member, runtime default,
host-injected mount, hook, annotation, environment value, capability, device,
namespace path, sysctl, personality, scheduler setting, time offset, Intel RDT
setting, or vendor extension rejects. The generated configuration has the
following meaning:

- top level: `ociVersion` is `1.3.0`; `hostname` is `eip0045-b4`; `domainname`,
  `hooks`, `annotations`, and non-Linux platform sections are absent;
- `root.path` is the local staged rootfs and `root.readonly` is true;
- `process.terminal` is false; no console size is present; user UID/GID are
  65,532 with no supplementary GID and umask decimal 18 (`0022`);
  `noNewPrivileges` is true and every capability set is empty;
- verification `process.args` is exactly one of the four implementation and
  subcommand vectors in
  `b4-verifier-cli-v2.md`; a build-step container uses exactly the applicable
  descriptor phase's absolute `executable` followed by its ordered
  `arguments`, without a shell inserted by the finalizer. The executable path,
  exact bytes, role, and argument vector are authoritative; a basename is not
  an executable-type attestation, and V1 does not infer program semantics from
  it. The JVM COPY-ONLY phase therefore has the exact seven-argument vector
  fixed in `b4-jvm-artifact-policy-v1.md`, following the bound packager
  executable. `process.cwd` equals `/src` for the Rust build and JVM
  application phase and `/phase-input` for the JVM packaging phase;
- `process.env`, for both build and verification roles and in this exact order,
  is exactly `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`, and `TZ=UTC`. Descriptor-supplied,
  inherited, image-provided, loader, Java-tool, classpath, or any other process
  variable rejects;
- `process.rlimits`, in ascending type order, contains exactly RLIMIT_CORE with
  soft/hard zero and RLIMIT_NOFILE with soft/hard equal to the profile limit.
  AppArmor/SELinux labels, OOM adjustment, scheduler, I/O priority, and every
  other optional process member are absent;
- `mounts` contains exactly the role mounts, one read-only `proc` mount at
  `/proc`, the declared fresh `tmpfs` at `/tmp`, and five pseudodevice bind
  mounts. Targets are strictly ordered by unsigned ASCII bytes. Bind sources
  are local fields but their measured types and profile source roles are not.
  Read-only role binds use `bind,rprivate,ro,nodev,nosuid` and add `noexec`
  exactly when the profile says so; writable output uses
  `bind,rprivate,rw,nodev,nosuid`; `/proc` uses
  `ro,nodev,nosuid,noexec`; `/tmp` uses
  `rw,nodev,nosuid,noexec,mode=1777,size=<profile bytes>`; pseudodevices use
  `bind,rprivate,rw,nosuid,noexec` and are never mounted `nodev`;
- the Rust build and JVM application phase role mounts are the read-only
  verified source at `/src`, the read-only dependency closure at `/deps`, and
  a fresh writable output root at `/out`. The JVM COPY-ONLY packaging phase
  replaces those role mounts with only the fresh, read-only
  `eip0045-b4-jvm-copy-only-phase-input-v1` tree at `/phase-input` and a
  distinct fresh writable `/out`. It receives neither `/src` nor `/deps`.
  `/phase-input` contains only the committed manifest and canonical archive
  filenames defined by `b4-jvm-artifact-policy-v1.md`; it is destroyed after
  that packaging repetition;
- `linux.namespaces` contains exactly mount, PID, IPC, UTS, user, network, and
  cgroup namespaces, each without a host namespace path. UID and GID mappings
  each contain one extent: container ID 65,532, local host ID equal to the
  finalizer's effective ID, size one. `rootfsPropagation` is `private`;
- `linux.devices` is empty because the five devices are bound over existing
  placeholders. The device-cgroup list first denies `rwm` for every device and
  then allows only `rw` for character devices `1:3`, `1:5`, `1:7`, `1:8`, and
  `1:9`. `maskedPaths` and `readonlyPaths` are empty; no host default is added;
- `linux.resources` contains only the profile's memory limit, zero swap,
  CPU period/quota, PID limit, and the exact device rules above. The local
  `cgroupsPath` is newly allocated for this run. Block-I/O, huge-page, network,
  RDMA, and unified-controller extensions are absent; and
- `linux.seccomp` is exactly the separately verified `linuxSeccomp` projection
  below. No second LSM or syscall filter is supplied.

Field order and local path spelling in `config.json` are not identities. The
finalizer parses its own generated document back through the pinned Runtime
Specification shape and compares the semantic projection above before giving
the bundle to `runc`.

### Lifecycle and inspection semantics

`policy.lifecycle` is
`derive-create-inspect-start-wait-inspect-delete-confirm-absence`. For every
build step and verification run, with no container reuse, the finalizer:

1. creates fresh bundle, rootfs, tmpfs, cgroup, and identifier paths; derives
   and validates the closed configuration; and remeasures every bound input;
2. invokes the bound `runc create`, then requires `runc state` to report the
   exact ID, status `created`, the local bundle path, and a live init PID;
3. before `runc start`, inspects that PID's namespace identities, UID/GID maps,
   cgroup membership and limits, mount table and mount flags, capability sets,
   `NoNewPrivs`, seccomp mode, and root identity against the projection. An
   unavailable or ambiguous observation rejects and proceeds directly to
   cleanup;
4. remeasures launch inputs, invokes `runc start`, supervises the init PID and
   bounded output through its terminal status, and never treats a timeout,
   signal, OOM, runtime error, or observation failure as validator output;
5. before deletion, requires `runc state` status `stopped`, the same ID and
   bundle, no live init PID, unchanged configuration and staged-root identity,
   and the expected cgroup terminal state; then invokes `runc delete`; and
6. requires subsequent state lookup to report that the ID does not exist and
   verifies absence of the owned cgroup, bundle, rootfs, tmpfs, mount, and
   process identities.

The schema's three inspection values name these predicates:
`semantic-projection-and-created-state-required`,
`semantic-projection-and-stopped-state-required`, and
`runtime-state-and-owned-path-absence-required`. They are deterministic
executor requirements, not attestations by `runc` or by the host.

For the JVM build role, this lifecycle is applied four times in phase-major
order: two complete application-intermediate invocations are destroyed and
their outputs compared and identity-checked before two complete COPY-ONLY
packaging invocations begin. Container identifiers, output roots, and, for the
packaging phase, phase-input roots are distinct across all applicable
repetitions. Repeating the whole pipeline in two containers or reusing one
container between phases rejects.

### Gate-rooted runtime-observation selectors

Every runner profile carries a closed `runtime.observationSelectors` object.
The `state` and `processIdentity` members select the two pure parsing contracts
defined below. The other nine members remain reserved identifiers, not
implemented policies and not observations supplied by a runner or caller. The
positive gate projects all eleven members together with the canonical role,
the bound static `runc` identity, the Runtime Specification pin, and the
configuration policy. Every projected token is inert: copying it, parsing
caller-supplied bytes, or structurally matching two parsed values does not prove
that a bundle was generated, that `runc` executed, that `/proc` was read, or
that any kernel state was observed.

The object contains exactly these members and values:

- `state`: `eip0045-b4-runtime-observation-runc-state-json-v1`;
- `processIdentity`:
  `eip0045-b4-runtime-observation-linux-boot-id-pid-starttime-jcs-v1`;
- `namespaces`: `eip0045-b4-runtime-observation-namespaces-reserved-v1`;
- `idMappings`: `eip0045-b4-runtime-observation-id-mappings-reserved-v1`;
- `mountinfo`: `eip0045-b4-runtime-observation-mountinfo-reserved-v1`;
- `securityStatus`:
  `eip0045-b4-runtime-observation-security-status-reserved-v1`;
- `cgroupV2`: `eip0045-b4-runtime-observation-cgroup-v2-reserved-v1`;
- `rootIdentity`:
  `eip0045-b4-runtime-observation-root-identity-reserved-v1`;
- `auxv`: `eip0045-b4-runtime-observation-auxv-reserved-v1`;
- `processMappings`:
  `eip0045-b4-runtime-observation-process-mappings-reserved-v1`; and
- `smokeIdentity`:
  `eip0045-b4-runtime-observation-smoke-identity-reserved-v1`.

The state contract accepts at most 16,384 bytes and only the exact UTF-8 JSON
form emitted by the pinned `runc state` codec: one object formatted by Go
`json.MarshalIndent` with a two-space indent, no BOM, no leading or trailing
bytes, and no terminal line feed. The members occur exactly once and in this
order: `ociVersion`, `id`, `pid`, `status`, `bundle`, `rootfs`, `created`, and
`owner`. Unknown, missing, duplicate, reordered, escaped-key, differently
spaced, or trailing input rejects. `annotations`, including an empty object,
rejects under this closed configuration. The member values are constrained as
follows:

- `ociVersion` is exactly `1.3.0`. It is the configured version echoed by runc,
  not evidence of general OCI 1.3.0 conformance;
- `id` is 1 through 128 ASCII bytes from `[A-Za-z0-9_+.-]` and is neither `.`
  nor `..`;
- `status` is exactly `created` with integer `pid` in
  `1..=4_194_303`, or exactly `stopped` with integer `pid` zero. Every other
  status and every non-integer JSON number rejects;
- `bundle` and `rootfs` are each 2 through 4,096 ASCII bytes. Each begins with
  `/`, has no trailing or doubled `/`, contains 1 through 64 components, and
  every component is 1 through 128 bytes from `[A-Za-z0-9._+-]` and is neither
  `.` nor `..`;
- `created` is the canonical UTC RFC3339Nano form emitted by Go: 20 through 30
  ASCII bytes, a terminal `Z`, an optional 1-through-9 digit fractional second
  with no trailing zero, and a calendar/time value that round-trips to the same
  bytes; and
- `owner` is the empty string.

These input-size, identifier, PID, timestamp, and path bounds are B4 rules, not
limits supplied by runc or OCI. The parsed path strings are data only: the
parser never normalizes or opens them and cannot establish their provenance.
No `Absent` state is constructible from this JSON contract. A future effectful
consumer must distinguish typed lookup absence from permission, corruption,
state-root, and other failures before joining all owned-path absences required
above.

The process-identity contract accepts at most 128 bytes and requires an exact
RFC 8785 canonical JSON object with exactly three keys. One valid example is
`{"bootId":"550e8400-e29b-41d4-a716-446655440000","pid":123,"startTimeTicks":"456"}`.
`bootId` is a lowercase canonical UUID with layout `8-4-4-4-12`, version nibble
`4`, and RFC 4122 variant nibble `8`, `9`, `a`, or `b`. `pid` is an integer in
`1..=4_194_303`.
`startTimeTicks` is a string containing the canonical nonzero decimal encoding
of an unsigned 64-bit integer: no sign, no leading zero, and at most 20 digits.
The parser rejects duplicate, unknown, missing, non-canonical, trailing, and
over-limit input before returning a role-bound parsed record.

The pure parser establishes no provenance for those three values and accepts a
synthetic, structurally valid record. A future trusted producer must read the
boot value from `/proc/sys/kernel/random/boot_id` as exactly a lowercase UUID
followed by one LF, and derive `pid` and `startTimeTicks` from fields 1 and 22 of
the same bounded `/proc/<pid>/stat` record while retaining the same procfs and
time-namespace view. Only after those obligations are joined does `bootId`
distinguish observed boots and does the triplet become PID-reuse-resistant
correlation data. Kernel start time is quantized in clock ticks, so even then
the triplet is not a mathematically unique process identity. A structural match
requires the same canonical role, a parsed `created` state, and the same PID;
it proves neither contemporaneity, source authenticity, liveness, nor
continuity.

The other nine identifiers reserve independently testable future slots. In
this version they bind no grammar, transition system, numeric bound, normal
form, parser, observation channel, or runtime meaning. The two former reserved
state/process-identity identifiers remain permanently uninterpreted and are no
longer accepted. A future implementation must replace any remaining reserved
identifier with a new contract identifier, or bind an immutable contract
artifact and digest; it must never assign semantics to a reserved identifier in
place. The remaining intended slots cover the seven namespace identities,
UID/GID mapping and `setgroups`, mount topology,
capability/`NoNewPrivs`/seccomp status, cgroup-v2 membership and limits,
process-root identity, amd64 auxiliary vector, byte-preserving process-mapping
classification, and the post-`exec` identity join. Any later codec must consume
its complete bounded input and reject an unavailable read, malformed or
ambiguous record, duplicate semantic field, unsupported extension, trailing
data, or limit excess. Its bounds and exact normal form must be
implementation-independent parts of that later contract, never values chosen
by a profile or caller.

A future runtime producer must obtain the state and process records from the
same custodied session, retain a pidfd or equivalent `/proc/<pid>` custody, bind
the boot, PID, time, procfs, and mount namespace identities, and re-read the
state and process tuple around every deciding observation. Neither parser nor
the structural match performs those effects, mints a completion, authorizes a
start or delete, or supports an H0/B4 readiness claim.

The future process-mapping contract must be a classifier, not equality with the
static `DT_NEEDED` closure. Application-directed mappings excluded from that
closure remain unresolved obligations until a separate runtime authority binds
them. Likewise, the reserved smoke-identity selector is only a routing
prerequisite for a future post-`exec` observation. This version does not select
a stop, freezer, ptrace, or handshake mechanism. Until a later contract
supplies a deterministic same-process barrier, an absent or racing
auxv/mapping observation rejects and cannot support a smoke,
loader-equivalence, H0, or B4 readiness claim.

### Java runtime and build-JDK identity

The JVM build profile requires `buildJdk`; the JVM verification profile
requires `javaRuntime`. Rust profiles carry neither. Both Java identities bind
the resolved `/runtime/bin/java` bytes and `/runtime/release`. `buildJdk` also
binds the resolved `/runtime/bin/javac` bytes. Every launcher and compiler uses
inspection policy `eip0045-b4-elf64-amd64-runtime-v1`. The build descriptor's
unique `runtime/java` and `compiler/javac` toolchain entries must exactly match
the build profile's binary paths, versions, lengths, and hashes.

The release file is a regular file of 1 through 65,536 bytes, is hashed before
and after the applicable build or verification run, and uses encoding
`openjdk-release-file-utf8-v1`.

That encoding is UTF-8 without BOM, uses LF only, ends in exactly one LF, and
contains no empty or comment line. Each line is
`KEY="VALUE"`, where `KEY` matches `[A-Z][A-Z0-9_]*`, keys are unique and
strictly ordered by unsigned ASCII bytes, and a value may use only the escapes
`\\` and `\"`. Unescaped control characters, CR, substitution syntax,
unquoted values, unknown escapes, duplicate keys, trailing whitespace, or bytes
after the final LF reject. The parser consumes the complete file.

There is exactly one `IMPLEMENTOR` and one `JAVA_VERSION`. After unescaping,
they respectively equal the applicable `vendor` and `version` projection and
must satisfy the schema's printable-ASCII bounds. `JAVA_VERSION` must match the
closed schema grammar, parse under Java 21 `Runtime.Version` syntax, have no
leading-zero numeric component or trailing zero version component, and have
feature component 21. The finalizer derives these fields from the physically
measured release file; descriptor-supplied text is not authoritative. The
release metadata is an image identity field, not a claim that its producer or
Java implementation is trustworthy; the archive, launcher/compiler bytes, ELF
structure, source/toolchain closure, and actual run remain separate evidence.

The canonical seccomp file has the exact wrapper:

```json
{
  "format": "Eip0045B4PositiveSeccompV1",
  "formatVersion": 1,
  "linuxSeccomp": {
    "defaultAction": "SCMP_ACT_ERRNO",
    "defaultErrnoRet": 1,
    "architectures": ["SCMP_ARCH_X86_64"],
    "flags": [],
    "syscalls": [{
      "names": ["... strictly sorted unique syscall names ..."],
      "action": "SCMP_ACT_ALLOW",
      "args": []
    }]
  }
}
```

The complete wrapper is RFC 8785 canonical JSON and matches the runner
profile's `seccomp.profile` length and SHA-256. The runner projection repeats
only the policy ID, format, file identity, and `allowedSyscalls`. The finalizer
requires that array to equal `linuxSeccomp.syscalls[0].names` exactly. Names are
strictly increasing by unsigned ASCII byte order.

Only `linuxSeccomp` is inserted at `linux.seccomp` in the runtime config. The
wrapper keys are not passed to `runc`. There is exactly one unconditional allow
rule, no argument filters, no notify listener, no errno override on the allow
rule, no implicit second architecture, and no additional rule supplied by the
descriptor, image, runtime defaults, or host. An unknown syscall name, an
unsupported seccomp action or architecture, or any `runc` or kernel error while
installing the exact profile refuses launch. The finalizer never retries with a
wider or modified filter.

The remaining isolation is the runner-profile contract. In particular, the
network namespace contains the loopback device but leaves it down, assigns no
IPv4 or IPv6 address, creates no non-loopback interface, and contains no route.
Container UID/GID 65,532 is mapped as a single ID to the finalizer's effective
UID/GID; supplementary groups are denied. The rootfs is read-only, and only the
declared mounts and pseudodevices are present. Missing kernel support never
widens the policy.

## Required executor checks and negative fixtures

The finalizer-executor, not the semantic gate alone, must test at least one
single-fault rejection for every independently relaxable obligation:

- wrong Image or Runtime Specification pin, layout version, media type,
  platform, descriptor size, descriptor digest, or reachability graph;
- extra archive entry or blob, nested index, malformed ustar metadata,
  nonzero padding, archive suffix, duplicate path, reordered path, an accepted
  8,589,934,591-byte size field, or a rejected 8,589,934,592-byte size;
- gzip nonzero FLG/MTIME/XFL, non-`ff` OS, optional-header field, truncation,
  bad CRC/ISIZE, second member, inflate overrun, wrong uncompressed length, or
  DiffID mismatch;
- absolute/parent path, hard link, special node, ownership/mode drift, unsafe
  whiteout, delete-plus-opaque on an empty directory, nested opaque markers,
  root-opaque plus another marker, symlink-following write, escaping/cyclic/
  41-hop bound symlink, final metadata drift, or rootfs count drift;
- malformed or wrong-architecture ELF, extended numbering, out-of-range
  program/section header, writable-executable load, executable stack, dynamic
  `runc`, missing/escaping Java interpreter, malformed dynamic string range, or
  Java/release-file identity drift;
- with an otherwise valid launcher and interpreter, one missing direct
  `DT_NEEDED`, one missing transitive `DT_NEEDED`, a root SONAME, a slash-bearing
  or duplicate `DT_NEEDED`, empty/241-byte/non-printable NEEDED or SONAME,
  absent/mismatched/duplicate `DT_SONAME`, loaded-SONAME reuse drift,
  launcher/compiler table leakage, `DT_RPATH`, a second `DT_RUNPATH`, an empty,
  seventeenth, or 241-byte RUNPATH component, an escaping `$ORIGIN`, `$LIB` or
  `$PLATFORM`, a semicolon separator, a RUNPATH on a symlink-reached requester,
  a root-only or missing RUNPATH/default directory,
  two rootfs entries with the requested basename, a candidate outside the
  closed search directories, any search/root/object path overlapping a runtime
  mount, a non-ELF or wrong-type selected dependency,
  nonzero DSO entry outside executable PT_LOAD, an unlisted dynamic tag or flag
  bit, `/etc/ld.so.cache` or `/etc/ld.so.preload` reached directly or through a
  parent alias, any live `glibc-hwcaps` basename, a cumulative directory-plus-
  candidate hop 41, `DF_1_NODEFLIB`, closure
  object/edge/depth/read-budget overflow, unobservable or nonzero
  `AT_SECURE`, or pre-start/post-exit static closure identity drift;
- injected OCI member/default/environment/mount/device, missing cgroup
  namespace, wrong mapping or resource value, pre-create projection drift,
  post-create namespace/mount/seccomp drift, wrong state transition, reused
  runtime ID, or incomplete owned-path cleanup;
- seccomp wrapper drift, unsorted/duplicate syscall name, extra rule,
  architecture expansion, argument filter, unsupported syscall, or filter
  installation failure; and
- loopback up, assigned address, additional interface, route, missing user
  mapping, unexpected mount/device, or unavailable post-destroy inspection.

The positive controls independently cover one direct dependency from a default
directory, one direct dependency through `$ORIGIN` `DT_RUNPATH`, loaded-SONAME
reuse, one transitive dependency whose child uses its own `DT_RUNPATH`, one
exactly-40-hop dependency symlink, and one two-object dependency cycle that
terminates by loaded-SONAME reuse. A DSO with entry point zero is
an explicit positive. Bound controls cover exactly 512 objects, 4,096 edges,
depth 64, and the exact aggregate-byte maximum; isolated `max + 1`
controls reject. The 4-GiB arithmetic boundary may use a counter model only
after a separate differential proves that model against the streaming physical
reader at smaller exact lengths; it must not allocate or read 4 GiB merely to
test addition. Each positive control changes only the named static-closure
property; none substitutes for its corresponding single-fault rejection or for
the later exact-loader/runtime smoke gate.

The executor records the exact failing predicate. A generic extraction or
launch failure is not a substitute for the named negative when another defect
could have caused rejection.

This policy binds and constrains a B4 reproduction environment. It does not
prove that an image producer is trustworthy, that two validators are
independent, or that a validator is correct; those are separate source,
lineage, build, differential, and review obligations.
