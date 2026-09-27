# B4 trusted-host F0 retained-rootfs metadata policy

This policy is a source-only declaration for the selected trusted Windows/WSL
host. Its identity is `eip0045-b4-retained-host-rootfs-metadata-obligations-th-f0-v1`.
It neither changes the V1 obligations nor admits an H0/V2 theorem packet. A
matching declaration does not prove a kernel, mount, inode, observer, or B4 run.

The conditional kernel basis is the observed release
`6.18.33.2-microsoft-standard-WSL2`, candidate Microsoft source commit
`c21a03b2943d147c280bdf32530d4fe6badfd6bd`, captured `/proc/config.gz`
SHA-256 `30e49f5d4d0a53d46f4f8056ecca9ab0be08e7949cf058f961d779e023f752b5`,
and installed kernel-image SHA-256
`d540850bfbf1beba3ded6b2965b9d0249b23fbcb3e90e7dc0845ac7ad86bc861`.
These observations do not establish which binary booted or that the candidate
source produced it. F0 must expressly accept that host premise; any stricter
binary claim needs separate evidence.

The closed table has eleven classes in this order: xattr-name set, POSIX access
ACL, POSIX default ACL, Linux file capability, immutable, append-only,
encrypted, verity, casefold, nonzero project ID, and project-inherit. Each has
five subjects: mount root, role root, retained directory, retained regular
file, and retained symbolic link. In class-major order, its 55 triples are
hashed with the domain `eip0045.b4.trusted-host.metadata-mode-table.f0.v1\0`;
the expected SHA-256 is
`e8ad5b5e41a6d3d3fab57e5055f85bc01ef736581b3e6f3935b9390bddd8c218`.

The selected securityfs diagnostic reported the stack
`capability,landlock,yama,safesetid,selinux,ima`; its captured stdout has
SHA-256 `9648a65d2b21f045668b2c22ef750d4720c60cf5b171ff5158ee994ac87a623b`.
The provider must observe and bind that exact stack in its own session. A
different stack requires a fresh source/coverage review, not silent
substitution. The diagnostic stack identity alone does not establish that LSM
label listing is complete.

The first four classes require empty xattr-name enumeration **and** direct
absence checks for names the active LSM may hide from that enumeration, on
every retained subject. The `tmpfs` path uses `simple_xattr_list`, which
includes POSIX ACL names, asks the active LSM for MAC labels, and then
enumerates stored names. It suppresses `trusted.*` without `CAP_SYS_ADMIN` in
the initial user namespace and skips names classified as MAC labels in the
stored-name walk. On this WSL boot, a private tmpfs diagnostic wrote and read
`security.selinux` while `listxattrat` omitted it. The candidate source's
uninitialized-SELinux branch can explain that result; the diagnostic does not
independently attest SELinux initialization state. The provider must require a
direct no-follow `getxattrat` result of `ENODATA` for `security.selinux` on the
same retained leaf, in addition to the empty complete listing.

In the pinned candidate source, SELinux is the only member of the selected
stack that registers `ismaclabel` or `inode_listsecurity`. Its label predicate
matches only `security.selinux`; an uninitialized SELinux instance can omit
that name from its list hook. The other selected modules' registered hooks do
not add a hidden MAC-label name. See the [SELinux definitions and hook
table](https://github.com/microsoft/WSL2-Linux-Kernel/blob/c21a03b2943d147c280bdf32530d4fe6badfd6bd/security/selinux/hooks.c),
[`simple_xattr_list`](https://github.com/microsoft/WSL2-Linux-Kernel/blob/c21a03b2943d147c280bdf32530d4fe6badfd6bd/fs/xattr.c#L1459-L1502),
and the reviewed hook tables for [capability](https://github.com/microsoft/WSL2-Linux-Kernel/blob/c21a03b2943d147c280bdf32530d4fe6badfd6bd/security/commoncap.c),
Landlock ([credentials](https://github.com/microsoft/WSL2-Linux-Kernel/blob/c21a03b2943d147c280bdf32530d4fe6badfd6bd/security/landlock/cred.c),
[tasks](https://github.com/microsoft/WSL2-Linux-Kernel/blob/c21a03b2943d147c280bdf32530d4fe6badfd6bd/security/landlock/task.c),
[filesystem](https://github.com/microsoft/WSL2-Linux-Kernel/blob/c21a03b2943d147c280bdf32530d4fe6badfd6bd/security/landlock/fs.c),
[network](https://github.com/microsoft/WSL2-Linux-Kernel/blob/c21a03b2943d147c280bdf32530d4fe6badfd6bd/security/landlock/net.c)),
[Yama](https://github.com/microsoft/WSL2-Linux-Kernel/blob/c21a03b2943d147c280bdf32530d4fe6badfd6bd/security/yama/yama_lsm.c),
[SafeSetID](https://github.com/microsoft/WSL2-Linux-Kernel/blob/c21a03b2943d147c280bdf32530d4fe6badfd6bd/security/safesetid/lsm.c),
and IMA ([main](https://github.com/microsoft/WSL2-Linux-Kernel/blob/c21a03b2943d147c280bdf32530d4fe6badfd6bd/security/integrity/ima/ima_main.c),
[appraisal](https://github.com/microsoft/WSL2-Linux-Kernel/blob/c21a03b2943d147c280bdf32530d4fe6badfd6bd/security/integrity/ima/ima_appraise.c)).

That source review covers the selected stack only. The provider must bind the
stack and initial-user-namespace `CAP_SYS_ADMIN` to its own session, then fail
closed on any difference. The policy declaration checks only claimed fields;
it cannot authenticate those syscalls or prove the booted kernel matches the
candidate source. The observer must retain listing privilege throughout its
observation, reject errors and truncated lists, and preserve no-follow leaf
identity.

Immutable and append-only require `statx` on each retained subject with the
respective attribute in the returned support mask and its value clear. The
remaining five classes are conditionally excluded by the exact source/config
and fresh-`tmpfs` premise; no symlink `fileattr` ioctl observation is claimed.
The root begins with zero `fsflags`; descendants inherit only the bounded
`tmpfs` mask. The source lacks a project-ID inode field, rejects FSX writes,
and cannot set casefold with `CONFIG_UNICODE` disabled. The captured config has
filesystem encryption and verity disabled. These are source deductions under
F0, not measurements of a booted kernel.

A future provider must bind one fresh private `tmpfs` mount, its mount ID,
complete retained-subject inventory, role, root and leaf descriptors, and the
same session epoch to each observation. It must exclude all concurrent
mutation from root creation through observation and read-only transfer. A
parent-descriptor plus basename lookup with `AT_SYMLINK_NOFOLLOW` needs that
exclusive closure: before/after identity checks alone cannot rule out an ABA
replacement. The provider must revalidate the retained inventory after
observation. No caller-provided packet or digest can substitute for that
physical custody.

The declaration module exposes only pure constants, a table digest, and
non-authorizing consistency checks. The trusted-host profile, precommit,
provider, OCI importer and physical replay require later, separately reviewed
joins under distinct wire and authority identities.
