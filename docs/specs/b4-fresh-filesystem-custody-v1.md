# B4 fresh-filesystem custody candidate V1

## Status and immutable identity

The immutable contract identifier is `eip0045-b4-fresh-filesystem-custody-v1`.

This document is a candidate contract for one effectful prerequisite of the B4
retained-host metadata producer. It is not an implemented producer, an
authenticated observation, a completion receipt, or launch authority. The
identifier may not be reinterpreted in place. Any semantic change to this
contract requires a new identifier and an explicit migration of every
consumer.

The candidate does not select a production system-call backend. In particular,
the successful use of an external `unshare` or `mount` command in a local
preflight does not select those command-line tools for production, and this
document does not authorize an `unsafe` Rust implementation. A later promotion
must pin an implementation, its complete input bounds, its kernel-facing ABI,
and its independent negative fixtures.

## Scope and non-authority

This contract establishes only the custody of one fresh, bounded, non-overlay
filesystem during one attempt. It does not establish any retained inode's
metadata result. It does not close extended attributes, ACLs, file
capabilities, inode flags, project identifiers, LSM visibility, observer
credentials, symbolic-link handling, archive extraction, rootfs content, or
runtime mount equivalence.

Conformance to this contract alone cannot:

- emit `absent` for any metadata class;
- mint H0 or a B4 completion;
- authorize extraction, launch, publication, or readiness;
- prove that a serialized receipt came from a live namespace or mount; or
- substitute for the separately pinned safe no-follow and symbolic-link ABI.

The positive live state is `LiveFreshFilesystemCustody`: an attempt-scoped,
affine capability held with every deciding descriptor, namespace handle, and
supervised process handle. It permits observation and staging only. It is
consumed in the same live session or discarded, never reconstructed from JSON,
a digest, a log, or another serialized record. These state names describe the
contract; they do not define a schema, public constructor, or H0 authority.

## Producer and consumer boundary

The future producer is an effectful finalizer component with two roles:

1. an external supervisor that remains outside the attempt's new user and
   mount namespaces, owns the target and stable supervision handles, applies
   bounds, records both primary and cleanup outcomes, and reaps every process
   it creates; and
2. one supervised child created in a fresh user namespace and a fresh mount
   namespace for exactly one attempt. The child creates, verifies, exposes, and
   removes the bounded filesystem while the supervisor retains custody.

The future consumer is the retained-host metadata observer referenced by
`eip0045-b4-retained-host-rootfs-metadata-obligations-v1`. It may begin only
while `LiveFreshFilesystemCustody` and all deciding handles remain live. It
must return its staged observation and every live filesystem handle to the
supervised join. It must independently satisfy the metadata, credential, LSM,
bounds, retry, descriptor-rooting, no-follow, and symbolic-link obligations;
this contract supplies none of those results.

A profile or semantic gate may carry the identifier only as an inert prerequisite.
No parser, caller Boolean, or structurally valid receipt is a producer.

## Closed attempt topology

Before each attempt, the supervisor opens an authenticated cleanup ancestor and
records its exact inventory. It creates one unique parent below that ancestor
and one empty target below the parent using create-only, descriptor-relative,
no-follow operations. It retains authenticated ancestor, parent, and target
handles through final removal. Each identity includes file type, device, inode,
and `(supervisor mount-namespace identity, mount ID)` from both the handle and
descriptor-relative lookup. A same-inode mount substitution is still a changed
identity and rejects.

The supervisor establishes kernel-enforced exclusive mutation custody of those
three directories for the complete attempt. No other process, thread,
descriptor, or mount operation may rename, replace, mutate, or attach on those
names. Ambient same-credential access, leaked handles, or an inability to prove
that exclusion rejects. The target must be empty and not a mount point in the
supervisor namespace. Every identity is revalidated immediately before child
release, before attachment, at the live barrier, and through final removal.

The supervisor creates the child with a fresh user namespace and a fresh mount
namespace, retains process and namespace custody, and applies a bounded
handshake. Namespace freshness is per attempt: neither namespace, any process
that entered it, nor any mount or mount handle created in it may be reused by a
retry. Before any creation or attachment, the child applies the semantics of
`MS_REC|MS_PRIVATE` to `/` and proves that every target ancestor is private,
with no shared, slave/master, `propagate_from`, unbindable, or undecidable
propagation. A partial result rejects before mount.

No workload process may enter the attempt namespaces before the custody
capability is established. Before release, every setup helper is reaped and a
kernel-enforced process domain is sealed to exactly one single-threaded child
held by a stable pidfd. Numeric PID enumeration is insufficient. `fork`,
`vfork`, `clone`, `clone3`, `execve*`, descriptor transfer, detach, and
daemonization are forbidden after sealing. Any descendant, second thread,
process or handle outside the sealed domain, or second process/namespace
reachability rejects.

## Fresh tmpfs contract

Before any mount effect, the child validates and retains one canonical typed
request for exactly one new `tmpfs` attachment on the custodied target. Its
filesystem type is `tmpfs`; `readonly` is explicitly false; `size_bytes` is
1,048,576; `nr_inodes` is 128; `root_mode` is `0700`; and the VFS set is exactly
`nosuid,nodev,noexec`. The equivalent display projection is:

```text
rw,nosuid,nodev,noexec,size=1MiB,nr_inodes=128,mode=0700
```

The byte size is exactly 1,048,576; `1024k` is an equivalent kernel rendering
only after exact numeric normalization. The inode bound is exactly 128 and the
root mode is exactly `0700`. `rw` is an explicit writable request, not an
omitted default. Option ordering and equivalent numeric rendering are not
identities. An omitted, duplicated, ambiguous, widened, defaulted, or
differently valued requested option rejects before the mount operation.

A separately pinned parser derives the effective VFS and superblock read-only
states, per-mount flags, tmpfs size, inode bound, root mode, and complete
mount-table entry. Both read-only states must be false and every required value
must equal the request. Atime policy, including `relatime`, child-visible root
UID/GID with their user-namespace mapping, `inode64`, and other exhaustively
parsed kernel fields are recorded but nondeciding in this contract; they cannot
satisfy or weaken a required value. An unknown or ambiguous field rejects.
Effective last-wins normalization cannot prove request uniqueness.

The mounted filesystem type must be exactly `tmpfs`. An overlay, bind mount,
host filesystem, reused tmpfs, remount of an existing filesystem, or mount
whose origin cannot be decided rejects. In its own mount namespace, the child
opens a target descriptor, binds it to the supervisor's authenticated anchor,
and attaches through `MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH` or a
separately pinned safe ABI with the same no-late-resolution property. A
path-only attachment is outside this contract. After attachment, the child
opens the mounted root, validates
the type, options, tuple, and sole graph delta, then closes every `fsopen`,
`fsmount`, detached-mount, and other mount-creation handle. Only after the
sealed descriptor inventory proves that none remains may it produce
`LiveFreshFilesystemCustody`; the mounted-root descriptor remains through final
live revalidation and is closed before ordinary unmount.

## Namespace-qualified mount identity

A mount is identified by the tuple `(custodied mount-namespace identity,
mount ID)`.

The mount-namespace identity is bound to a live namespace handle and its stable
descriptor identity for the attempt. A numeric mount ID alone is never an
identity and may not be compared across namespace observations. Every deciding
mount observation is made through a source pinned to the corresponding live
namespace custody.

After recursive propagation isolation and before tmpfs creation, the child
captures a bounded complete mount-table baseline. At the positive barrier, the
sole graph delta is exactly one new tmpfs attachment at the authenticated
target. A bind or `open_tree` clone, `move_mount` alias, detached mount tree,
child mount, peer/export, or second path or namespace reachability rejects.
The sealed process and descriptor inventories must also prove that no
unaccounted mount reference escaped the visible table.

The positive attempt proves all of the following at the same bounded barrier:

- the child's pre-mount target resolves to the supervisor-custodied target;
- the live mounted root has a child mount tuple different from the underlying
  parent mount tuple;
- the mounted-root descriptor, target lookup, filesystem type, normalized
  request, effective options, complete graph delta, and child mount tuple agree;
- the supervisor, while the child mount is still live, resolves the same target
  path and open target descriptor to the original underlying directory and
  never observes the child's mount tuple; and
- the child and supervisor namespace identities remain unchanged around the
  paired observations.

That paired live observation is the parent simultaneous-invisibility check. A
check performed only before mount or after unmount is insufficient. Mount-ID
inequality without namespace identity, or namespace inequality without target
and descriptor identity, is also insufficient.

## Affine observation and cleanup join

`LiveFreshFilesystemCustody` authorizes only an in-session observation whose
result remains staged inside the attempt. The consumer returns that staged
observation and every live filesystem handle; it cannot publish an `absent`
result or H0 source. Only the supervisor may consume the returned state together
with successful ordinary unmount, descriptor-rooted removal, and residue
closure to produce `ClosedFreshFilesystemAttempt`.

The closed state is only an input to the separately versioned metadata
producer; this contract cannot interpret or publish the observation. A primary
or cleanup failure destroys the staged observation and forbids the closed
state. No observation, `absent` result, H0 source, or completion may escape
before this join.

## Success and cleanup

The primary consumer operation and cleanup have separate outcomes. An accepted
attempt requires both a successful primary outcome and successful ordinary
cleanup. A primary failure is never hidden by cleanup success, and a cleanup
failure is never hidden by primary success or by reporting only the first
error.

On the success path, in order, the child:

1. ends the consumer operation, retains its result only as staged state, and
   returns every live filesystem handle;
2. revalidates the mounted-root descriptor, child namespace identity, child
   mount tuple, filesystem type, requested/effective options, and sole mount
   graph delta;
3. proves no mount-creation handle remains, enters a barrier that forbids every
   new open, fork, exec, mount, or descriptor transfer, then closes the
   mounted-root descriptor and every descriptor, mapping, current/root
   directory, or process reference into the mounted filesystem, retaining only
   copied observations, namespace handles, and the underlying anchors;
4. performs bounded `umount2` with flags zero; `EBUSY`, lazy unmount, and
   `MNT_DETACH` are cleanup failures, and no intervening operation may reacquire
   the mount; and
5. proves in the same child namespace that the complete mount table equals its
   baseline and the target again resolves to the original underlying inode,
   then closes its child-side resources and exits.

The supervisor then waits and reaps the child, proves that no supervised process
remains and that its own namespace and target observations never changed, and
revalidates the ancestor, parent, and target identities. While their handles
remain open, it removes the target descriptor-relatively, proves both name
absence and that the pinned target inode was unlinked, then removes the parent
relative to the retained ancestor and proves the same facts. It finally proves
the ancestor inventory equals its pre-attempt value before closing custody
handles. Path-only or close-before-remove cleanup, residue, or drift rejects.

## Failure, forced teardown, and retry

Every bounded failure enters cleanup. The outcome preserves the primary error
and the complete cleanup error independently. Cleanup continues after a failed
ordinary step when doing so can reduce residue without destroying evidence,
but no later recovery converts the attempt to success.

If the child does not complete ordinary cleanup, the external supervisor sends
`SIGKILL` through the stable pidfd, reaps that exact child, proves the sealed
population is zero and no namespace or detached-mount handle escaped, then
drops its retained namespace handles so teardown destroys the private mount.
This is fail-closed recovery, not ordinary-unmount success or positive custody.
After namespace teardown, while the ancestor, parent, and target handles remain
live, the supervisor performs the same descriptor-relative removals and exact
ancestor-inventory restoration as on the ordinary path. Only then may it close
custody handles and report the failed attempt as contained. An uninterruptible
child, escaped handle, removal failure, residue, or undecidable check is
blocking cleanup failure.

No lazy unmount is permitted on either the primary or recovery path. No retry
may enter either namespace from a previous attempt. A retry allocates a fresh
user namespace, mount namespace, child/pidfd, parent, target, mount graph, and
supervision handles, then repeats every precondition. Retry count and timing are
owned by a later producer contract; this candidate grants no unbounded retry.

## Diagnostic records are not custody

An implementation may produce a bounded diagnostic record containing the
attempt identifier, normalized observations, and the two outcomes. Such a
record is evidence for debugging only. It cannot carry the affine capability,
file descriptor custody, namespace custody, contemporaneity, or cleanup
authority. Authenticating or hashing it does not permit a later process to
mint an `absent` result, H0, or B4 completion.

## Positive and single-fault falsifier matrix

Each negative fixture changes only the named fault from the positive attempt,
must reject, and must exercise the same cleanup and residue checks.

| Boundary | Positive witness | Single changed fault | Required result |
| --- | --- | --- | --- |
| Attempt namespace | Fresh user and mount namespace handles retained for one attempt | Reuse either namespace from a prior attempt | Reject before consumer start |
| Process domain | One single-threaded child is sealed and held by pidfd | Fork once after teardown enumeration | Reject; kill/reap cannot claim closure |
| Handle confinement | No namespace, mount, or target handle leaves the sealed domain | Transfer one mount-namespace FD | Reject as blocking cleanup failure |
| Propagation | Every target ancestor is recursively private | Leave one shared, slave, unbindable, or undecidable ancestor | Reject before mounting |
| Requested options | Canonical typed request contains each required semantic once | Omit `rw` or duplicate one last-wins value | Reject before mounting |
| Effective options | Required VFS/superblock projection exactly matches the request | Change one effective required value | Reject |
| Filesystem origin | New `tmpfs` is created on the empty custodied target | Bind, overlay, remount, or reused tmpfs | Reject |
| Attachment target | Child-owned target FD matches the supervisor anchor and is attached without late path resolution | Substitute a path-only target | Reject before attach |
| Mount graph | Complete live delta is one attached tmpfs; every authorized creation handle was enumerated and closed | Add one unaccounted detached clone, bind alias, or child mount | Reject; ordinary success forbidden |
| Mount identity | Live child tuple is `(child mount namespace, child mount ID)` | Compare or retain only the numeric mount ID | Reject |
| Mount separation | Child mounted-root tuple differs from its underlying parent tuple | Child mount ID equals parent mount ID in the same namespace | Reject |
| Mutation custody | Ancestor, parent, and target identities are exclusively frozen through removal | Swap away and restore the target once | Reject |
| Mounted-root custody | Mounted-root descriptor, lookup, type, options, and tuple agree | Substitute one descriptor or lookup result | Reject |
| Parent invisibility | At a live barrier, supervisor still observes the original target and no child tuple | Observe only before mount or only after unmount | Reject |
| Staged-result join | Staged observation escapes only with `ClosedFreshFilesystemAttempt` | Publish it before ordinary cleanup | Destroy the staged result and reject |
| Primary/cleanup join | Primary and ordinary cleanup both succeed | Primary succeeds but ordinary unmount fails | Reject and preserve both outcomes |
| Error preservation | Primary and cleanup outcomes are independently retained | Replace the primary error with the cleanup error | Reject the record |
| Busy-reference barrier | Every reference into tmpfs is closed after final validation | Retain mounted-root, detached-mount, cwd, or mapping once | `EBUSY` or any success claim rejects |
| Unmount mode | Flags-zero unmount restores the complete baseline | Use lazy unmount or prove only target-tuple absence | Reject |
| Forced teardown | Stuck child is killed, reaped, namespace handles dropped, and the attempt remains failed | Describe `SIGKILL` namespace teardown as successful cleanup | Reject |
| Retry isolation | Retry allocates all-new namespaces, child, target, and handles | Retry in either prior namespace | Reject before retry work |
| Descriptor removal | Open target and parent inodes are removed relative to retained ancestors | Close either custody FD before removal | Reject cleanup |
| Final inventory | Ancestor inventory and all identities equal their pre-attempt state | Leave one path, process, descriptor, mount, or changed inode | Reject as cleanup failure |
| Serialization boundary | Consumer holds the live affine capability and deciding handles | Reconstruct acceptance from a valid-looking serialized receipt | Reject without metadata observation or H0 mint |

Passing this matrix closes only the filesystem-custody boundary described here.
The metadata/LSM observer, safe descriptor and symbolic-link ABI, production
backend, consumer join, and H0 authority remain separately blocked.
