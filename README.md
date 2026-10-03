# storekit

A store kit: a rooted, descriptor-confined store with atomic writes, an advisory
lock, and validated identifiers — plus the transport that moves a tree of it
between hosts. No application's domain model.

Callers are other projects, mostly agent-written, and will not read the
implementation before calling. So the crate enforces, and never relies on the
caller.

## The constitution

1. **The crate enforces; the caller is not trusted.** Make misuse unrepresentable
   at the API; otherwise refuse the input, or detect the violation and fail
   closed. A rule that lives only in prose is not a rule.
2. **The safe path is the default.** A weaker guarantee is reachable only through
   an entry point whose name states it. A destructive choice is an enum, never a
   boolean. An operation that can take its own lock takes it.
3. **Addresses are faithful and injective.** A manifest value is byte-exact:
   names UTF-8 in NFC, symlink targets UTF-8 and separator-free, no CR, LF or
   TAB. Anything else is refused, never normalized or substituted.
4. **A view is faithful, or the check does not run.** No lossy decode, no
   trimming, no defaulted field, on any path that decides something. A listing
   carries the live kind of each entry beside its name.
5. **No decision crosses views.** A sanction, an outcome, a kind and a listing
   are each valid only for the moment they were observed; anything that selects
   a mutation is read from the live tree.
6. **Destroy only under a sanction for that path**, re-established against the
   live tree. Never let a recursive removal delete an unenumerated name. Count a
   mutation before attempting it, and name it if it fails.
7. **A run owns its destination.** Take the operation lock wherever it can be
   taken, hold it for the whole run, release it on every exit path. A write made
   outside that lock is detected and fails the run.
8. **Fail closed.** Refuse rather than transform; error rather than guess; a
   check that cannot run is a failure. Never document a guarantee that is not
   implemented.
9. **Frame or refuse at every boundary that re-interprets a value.** Shell
   operands are one quoted word each, parents computed rather than derived by a
   shell, `--` before a value that may start with `-`. Wire records are
   delimited by a byte a name cannot contain, with the name last.

## Refused, by rule

Names not UTF-8 or not NFC · names or targets containing CR, LF or TAB ·
absolute or escaping symlink targets · hard links · devices, sockets, FIFOs ·
reserved-name collisions · overlapping roots (equal is an idempotent no-op;
ancestor or descendant is refused) · any root or entry reached through a symlink
component — where a destination's lock cannot be taken, a component swapped
between the check and the operation is a stated residual, not a guarantee.

As a DESTINATION member, an absolute/escaping symlink or a hard link is not
refused: the destination manifest records it, the diff reports it extraneous,
and `Extraneous::Delete` removes it. It is never TRANSFERRED — a source entry
at the same path is refused before any mutation. `Extraneous` is all-or-nothing
(no per-path delete policy): `Delete` cannot PRUNE EXACTLY one destination-only
path (for example snapshot 002 while 001 and 003 are kept) — it removes every
destination-only entry the diff classified extraneous, and `Keep` removes none.
The sanctioned route for a partial retention is `Keep` everything and remove
the unwanted paths out of band through the destination's own removal
primitives (or make every path you want kept part of the source).

A consumer can ask whether a name is reserved BEFORE it fails:
`store_sync::is_reserved_name` (one path segment) and
`store_sync::is_reserved_path` (a canonical manifest path) report the crate's
reserved spellings — the `.sync-aside.` claim-aside prefix and the
`.<name>.operation.lock` record. A reserved spelling is refused as an
identifier, is never transferred by a sync, and is never destroyed by
`Extraneous::Delete`.

## Fidelity scope

Carried: name, kind, mode (including setuid, setgid, sticky), content, symlink
target. Not carried: ownership, extended attributes, POSIX ACLs, timestamps,
file flags, sparseness. Refused rather than dropped: hard links. The loss is
INVISIBLE TO THE DIFFER: a dropped xattr or ACL leaves `local_manifest ==
remote_manifest` true and the sync reporting no difference, so only
xattr/ACL-aware tooling on the destination can reveal it. Authoritative
statement: the `manifest` module documentation; the sync entry points restate
the scope.

Because the manifest carries NO TIMESTAMPS, "the newest N snapshots" must come
from the snapshot ID's LEXICAL order (or from a timestamp record the caller
keeps itself). The crate cannot rank two snapshots by time, and two snapshots
that differ only in mtime compare `Same`.

## This is not a backup or checkpoint format

`store-sync` moves a tree faithfully WITHIN THE MANIFEST MODEL; it is **not a
backup or checkpoint format**, and it cannot stand in for one:

- A source containing a **hard link** or an **absolute (or escaping) symlink**
  cannot be snapshotted AT ALL: the strict source manifest refuses the run, so
  such a tree must be normalized (copy the hard-linked content, make the
  symlink relative) before it can be pushed.
- A **restore drops metadata with the differ blind**: `diff(snapshot, live)` is
  EMPTY while `mtime`, xattrs and sparseness differ. Ownership,
  `security.capability`, ACLs, timestamps, file flags and sparseness are not
  carried, and nothing reports their loss. Apply them out of band and verify
  with tooling that can see them.

## Durability and atomicity

A file a sync writes is published ATOMICALLY and DURABLY for every Unix
reachable destination kind: a LOCAL destination (a pull, or a push whose
transport is `LocalTransport`) uses the crate's durable atomic replace (unique
temp + `fsync` + `rename` + parent-directory `fsync`), and a REMOTE destination
uses the same shape on the far side (temp, payload on stdin, mode, perl
`fsync(2)`, perl `rename(2)`, parent-directory `fsync(2)`). A write that fails
before the rename leaves the PREVIOUS content in place and removes the temp, so
a failed push can no longer destroy the snapshot it was replacing. The Windows
local port's replace is the ONE non-atomic case (no directory fsync; the target
is removed before the rename) and is unverified. The exact commit points are in
the `manifest` module's "Durability and atomicity of a written entry".

`EntryPolicy::AppendTail` costs O(TOTAL SIZE) per append: appending 32 bytes to
a 1 MiB log reads ~3.1 MB and writes ~1 MB, because there is no remote append
primitive and the append is a compare-and-replace of the whole file. Batch
small appends, or keep the log outside the synced tree and ship it whole.

To make a freshly pushed SUBTREE durable, call `fsync_tree(child)` AND
`fsync_parent(child)` on the transport rooted at the child's PARENT. A
`RootedRelativePath` cannot be empty, so a transport rooted at the child itself
cannot name its own root to fsync the parent directory entry.

## A fresh destination

A `PUSH` provisions its destination before reading the destination manifest: the
destination ROOT and the caller's `Layout::bootstrap_dirs` are created, so a
fresh remote destination works without the caller pre-creating it and
`Layout::empty()` is enough. A `PULL` into a local destination creates that root
lazily, on the first mutation.

## Platform

Linux and macOS are supported and exercised. The far side of a remote transfer
may be GNU or BSD userland; both are exercised. The Windows implementation
type-checks but is not exercised, and is described as unverified.

## Assumptions the logic rests on

Restrictions the crate does not enforce, because it cannot. Each buys a
simplification; removing one means adding back the logic it removes.

- **The destination changes only through this run.** *Buys:* one read of the
  destination is authoritative for the whole run, so work is never ordered
  against an unknown mutation. The crate takes the destination's operation lock
  wherever it can, making this true for cooperating writers; a write made
  outside that lock is still detected and fails the run.
- **The source does not change during the run.** *Buys:* one read of the source
  describes it for the whole run. Nothing in the crate can prevent a source
  write, so the caller owes this.
- **The destination filesystem's case and normalization behaviour is constant.**
  *Buys:* it is probed once and cached for the run rather than re-probed per
  decision.
- **The destination filesystem renames atomically within a directory.** *Buys:*
  an entry can be moved aside and published by rename, so a replacement never
  passes through a state with neither the old nor the new content.
- **The far side provides a POSIX shell and `perl`.** *Buys:* one script per
  operation, with no binary agent to deploy or version on the far side.
- **The far side's userland is GNU or BSD.** *Buys:* portability is a tested
  property of the scripts instead of a runtime negotiation.
- **The process's descriptor limit exceeds the tree's depth.** *Buys:* a walk
  holds one descriptor per directory level instead of pooling or segmenting.
- **A path-based operation addresses no more than the platform's path limit.**
  *Buys:* path-shaped operations need no segmented traversal. This limit DOES
  apply to the manifest walk: `canonicalize_tree` (`crate::manifest`) uses
  `WalkDir` plus `symlink_metadata`/`read` on accumulated PATHS, so a tree
  deeper than the platform's path limit is refused with `ENAMETOOLONG` at the
  first path that overflows. With 1-byte components the path grows 2 bytes per
  level, so the bound is `floor((PATH_MAX - 1 - base_len)/2)`, where
  `base_len` is the length in BYTES of the base path AS IT RESOLVES on the
  filesystem (work in resolved form: on macOS `/tmp` is `/private/tmp`, 4-8
  bytes longer). The bound has no single number — it is a function of the
  base. Worked examples, one per platform, each measured one level above where
  `ENAMETOOLONG` first lands: Linux (`PATH_MAX` 4096) admits depth 2047 at a
  1-byte base, 2041 at a 13-byte base, and 2040 at a 15-byte base; macOS
  (`PATH_MAX` 1024) admits depth 511 at a 1-byte base and 482 at a 59-byte
  resolved base (an unresolved `/tmp/B*59` base measures 478 once `/tmp`
  resolves to `/private/tmp`). A
  descriptor-relative manifest walk would lift this; it is not implemented, and
  this bullet is the statement of the real limit. The descriptor-relative
  REMOVAL walk (`crate::atomic::remove_dir_contents_fd`) holds one descriptor
  per level and is NOT limited by the path limit, so removal supports deeper
  trees than the walk that describes them — but that advantage is itself
  bounded by the descriptor limit, the assumption bullet above ("the process's
  descriptor limit exceeds the tree's depth"), which is the real ceiling on
  removal depth.
- **Metadata beyond name, kind, mode, content and symlink target is outside the
  model.** *Buys:* a small manifest, and no extended-attribute, ACL, ownership,
  timestamp or sparseness machinery.

## Rules for changing this crate

- A behaviour fix lands with a test that fails before the change. A test that
  cannot fail before says so in its own comment.
- No assertion is weakened or deleted to make a change land.
- A green gate on one platform is not evidence for another.
- Fix the class, not the instance: a rule bypassed on a path other than the one
  reported is still broken.
- An oracle must be able to express the failure it is meant to catch — in the
  inputs it varies and in the paths it samples.
- A document that contradicts the code is a defect in whichever is wrong.
- A fold is a DENIAL tool, never a PERMISSION tool. Unifying spellings (case,
  trailing dot/space) may only make the crate refuse MORE; it must never decide
  that two spellings are one thing when the thing grants a right. Ownership of
  a resource is decided by IDENTITY — the resolved on-disk entry (device and
  inode) — not by whether two spellings fold together, because on some
  filesystems a folded spelling is a different entry that another holder owns.
  The one spelling fallback allowed is byte-exact equality while the entry does
  not exist yet (creating it). Concretely: refusing a lock-record spelling folds
  case and the Win32 trailing dot/space, while the protocol's authority to
  break the lock record it owns compares the candidate's resolved identity with
  the layout lock's and refuses every alias that is a distinct entry.
- Refusing a case beats transforming it; deleting a capability beats shipping a
  broken one.
- State every bound with the reason it holds.
