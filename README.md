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
(no per-path delete policy).

## Fidelity scope

Carried: name, kind, mode (including setuid, setgid, sticky), content, symlink
target. Not carried: ownership, extended attributes, POSIX ACLs, timestamps,
file flags, sparseness. Refused rather than dropped: hard links. The loss is
INVISIBLE TO THE DIFFER: a dropped xattr or ACL leaves `local_manifest ==
remote_manifest` true and the sync reporting no difference, so only
xattr/ACL-aware tooling on the destination can reveal it. Authoritative
statement: the `manifest` module documentation; the sync entry points restate
the scope.

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
  *Buys:* path-shaped operations need no segmented traversal. The manifest walk
  is descriptor-relative and is not limited by this.
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
- Refusing a case beats transforming it; deleting a capability beats shipping a
  broken one.
- State every bound with the reason it holds.
