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
   names UTF-8 in NFC, no CR, LF or TAB. A symlink target is link DATA, stored
   UTF-8-verbatim: it may contain `/` and `..`, and a relative target is
   resolved against the directory CONTAINING the link (POSIX). It is refused
   when it is ABSOLUTE, when a `..` walks above the root, or when the walk
   reaches a symlink component — final or intermediate — because the kernel
   FOLLOWS that component and a lexical collapse past it is not the kernel's
   answer; the crate refuses rather than guess where the follow ends. A
   component counts as a symlink component when its EXACT entry is one, or —
   when no exact entry exists — when it folds onto a symlink entry under the
   crate's platform-independent name fold (NFC, Unicode lowercase, trailing
   `.`/space), so a case- or normalization-folding spelling cannot be missed by
   one view and accepted by another. Nothing is normalized or substituted.
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
   outside that lock is DETECTED over the paths the run reads, by re-checking
   the destination, and fails the run — the detection is not total, so an ABA or
   a write after the last verification is undetectable.
8. **Fail closed.** Refuse rather than transform; error rather than guess; a
   check that cannot run is a failure. Never document a guarantee that is not
   implemented.
9. **Frame or refuse at every boundary that re-interprets a value.** Shell
   operands are one quoted word each, parents computed rather than derived by a
   shell, `--` before a value that may start with `-`. Wire records are
   delimited by a byte a name cannot contain, with the name last.

## Refused, by rule

Names not UTF-8 or not NFC · names or targets containing CR, LF or TAB ·
absolute or escaping symlink targets · a relative target that walks through a
symlink component (the kernel follows it, so a lexical collapse past it is not
its resolution) · hard links · devices, sockets, FIFOs ·
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

A consumer can ask whether a name may be used BEFORE it fails. The authority
is `storekit::is_unaddressable_name` (one path segment) and its path form
`storekit::is_unaddressable_path` (a canonical manifest path): these are the
predicate the identifier rule `storekit::id::valid_name` itself consults, so
`valid_name(s)` is false exactly when `s` is not a single safe segment OR is
unaddressable. They report every spelling the crate refuses to name — the
`.sync-aside.` claim-aside prefix, the `.<name>.operation.lock` record, the
application lock record `operation.lock`, case aliases of any of those, crate
temp shapes, and the Win32 trailing-dot/space aliases of a lock record (refused
on every platform, so an id does not mean different things on different hosts).
`is_reserved_name` / `is_reserved_path` are NARROWER: the byte-exact reserved
MATCH the sync uses to strip reserved components, and they deliberately leave
the application lock record and the case/trailing-dot aliases alone — they are
NOT, on their own, the answer to "may I use this name". An unaddressable
spelling is refused as an identifier, is never transferred by a sync, and is
never destroyed by `Extraneous::Delete`.

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

`storekit` moves a tree faithfully WITHIN THE MANIFEST MODEL; it is **not a
backup or checkpoint format**, and it cannot stand in for one:

- A source containing a **hard link**, an **absolute symlink**, or an
  **escaping symlink** cannot be snapshotted AT ALL: the strict source manifest
  refuses the run, so such a tree must be normalized (copy the hard-linked
  content, make the symlink relative) before it can be pushed. A relative
  symlink target that contains `/` or `..` but stays inside the root WITHOUT
  walking through a symlink component (`dir/link -> ../other`) is lawful and is
  NOT one of these refusals; a target whose walk reaches a symlink component is
  refused even when it happens to land inside, because the kernel may follow
  that component out. Containment is decided against the RESULT: a source link
  whose target walks through a component that only the DESTINATION supplies as a
  symlink (and that the source does not replace, kept under the default
  `Extraneous::Keep`) also fails the run rather than installing an escaping link
  or silently removing the destination entry.
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

`EntryPolicy::AppendTail` costs O(TOTAL SIZE) per append, because there is no
remote append primitive and the append is a compare-and-replace of the whole
file. Measured on Linux release with `strace` byte accounting (kache
neutralised, load ~1), ONE run that appends 32 bytes to a 1 MiB log reads
**8,388,768 bytes** and writes **1,048,678 bytes**: three whole reads of the
1 MiB destination (the destination manifest, the prefix test, and the
compare-and-replace), three whole reads of the 1 MiB + 32 source (the source
manifest, the prefix test, and the end-of-run source re-check), and two whole
reads of the 1 MiB + 32 result for the TWO post-transfer verification passes —
plus the whole 1 MiB + 32 result written through the atomic temp and the
70-byte lock record. The old "~3.1 MB read" figure counted only the append
rule's three whole-file reads and omitted the verification reads. Budget the
verification, not just the append rule. Batch small appends, or keep the log
outside the synced tree and ship it whole.

**`AppendTail` is NOT a concurrency-safe append.** It is a whole-file
compare-and-replace: concurrent appends are NOT preserved (two runs can read
the same prefix and the later publish discards the other's line — a lost
update on a remote destination, and a `renameat`-wide window locally). A
consumer that relies on one `O_APPEND` write of a complete line landing under
concurrent appenders must keep those writes OUTSIDE the synced tree; see the
`EntryPolicy::AppendTail` warning for what to do instead.

To make a freshly pushed SUBTREE durable, call `fsync_tree(child)` AND
`fsync_parent(child)` on the transport rooted at the child's PARENT. A
`RootedRelativePath` cannot be empty, so a transport rooted at the child itself
cannot name its own root to fsync the parent directory entry.

## What a snapshot costs

Two costs a checkpoint tool must budget for, both measured on a 350 MB tree
unless stated otherwise.

**Memory is O(largest entry), not O(changed bytes).** `Remote::write` takes
`data: &[u8]` and the read side materializes the whole entry, so a single
350 MB file costs peak RSS 362,064 KB (macOS) / 362,860 KB (Linux) for
snapshot AND for restore — a 4 GB file needs roughly 4 GB of addressable
memory in the process doing the transfer. The two destination kinds are NOT
equally protected against a slow link: the SSH path derives a size-aware
deadline from the payload (`upload_deadline` / `transfer_deadline(bytes,
min_rate, command_deadline)`), while the LOCAL path has neither a deadline
nor streaming. Workaround: keep the largest entry under the process's memory
budget, or move large blobs outside the synced tree and ship them with a
tool that streams. A streaming transport API would remove the bound; it is a
deliberate future direction, not part of this change (adding it would
transport-layer-wide redesign under a change that is about residue).

**A snapshot still scans and hashes the WHOLE tree, so it is O(bytes
scanned), not O(bytes changed).** Content addressing makes the STORE
deduplicated — equal content is stored once — but there is no dirty tracking
and no reuse of the previous manifest: `canonicalize_tree`
(`crate::manifest`) reads every file to hash it, and `install_file`
(`crate::sync::apply`) reads the whole source again to write it. Measured on
the 350 MB tree, changing one 4-byte file: 1.327 s before -> 1.384 s after
(macOS); 2.739 s -> 2.690 s (Linux). A periodic checkpoint therefore pays
O(total bytes scanned) every run, which is a design cost of the
manifest-and-hash model, not a bug; an implementation that reused a
previously computed manifest or skipped the second read would change it, and
neither is built here.

**A deep tree is worse than the incremental measurement suggested, and the
shape depends on fresh vs incremental.** A LOCAL path-based destination
re-verifies a path's ancestry before mutating it, at O(depth) per probe. A
depth-D chain with ONE changed leaf is therefore SUPER-LINEAR in D, and the
measured exponent is PLATFORM-DEPENDENT: ≈2.0 on Linux (measured 99 / 373 /
1472 ms at D = 100 / 200 / 400; ratios 3.76 / 3.95) but ≈2.5 on macOS
(measured 0.64 / 3.44 / 21.2 s at the same depths; ratios 5.4 / 6.2; the
consumer's earlier 0.63 / 3.38 / 21.6 s agree). The single O(D^2) label was
wrong on macOS — budget for worse than quadratic. A FRESH destination installs
all D entries, and EACH install pays its own ancestry probe, so it is O(D^3):
the cubic shape was verified, over the consumer's 4.855 s / 41.39 s / 582.1 s
at the same depths. `canonicalize_tree` alone is cheap (2.76 ms / 6.53 ms /
25.4 ms), so the engine's per-path verification is the cost, and a checkpoint
tool that recreates its destination per snapshot should budget the CUBIC. The
Linux and macOS incremental figures above are re-measured under the audit
(release build, kache neutralised, load ≈0.3 Linux / ≈1.4 macOS); the
fresh-destination and `canonicalize_tree` figures are the reviewing consumer's,
not re-measured here.

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

The Windows check compiles the WHOLE target, tests included:
`cargo check --all-targets --target x86_64-pc-windows-msvc`. A signature change
to a Windows code path — production or test — therefore fails this gate instead
of staying invisible until someone builds on Windows. The tests cannot EXECUTE
on this host, so the reproductions that need a Unix filesystem primitive
(`O_NOFOLLOW`, `flock`, `pipe`/`poll`, `symlink`, mode bits, `mkfifo`, raw fds)
are `#[cfg(unix)]`; the rest of the suite is compiled for Windows.

## Assumptions the logic rests on

Restrictions the crate does not enforce, because it cannot. Each buys a
simplification; removing one means adding back the logic it removes.

- **The destination changes only through this run.** *Buys:* one read of the
  destination is authoritative for the whole run, so work is never ordered
  against an unknown mutation. The crate takes the destination's operation lock
  wherever it can, making this true for cooperating writers; a write made
  outside that lock is still detected over the paths the run reads (rule 7
  states the limit — it is not total) and fails the run.
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
  level, so the bound is `floor((L - base_len)/2)`, where `base_len` is the
  length in BYTES of the base path AS IT RESOLVES on the filesystem and `L` is
  the longest pathname the kernel accepts for the tree: measured `PATH_MAX - 1`
  on Linux (4095, because `/tmp` is real) and `PATH_MAX` on macOS (1024). The
  older form `floor((PATH_MAX - 1 - base_len)/2)` is exact on Linux but
  under-predicts by one on macOS when `base_len` is EVEN (the parity is hidden
  when every worked example has an odd base). Worked examples, each measured
  one level above where `ENAMETOOLONG` first lands: Linux (`PATH_MAX` 4096)
  admits depth 2047 at a 1-byte base, 2041 at a 13-byte base, and 2040 at a
  14-byte base; macOS (`PATH_MAX` 1024) admits depth 511 at a 1-byte base, 495
  at a 34-byte resolved base (EVEN — the old form predicts 494), and 482 at a
  59-byte resolved base. A descriptor-relative manifest walk would lift this;
  it is not implemented, and this bullet is the statement of the real limit.
  The descriptor-relative
  REMOVAL walk (`crate::atomic::remove_dir_contents_fd`) holds one descriptor
  per level and is NOT limited by the path limit, so removal supports deeper
  trees than the walk that describes them — but that advantage is itself
  bounded by the descriptor limit, the assumption bullet above ("the process's
  descriptor limit exceeds the tree's depth"), which is the real ceiling on
  removal depth.
- **Metadata beyond name, kind, mode, content and symlink target is outside the
  model.** *Buys:* a small manifest, and no extended-attribute, ACL, ownership,
  timestamp or sparseness machinery.

## Design conflicts surfaced by the consumer audit

Three places where this crate's guarantees and a real consumer's design pull
apart. They are recorded here, with evidence and the decision, so the owner
decides them deliberately rather than by omission. (a), (b) and (c) are CLOSED —
(a) by the composed ownership form below, (b) by the persistent far-side lock
session below, (c) by the fd-confined tree helpers.

### (a) The sync lock is a SIBLING of the destination root, not the in-root layout lock — CLOSED (composed BY NAME)

The ONE entry point `sync` takes `<parent>/.<name>.operation.lock`
(`sync::destination_lock_path`; the rationale is in the `sync` module docs)
when its `ownership` argument is the unforgeable
`DestinationOwnership::Locked` token (acquired by
`DestinationOwnership::lock`), while `Layout::lock` names the IN-ROOT
`state/operation.lock` (`transport::Layout::lock`). They are DIFFERENT FILES, so
the two locks do NOT exclude each other on their own: a consumer that holds its
own in-root `operation.lock` and then calls a plain `sync` ends up with two
files that both claim to be "the operation lock", and that run is not excluded
by the consumer's lock (also in the `sync` module docs).

DECISION (the crate's own recommendation, taken): the acquiring constructor now
has a NAMED composed form,
`DestinationOwnership::lock_with_in_root_lock(direction, local_root, remote,
&layout.lock)`, which takes BOTH records and holds them for the whole run. It
returns the unforgeable `DestinationOwnership::LockedWithInRoot(LockedDestination,
InRootLock)` token; `DestinationOwnership::lock` is UNCHANGED and still takes the
sibling record alone, so the plain path is byte-for-byte the same. The caller
supplies its own `Layout::lock` path (a `RootedRelativePath`), because `Remote`
exposes no `Layout` accessor and a hard-coded `state/operation.lock` would be
wrong for a custom layout.

The composition is honest about its costs, all pinned by tests:

* **Canonical order, no deadlock.** The sibling record is taken FIRST and the
  caller's in-root record second; the order is enforced in the constructor, not
  selectable by the caller. Both acquisitions are NON-BLOCKING (`flock LOCK_NB`
  / `LockFileEx` with `LOCKFILE_FAIL_IMMEDIATELY`), so a process can never WAIT
  while holding one record — two composed runs contending in either order fail
  with the typed `Error::LockContended` instead of deadlocking. Sibling-first is
  the outer gate: a run that loses the sibling record never touches the
  destination root.
* **The destination ROOT must already exist.** Taking an in-root record creates
  the record and any missing parent directory inside the root, so a composed
  run that let the root be created would create the destination root before the
  destination manifest is read — the surprise the sibling location exists to
  avoid, and (for a PULL) a contradiction of the lazy-root adoption rule. The
  composed constructor therefore REFUSES a missing (typed `Error::NotFound`) or
  non-directory destination root BEFORE the sibling record is created, so the
  refusal leaves nothing behind. The in-root record's own missing parent
  directory INSIDE the existing root is still created (at the store-private
  mode).
* **The in-root record is invisible to the run, but its parent directory is
  not.** The record is destination RESIDUE
  (`reserved::is_residue_path`: its component is the application-lock spelling),
  so `apply_manifests` strips it from the destination view — it is never
  transferred and never destroyed; it is reported in `SyncReport::residue`. An
  empty parent directory the lock creates is ordinary content: under
  `Extraneous::Delete` its removal is refused because it holds residue, so
  neither the directory nor the record is destroyed. (The earlier claim in this
  section that an in-root record "would enter the destination manifest the run
  is judging" was FALSE for the record itself; see `docs/CONSISTENCY.md`.)
* **The default does not change.** Plain `sync`/`push`/`pull` behaviour —
  including "a fully-refused pull creates NOTHING, not even the root" — is
  untouched: the plain constructor never creates or holds the in-root record.

Do NOT move the sync's own record in-root: that still breaks the
"a fully-refused pull creates NOTHING" contract. The composed form exists
precisely so the in-root record is only taken when the caller names it and
accepts the root-must-exist cost.

### (b) Ownership enforcement was unavailable for exactly the remote case — CLOSED (a persistent far-side lock session)

The ONE entry point `sync` took the destination's operation lock only through
the unforgeable `DestinationOwnership::Locked` token, which
`DestinationOwnership::lock` produces by ACTUALLY taking the lock on a LOCAL
record; a remote (SSH) destination could never be locked, because a one-shot
far-side `flock` lived inside a single remote command and died with it (the
`sync` module docs). The acquiring constructor therefore REFUSED such a
destination, and the only way to reach it was to pass
`DestinationOwnership::Unowned` at the call site. The crate's strongest
guarantee therefore applied to the case a cross-host tool uses LEAST.

DECISION (the crate's own recommendation, taken): a remote destination can now be
OWNED, BY NAME, through
`DestinationOwnership::lock_remote(direction, local_root, remote)`, which holds
the destination's operation lock ON THE FAR SIDE for the whole run. The refusal
is KEPT: `DestinationOwnership::lock` still refuses a remote destination exactly
as before, and `DestinationOwnership::Unowned` still reaches it; `lock_remote`
is an ADDITIONAL, explicitly-named way to own it, not a widening of the weak
path.

* **The record is the SAME one the local case uses.**
  `destination_lock_path`'s derivation — a SIBLING of the destination root,
  `.<name>.operation.lock` — is applied to the far-side root spelling, so a
  far-side holder and a local one contend on one record by construction.
* **The mechanism is a persistent far-side lock session, not a widened
  `sync`.** `lock_remote` spawns a long-lived local `ssh` client whose remote
  `perl` opens the record `O_RDWR|O_CREAT|O_NOFOLLOW` at `0600`, takes
  `flock(LOCK_EX|LOCK_NB)`, writes the holder identity into the record, prints a
  `LOCKOK` readiness line, and then BLOCKS reading stdin. `perl`'s built-in
  `flock` is used deliberately: the far side may be GNU or BSD, `flock(1)` does
  not exist on macOS, and perl is already required for the crate's other
  far-side primitives.
* **Acquisition is NON-BLOCKING.** A live holder is the typed
  `Error::LockContended` IMMEDIATELY, never a wait (the far-side `flock` is
  `LOCK_EX|LOCK_NB`).
* **The lock is held for the run's duration and released on EVERY exit path.**
  The session guard lives for the whole `sync` call (it is in `sync`'s stack
  frame, exactly as `HeldLocks` is); its `Drop` closes the client's stdin, waits
  bounded for the far-side holder to exit, then kills and reaps the client — so
  an ordinary return, an error return, and a panic unwind all release it.
* **A lost connection releases it, and is REPORTED.** A far-side lock cannot
  outlive its client: if the connection dies, the holder sees EOF and exits and
  the kernel releases the `flock`. That is a real property with a consequence
  the crate STATES rather than hides — the far-side lock SERIALISES concurrent
  runs but is NOT a lease. A run whose session died mid-run returns a typed
  transport failure naming the lost lock, never a clean `Ok`.
* **Fail closed on an unusable far side.** No `perl` is
  `TransportKind::InterpreterMissing`; an uncreatable or read-only parent, or a
  real `flock` failure, is `TransportKind::FarSideScript` with an actionable
  message; a transport that does not implement far-side locking
  (`Remote::lock_far_side`'s DEFAULT) is a typed `Preflight` refusal naming the
  override it needs. The run never proceeds unowned.
* **The unowned path is UNCHANGED.** A remote destination without `lock_remote`
  is still refused by `DestinationOwnership::lock` exactly as before, and
  `DestinationOwnership::Unowned` still reaches it.

The limitation that REMAINS: a NON-COOPERATING far-side writer that never takes
the record is outside the crate's exclusion, exactly as for a local
destination — the crate cannot force another program to take the lock — and a
far-side lock cannot outlive its client, so it is not a lease.

### (c) The fd-confined tree helpers the source tool calls had no public equivalent — CRATE DEFECT, FIXED HERE

`~/code/deploy` calls `copy_dir_recursive_fd` and `fsync_tree_recursive_fd`
(from its `store::local`, defined in its `store::atomic::unix`), but the crate
had dropped them
and `Remote::{copy_tree,fsync_tree}` are NOT 1:1 replacements: both require
`RootedRelativePath` endpoints under ONE transport root (the deploy call site
copies from an arbitrary, possibly out-of-root source), and `Remote::fsync_tree`
is PATH-based (`WalkDir`, so a symlinked component is followed) where the
source tool's version refuses one. The migration was blocked on this, so this
change re-adds the PUBLIC `atomic::copy_dir_recursive_fd` and `atomic::fsync_tree_recursive_fd`,
ITERATIVE and descriptor-confined. Their exact
deltas from `deploy`'s originals (each documented on the primitive itself):

* ITERATIVE, not recursive — the source tool's original recursed one Rust
  frame per level, so a deep tree aborted the host; the re-added forms hold an
  explicit heap `Vec` stack and surface a clean `Err` at the descriptor limit.
  Proven by `deep_tree_fd_copy_does_not_abort_the_process` and
  `deep_tree_fd_fsync_does_not_abort_the_process` (depth 256). The stack is
  PROFILE-DEPENDENT and the numbers are MEASURED (depth 256, both platforms):
  in DEBUG the fd copy aborts at 16/24 KiB on Linux and fits from 32 KiB
  (macOS fits 16 KiB), while the recursive reference aborts at 64 KiB and
  needs >256 KiB on macOS — so the tests use 64 KiB; in RELEASE the fd copy
  and fsync fit 8 KiB on both platforms, while the recursive reference aborts
  through 64 KiB and first survives at 96 KiB — so the tests use 24 KiB. The
  calibration test (`deep_tree_recursive_reference_copy_aborts_at_the_fd_stack`)
  additionally requires the recursive reference to abort at TWICE the fd
  stack, asserting a >=2x margin rather than relying on a hard-coded number
  that sat 1.5x below the release cliff.
* `fsync_tree_recursive_fd` reopens each root-relative path COMPONENT-WISE, so
  its cost is O(depth^2) `openat` calls (measured 1202 / 17042 / 264722 at
  depth 32 / 128 / 512 on Linux). It stays fail-closed, error-propagating,
  deepest-first, and iterative; the cost is stated on the primitive (documented,
  not changed).
* TWO-PHASE mode finalize — a read-only source directory copies cleanly (the
  source tool's one-phase original failed with `EACCES`); the final modes are
  still EXACT, including the setuid/setgid/sticky bits.
* The destination intermediates are created at the store-private `0o700` mode
  (the shared directory authority); only the FINAL copied directory takes the
  source's mode, and an intermediate staging directory is outside the copied
  tree, so it is not part of a staged-object digest.
* The ONE reserved-spelling gate runs on every destination mutation (the
  source tool's original had none), so a source entry named like a lock record
  (e.g. `operation.lock`) is REFUSED rather than copied into the destination
  namespace, and a residue-spelled destination component is refused BEFORE
  anything is created (the source tool's original created it and then reported
  the refusal in removal vocabulary).
* Every landed NAME runs the crate's ONE name authority: valid UTF-8, already
  NFC, free of NUL/LF/CR/TAB, within `NAME_MAX`, and not
  [`reserved::is_unaddressable_name`] — so a crate-temp-shaped or reserved
  name (which the documented recovery sweep or the manifest strip would
  remove) is REFUSED instead of landed, while spaces, quotes, `$`, `;`, `*`,
  leading `-`, and 255-byte names still copy.
* A source entry that is not a regular file, directory, or symlink (a FIFO,
  socket, or device) is REFUSED through the crate's `O_NONBLOCK`-classified
  open, so a FIFO cannot block the copy, and a HARD LINK is refused rather
  than silently duplicated into an independent regular file.
* A source/destination OVERLAP (either inside the other, or equal) is refused
  before anything is created, decided by directory IDENTITY (`(st_dev, st_ino)`
  on Unix, volume serial + file index on Windows), not by path spelling, so a
  Linux `mount --bind` alias, a macOS firmlink, a Windows junction, or a
  case-fold-equal `dst_rel` can no longer be created INSIDE the source and run
  the walk without bound. The destination ANCHOR (the deepest existing
directory on `dst_rel`) is compared with the opened source; a component that
  cannot be opened as a directory, and any identity-probe failure, refuse (fail
  closed). The one case identity cannot catch (two paths onto one tree that
  report DIFFERENT device numbers) is documented rather than hidden.
* A FAILED COPY RESTORES EVERY MODE IT CHANGED (an RAII journal): a
  pre-existing destination directory goes back to its original mode and a
  directory the call created goes back to the removable `0o700`, so a failed
  copy can never leave the SOURCE mutated (the fold-equal case), nor leave a
  destination the CALL CREATED that the crate's own `remove_dir_all_fd` cannot
  remove. A pre-existing destination keeps its own mode. On success the exact
  modes are applied and the journal is disarmed.
* SYMLINK LANDING IS ALL-OR-NOTHING, like the file (`O_EXCL`) and directory
  (`mkdirat`) rules: a copied symlink over a pre-existing file, directory, or
  symlink is REFUSED (`symlinkat` `EEXIST`) and the old entry is left intact,
  where the public `symlink_fd`'s replace semantics used to unlink and destroy
  a live destination file. A copied file uses create-new and a copied directory
  `mkdirat`, so all six kind pairs refuse rather than replace.
* The SOURCE spelling is normalized (`normalize_root`) and its FINAL component
  must not be a symlink, so a trailing-separator symlink source (`link/`) is
  refused instead of followed — POSIX resolves a trailing separator as an
  intermediate component, whose `lstat` reports a directory.
* The descriptor bound is stated and MEASURED: the walk holds one source
  descriptor per level, and a destination mutation holds O(1) because the
  ancestor chain is re-opened one component at a time (depth 256 succeeds at
  `RLIMIT_NOFILE=262`); the TIME cost is O(depth) `openat` calls per
  destination entry. `dir_entry_names` buffers a directory's whole name list
  (measured ~50 B/entry); the widest directory, not the depth, bounds that
  heap.
* FIDELITY IS TO THE MANIFEST MODEL: content, modes (with the special bits),
  and symlink targets — the fields `canonicalize_tree` digests — are faithful,
  so a copied tree passes the digest. mtime/atime/xattrs/ACLs/ownership are NOT
  carried; a caller that needs them restores them.
* A symlink's TARGET is judged by the crate's own containment rule through the
  SAME indexed authority the two manifest views use
  (`manifest::SymlinkContainmentIndex` + `check_relative_symlink_target_indexed`,
  full-Unicode-case-fold), built from a filesystem enumeration of the source
  subtree and the destination entries the run leaves in place, so a target that
  escapes the root or resolves through a symlink component (inside the copied
  subtree, or a surviving destination-only symlink in the destination root) is
  refused and the destination always `canonicalize_tree`s cleanly. A tree that
  cannot be enumerated is refused (fail closed), and a source that changes
  shape during the copy is detected by an end-of-run re-enumeration (the copy's
  analogue of `sync`'s source re-read); the copy does not lock an arbitrary
  source, so a caller that needs a hard guarantee must serialize the source.
* NOT atomic, NOT durable, and PARTIAL ON FAILURE: there is no temp directory
  and no final rename, so entries appear in place, an error mid-walk leaves a
  partial destination tree, and nothing is fsynced; a caller that needs more
  copies into a staging path it owns and renames it into place. A partial
  destination the call CREATED is removable with `remove_dir_all_fd` (the modes
  were restored); a pre-existing one keeps its own mode. The empty ancestors
  the call created are kept so that documented cleanup keeps working.
* The `dst_rel` PATH is exempt from the documented recovery sweep (a
  temp-shaped staging component like `.staged.tmp.1.2/root` is needed by
  `deploy`), but a temp-shaped ENTRY name is refused — so a caller that leaves
  a copy AT a temp-shaped destination loses the whole tree to the sweep and
  must rename it into place.
* The destination side is descriptor-confined (a symlinked component is
  refused); the source side is a path-based READ, exactly as the original. The
  Windows port is path-based with the port's documented weaker guarantee, and
  it materializes each file whole through `std::fs::read` (the Unix port
  streams through a 64 KiB heap buffer).

## Rules for changing this crate

**Mechanically enforced today.** The crate has exactly TWO source audits, both
in `atomic::guard::tests`: `no_libc_reference_outside_the_funnel` fails on any
new `libc` reference outside `src/atomic/unix.rs` (a mutating symbol, a
`use libc as alias`, a braced self-alias, a re-export, a glob, or a call broken
across a newline), and `std_fs_name_mutation_counts_are_pinned` fails when a
production `std::fs` removal/replace/rename call count changes. Together they
back the rule that every name mutation goes through the ONE guarded funnel.

**Review conventions, NOT mechanical checks.** The rest of this list is enforced
by review: in particular "fix the class, not the instance", "an oracle must be
able to express the failure it is meant to catch", "a document that contradicts
the code is a defect in whichever is wrong", "a green gate on one platform is
not evidence for another", and "no assertion is weakened or deleted" have no
test that would catch their violation. An aspiration presented as an enforcement
is the same defect as a false claim, so they are labelled here rather than
implied to be checked.

- A behaviour fix lands with a test that fails before the change. A test that
  cannot fail before says so in its own comment.
- No assertion is weakened or deleted to make a change land.
- **A public-API deletion is justified only by a CONSUMER's need, never by this
  crate's own tests.** The crate exists to be consumed, so its own suite passing
  means nothing about a consumer's call sites: "our production never did" and
  "only a test used it" are evidence about the WRONG population, and a consumer
  that DECLARES the name in its interface or CALLS it in production is the
  authority. When a name is weak, NAME the weakness — a default whose doc states
  what it discards, a doc that points at the typed alternative — rather than
  deleting it; that is rule 2 ("a weaker guarantee is reachable only through an
  entry point whose name states it"), not an exception to it.
  `tests/consumer_fit.rs` is the backstop: it exercises the shapes a consumer
  requires (against the public API only), so a deletion is a compile failure
  rather than a silent green.
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
- State every bound with the reason it holds, and every cost with its number.
  A cost asserted without a measurement is a guess wearing a number's clothes.
- **A guarantee belongs at ONE authority every path passes through.** And the
  corollary that cost three separate fixes: *co-location is not co-application*.
  Two authorities applied at the same call sites diverge by one line each
  (a guarded `renameat_paths` beside an unguarded `renameat_fd`; a lock-record
  check beside a missing residue check). When two must both apply, they are ONE
  function, so that carrying one and skipping the other is not expressible.
- **A residual must be scoped to exactly the operation it justifies.** A stated
  limit, an exemption or a sanctioned break that is broader than its reason
  reads as a documented guarantee while acting as a hole. "The sanctioned lock
  protocol" excused a method that accepted any path; check each residual's reach
  against its justification, not its wording.
- **Agreement between views is not soundness.** Unifying two views onto one rule
  makes a wrong rule *consistent*, not correct — and consistency is what makes it
  harder to see. Prove the shared rule against the world; do not infer it from
  the views agreeing with each other.
- **A safety argument must cover the part of the input whose treatment changed,**
  not the part that was already correct. An argument about the link's parent
  components says nothing about the target's components, and the target is the
  half the change altered.
- **A fold that feeds a decision which GRANTS must be at least as broad as the
  host's fold.** The rule above (a fold is for denial) has this corollary: reuse
  a denial-grade fold for a permission decision and over-refusal silently becomes
  under-refusal. `str::to_lowercase` is a lowering, not a case fold.
- **A bound that is not injective converts a loud failure into a silent alias.**
  Check that a bounded derivation is a bijection on the inputs it accepts.
- **Pin the MAPPING, not just the mechanism.** A test that the machinery runs is
  not a test that it maps correctly; an inverted mapping once passed every test
  in the suite.
- **A bound test must measure the quantity that can regress** — not a proxy that
  happens to move with it (a count is blind to a quadratic).
- **When a fix changes what a signal MEANS, revisit every consumer of it.**
- **Whatever the address model accepts, every operation must be total over it.**
  If parsing admits a shape, every primitive that receives it must have a defined
  answer — otherwise the boundary is the bug.
- **A value feeding a length-limited resource must be bounded**, with the limit
  named and the overflow refused.
- **A primitive re-added from legacy code re-imports that legacy's hazards**
  unless each one is re-closed against the authorities the codebase has built
  since. It arrived with a FIFO hang, an unbounded recursion and a data-loss
  route that the newer substrate already knew how to refuse.
- **A test that cannot fail is worse than no test**, and a pre-fix proof that was
  not RUN is not a proof. Record which of the two you have.
- **A green gate can be a stale binary.** Cargo's fingerprint does not include
  `CARGO_MANIFEST_DIR`, so moving the crate's directory reuses objects compiled
  at the old path — and a test that bakes `env!("CARGO_MANIFEST_DIR")` (both
  source audits do) then reads a directory that no longer exists. Run
  `cargo clean -p storekit` after moving the tree, and treat a gate that ran
  without a rebuild after a path change as NOT RUN. The same applies to the
  REVISION: a checkout whose working copy is still parented to an older tip
  reports on a tree that no longer exists, so name the revision a gate or a
  count was taken from — a number measured against the wrong tree reads exactly
  like a real one.
- **A signature change is not verified until every supported platform has
  COMPILED it.** A call site inside a `#[cfg(...)]` block is invisible to the
  other platform's gate: a test gated to Linux is never built by a macOS run, so
  a changed parameter type can compile clean there and fail to compile on the
  other host. A green gate on one platform is not evidence for the other — it is
  not even evidence that the other platform BUILDS.
