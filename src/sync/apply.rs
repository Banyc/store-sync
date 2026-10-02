//! Policy-driven transfer of the entries a [`TreeDiff`] says differ.
//!
//! [`sync`] describes both sides as manifests, diffs them, and then moves the
//! `Missing` and `Changed` entries in the caller's [`Direction`] under the
//! caller's [`Policy`]:
//!
//! * only `Missing` and `Changed` entries are eligible — `Same` entries are
//!   skipped with no content I/O, and `Extraneous` (destination-only) entries
//!   are REPORTED and never deleted unless the caller passes
//!   [`Extraneous::Delete`] (the default is [`Extraneous::Keep`]);
//! * [`EntryPolicy::Replace`] overwrites the destination entry,
//!   [`EntryPolicy::Refuse`] leaves it alone and reports a conflict, and
//!   [`EntryPolicy::AppendTail`] applies the append-only prefix rule (below);
//! * directories are created before their children (the diff is path-ordered,
//!   and a parent path is a proper prefix so it sorts first); modes and
//!   symlinks are transferred faithfully; a symlink is never followed;
//! * the PULL direction writes through this crate's durable, fd-confined
//!   primitives (`crate::atomic`) so an interrupted pull cannot leave a torn
//!   entry; the PUSH direction writes through [`Remote::write`],
//!   [`Remote::create_dir_all`], [`Remote::symlink`], and [`Remote::set_mode`];
//! * after applying, every written entry is re-read and its hash, its symlink
//!   target, and the MODE of every path this sync touched are checked against
//!   the source — a mismatch is an ERROR, never a silent success.
//!
//! # The destruction invariant
//!
//! > A path may be destroyed only when the sync holds an explicit sanction for
//! > that path; every conflict that leaves a path alone also forbids destroying
//! > it, derived from ONE definition rather than a parallel set; and a path left
//! > in place is restored, never mistaken for a path that is gone.
//!
//! Each clause is structural:
//!
//! * **One definition of the prohibition.** A conflict does not need a
//!   separately-populated `blocked` set: the conflict VALUE carries the
//!   prohibition. [`ConflictReason::forbids_destruction`] is an EXHAUSTIVE
//!   match, so adding a conflict reason fails to compile until its author
//!   decides whether the path it names is off-limits to destruction. The
//!   prohibition is then DERIVED from the conflict record at the point of use
//!   ([`Applier::is_prohibited`]), so a conflict site cannot forget to block:
//!   there is nothing separate to forget. This is what covers every
//!   `AppendNotAFile` arm uniformly — a source file, directory, OR symlink over
//!   a destination directory is forbidden, not only the two arms that used to
//!   remember to insert into the set.
//! * **Proof-carrying deletion.** [`Applier::remove_subtree`] requires a
//!   [`Sanction`], not an ancestry question. [`Sanction::ExtraneousFlag`] is the
//!   caller's [`Extraneous::Delete`], and it refuses any path the conflict-derived
//!   prohibition covers; [`Sanction::OwnClaim`] carries the [`Claim`] naming the
//!   aside this sync itself renamed away, so the sync's own cleanup cannot
//!   strand residue under a conflicted writable ancestor — but the claim is
//!   re-established against the LIVE listing before a directory under it is
//!   destroyed, because a child a concurrent writer added after the claim was
//!   taken is NOT the sync's to destroy; [`Sanction::OwnPartial`] carries that
//!   same [`Claim`] for the sync's own rollback creation, so it rests on the same
//!   proof and is subject to the same total live re-establishment. A live entry
//!   that NO manifest spelling addresses is preserved and NAMED under EVERY
//!   variant: the decision is made at ONE authority
//!   ([`Applier::live_entry_manifest_spelling`]), which returns the manifest
//!   spelling a live path must have, so no variant can carry an unconditional
//!   `true`.
//! * **The live kind selects the mutation.** A kind OBSERVED at an earlier
//!   moment — in a manifest snapshot, a [`Claim`], or the mode journal — is
//!   never used to choose a mutation primitive that can destroy a live entry.
//!   [`Applier::remove_subtree`] takes NO kind and reads it from the live
//!   destination at its own entry, so its `Dir` arm (the ONLY place the
//!   per-child authority runs) cannot be bypassed by a caller presenting a
//!   stale non-`Dir` kind; [`Claim`] stores no kind; `transfer_file`,
//!   `append_tail`, and `make_overwritable` route on a live probe
//!   ([`Applier::live_dest_kind`]); and [`Applier::restore`] reads the live kind
//!   and REFUSES (and names) a kind the journal never recorded rather than
//!   applying a mode to it. `transfer_dir` and `transfer_symlink` still choose
//!   the ROUTE (a mode-only change over a directory, versus a claim+create)
//!   from the snapshot, but that choice cannot select a destruction primitive:
//!   the claim carries no kind, the removal re-reads the live kind, and a
//!   snapshot `Dir` whose live object is not a directory takes the mode-only
//!   route where the live guards refuse the chmod/install.
//! * **The final directory removal is NON-RECURSIVE.** `remove_subtree`'s `Dir`
//!   arm removes every child it enumerated through the live authority and THEN
//!   removes the directory itself with `rmdir` semantics (a descriptor-relative
//!   `unlinkat(AT_REMOVEDIR)` locally, `rmdir` through the exec seam remotely),
//!   which fails LOUDLY when the directory is not empty. A non-reserved entry a
//!   writer creates after the last enumeration is therefore REFUSED and NAMED,
//!   never destroyed unnamed, so the walk's claim — everything under this
//!   directory was enumerated and sanctioned — is re-established by the
//!   filesystem AT THE MOMENT OF REMOVAL. There is no recursive removal
//!   primitive at all: the walk of a directory's children is iterative (an
//!   explicit heap stack, one frame per directory), and every child is
//!   re-checked against the live authority on the way in, so a deep tree is
//!   bounded by memory rather than by the thread stack.
//! * **"Left in place" is a state, not `removed`.** A path that becomes residue
//!   is recorded `abandoned` in the mode journal: it is NOT deleted, NOT
//!   transferred, REPORTED in [`SyncReport::residue`], and — because it still
//!   exists — its transient widen is STILL restored. A path this sync removed is
//!   `removed`: there is no mode left to restore and it is never residue.
//!   Conflating the two silently left a widened residue directory at its
//!   widened mode.
//!
//! # The mode-record invariant
//!
//! Installing a child into a read-only destination directory requires
//! transiently widening that directory: creating, replacing, or unlinking an
//! entry inside a directory needs owner write permission on it, and a local
//! durable write additionally chmods the immediate parent private. The whole
//! mechanism is one `ModeJournal`, and it enforces exactly:
//!
//! > Every mode the sync changes is recorded ONCE, with its original value, at
//! > the single place that changes it; every recorded path is restored unless
//! > its final intended mode was successfully applied; and the report is
//! > derived from that record, never from bookkeeping that has been drained or
//! > overwritten.
//!
//! Each clause is realized structurally, not by convention:
//!
//! * **One entry per live path.** `ModeJournal` is a `BTreeMap<path,
//!   ModeEntry>`. `original` is recorded on the FIRST touch only and never
//!   overwritten, so the value a restore must return to cannot be lost by a
//!   later widen, and a second touch cannot create a second bookkeeping record
//!   to get out of sync. A path this sync REMOVED ends its identity; if the same
//!   path is created again (a source file or symlink replacing a destination
//!   directory), the record restarts, because the old identity no longer exists
//!   to restore. A SYMLINK has no mode step (its manifest mode is fixed and
//!   never chmodded), so it counts as settled once its target is verified.
//! * **One widen choke point.** `widen_ancestors` (through `widen_dir`) is the
//!   only path that widens a directory, and EVERY mutation kind calls it before
//!   writing into a directory: a directory create, a regular-file write, an
//!   append write, a symlink create, and a removal — which additionally widens
//!   the TARGET of a subtree removal, not only its ancestors. The
//!   decision is read from the directory's CURRENT mode, never the source's and
//!   never a cached "already widened" bit (a directory can need widening again
//!   after `finalize` reinstated a read-only final mode, and the read-only
//!   overwrite widen decides from the live file mode).
//! * **One prohibition.** A path whose OWN entry a conflict left alone is never
//!   widened, created, finalized, or removed, and a child that would need it
//!   widened is reported [`ConflictReason::ParentRefused`]. That set is the
//!   conflict-derived prohibition ([`ConflictReason::forbids_destruction`]), not
//!   a parallel `blocked` set. A no-write transfer (a mode-only change — a
//!   file's, or a directory over an existing directory — or an append whose
//!   source is a prefix of the destination) needs no widen and is therefore not
//!   blocked.
//! * **One restore site.** `settle` calls `restore` on the SUCCESS and the
//!   FAILURE path. `restore` does not drain the journal (the report still
//!   derives from it), skips a path whose own final mode was applied
//!   successfully or that was removed, is idempotent (a path already at its
//!   target is not chmodded again), COUNTS every chmod it performs, and
//!   re-reads the mode it wrote back so a dropped restore is never silent.
//! * **The report is derived.** `transient_dirs` is the journal's set of
//!   widened, not-removed paths; an entry is in `applied` only after its final
//!   mode landed AND EVERY verification check passed — content/target AND mode;
//!   `skipped` omits every path the journal touched. No field is accumulated by
//!   a parallel pass that could be drained or overwritten.
//!
//! ## Failure accounting: attempt-first, and the report partition
//!
//! A destination mutation is recorded as an ATTEMPT BEFORE the fallible call
//! runs: `begin_mutation` counts the transfer and names the path, and
//! `commit_mutation` clears the name once the call reports `Ok`. A call that
//! fails AFTER publishing its effect — a write whose bytes are visible while
//! its chmod/fsync/durability check fails (`ReplacedDurabilityUnknown`), a
//! `create_dir_all` that created the directory and then failed, a chmod whose
//! result is unconfirmed — is therefore never invisible: the path it may have
//! changed is named in [`SyncReport::indeterminate`] and its step is counted in
//! `transfers`. This is what keeps `transfers == 0` a valid "nothing was
//! mutated" oracle; the old order (count only after `Ok`) let a
//! partially-applied mutation leave no trace at all.
//!
//! The name is cleared only by a LATER successful call OF THE SAME KIND. A
//! successful chmod (the `settle` restore re-establishing a widened mode)
//! resolves a pending MODE attempt, because the path's mode is then known again;
//! it never resolves a pending CONTENT attempt, because whether a failed write,
//! create, rename, or removal landed is a separate fact a mode restore cannot
//! establish. A failed content mutation therefore STAYS in `indeterminate` even
//! after its mode has been restored.
//!
//! The report lists PARTITION under ONE explicit precedence, applied in
//! `Applier::derive_report`:
//!
//! > `indeterminate` > `conflicts` > `residue` > `applied` > `skipped` >
//! > `extraneous` > `verify_failures`
//!
//! A path named by a higher list is omitted from every lower one.
//! `indeterminate` is the least certain claim (a failed mutation may or may not
//! have landed), so it subsumes every other; `conflicts` is the caller's
//! decision surface and is never hidden; `residue` still EXISTS and must be
//! recovered by hand, so it wins over the verification bookkeeping in
//! `verify_failures` (whose failure is also carried in
//! `SyncError::restore_failures`); `applied`/`skipped`/`extraneous` describe a
//! known outcome; `verify_failures` is the catch-all for a mutation that did
//! not reach a passed final state. `transient_dirs` is deliberately OUTSIDE the
//! partition: it may share a path with `applied` or `verify_failures` (a
//! widened directory that was also applied, or whose verification failed), but
//! never with `indeterminate`, `conflicts`, `residue`, `skipped`, or
//! `extraneous`.
//!
//! ## Kind-changing replacement, the reserved namespace, and residue
//!
//! When the destination entry has a different KIND than the source — a file
//! over a directory, a symlink over a directory, a directory over a file, or a
//! file or directory over a SYMLINK — the stale entry is CLAIMED by renaming it
//! aside to a hidden sibling whose name starts with `.sync-aside.`, the new
//! entry is installed at the real name, and only then is the aside deleted by
//! the ONE deepest-first, widening removal (`remove_subtree`): a read-only
//! directory nested anywhere in the stale subtree is widened before anything is
//! unlinked from it. Before replacing a destination directory, the sanction
//! check consults the UNSTRIPPED residue set as well as the diff, so a directory
//! whose only child is an aside is never mistaken for an empty one. Same-kind
//! file overwrites are already atomic (temp + rename) and are not claimed.
//!
//! The `.sync-aside.` prefix is a RESERVED namespace. Before the diff, every
//! manifest entry with a reserved component is stripped from BOTH sides. A
//! DESTINATION reserved entry is abandoned residue: it is reduced to its topmost
//! path in [`SyncReport::residue`], NEVER transferred (a pull must not copy a
//! stranded aside into the other tree), and NEVER removed — not even by
//! [`Extraneous::Delete`]: a destination-only directory that contains residue has
//! its removal refused as [`ConflictReason::ResidueBelow`], and a CLAIMED subtree
//! that contains residue is left in place (the removal stops at the reserved
//! child instead of handing the directory to a recursive removal, which
//! would delete exactly the entry that was skipped) — and ALWAYS reported, so the
//! caller can recover it by hand instead of losing it. Residue has a SECOND
//! kind, NOT in the reserved namespace: a live ORDINARY destination path the run
//! refused to remove or displace — a child a concurrent writer added under a
//! subtree the sync was walking under its own claim (no manifest spelling
//! addresses it, so it is not the sync's to destroy), or a writer's live entry
//! at a rollback target (the sync refuses to let a `rename` displace it). Both
//! kinds are the same state and obey the same rules below; the ordinary kind is
//! named under its own spelling rather than reduced to an aside. Every path
//! named in `residue` still EXISTS afterward: a claim that moves a
//! residue-holding subtree re-roots the reported paths to their current location,
//! and because the path still exists a transient widen of it is RESTORED (the
//! journal records it abandoned, not removed). This is made true BY CONSTRUCTION
//! by the final reconciliation (`Applier::reconcile_residue`), which confirms
//! every residue candidate present at report time: a candidate that is gone, or
//! whose presence cannot be confirmed because the probe itself fails, is NOT
//! reported as residue — it is routed to the possibility channel instead.
//!
//! Two rules make the report honest about LOCATION:
//!
//! > the LISTS assert EXISTENCE and contain only CONFIRMED paths; the MESSAGES
//! > describe.
//!
//! `residue` is a LIST: every entry is confirmed present at report time, so no
//! message ever has to guess. The POSSIBILITY channel is the other half and it
//! asserts NOTHING: every claim or rollback RENAME whose landed-or-not could not
//! be confirmed is surfaced UNCONDITIONALLY, whether or not any residue
//! candidate falls under it. Each such move names BOTH possible spellings in
//! `indeterminate` (a list that asserts no location) and in a restore failure
//! explicitly marked unconfirmed. The same read-back governs a rename that
//! REPORTS an error: the entry's actual location is READ BACK (the fd-confined
//! kind primitive locally, the transport's typed metadata remotely) and the
//! aside is named as residue ONLY when the entry is confirmed to be there, so a
//! move that landed and then returned an error names the aside while a move that
//! did not land names nothing residue-ish and a move whose location could not be
//! confirmed names neither path AS RESIDUE. The message rule applies to
//! DELETIONS too: a leftover claim-aside is named as still holding the original
//! only after a read-back CONFIRMS it, so a removal that landed and then
//! reported failure names no path that is gone. A SOURCE entry that
//! collides with the reserved namespace is a [`ConflictReason::ReservedName`]
//! conflict, never a silent skip
//! and never residue: it is not a destination path this sync left in place.
//!
//! ## Refusal: transfer versus destruction
//!
//! A path whose own entry a conflict left alone is off-limits to DESTRUCTION:
//! the prohibition is derived from the conflict record
//! ([`ConflictReason::forbids_destruction`]), NEVER from a parallel set, so
//! [`Applier::remove_extraneous`] refuses to delete that path or any entry under
//! it — independent of the directory's mode — and reports
//! [`ConflictReason::ParentRefused`]. The same prohibition refuses a deletion
//! attempted under [`Sanction::ExtraneousFlag`]. The TRANSFER rule is narrower:
//! a refused but WRITABLE existing directory may still admit a transferred
//! child, because that writes a source entry rather than destroying a
//! destination one.
//!
//! Deletion is therefore proof-carrying. The sync's OWN claim aside is deleted
//! under [`Sanction::OwnClaim`] — the caller holds the [`Claim`] naming it — and
//! its own partial creation during a rollback under [`Sanction::OwnPartial`],
//! which carries that same [`Claim`]; neither names caller data, so neither
//! consults the prohibition. Both are still re-established against the LIVE
//! listing at ONE authority ([`Applier::live_entry_manifest_spelling`]): a live
//! entry no manifest spelling addresses is preserved and reported, never
//! recursively destroyed. This is what
//! lets a legitimately admitted transfer clean up after itself instead of
//! stranding residue under a conflicted writable ancestor.
//!
//! What each failure leaves behind:
//!
//! * install fails and the rollback rename succeeds — the destination is
//!   BYTE-IDENTICAL (`canonicalize_tree` equal) and no aside remains. A LOCAL
//!   install goes through `crate::atomic::write_atomic_replace_fd`, which
//!   unlinks its dot-prefixed temp on EVERY failure path, so a failed local
//!   install leaves NO stray entry either: the destination is byte-identical,
//!   not merely aside-free;
//! * install fails and the rollback ALSO fails — including a `create_dir_all`
//!   that created the directory and then failed, where the sync first removes
//!   its OWN partial creation — the destination may hold a stranded aside:
//!   reported in [`SyncError::restore_failures`], and in
//!   [`SyncReport::residue`] when the read-back CONFIRMS it is still there (a
//!   probe that itself fails routes the aside to the possibility channel
//!   instead, exactly as for a leftover aside above);
//! * install succeeds but deleting the aside fails — the destination is
//!   CORRECT (the entry is verified and reported `applied`), and the removal
//!   failure is READ BACK before anything is named. The aside is `residue` only
//!   when it is CONFIRMED present — the removal stopped at a reserved child, so
//!   the holding directory is KNOWN to remain, or the failed call did not unlink
//!   the aside; a removal that LANDED and then reported failure leaves the path
//!   in `indeterminate` and names NO aside that is gone; and a probe that itself
//!   fails records the candidate for the report-time reconciliation rather than
//!   asserting existence. The message describes only what the read-back
//!   CONFIRMED: a present FILE or SYMLINK aside IS the claimed original, so it
//!   still holds it, but a present DIRECTORY aside is confirmed only to EXIST —
//!   `drop_claim` may already have unlinked some of its children before a later
//!   removal failed — so the message says it remains without claiming its
//!   content is intact;
//! * a claim (or rollback) rename REPORTS failure — the entry's actual location
//!   is read back before anything is recorded. A LANDED claim names the aside as
//!   residue and as a restore failure (the caller's only copy is there); a
//!   LANDED rollback re-roots any residue and reports NO stranded aside (the
//!   entry is back at its real path); a rollback that did NOT land records the
//!   aside as residue and as a restore failure; and a location that cannot be
//!   confirmed names neither path AS RESIDUE — instead a restore failure names
//!   BOTH possible spellings and says the location could not be confirmed. The
//!   attempted rename is always counted and, because whether it landed is a
//!   separate fact a mode restore cannot settle, left in `indeterminate`.
//!
//! ## Ordering
//!
//! `transfer` → `finalize` → `verify` (content, targets, final modes) →
//! `remove_extraneous` → `settle` (`restore`, then the mode verification that
//! includes the restored modes). Transfers and verification therefore complete
//! before any extraneous removal, so a sync that fails DURING transfer or
//! verification destroys nothing (the removal phase has not begun): a removal
//! runs only after every write and every final mode has been checked, and a
//! kind-changing replacement claims rather than removes. The one exception is a
//! SANCTIONED removal that fails part-way (a read-only destination root, below):
//! entries the caller asked to delete may already be unlinked, which is why the
//! invariant is stated over UNSANCTIONED entries. The removals' own parent
//! widenings are reverted by the single `settle`.
//!
//! ## The two roots must be disjoint (overlap refusal)
//!
//! [`sync`] refuses a local/remote root pair where one is a STRICT ANCESTOR of
//! the other, before any mutation. Nested roots put the run on both sides of an
//! overlap: a `dst` inside `src` makes the destination manifest enumerate the
//! source's own subtree (the run copies `sub/x` to `sub/sub/x` and, with
//! [`Extraneous::Delete`], destroys `sub/x`), and an `src` inside `dst` makes the
//! destination manifest enumerate the source (an extraneous removal destroys
//! it). Equal roots are ALLOWED: the manifests are identical, the diff is
//! empty, and the run is an idempotent no-op — refusing them would break a
//! legitimate call, so the equality case is carved out of the rule. The rule
//! itself is NOT a second comparison: it is `crate::root::roots_overlap`, the
//! single authority [`crate::root::OwnedRoot::parse`] uses, applied to the
//! CANONICAL roots (trailing separators, `..`, and symlinked components
//! resolved; a not-yet-created destination canonicalized up to its longest
//! existing prefix). The refusal is an error naming BOTH roots.
//!
//! UNDECIDABLE CASE: when `remote.is_local()` is false the remote root names a
//! path on ANOTHER host, which this host cannot resolve — the far-side path may
//! coincide with, contain, or be contained by the local root (a bind mount, a
//! shared filesystem, or an `ssh` target that is this very host). NO refusal is
//! computed there, and none is implied: the two roots are NOT guaranteed
//! disjoint for an [`SshTransport`](crate::transport::SshTransport)
//! destination, and a caller that co-locates them on one filesystem must
//! enforce disjointness itself. This is stated rather than papered over: the
//! guarantee this module computes is exactly the one it can see from here.
//!
//! ## The lock discipline: the destination is exclusively owned
//!
//! [`sync`] TAKES the destination's operation lock and holds it for the WHOLE
//! run — acquired before the destination manifest is read and released only
//! after the transfers, the post-transfer verification, and any removal
//! phase. The lock is a [`crate::lock::FileLock`]: an advisory `flock`
//! (`LockFileEx` on Windows) held by an open descriptor, which the kernel
//! releases when the descriptor drops. The guard is therefore released on the
//! success path, on EVERY error return, and on a panic that unwinds; a
//! `SIGKILL`ed holder releases it too, because the kernel closes the process's
//! descriptors. There is ONE authority for how a lock is taken —
//! [`crate::lock::FileLock`], the same primitive the crate documents for its
//! push and checkpoint pipelines — and the record name reuses the crate's
//! reserved `operation.lock` spelling (see [`destination_lock_path`]).
//!
//! ### The conditions the crate ENFORCES (and what a caller still owes)
//!
//! The crate does not trust these conditions to documentation; it builds them
//! into the entry points and into the run itself.
//!
//! 1. **The destination is exclusively owned. The crate enforces this for a
//!    LOCAL destination by TAKING the lock itself.** The owned entry points —
//!    [`sync`], [`push`], and [`pull`] — acquire the destination's operation
//!    lock (a [`crate::lock::FileLock`] on the record named by
//!    [`destination_lock_path`]) BEFORE reading the destination manifest and
//!    hold it for the WHOLE run. A cooperating writer that tries to acquire the
//!    same record while the run holds it is refused at acquisition
//!    (`FileLock::acquire` is non-blocking), so the run's writes and reads
//!    cannot be interleaved by one. A destination the crate CANNOT lock — a
//!    REMOTE (far-side) one, or a root with no sibling record location — is
//!    REFUSED by those entry points rather than silently run unowned. A caller
//!    that holds such a destination itself must say so by calling
//!    [`sync_unowned`] (or [`push_unowned`]/[`pull_unowned`]): the NAME is the
//!    only place the weaker choice appears, so it cannot be made by omission.
//! 2. **The source is quiescent. The crate cannot lock the source, so it
//!    VERIFIES it instead.** The source is a remote tree the crate does not own
//!    (a PULL) or the caller's local tree (a PUSH), and there is no lock record
//!    for it. The run therefore re-reads the source manifest after the transfer
//!    and compares it to the one the plan was made against: an entry that ADDED,
//!    DISAPPEARED, or CHANGED makes the run FAIL CLOSED and is NAMED, and a
//!    source read that cannot be repeated is likewise a failure. What a caller still owes is honesty about
//!    ABA: a source that changes and changes BACK between the two reads is
//!    indistinguishable from a stable one — two samples can refute quiescence,
//!    never prove it.
//! 3. **A writer using a DIFFERENT version of this tool, or a different tool
//!    sharing the store, is a NON-COOPERATING writer unless it takes the same
//!    lock.** The ownership claim is only as strong as the ecosystem's
//!    discipline; the crate cannot force another program to take the record.
//!
//! ### What happens when a non-cooperating writer violates the ownership condition
//!
//! A COOPERATING writer cannot interleave: the crate holds the lock, so the
//! writer is refused when it tries to take the same record. A NON-cooperating
//! writer — one that does not take the lock, which includes a writer using a
//! different version of this tool or a different tool sharing the store —
//! still can, and the answer is DETECTION THAT FAILS CLOSED, never permission
//! to lose its data. The post-transfer verification is retained UNCHANGED: it
//! reads every written entry, the touched directories' live listings, and the
//! entries the run claims to have left alone, and surfaces a violation as a
//! conflict, a [`SyncReport::verify_failures`] entry, or a hard error naming
//! the unplanned path. An out-of-band write the verification OBSERVES is
//! therefore reported and the run does not return a clean `Ok`; taking the lock
//! did not narrow that detection and removed no check. The honest limit is
//! COVERAGE, not intent: the verification is scoped to the paths it reads, so a
//! writer that touches only paths the run never inspects can still escape it,
//! and an `Ok` run is not by itself a claim that the destination is clean.
//!
//! ### The far-side (remote destination) limitation
//!
//! [`destination_lock_path`] is a path on THIS host and [`crate::lock::FileLock`]
//! is a LOCAL descriptor lock. A destination whose [`Remote::is_local`] is
//! `false` names a far-side tree, and the existing machinery cannot hold a
//! far-side lock across the run: the transport's sidecar `flock` is taken
//! INSIDE a single remote command and dies when that command exits, so it
//! serializes one lock-record mutation, not a whole run. The owned entry points
//! therefore REFUSE a remote destination; only [`sync_unowned`] reaches it, and
//! for that run the crate enforces NEITHER the destination lock NOR any
//! far-side exclusion, so a cooperating far-side writer is not excluded and the
//! caller must supply the serialisation itself. The SOURCE-quiescence re-read
//! still runs. Closing the gap needs a persistent far-side session, which does
//! not exist here.
//!
//! ### Why the lock record is a SIBLING of the destination root
//!
//! The lock record is deliberately NOT placed inside the destination tree.
//! Creating `<root>/state/operation.lock` would create the destination ROOT
//! itself for a run that must create nothing, and it would enter the
//! destination manifest the run reads, destroying the "a fully-refused pull
//! creates NOTHING, not even the root" and "two empty trees are a no-op"
//! contracts (both pinned by tests). [`destination_lock_path`] therefore
//! derives a dot-prefixed sibling record in the destination root's parent:
//! taking the lock never creates or enters the tree the run is judging, and
//! the record reuses the reserved `operation.lock` spelling
//! ([`crate::transport::Layout::lock`]) rather than inventing a mechanism.
//!
//! Because the record is a SIBLING, placing it can touch a directory OUTSIDE
//! the destination root that the CALLER owns — the root's parent, and any
//! missing ancestor of it. Two things are true of that touch, and they are the
//! contract:
//!
//! * **The parent chain is created at the PLATFORM DEFAULT mode, never the
//!   store-private `0o700`.** The owned entry points pre-create a missing chain
//!   with `create_dir_all` ([`create_lock_parent`]), the same mode the run's own
//!   `root_for_mutation` gives a destination root's missing ancestors, so the
//!   lock path introduces no mode the run would not itself have used. (This is
//!   deliberately NOT a change to [`crate::lock::FileLock`] or
//!   [`crate::atomic::ensure_private_dir_durable`], which serve the transport's
//!   sidecar locks where the private mode IS required.)
//! * **The DESTINATION TREE is still created lazily and only by a mutation.**
//!   "A fully-refused pull creates NOTHING" holds for the root and everything
//!   under it: the record location is outside the root, so a refused run may
//!   still leave the root's PARENT chain present at the platform default mode,
//!   but it never creates the root itself. This is the honest limit of the
//!   contract; it is stated here rather than implied.
//!
//! A single-component RELATIVE root resolves through the current directory
//! ([`destination_lock_path`] maps an empty `Path::parent` to `.`), exactly as
//! the rest of the path handling resolves a relative root, so the owned entry
//! points accept a relative destination instead of failing on `mkdir ""`.
//!
//! ## Root pinning, and the race that remains
//!
//! [`sync`] opens the local root descriptor BEFORE it reads either manifest
//! (when the root exists), and every local mutation resolves through that
//! pinned descriptor. The manifest itself is produced by the path-based
//! canonicalizer, so the difference between the descriptor's inode and the
//! path's inode is checked immediately after the walk on Unix: a replaced root
//! is an error, not a diff about one inode and mutations against another. What
//! is NOT guaranteed: an ABA race (the path swapped away and back during the
//! walk) is not detectable by a post-walk identity check, and a swap after the
//! check cannot redirect a mutation (they use the pinned descriptor) but can
//! still make the diff describe the pre-swap tree. Closing those requires
//! descriptor-relative walking, which this module does not have. On Windows
//! there is no directory descriptor, so the pinned-inode check does not exist
//! (the documented weaker guarantee of the Windows port).
//!
//! The destination root is created LAZILY, immediately before the first
//! mutation that needs it, so a pull whose every entry is refused leaves the
//! root ABSENT, not merely empty. Because the diff of a root that was absent
//! describes the EMPTY tree, a directory that has appeared at the path since is
//! adopted only if it is still EMPTY (exactly what this would have created); a
//! NON-EMPTY one is an error rather than silently ignoring its entries (which
//! would be neither reported nor removed). A narrow race remains between that
//! emptiness check and the mutations — the same pinned-descriptor gap as above.
//!
//! ## Destination-component confinement
//!
//! Every destination mutation consults ONE preflight
//! ([`Applier::guard_destination`]) before it runs: with `lstat` (`kind_opt`,
//! never `stat`/`exists`) it verifies that every STRICT ancestor component of
//! the destination path is a REAL directory (a symlink, a file, or — where the
//! operation requires it — a missing component is refused) and that the FINAL
//! component satisfies what the operation does to it. This is what keeps a
//! destination mutation inside the destination root on a path-based [`Remote`]:
//! without it a symlink at a directory position redirects a write, a chmod, a
//! rename, a removal, or a listing OUTSIDE the root. [`Applier::dir_listing`]
//! additionally refuses to enumerate a path that is not a real directory (only
//! a CONFIRMED absent path enumerates as empty) and carries the live KIND, so a
//! symlink where the manifest says `Dir` is never treated as an intact
//! directory. The preflight duplicates a window a component-confined
//! destination already closes in `crate::atomic` (the platform property is
//! [`crate::atomic::COMPONENT_CONFINED`]; on Unix every `_fd` primitive
//! resolves components with `O_NOFOLLOW`); for a
//! [`LocalTransport`](crate::transport::LocalTransport) the transport itself
//! resolves every non-root path component-wise with `O_NOFOLLOW` (no window) —
//! mutations AND the reads this applier verifies against (`read`, `read_link`,
//! `metadata_opt`, `exists`), so a verification verdict cannot be sourced from
//! outside the pinned root; for an
//! [`SshTransport`](crate::transport::SshTransport) the far-side script cannot
//! be changed, so the preflight is the guarantee and a component SWAPPED
//! between the check and the operation is a residual race — the same class as
//! the root-swap race above, not a guarantee this module claims to close.
//!
//! The applier sees only [`Side::is_confined_local`], a property of the SIDE
//! AND THE PLATFORM it was handed, not of a concrete transport: a
//! [`Side::Remote`] destination may be backed by a
//! [`LocalTransport`](crate::transport::LocalTransport) whose own primitives
//! happen to be fd-confined, but the applier cannot know that, and a
//! [`Side::Local`] destination on a platform whose primitives are path-based is
//! not confined either ([`crate::atomic::COMPONENT_CONFINED`]). It therefore
//! treats every destination whose own primitives are not component-confined as
//! path-based, where the preflight IS the confinement, and caches nothing that
//! would let a repeated probe be skipped (see [`Applier::ancestry_dirs`]).
//!
//! ## The destination root's mode is NOT journalled
//!
//! The widen machinery covers every destination DIRECTORY the manifest
//! describes, but not the destination ROOT: `ancestor_paths` deliberately
//! excludes it ("a manifest does not describe the root"), so neither
//! `widen_ancestors` nor `forbidden_ancestor_blocks_write` reaches it, and
//! `root_for_mutation` creates an absent root without recording or adjusting its
//! mode. A READ-ONLY destination root is therefore NOT transiently widened, and
//! every TOP-LEVEL mutation — a `Missing` file or directory, a `Changed` file or
//! symlink, a top-level removal — fails. The failure is LOUD and never SILENTLY
//! destructive: the attempt is counted in `transfers` and the path is named in
//! [`SyncReport::indeterminate`], and the root keeps its original mode (nothing
//! restores it, because nothing widened it). Two things are NOT claimed here.
//! First, `no entry is destroyed` holds only for UNSANCTIONED entries: a
//! top-level `Changed` or `Missing` mutation fails before it touches any entry,
//! so nothing is mutated at all, but a top-level removal the caller SANCTIONED
//! ([`Extraneous::Delete`] over an extraneous directory) may unlink that
//! directory's children before the removal's own final `rmdir` fails on the
//! read-only root — a sanctioned deletion that stops part-way, not a destroyed
//! caller entry. Second, the sync's own residue cleanup is likewise a sanctioned
//! removal and can fail the same way. This is a deliberate, DOCUMENTED
//! limitation: correcting it would require a root-mode operation on the
//! [`Remote`](crate::transport::Remote) transport, and `Remote::root()` is
//! documented to name an entry on a REMOTE
//! host for an [`SshTransport`](crate::transport::SshTransport), so the root
//! cannot be chmodded portably from this module. Widening only the LOCAL
//! destination root would make the guarantee depend on the direction and the
//! transport, so the invariant is stated uniformly: the root is not ours to
//! chmod, and a read-only one fails loudly rather than being repaired.
//!
//! ## Missing ancestors of the destination root are created, not accounted
//!
//! When the destination root is ABSENT, `root_for_mutation` creates it with
//! `std::fs::create_dir_all`, which also creates any MISSING ANCESTOR
//! directories of the root path (OUTSIDE the root itself). What is created:
//! each absent component of the caller-supplied root path, with the
//! platform's default directory mode, at the moment of the FIRST mutation that
//! needs the root. When: LAZILY — a sync whose every entry is refused never
//! calls it, so no root and no ancestor appears — and only ever from inside a
//! mutating primitive that has ALREADY recorded its attempt
//! ([`Applier::begin_mutation`]), so `transfers == 0` still implies nothing was
//! mutated. The creation is NOT journalled, NOT counted in `transfers`, and NOT
//! rolled back if a later step fails. That is safe: the ancestors are neither
//! manifest entries nor caller data (they did not exist), they are the
//! prerequisites of the caller's own requested destination path, and rolling
//! them back would risk deleting a directory a concurrent process has since
//! come to depend on. The root's own mode is likewise not journalled (above).
//!
//! ## Path ancestry
//!
//! Ancestry is always interpreted with `std::path::Path` (`parent`,
//! `strip_prefix`, `components`), never by splitting the manifest string on a
//! literal separator. The code is therefore correct whether the manifest
//! spells paths with `/` (the canonicalizer) or with the platform separator,
//! and a sibling whose name shares a prefix with a directory (`px` beside `p`)
//! is never mistaken for a descendant.
//!
//! ## Manifest paths are addresses
//!
//! A manifest path is used as a filesystem ADDRESS (through [`rooted`]), so the
//! stored spelling must BE the on-disk name. That guarantee belongs to the
//! canonicalizer, not to this module: [`canonicalize_tree`] and
//! [`canonicalize_remote_entries`](crate::manifest::canonicalize_remote_entries)
//! refuse any name that is not already NFC and UTF-8, so a stored path can never
//! be a spelling the filesystem does not contain. This module therefore never
//! re-normalizes a manifest path: on a normalization-sensitive filesystem
//! (Linux/ext4) re-normalizing is exactly how a decomposed on-disk name became a
//! stored spelling with no file behind it — a source read that failed, a second
//! entry written beside the original (a tree that then refuses to canonicalize
//! at all), or an [`Extraneous::Delete`] removal that silently addressed a path that
//! did not exist. Every bookkeeping string this module builds
//! (`manifest_spelling`, `join_manifest_path`, `re_root_path`) is derived from an
//! already-canonical path or from the LIVE directory listing, and the address a
//! removal uses is `RootedRelativePath::join` of the listed name itself, so a
//! bookkeeping conversion is never used as an address.
//!
//! ## The destination filesystem can fold the address anyway
//!
//! A canonical spelling is faithful to the SOURCE filesystem's listing, which
//! says nothing about the DESTINATION's: an aliasing destination — a
//! case-insensitive one (macOS APFS, Linux ext4 with `casefold`) or one that
//! folds any other way — resolves a spelling to a pre-existing,
//! differently-spelled entry. The address then does not name what the sync
//! thinks, and two contracts would break silently: "make the destination match
//! the source" (the on-disk name never changes, so the sync never converges)
//! and "a path may be destroyed only under a sanction FOR THAT PATH" (the
//! [`Extraneous::Delete`] sanction is keyed on a spelling that aliases another
//! file, so the pass destroys the entry just transferred through the fold).
//! Three rules close it, all in this module because only this module knows the
//! destination at run time:
//!
//! * **The installed NAME is verified in the same pass as content and mode.**
//!   [`Applier::verify_names`] reads each installed entry's parent DIRECTORY and
//!   requires a BYTE-IDENTICAL entry; a mismatch is a
//!   [`ConflictReason::NameNotFaithful`] conflict naming the on-disk spelling in
//!   [`Conflict::on_disk`], is never `applied`, and records the on-disk spelling
//!   in [`Applier::aliased_dest`]. Resolving the manifest spelling (`open`/
//!   `stat`) is deliberately NOT used: the filesystem folds it onto the very
//!   entry the check is meant to notice.
//! * **Every TOUCHED directory is verified BYTE-IDENTICALLY, and no install may
//!   land through a fold.** This is the structural backstop, independent of any
//!   fold RULE. Before an install, [`Applier::refuse_address_folded_onto_-
//!   another_name`] asks the destination two exact questions — is the manifest
//!   spelling in its parent's live listing, and does the address nevertheless
//!   RESOLVE? — and refuses when the filesystem folded the spelling onto a
//!   differently-spelled entry. After the transfers, [`Applier::verify_-
//!   directory_listings`] compares the LIVE listing of EVERY directory the run
//!   touched (installed into, created, or removed from) against the names the
//!   run expected there, BYTE-IDENTICALLY, and reports an absent expected name
//!   or an unplanned on-disk name as a [`ConflictReason::NameNotFaithful`]
//!   conflict; [`Applier::verify_claimed_untouched`] re-reads the KIND and
//!   content of the entries the report calls `Skipped` (a fold must not destroy
//!   or kind-swap a victim the run never names). These checks hold for folds [`alias_in`]'s
//!   `to_lowercase` model cannot name (`ß`/`ss`, `ﬁ`/`fi`, `ς`/`σ`), and a fold
//!   in a PARENT component is caught because [`Applier::verify_names`] verifies
//!   EVERY ancestor component against its own parent's live listing, not only
//!   the final one. A source manifest whose path has a parent that is not itself
//!   an entry (`d/x` with no `d`) cannot reach this module at all: the manifest
//!   assemblers ([`canonicalize_tree`] and
//!   [`canonicalize_remote_entries`](crate::manifest::canonicalize_remote_entries))
//!   both enforce parent-closure, and the local walk is closed by construction.
//!   That assembler gate is THE guarantee; the applier does not repeat it,
//!   because every manifest it can be handed has already passed it.
//! * **Removal is identity-aware.** [`Applier::remove_extraneous`] removes a
//!   destination-only entry only when its manifest spelling is present in its
//!   parent's LIVE listing AND no source entry aliases the on-disk spelling; a
//!   spelling that is absent from the listing, or aliased, is a
//!   [`ConflictReason::NameNotFaithful`] conflict and is left in place. This is
//!   what stops [`Extraneous::Delete`] from destroying the entry a fold just
//!   transferred.
//! * **A case pair the destination cannot represent is refused up front.**
//!   [`Applier::refuse_unrepresentable_case_aliases`] groups source entries by
//!   case-folded name and, when a transfer is at stake, ASKS THE DESTINATION
//!   what it is with a probe ([`Applier::dest_case_insensitive`]: create a
//!   unique mixed-case directory in the reserved namespace, look it up with the
//!   case flipped, remove it — a `create_dir_all`, an existence lookup, and a
//!   `remove` on the destination root, at most once per run). On a
//!   case-insensitive destination the member(s) that cannot be represented are
//!   [`ConflictReason::NameNotFaithful`] conflicts; on a case-SENSITIVE
//!   destination the pair is legitimate and transfers normally. This is an
//!   EARLY, cheaper check, not the backstop: a destination whose root is ABSENT
//!   cannot be probed without creating it, and a run that refuses every entry
//!   must not create it, so the pair is conservatively refused WITHOUT probing
//!   (the structural per-directory check still covers whatever transfers).
//!
//! A directory the run cannot ENUMERATE faithfully — the transport's listing
//! refuses a name that is not valid UTF-8 rather than hand out a lossy view —
//! is a directory against which the run cannot verify its OWN result. Such a
//! listing failure is therefore raised ONCE at the run level
//! ([`unenumerable_directory_error`]) and propagates out of
//! [`Applier::verify_names`], [`Applier::verify_directory_listings`],
//! [`Applier::verify_claimed_untouched`], the pre-install fold gate
//! ([`Applier::refuse_address_folded_onto_another_name`]), and
//! [`Applier::remove_extraneous`]; it is never re-classified as a per-path
//! [`ConflictReason::NameNotFaithful`] conflict. No entry in a directory the run
//! could not enumerate is ever removed. The `NameNotFaithful` conflict path is
//! reserved for a fold the run CAN see (the on-disk spelling is nameable) and
//! for an unnameable fold in a directory that WAS enumerated.
//!
//! ## Which fold checks the test suite pins on which platform
//!
//! The fold reproductions in `apply/tests.rs` come in two kinds, and they do
//! NOT have the same platform coverage:
//!
//! * The checks that need only a DIFFERENTLY-SPELLED entry to exist — the
//!   ancestor walk in [`Applier::verify_names`] and the per-directory
//!   byte-exact listing backstop in [`Applier::verify_directory_listings`] —
//!   are exercised on BOTH a case-insensitive and a case-sensitive filesystem:
//!   the writer seam renames (`d` -> `D`) or creates a differently-spelled
//!   entry directly, so the address simply does not name what the manifest
//!   holds. `a_folded_ancestor_after_an_install_is_not_reported_applied` runs
//!   on Linux too.
//! * The checks whose PREMISE is that the destination filesystem RESOLVES a
//!   spelling to a differently-spelled entry — the pre-install fold gate
//!   ([`Applier::refuse_address_folded_onto_another_name`]) and the
//!   identity-aware removal branch ([`Applier::remove_extraneous`]) — are
//!   pinned ONLY on a case-insensitive (or otherwise aliasing) destination.
//!   Their tests skip when `filesystem_is_case_insensitive()` is false, and a
//!   disable-alone run on a case-sensitive Linux/ext4 destination leaves the
//!   suite GREEN: neither check's refusal is exercised there. This is recorded
//!   rather than claimed away. Pinning them on Linux needs a TEST-ONLY aliasing
//!   [`Remote`] wrapper (one that folds names as it stores and lists them so a
//!   manifest spelling resolves to a differently-spelled entry on ext4); none
//!   is present, so the Linux coverage of those two checks is, precisely: not
//!   covered by the reproductions, only on macOS/ext4-with-casefold.
//!
//! # `AppendTail`
//!
//! A manifest carries hashes, not bytes, so the append-only rule reads the
//! bytes of BOTH sides: if the destination is a prefix of the source, the
//! source is written through the durable replace primitive (the same
//! observable result as appending the tail, and it can never truncate); if the
//! source is a prefix of the destination, no bytes are written; otherwise the
//! two DIVERGED — reported as a conflict, never merged and never truncated. A
//! destination that is absent is written whole, INCLUDING a zero-length
//! source. The rule constrains bytes only: when no bytes need writing a
//! differing mode is still applied. It is defined only for regular files:
//! applying it to a directory or a symlink is an
//! [`ConflictReason::AppendNotAFile`] conflict, never a destructive
//! substitute.
//!
//! The crate encodes no application's file names or record kinds: the caller
//! supplies the [`Policy`] keyed on the path and entry kind, and
//! [`ReplaceAll`] is provided as the default "make the destination match the
//! source".

use crate::atomic::ReplaceOutcome;
use crate::error::{Error, Result};
use crate::lock::FileLock;
use crate::manifest::{
    TREE_SCHEMA_VERSION, TreeEntry, TreeMetadata, canonicalize_tree, compute_tree_digest,
};
use crate::sync::diff::{EntryDiff, EntryKind, TreeDiff, diff_trees, remote_manifest};
use crate::transport::{Remote, RootedRelativePath};
use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

/// A permission mode: the low 12 bits of a platform mode.
type Mode = u32;
/// The RESERVED claim-aside namespace: any manifest path with a component whose
/// file name starts with this prefix belongs to the claim-by-rename machinery,
/// never to the caller's tree.
const ASIDE_PREFIX: &str = ".sync-aside.";
/// Owner traverse (`x`), needed to resolve an entry inside a directory.
const OWNER_TRAVERSE: Mode = 0o100;
/// Owner write (`w`), needed to create or unlink an entry inside a directory.
const OWNER_WRITE: Mode = 0o200;
/// Owner `rwx`.
const OWNER_RWX: Mode = 0o700;

/// The direction of a transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// The LOCAL tree is the source; the remote is the destination.
    Push,
    /// The REMOTE tree is the source; the local tree is the destination.
    Pull,
}

/// Whether a sync may DELETE destination-only entries.
///
/// This is deliberately NOT a `bool`: the choice permanently deletes
/// destination data the source does not contain, and a positional `bool` is
/// exactly the argument an agentic caller passes wrongly. Spelling the
/// decision at the call site is the point — `Extraneous::Keep` and
/// `Extraneous::Delete` say what they do.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Extraneous {
    /// Leave every destination-only entry in place and report it in
    /// [`SyncReport::extraneous`]. The default, and the safe choice.
    #[default]
    Keep,
    /// Remove every destination-only entry after the transfers and the
    /// verification have succeeded, under the fold-aware identity checks.
    /// This PERMANENTLY destroys destination data the source does not hold.
    Delete,
}

/// What to do with one `Missing`/`Changed` destination entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryPolicy {
    /// Overwrite (or create) the destination entry so it matches the source.
    Replace,
    /// Leave the destination entry alone and report a conflict.
    Refuse,
    /// The append-only rule for regular files: append the source's tail when
    /// the destination is a prefix of the source, write nothing when the
    /// source is a prefix of the destination, and report a conflict when the
    /// two diverge.
    AppendTail,
}

/// The caller's per-entry decision, keyed on the manifest-relative path and
/// the entry kind. The crate knows no application's file names, so this is the
/// seam that supplies them.
pub trait Policy {
    /// The policy for `rel` (a canonical manifest path) of `kind`.
    fn for_path(&self, rel: &str, kind: EntryKind) -> EntryPolicy;
}

/// Any `Fn(&str, EntryKind) -> EntryPolicy` is a policy, so a caller can pass
/// a closure instead of a named type.
impl<F> Policy for F
where
    F: Fn(&str, EntryKind) -> EntryPolicy,
{
    fn for_path(&self, rel: &str, kind: EntryKind) -> EntryPolicy {
        self(rel, kind)
    }
}

/// The default policy: replace every entry, making the destination match the
/// source exactly.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReplaceAll;

impl Policy for ReplaceAll {
    fn for_path(&self, _rel: &str, _kind: EntryKind) -> EntryPolicy {
        EntryPolicy::Replace
    }
}

/// Why an eligible entry was not transferred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictReason {
    /// The caller's [`EntryPolicy::Refuse`] left the destination untouched.
    Refused,
    /// The append-only prefix relation did not hold: the destination and the
    /// source share some prefix but neither is a prefix of the other. Never
    /// merged, never truncated.
    Diverged,
    /// [`EntryPolicy::AppendTail`] was selected for an entry that is not a
    /// regular file on both sides, where the byte-stream prefix relation is
    /// undefined.
    AppendNotAFile,
    /// A destination DIRECTORY had to be removed to replace it with a file or
    /// symlink, but it still contains destination-only entries and
    /// [`Extraneous::Keep`] is selected — those entries were not sanctioned for
    /// removal, so the replacement is refused and the tree is left intact.
    ExtraneousBelow,
    /// The entry's parent directory was NOT created or replaced by this sync
    /// (a `Refuse`, or an `AppendTail` on a non-file directory), or installing
    /// the entry would need a REFUSED directory's mode widened. Also reported
    /// when a DELETION is refused because the entry has an ancestor a conflict
    /// left alone — mode-independently, so a writable conflicted directory
    /// protects its destination-only children too. Reported in both
    /// directions; nothing is mutated.
    ///
    /// The TRANSFER rule is uniform: a refused directory is never widened,
    /// created, finalized, or removed. Whether a child is blocked depends only
    /// on whether installing that child would need the refused directory's mode
    /// changed for THIS direction's write path. A directory-over-directory mode
    /// change writes nothing into the parent and needs TRAVERSE only; an
    /// unlink/create needs owner write and traverse; the confined local durable
    /// write chmods its immediate parent to `0o700`. A refused directory that
    /// already satisfies its need admits its children; one that does not reports
    /// them `ParentRefused`. DELETION is stricter: any entry under a
    /// conflict-forbidden path is off-limits regardless of mode.
    ParentRefused,
    /// The entry's NAME falls in the RESERVED claim-aside namespace. It is not
    /// transferred (it never enters the diff) and it is not removed: a SOURCE
    /// entry with a reserved name is a collision with this crate's own
    /// bookkeeping, reported rather than silently skipped so a legitimate file
    /// that happens to match can be renamed by the caller. See
    /// [`SyncReport::residue`] for the DESTINATION side of the same rule.
    ReservedName,
    /// A destination-only DIRECTORY that would have to be removed contains a
    /// reserved claim-aside entry (residue). Removing the directory would
    /// destroy the stranded original the residue holds, so its removal — and
    /// the removal of every entry below it — is refused and reported. Nothing
    /// is mutated.
    ResidueBelow,
    /// The entry's on-disk NAME is not the manifest spelling. A manifest entry
    /// is an ADDRESS, and on an aliasing destination filesystem — a
    /// case-insensitive one (macOS APFS, Linux ext4 with `casefold`), or one
    /// that folds any other way — installing the manifest spelling can land on
    /// a pre-existing, differently-spelled entry, so the address does not name
    /// what the sync thinks it names.
    ///
    /// The check is BYTE-IDENTICAL and reads the parent DIRECTORY's listing
    /// ([`Applier::verify_names`]); it deliberately never resolves the manifest
    /// spelling with an `open`/`stat`, which the filesystem folds onto the
    /// aliased entry. The same rule guards a removal
    /// ([`Applier::remove_extraneous`]): a destination-only entry is removed
    /// only when its manifest spelling is present in its parent's listing AND
    /// no source entry aliases that on-disk spelling.
    ///
    /// The path is left alone, is never reported `applied`, and is never
    /// destroyed. [`Conflict::on_disk`] names the destination's actual spelling
    /// when it could be read. On a case-insensitive destination a SOURCE pair
    /// that differs only by case is likewise reported here for every member
    /// that cannot be represented (see [`Applier::refuse_unrepresentable_case_aliases`]).
    NameNotFaithful,
}

impl ConflictReason {
    /// Whether a conflict with this reason forbids DESTROYING the path it names
    /// (and everything below it).
    ///
    /// This is the ONE definition of the deletion prohibition: the guard at
    /// every deletion site is derived from the conflict record through it, so a
    /// conflict site has no separate set to forget to update. The match is
    /// EXHAUSTIVE — no wildcard — so adding a [`ConflictReason`] variant fails
    /// to compile until its author decides whether the path is off-limits.
    ///
    /// Every CURRENT reason leaves the path in place (the caller refused it, the
    /// append-only rule declined it, the path is a collision with this crate's
    /// own namespace, or it is below such a path), so every arm is `true`; the
    /// value of the exhaustive match is that a future reason which DOES consume
    /// the path must say so explicitly.
    pub fn forbids_destruction(self) -> bool {
        match self {
            ConflictReason::Refused
            | ConflictReason::Diverged
            | ConflictReason::AppendNotAFile
            | ConflictReason::ExtraneousBelow
            | ConflictReason::ParentRefused
            | ConflictReason::ReservedName
            | ConflictReason::ResidueBelow
            | ConflictReason::NameNotFaithful => true,
        }
    }
}

/// One entry the caller must resolve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    /// The canonical manifest path.
    pub path: String,
    /// The source entry kind.
    pub kind: EntryKind,
    /// The policy that produced the conflict.
    pub policy: EntryPolicy,
    /// Why no transfer happened.
    pub reason: ConflictReason,
    /// The destination's ACTUAL on-disk spelling when [`Conflict::reason`] is
    /// [`ConflictReason::NameNotFaithful`] and it could be read: the parent
    /// directory's entry the filesystem folded the manifest spelling onto, so
    /// the caller can find what the address really names. `None` for every
    /// other reason, and for a name conflict whose on-disk spelling could not
    /// be read (the parent could not be listed, or no listing entry aliases the
    /// spelling).
    pub on_disk: Option<String>,
}

/// What a [`sync`] did, or — on failure — what it had already done when the
/// failure occurred. See [`SyncError`].
///
/// The lists are DERIVED at the end of a run from two records: the per-entry
/// outcome map and the `ModeJournal` (both private). They are mutually
/// consistent: they are sorted by path, and a path never appears in two
/// contradictory lists.
#[derive(Clone, Debug, Default)]
pub struct SyncReport {
    /// Source entries whose content/symlink target was written (or whose
    /// already-equal content was left alone), whose final mode was applied, AND
    /// for which EVERY post-transfer verification check passed — the entry's
    /// KIND, the file content hash or symlink target, and the journal's mode
    /// check. A path whose bytes were written but whose later verification
    /// failed is NOT here; it is named in [`SyncReport::verify_failures`], so a
    /// caller can structurally separate "nothing applied" from "written but not
    /// verified". A MODE-ONLY transfer is mutated (the chmod) and is therefore
    /// content-verified too, so `applied` never names a path whose bytes a
    /// concurrent writer changed.
    pub applied: Vec<String>,
    /// Source entries that needed NO mutation at all and whose mode this sync
    /// did not touch. A `Skipped` entry is reported on the strength of the
    /// destination manifest when its parent directory was NOT touched by this
    /// run; when the parent directory WAS touched, its KIND and content are
    /// additionally re-confirmed against the LIVE listing there
    /// ([`Applier::verify_claimed_untouched`]). The re-confirmation is
    /// therefore scoped to a TOUCHED parent, exactly as
    /// [`Applier::touched_dirs`] documents: a run that touches no directory
    /// above an entry performs no re-read of that entry, and a concurrent
    /// writer can change it in the window before report time without this list
    /// claiming otherwise. An entry the journal widened (a read-only
    /// `Same` directory that admitted a changed child) is NEVER here: it is
    /// named in [`SyncReport::transient_dirs`]. A `Same` directory a writer
    /// replaced with a regular file is NOT here either when its parent was
    /// touched: it is named in [`SyncReport::verify_failures`].
    pub skipped: Vec<String>,
    /// Entries left alone for the caller to resolve, ordered by path.
    pub conflicts: Vec<Conflict>,
    /// Every destination-only path, whether or not [`Extraneous::Delete`] removed
    /// it, EXCEPT one whose sanctioned removal a conflict blocked: that path is
    /// reported in `conflicts` (reason `ParentRefused`) instead, so the four
    /// derived lists stay mutually exclusive. Ordered by path.
    pub extraneous: Vec<String>,
    /// Every path whose MODE this sync transiently ADJUSTED to install a child
    /// — not only a WIDENING: a read-only destination directory widened so a
    /// changed child could be written, a read-only destination file widened so a
    /// `Replace` could overwrite it, or a WRITABLE directory the confined local
    /// durable write path transiently NARROWED to `0o700` — on the SUCCESS and
    /// the FAILURE path alike. Excluded: a path
    /// the sync removed (its widening left no residue; its terminal state is
    /// absence, reported in [`SyncReport::extraneous`]), a path that became
    /// abandoned residue (it still exists and its widen is RESTORED, but it is
    /// reported in [`SyncReport::residue`] instead), and a path that is
    /// destination-only or conflicted (it was merely PASSED THROUGH on the way
    /// to a failed removal and is reported there instead).
    ///
    /// [`SyncReport::transient_dirs`] is therefore disjoint from
    /// [`SyncReport::skipped`], [`SyncReport::conflicts`],
    /// [`SyncReport::extraneous`], and [`SyncReport::residue`]. It MAY share a
    /// path with [`SyncReport::applied`]: a `Changed` directory that was widened
    /// before its own final mode landed was both temporarily adjusted and applied;
    /// and it MAY share a path with [`SyncReport::verify_failures`] (a path whose
    /// mode was widened and whose verification then failed).
    pub transient_dirs: Vec<String>,
    /// Every DESTINATION path that was deliberately LEFT IN PLACE as abandoned
    /// residue, reduced to its TOPMOST such path. There are exactly TWO kinds,
    /// and the lists state EXISTENCE for both:
    ///
    /// * a STRANDED CLAIM-ASIDE — a name in the RESERVED `.sync-aside.`
    ///   namespace, the last component of the reported path (the aside holds
    ///   the stranded subtree, so nothing below it is named); or
    /// * an ORDINARY destination path this run refused to remove or displace —
    ///   a live entry no manifest spelling addresses, found while walking a
    ///   directory under this sync's own [`Claim`], or a writer's live entry
    ///   sitting at a rollback target. It is NOT in the reserved namespace, and
    ///   its content is the destination's/foreign entry's, never anything this
    ///   sync wrote.
    ///
    /// Both kinds are the same state: the run made no decision that could
    /// destroy the path, so it still EXISTS at report time and must be
    /// recovered by hand. Reserved residue is
    /// stripped from the destination manifest BEFORE the diff, so it is NEVER
    /// transferred and NEVER removed — not even by [`Extraneous::Delete`], whose
    /// removal of a destination-only directory holding residue is refused as
    /// [`ConflictReason::ResidueBelow`] — and ALWAYS reported here so the caller
    /// can recover it by hand. Every named path still EXISTS after the sync: a
    /// claimed subtree that holds residue is left in place (never recursively
    /// removed), the path is re-rooted to its current location when a claim moves
    /// it, and — because it still exists — a transient widen of it is RESTORED
    /// to its original mode. It is disjoint from [`SyncReport::applied`],
    /// [`SyncReport::skipped`], [`SyncReport::conflicts`],
    /// [`SyncReport::extraneous`], [`SyncReport::transient_dirs`],
    /// [`SyncReport::verify_failures`], and [`SyncReport::indeterminate`] (a
    /// path whose own removal was attempted and failed is INDETERMINATE and is
    /// named there instead). A SOURCE entry whose name collides with the
    /// reserved namespace is NOT residue — it is neither a destination path
    /// nor left in place by this sync — but a [`ConflictReason::ReservedName`]
    /// conflict in [`SyncReport::conflicts`], so the caller resolves it rather
    /// than losing it.
    pub residue: Vec<String>,
    /// Every mutated path whose post-transfer verification did not reach a
    /// passed final state: its content/target hashed differently, its final mode
    /// did not land, a restored mode could not be confirmed, or a transfer that
    /// mutated the destination was never verified at all (a directory created on
    /// a run that failed before `finalize`). Such a path is mutated but is NOT in
    /// [`SyncReport::applied`]; naming it here makes "written but not verified"
    /// machine-readable instead of living only in the error string, and it is
    /// what makes the report account for every path the run mutated on the
    /// FAILURE path too. Disjoint from the four derived lists and from
    /// [`SyncReport::residue`].
    ///
    /// A SUCCESSFUL run (`Ok`) MAY carry entries here. A destination entry the
    /// run CLAIMED to leave untouched (a `Skipped` path in a touched directory)
    /// whose content a concurrent or mirrored writer changed during the run is
    /// the case: it is excluded from [`SyncReport::skipped`] and named here, and
    /// there is no conflict because the run itself made no decision about it.
    /// The same applies to its KIND: a `Same` directory replaced by a regular
    /// file is named here, never `skipped`.
    /// A caller therefore MUST inspect `applied`/`skipped`/`verify_failures`
    /// (and `conflicts`) on the `Ok` path too; `Ok` means the run completed,
    /// not that the destination is clean. An unplanned on-disk name that NO
    /// manifest spelling addresses, inside a directory the run TOUCHED
    /// (including the destination ROOT), is a hard error instead (see
    /// [`Applier::verify_directory_listings`]).
    pub verify_failures: Vec<String>,
    /// Every path whose mutating call was ATTEMPTED and returned an error:
    /// the transport may or may not have applied the change, so the path is in
    /// an UNKNOWN state. This is the honest accounting of a failed mutation:
    /// `transfers` counts the attempt, so `transfers == 0` remains a valid
    /// "nothing was mutated" oracle, and a caller cannot mistake a partially
    /// mutated destination for an untouched one. [`SyncReport::indeterminate`]
    /// has the HIGHEST precedence in the list partition: an indeterminate path
    /// may be in any state, so every other claim about it would be a guess.
    /// The name is cleared only by a LATER successful step OF THE SAME KIND on
    /// the SAME path — a rollback rename that puts the original back resolves a
    /// CONTENT attempt, and a restore that confirms the intended mode resolves a
    /// MODE attempt — because the path's state is then known again. A mode
    /// restore never clears a failed CONTENT attempt: whether a write, create,
    /// rename, or removal landed is a separate fact, so such a path STAYS here.
    /// The report-time residue reconciliation
    /// (`Applier::reconcile_residue`) also routes a residue candidate whose
    /// presence could not be CONFIRMED here: its location is unknown, so no
    /// other claim about it can be made and a restore failure names both
    /// possible spellings.
    pub indeterminate: Vec<String>,
    /// The number of destination MUTATION STEPS attempted: every call to a
    /// mutating transport primitive is counted BEFORE it runs (a directory
    /// creation, a file write, a symlink creation, the claim-by-rename aside
    /// move and its rollback rename, each entry unlink and each directory rmdir
    /// performed by a removal, and every mode application — a transient widen,
    /// a final mode, a mode-only change, and a RESTORE), so a call that FAILS
    /// after partially applying still counts. Two equal trees with no read-only
    /// parent perform 0; a mode-only file change performs 1 (and no content
    /// write). EVERY attempted mutation is counted, so `transfers == 0` is the
    /// one valid "nothing was mutated" oracle; an exact non-zero value is an
    /// implementation detail, so tests use a lower bound or a set-equality
    /// except where they deliberately document a mutation sequence.
    pub transfers: usize,
}

/// [`SyncError`]-carrying result: on failure the partial [`SyncReport`] is
/// still reachable, so a caller can see exactly what the failed sync had
/// already done.
pub type SyncResult = std::result::Result<SyncReport, SyncError>;

/// A failed [`sync`] that still carries what it had already done.
///
/// The engine performs mutations before it can know a later step will fail, so
/// a bare `Err` would hide partial progress (and the caller could not decide
/// how to recover). This error holds the underlying [`Error`], the partial
/// [`SyncReport`], and every failure encountered while restoring the
/// destination: a mode this sync had transiently adjusted, a CLAIMED entry
/// whose rollback failed, or a post-restore mode verification. A non-empty
/// list means the destination may still carry a temporary mode or a leftover
/// aside the caller must repair.
#[derive(Debug)]
pub struct SyncError {
    error: Error,
    report: Box<SyncReport>,
    restore_failures: Vec<String>,
}

impl SyncError {
    /// The underlying failure.
    pub fn error(&self) -> &Error {
        &self.error
    }

    /// What the failed sync had already done (all lists ordered by path).
    pub fn report(&self) -> &SyncReport {
        &self.report
    }

    /// Failures encountered while restoring the destination: a temporarily
    /// adjusted mode that could not be reverted, a claim-by-rename rollback
    /// that failed, a leftover aside that could not be deleted after a
    /// successful install, and any post-restore verification failure. Non-empty
    /// means the destination may still carry a mode or a leftover aside the
    /// caller must repair; a leftover aside is ALSO named in
    /// [`SyncReport::residue`].
    pub fn restore_failures(&self) -> &[String] {
        &self.restore_failures
    }

    /// Consume the error, yielding `(underlying error, partial report)`.
    pub fn into_parts(self) -> (Error, SyncReport) {
        (self.error, *self.report)
    }
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)?;
        if !self.restore_failures.is_empty() {
            write!(
                f,
                " (additionally, {} path(s) the sync could not fully restore or clean up: {})",
                self.restore_failures.len(),
                self.restore_failures.join("; ")
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for SyncError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<Error> for SyncError {
    /// A pre-transfer failure (root resolution, manifest production): no
    /// mutation has happened yet, so the partial report is empty.
    fn from(error: Error) -> Self {
        SyncError {
            error,
            report: Box::new(SyncReport::default()),
            restore_failures: Vec::new(),
        }
    }
}

/// The operation-lock record path for a LOCAL destination root.
///
/// The record is a dot-prefixed SIBLING of the destination root, in that
/// root's parent directory: `<parent>/.<name>.operation.lock`. It is
/// deliberately outside the tree the run judges, because taking a lock inside
/// the tree would create the destination root for a run that must create
/// nothing and would enter the destination manifest — see the module docs
/// ("Why the lock record is a SIBLING of the destination root"). The spelling
/// reuses the crate's reserved `operation.lock` name
/// ([`crate::transport::Layout::lock`]), so it is the SAME record name a push
/// or checkpoint pass would use, not a new lock mechanism.
///
/// `None` when no sibling location can be derived: a filesystem root (`/`) has
/// no parent, and a path with no final component names no record. [`sync`],
/// [`push`], and [`pull`] REFUSE such a destination rather than run it unowned;
/// only the explicitly-named [`sync_unowned`] reaches it, and the caller must
/// supply the serialisation itself.
///
/// A writer that does not take this record is NON-COOPERATING. That includes a
/// writer using a different version of this tool and a different tool sharing
/// the store: the ownership claim is only as strong as the discipline of every
/// program that can reach the tree, and the crate cannot force one to take the
/// record. A non-cooperating write is not silently absorbed — the run's
/// post-transfer verification still detects one it can see and fails closed
/// (see the module docs, "The lock discipline").
///
/// Two runs of [`sync`] against the same destination root derive the same path
/// and so exclude each other; a caller that wants to cooperate with a `sync`
/// can acquire the same record with [`crate::lock::FileLock::acquire`].
pub fn destination_lock_path(dest_root: &Path) -> Option<PathBuf> {
    let root = normalize_root(dest_root);
    let parent = root.parent()?;
    let base = root.file_name()?;
    let mut record = OsString::from(".");
    record.push(base);
    record.push(".operation.lock");
    // A single-component RELATIVE root (`foo`) has `Path::parent() == Some("")`:
    // the directory the record must be placed in is the CURRENT one, and an
    // empty parent would make the lock helper run `mkdir ""` (ENOENT). Resolve
    // it to `.` exactly the way the rest of the path handling resolves a
    // relative root ([`canonicalize_with_missing_tail`] joins the current
    // directory), so the record is the SAME `.foo.operation.lock` sibling a
    // caller reaches by name. Only a root with NO parent at all (`/`, or an
    // empty root) still has no record location.
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    Some(parent.join(record))
}

/// Create the destination lock record's PARENT chain at the platform default
/// directory mode.
///
/// The lock record is a SIBLING of the destination root, so its parent is a
/// directory OUTSIDE the destination tree that the CALLER owns. The lock helper
/// ([`crate::lock::FileLock::acquire`]) creates a missing parent chain through
/// [`crate::atomic::ensure_private_dir_durable`], which chmods every component
/// it creates to the store-private `0o700`. That is correct for a directory
/// INSIDE the store, but a caller that syncs into `<missing>/local` would find
/// the caller-visible `<missing>` created AND narrowed to `0o700` — on a run
/// that refuses every entry, to boot. Pre-creating the chain here with the
/// platform default (`create_dir_all`, exactly the mode
/// [`Applier::root_for_mutation`] gives a destination root's missing ancestors)
/// leaves [`crate::atomic::ensure_private_dir_durable`] nothing to create or
/// chmod.
///
/// This is a change LOCAL to the sync path by design: [`crate::lock::FileLock`]
/// and the atomic helper also serve the transport's sidecar locks, where the
/// private mode is REQUIRED, so changing them would change every caller's
/// on-disk modes. The behaviour is stated in the module docs, "Why the lock
/// record is a SIBLING of the destination root".
fn create_lock_parent(parent: &Path) -> Result<()> {
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(parent).map_err(|e| {
        Error::preflight(format!(
            "the destination lock record's parent directory {} cannot be created: {e}",
            parent.display()
        ))
    })
}

/// A human-readable holder identity recorded in the lock record, so a refused
/// contender's "held by ..." diagnostic names the run that holds it.
fn destination_op_id(direction: Direction, dest_root: &Path) -> String {
    format!(
        "store-sync {direction:?} of {} (pid {})",
        dest_root.display(),
        std::process::id()
    )
}

/// Acquire the destination's operation lock for a run that REQUIRES it, or
/// refuse; this is the enforcement behind [`sync`]'s owned-by-default
/// contract.
///
/// A destination the crate cannot lock — a REMOTE one (`is_local()` false), for
/// which no local descriptor lock exists, or one with no sibling record
/// location ([`destination_lock_path`] is `None`) — is an ERROR here rather
/// than a silent unowned run: the caller who wants the run must name
/// [`sync_unowned`]. The [`FileLock`] is returned inside the token so it lives
/// exactly as long as the run: the drop runs on the success path, on every
/// error return, and on a panic that unwinds, and the kernel releases the flock
/// when the descriptor closes even if the drop never runs (a `SIGKILL`ed
/// holder).
fn lock_destination(
    direction: Direction,
    dest_is_local: bool,
    dest_root: &Path,
) -> Result<DestinationOwnership> {
    if !dest_is_local {
        return Err(Error::preflight(format!(
            "refusing to sync into the REMOTE destination {} without its operation lock: the crate cannot hold a far-side lock for the whole run, so this call cannot own the destination. If the caller holds the destination for the run, call `sync_unowned` (the explicitly weaker entry point); otherwise sync into a LOCAL destination.",
            dest_root.display()
        )));
    }
    let Some(path) = destination_lock_path(dest_root) else {
        return Err(Error::preflight(format!(
            "refusing to sync into the destination {} without its operation lock: no lock record can be placed as a sibling of that root. If the caller holds the destination for the run, call `sync_unowned`.",
            dest_root.display()
        )));
    };
    // The record must be placed in a real directory. A single-component
    // RELATIVE root resolves to `.` above; anything else that still yields an
    // EMPTY parent is named here rather than surfacing as a bare `mkdir ""`
    // ENOENT from the lock helper.
    let Some(parent) = path.parent() else {
        return Err(Error::preflight(format!(
            "refusing to sync into the destination {}: the operation lock record {} has no directory to be placed in",
            dest_root.display(),
            path.display()
        )));
    };
    if parent.as_os_str().is_empty() {
        return Err(Error::preflight(format!(
            "refusing to sync into the destination {}: the operation lock record {} has no directory to be placed in",
            dest_root.display(),
            path.display()
        )));
    }
    // Create a MISSING parent chain at the platform default mode BEFORE the
    // lock helper sees it, so the helper never narrows a caller-owned directory
    // to store-private `0o700` (see [`create_lock_parent`]).
    create_lock_parent(parent)?;
    let op_id = destination_op_id(direction, dest_root);
    Ok(DestinationOwnership::Locked(FileLock::acquire(
        &path, &op_id,
    )?))
}

/// The proof a mutating run holds its destination.
///
/// PRIVATE by design. [`DestinationOwnership::Locked`] can only be produced by
/// [`lock_destination`], which takes the [`FileLock`] FIRST, and
/// [`DestinationOwnership::Unowned`] only by the explicitly-named `*_unowned`
/// entry points. [`run`] takes the token BY VALUE, so no code path — and no
/// caller, since the type has no public constructor — can reach the mutating
/// core without stating which ownership it established. That is what makes an
/// unowned run reachable only through the name that says so.
enum DestinationOwnership {
    /// The crate TAKES the destination's operation lock and holds it for the
    /// whole run.
    Locked(FileLock),
    /// The caller has taken the destination for the run out of band; the crate
    /// holds no lock.
    Unowned,
}

/// Sync `local_root` and `remote` in `direction` under `policy`, reporting
/// every action and conflict.
///
/// THIS IS THE OWNED ENTRY POINT. It TAKES the destination's operation lock
/// (when the destination is local) and holds it for the WHOLE run, and it
/// REFUSES a destination whose lock the crate cannot take — a REMOTE one, or a
/// root with no sibling record location — instead of running unowned. The
/// explicitly-named [`sync_unowned`] is the only way to reach such a
/// destination, so the weaker choice cannot be made by omission. `extraneous`
/// selects whether destination-only entries are [`Extraneous::Keep`] (the
/// default, and what [`push`]/[`pull`] pass) or [`Extraneous::Delete`]d after
/// the transfers and the verification have succeeded.
///
/// The local root descriptor is opened (pinned) BEFORE either manifest is
/// read, when the root exists; see the module docs for exactly what that does
/// and does not guarantee. The local destination root is created lazily,
/// immediately before the first mutation that needs it, so a pull whose every
/// entry is refused leaves the root ABSENT.
///
/// A destination root that already exists but is not a directory is an error,
/// and a missing local root is an error in the PUSH direction (the source must
/// exist) — never a silently fabricated empty tree.
///
/// A successful `Ok(report)` is NOT by itself a clean-destination claim: the
/// caller must consult the report's lists. In particular
/// [`SyncReport::verify_failures`] can be non-empty on `Ok` (a destination
/// entry the run claimed to leave untouched whose content changed under the
/// run), and [`SyncReport::conflicts`] names every path left for the caller to
/// resolve.
///
/// # What the crate enforces, and what a caller still owes
///
/// 1. **The destination is exclusively owned, and `sync` ENFORCES it by
///    TAKING the lock itself** ([`crate::lock::FileLock`] on the record named
///    by [`destination_lock_path`]), before the destination manifest is read
///    and for the whole run, so a cooperating writer is refused at acquisition
///    instead of interleaving. A destination the crate cannot lock is REFUSED
///    here, not run unowned.
/// 2. **The source is quiescent, and the crate VERIFIES it.** The source
///    cannot be locked, so the run re-reads its manifest at the end and fails
///    closed, naming the paths that moved, if it differs from the plan.
/// 3. **A writer using a DIFFERENT version of this tool, or a different tool
///    sharing the store, is a NON-COOPERATING writer unless it takes the same
///    lock** — the ownership claim is only as strong as the ecosystem's
///    discipline.
///
/// A non-cooperating writer that writes the destination anyway is still
/// DETECTED and the run still FAILS CLOSED: the post-transfer verification is
/// retained unchanged (detection is scoped to the paths the run reads, so its
/// coverage is not total). For a REMOTE destination `sync` refuses outright;
/// [`sync_unowned`] is the explicitly weaker entry point, and the module docs
/// ("The lock discipline" and the far-side limitation) state the residual.
///
/// # The two roots must be disjoint
///
/// The local root and the remote root must be DISJOINT: neither may be an
/// ANCESTOR of the other, in either direction. A destination nested inside the
/// source makes the destination manifest enumerate the source's own subtree, so
/// the run copies `sub/x` to `sub/sub/x` and — with [`Extraneous::Delete`] —
/// destroys `sub/x`; a source nested inside the destination makes the
/// destination manifest enumerate the source, so an extraneous removal destroys
/// the source. Either way the run is on both sides of an overlap and no report
/// can be trusted. EQUAL roots are NOT refused: the two manifests are
/// identical, the diff is empty, and the run is an idempotent no-op.
///
/// The refusal happens BEFORE any mutation and names BOTH roots. It reuses the
/// crate's ONE overlap authority ([`crate::root::roots_overlap`], the rule
/// [`crate::root::OwnedRoot::parse`] enforces) applied to the CANONICAL paths,
/// so two spellings of one tree (`..`, a trailing separator, a symlinked
/// component) compare equal and a nested tree compares nested. A destination
/// root that does not exist yet is canonicalized up to its longest existing
/// prefix.
///
/// The check is only computed when `remote.is_local()`: for a
/// remote ([`SshTransport`](crate::transport::SshTransport)) root the far-side
/// path cannot be resolved from this host, so the relationship is UNDECIDABLE
/// here and NO refusal is computed — see the module docs for the residual the
/// caller must cover in that case.
pub fn sync(
    direction: Direction,
    local_root: &Path,
    remote: &dyn Remote,
    policy: &dyn Policy,
    extraneous: Extraneous,
) -> SyncResult {
    run_entry(
        direction,
        local_root,
        remote,
        policy,
        extraneous,
        RequestedOwnership::Locked,
    )
}

/// [`sync`] WITHOUT holding the destination's operation lock: the caller
/// asserts that it has taken the destination for the run itself.
///
/// The NAME states the weaker guarantee, deliberately: this is the ONLY way to
/// reach a run whose destination the crate did not lock, so the weaker choice
/// cannot be made by omission. It exists for the destinations the crate CANNOT
/// lock — a REMOTE (far-side) destination, or a root with no sibling lock
/// location — and for a caller whose own protocol already serialises every
/// writer. For every other destination use [`sync`], which is the default and
/// ENFORCES the lock.
///
/// Only the LOCK is weaker here. The post-transfer verification is IDENTICAL,
/// so an out-of-band write is still DETECTED and the run still FAILS CLOSED;
/// the SOURCE-quiescence re-read also still runs. What the caller gives up is
/// the crate's own exclusion of a cooperating writer for the duration, and it
/// must supply that exclusion itself.
///
/// `extraneous` selects whether destination-only entries are
/// [`Extraneous::Keep`] or [`Extraneous::Delete`]d.
pub fn sync_unowned(
    direction: Direction,
    local_root: &Path,
    remote: &dyn Remote,
    policy: &dyn Policy,
    extraneous: Extraneous,
) -> SyncResult {
    run_entry(
        direction,
        local_root,
        remote,
        policy,
        extraneous,
        RequestedOwnership::Unowned,
    )
}

/// Which ownership the caller asked the entry point to establish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestedOwnership {
    /// The crate must take the destination's operation lock, or refuse.
    Locked,
    /// The caller asserts it holds the destination; the crate takes no lock.
    Unowned,
}

fn run_entry(
    direction: Direction,
    local_root: &Path,
    remote: &dyn Remote,
    policy: &dyn Policy,
    extraneous: Extraneous,
    requested: RequestedOwnership,
) -> SyncResult {
    // Pin the local root BEFORE the manifests: the manifest walk and the
    // mutations must describe the same inode (checked on Unix after the walk,
    // with the residual race documented on the module).
    let local =
        LocalSide::open(local_root, direction == Direction::Pull).map_err(SyncError::from)?;
    // Relate the two roots BEFORE the first mutation. A local remote is a path
    // on THIS host, so the two roots can be compared exactly; a remote one
    // cannot be resolved here and is documented as undecidable.
    refuse_overlapping_roots(&local, remote).map_err(SyncError::from)?;
    let (source, dest) = match direction {
        Direction::Push => (Side::Local(&local), Side::Remote(remote)),
        Direction::Pull => (Side::Remote(remote), Side::Local(&local)),
    };
    // Establish ownership BEFORE `run` reads the destination manifest, and
    // hold it for the WHOLE run: `run` takes the token by value, so the lock is
    // released only when the run returns.
    let dest_root = match direction {
        Direction::Push => normalize_root(remote.root()),
        Direction::Pull => local.root_path.clone(),
    };
    let dest_is_local = match direction {
        Direction::Push => remote.is_local(),
        Direction::Pull => true,
    };
    let ownership = match requested {
        RequestedOwnership::Locked => {
            lock_destination(direction, dest_is_local, &dest_root).map_err(SyncError::from)?
        }
        RequestedOwnership::Unowned => DestinationOwnership::Unowned,
    };
    run(&source, &dest, policy, extraneous, ownership)
}

/// [`sync`] in [`Direction::Push`], without removing extraneous entries. The
/// destination must be one whose lock the crate can take; use
/// [`push_unowned`] for a destination it cannot lock.
pub fn push(local_root: &Path, remote: &dyn Remote, policy: &dyn Policy) -> SyncResult {
    sync(
        Direction::Push,
        local_root,
        remote,
        policy,
        Extraneous::Keep,
    )
}

/// [`sync`] in [`Direction::Pull`], without removing extraneous entries. The
/// destination must be one whose lock the crate can take; use
/// [`pull_unowned`] for a destination it cannot lock.
pub fn pull(local_root: &Path, remote: &dyn Remote, policy: &dyn Policy) -> SyncResult {
    sync(
        Direction::Pull,
        local_root,
        remote,
        policy,
        Extraneous::Keep,
    )
}

/// [`push`] WITHOUT the destination lock; the caller owns the destination.
pub fn push_unowned(local_root: &Path, remote: &dyn Remote, policy: &dyn Policy) -> SyncResult {
    sync_unowned(
        Direction::Push,
        local_root,
        remote,
        policy,
        Extraneous::Keep,
    )
}

/// [`pull`] WITHOUT the destination lock; the caller owns the destination.
pub fn pull_unowned(local_root: &Path, remote: &dyn Remote, policy: &dyn Policy) -> SyncResult {
    sync_unowned(
        Direction::Pull,
        local_root,
        remote,
        policy,
        Extraneous::Keep,
    )
}

/// A mode kind this sync knows how to widen and restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ModeEntry {
    /// The kind, so a restore chmod resolves the path with the right flags
    /// (`O_DIRECTORY` for a directory).
    kind: EntryKind,
    /// The mode observed the FIRST time this sync touched the path, or `None`
    /// when the path did not exist then (a path this sync created). Recorded on
    /// the first touch only; a later touch never overwrites it.
    original: Option<Mode>,
    /// The intended final mode, when this sync has one for the path.
    final_mode: Option<Mode>,
    /// This sync transiently changed the path's mode to admit a child.
    widened: bool,
    /// The intended final mode was successfully applied (a chmod ran, or the
    /// mode already matched).
    final_applied: bool,
    /// The path was removed by this sync, so there is no mode left to restore.
    removed: bool,
    /// The path was deliberately LEFT IN PLACE as abandoned residue. It still
    /// EXISTS (so a transient widen must still be restored) but it is not a live
    /// subject of the transfer (so it is never reported `transient_dirs`, never
    /// transferred, and never deleted). Distinct from [`ModeEntry::removed`] by
    /// construction: this is exactly the distinction whose conflation silently
    /// left a widened residue directory at its widened mode.
    abandoned: bool,
}

/// The single record of every mode this sync changes: at most one entry per
/// LIVE path identity, `original` fixed at that identity's first touch.
/// Nothing here is drained or overwritten; the report derives from it and a
/// restore reads it idempotently. A path this sync REMOVED ends its identity:
/// if the same path is created again in the same run (a source file replacing
/// a destination directory), `note_first_touch` starts a fresh record, because
/// the old identity no longer exists to restore.
#[derive(Debug, Default)]
struct ModeJournal {
    entries: BTreeMap<String, ModeEntry>,
}

impl ModeJournal {
    /// Record the ORIGINAL mode the first time this sync touches `path` (for
    /// the path's current identity). `None` means the path did not exist at
    /// first touch (this sync created it). A second call for the SAME identity
    /// never overwrites the first value; a call after the path was REMOVED
    /// starts a fresh identity.
    fn note_first_touch(&mut self, path: &str, kind: EntryKind, original: Option<Mode>) {
        if let Some(entry) = self.entries.get_mut(path) {
            if entry.removed {
                *entry = ModeEntry {
                    kind,
                    original,
                    final_mode: None,
                    widened: false,
                    final_applied: false,
                    removed: false,
                    abandoned: false,
                };
            }
            return;
        }
        self.entries.insert(
            path.to_string(),
            ModeEntry {
                kind,
                original,
                final_mode: None,
                widened: false,
                final_applied: false,
                removed: false,
                abandoned: false,
            },
        );
    }

    /// Whether the journal recorded a widen for `path` (used by the report to
    /// keep a mode-touched path out of `skipped`). This is NOT a "currently
    /// widened" test: the live mode is always read before deciding a chmod, so
    /// a directory whose read-only final mode was reinstated by `finalize` can
    /// be widened again.
    fn is_widened(&self, path: &str) -> bool {
        self.entries.get(path).is_some_and(|e| e.widened)
    }

    /// Note that `path`'s mode was transiently changed. The caller has already
    /// chmodded and counted it.
    fn mark_widened(&mut self, path: &str) {
        if let Some(entry) = self.entries.get_mut(path) {
            entry.widened = true;
        }
    }

    /// Record `path`'s intended final mode and whether it actually landed
    /// (`live` is the mode read immediately after the operation). A mode the
    /// transport never applied leaves `final_applied = false`, so the restore
    /// targets the ORIGINAL mode and verification still requires the INTENDED
    /// mode — a dropped chmod is loud, never repaired-and-forgotten.
    fn mark_final_mode(&mut self, path: &str, intended: Mode, live: Option<Mode>) {
        if let Some(entry) = self.entries.get_mut(path) {
            entry.final_mode = Some(intended);
            entry.final_applied = live == Some(intended);
        }
    }

    /// Whether `path` has no mode step left to wait for. A path with no journal
    /// entry does not, and neither does a SYMLINK (its manifest mode is the
    /// fixed `0777` and is never chmodded); a recorded file/directory requires
    /// its intended mode to have landed.
    fn final_applied(&self, path: &str) -> bool {
        self.entries
            .get(path)
            .is_none_or(|e| e.final_applied || e.kind == EntryKind::Symlink)
    }

    /// Note that `path` was removed: it has no mode left to restore.
    fn mark_removed(&mut self, path: &str) {
        if let Some(entry) = self.entries.get_mut(path) {
            entry.removed = true;
        }
    }

    /// Note that `path` was deliberately LEFT IN PLACE as abandoned residue. It
    /// still exists, so a transient widen is still restored; but it is no longer
    /// a live subject of the transfer, so it is not reported transient.
    fn mark_abandoned(&mut self, path: &str) {
        if let Some(entry) = self.entries.get_mut(path) {
            entry.abandoned = true;
        }
    }

    /// Every path this sync widened and did NOT remove or abandon, ordered by
    /// path. An abandoned path is reported [`SyncReport::residue`], never
    /// [`SyncReport::transient_dirs`].
    fn widened_paths(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, e)| e.widened && !e.removed && !e.abandoned)
            .map(|(p, _)| p.clone())
            .collect()
    }

    /// The mode a settled `path` must carry. A SYMLINK has no mode check (its
    /// manifest mode is fixed and never chmodded). A path with an INTENDED mode
    /// on record is checked against that intended mode — even when
    /// `final_applied` is false, so a dropped mode is a verification failure
    /// rather than being silently repaired by a restore. A merely-widened path
    /// is checked against its original mode once `include_restored` is set.
    /// `None` means there is nothing to check.
    fn settled_mode(&self, entry: &ModeEntry, include_restored: bool) -> Option<Mode> {
        if entry.removed || entry.kind == EntryKind::Symlink {
            return None;
        }
        if entry.final_mode.is_some() {
            return entry.final_mode;
        }
        if entry.widened {
            return if include_restored {
                entry.original
            } else {
                None
            };
        }
        None
    }

    /// The restore plan, deepest-first (so a read-only parent is restored only
    /// after every descendant). Only a widened path whose final mode did not
    /// supersede the widen, and that still exists, is planned. An ABANDONED
    /// (residue) path is included: it was left in place, so its widen must be
    /// undone — only a REMOVED path has no mode left to restore.
    fn restore_plan(&self) -> Vec<(String, EntryKind, Mode)> {
        let mut plan: Vec<(String, EntryKind, Mode)> = self
            .entries
            .iter()
            .filter(|(_, e)| e.widened && !e.removed)
            .filter_map(|(path, e)| {
                let target = if e.final_applied {
                    e.final_mode
                } else {
                    e.original
                };
                target.map(|mode| (path.clone(), e.kind, mode))
            })
            .collect();
        plan.sort_by(|a, b| {
            let da = Path::new(&a.0).components().count();
            let db = Path::new(&b.0).components().count();
            db.cmp(&da).then_with(|| a.0.cmp(&b.0))
        });
        plan
    }

    /// Every path with a mode to verify, ordered by path.
    fn mode_targets(&self, include_restored: bool) -> Vec<(String, EntryKind, Mode)> {
        self.entries
            .iter()
            .filter_map(|(path, e)| {
                self.settled_mode(e, include_restored)
                    .map(|mode| (path.clone(), e.kind, mode))
            })
            .collect()
    }
}

/// The KIND of destination mutation an attempt represents. This is what makes
/// [`Applier::begin_mutation`]'s attempt-first record precise enough to clear:
/// re-establishing a path's MODE says nothing about whether a failed CONTENT
/// mutation landed, so only a MODE attempt may be resolved by
/// [`Applier::restore`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MutationKind {
    /// A mode change (chmod): a transient widen, a final mode, a mode-only
    /// change, or a restore. A later successful chmod makes the path's mode
    /// KNOWN again, so a MODE attempt may be cleared by the restore.
    Mode,
    /// A content mutation: a file write, a directory create, a symlink create, a
    /// claim/rollback RENAME, or a removal. A failed attempt leaves the path's
    /// CONTENT unknown; only a later successful call of the SAME kind resolves
    /// it, never a mode restore.
    Content,
}

/// The begun-but-uncommitted mutation attempts at ONE path, counted PER KIND.
/// [`Applier::begin_mutation`] increments the counter for the attempt it is
/// about to make; [`Applier::commit_mutation`] decrements it only when a call
/// of the SAME kind reports `Ok`. A failed attempt is never decremented, so a
/// LATER successful mutation at the same path cannot erase the fact that an
/// earlier attempt failed: the path stays in [`SyncReport::indeterminate`]
/// while ANY begun attempt is uncommitted. This is what keeps a ROLLED-BACK
/// path named: a removal that discards this sync's own partial and a rename
/// that restores the original both commit their OWN attempts, but neither can
/// resolve the failed write/install that preceded them.
#[derive(Clone, Copy, Debug, Default)]
struct PendingMutations {
    content: usize,
    mode: usize,
}

impl PendingMutations {
    fn is_empty(&self) -> bool {
        self.content == 0 && self.mode == 0
    }
}

/// The per-entry outcome record. The report's `applied`/`skipped` lists are
/// derived from this, never pushed during the transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// The entry needed no mutation and the journal did not touch its mode.
    Skipped,
    /// The entry's content/target/mode mutation was performed. It is reported
    /// `applied` only after verification and its final mode.
    Transferred,
}

/// An entry whose written bytes must be re-read and hash-checked.
struct VerifyItem {
    path: String,
    kind: EntryKind,
    expected_sha256: String,
}

/// A destination entry CLAIMED by renaming it aside during a kind-changing
/// replacement. It is deleted after a successful install, or renamed back
/// after a failed one.
///
/// A claim carries NO kind. The kind the aside actually has is read from the
/// LIVE object by the one removal entry point ([`Applier::remove_subtree`]), so
/// a kind observed at claim time (or taken from the manifest snapshot that
/// motivated the claim) can never select the removal primitive. A stored kind
/// here would be exactly the stale-kind-to-live-mutation edge this module
/// forbids; there is nothing to store because nothing may be consulted.
struct Claim {
    /// The real path the stale entry was moved away from.
    original: RootedRelativePath,
    /// The hidden aside path the stale entry now lives at.
    rel: RootedRelativePath,
}

/// A claim or rollback RENAME whose call reported failure and whose landed-or-
/// not could NOT be confirmed (the follow-up probe failed, or both spellings
/// were absent). The entry — and any reserved residue it carried — may be at
/// EITHER spelling, so this records the two names for
/// [`Applier::reconcile_residue`] to name as POSSIBILITIES. Nothing is asserted
/// about where the entry actually is.
struct UnconfirmedMove {
    /// The rename's source spelling.
    from: String,
    /// The rename's destination spelling.
    to: String,
}

/// The proof a deleter must hold: WHY the path it is about to destroy is the
/// sync's to destroy. This replaces the ancestry-based guard, so the guard can
/// neither forget a conflict site (the prohibition is derived from the conflict
/// record) nor over-block the sync's own bookkeeping.
#[derive(Clone, Copy)]
enum Sanction<'a> {
    /// The caller's [`Extraneous::Delete`]. It sanctions ONLY a destination-only
    /// entry absent from the source manifest, and it is still refused for any
    /// path the conflict-derived prohibition covers.
    ExtraneousFlag,
    /// The sync's own claim aside, named by the [`Claim`] the caller holds: the
    /// path was renamed aside by THIS sync, so it is not caller data and is
    /// deletable by construction — no ancestry test, no prohibition.
    OwnClaim(&'a Claim),
    /// The sync's own partial creation, being discarded while rolling back a
    /// failed kind-changing replacement. It carries the SAME [`Claim`] as
    /// [`Sanction::OwnClaim`], so it rests on the identical proof: this sync
    /// renamed the ORIGINAL at the claim's path aside, and anything that
    /// appeared at the real path since is only the sync's own partial. It
    /// reaches ONLY that single entry — the sync's own creation is
    /// `create_dir_all`'s EMPTY directory or one file/symlink, so nothing below
    /// it was written by this sync and a live descendant is preserved and named
    /// (see [`Applier::live_entry_manifest_spelling`]).
    OwnPartial(&'a Claim),
}

/// Whether a destination mutation may CREATE a missing strict ancestor (it
/// resolves it with `mkdir`-like semantics) or must require every strict
/// ancestor to exist. Either way an ancestor that EXISTS as anything but a real
/// directory is refused: only a symlink or file ancestor can redirect a
/// mutation outside the destination root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AncestorPolicy {
    /// Every strict ancestor component must already exist as a real directory.
    MustExist,
    /// A missing strict ancestor is permitted (the operation creates it as a
    /// real directory); an existing non-directory is still refused.
    MayCreate,
}

/// What an operation does to the FINAL component of the destination path it
/// guards (see [`Applier::guard_destination`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FinalPolicy {
    /// The operation does not resolve the final component as a directory (a
    /// rename source, an unlink, an `lstat`): only the strict ancestors are
    /// checked.
    Unresolved,
    /// The operation follows the final component (a write, a create, a mode
    /// change), so a SYMLINK there is refused; an existing file or directory is
    /// handled by the operation itself.
    NotSymlink,
    /// The operation requires the final component to be a REAL directory (a
    /// directory listing, a directory chmod, a recursive directory removal). A
    /// symlink or file there is refused.
    Directory,
}

/// One live destination directory listing: each entry's exact on-disk NAME
/// bytes and its LIVE kind (a symlink-to-directory is [`EntryKind::Symlink`],
/// never [`EntryKind::Dir`]). See [`Applier::dir_listing`].
type DirListing = Vec<(Vec<u8>, EntryKind)>;

/// A cached listing outcome. [`Error`] is not `Clone`, so the (rare) failure is
/// held behind an [`Rc`](std::rc::Rc) to let the ONE cached read be handed to
/// every consumer of the same directory; every consumer only reads the cause's
/// `Display`, which is unchanged.
type CachedListing = std::result::Result<DirListing, std::rc::Rc<Error>>;

/// TEST-ONLY instrumentation: the number of times the CURRENT thread's applier
/// obtains a directory listing through [`Applier::listing`] (a cache read OR the
/// single raw fetch). A thread-local, so the parallel libtest threads do not
/// share a count. The F2 bound uses it because the destination-level
/// `Remote::list` count cannot see the defect: the run-scoped cache already
/// makes the number of RAW fetches O(1) per directory, while pre-fix
/// `remove_extraneous` still CONSUMED (cloned and scanned) the parent listing
/// once PER ENTRY. This counter measures that per-entry consumption: it must not
/// grow with the number of extraneous entries in one directory.
#[cfg(test)]
pub(crate) mod listing_reads {
    use std::cell::Cell;
    thread_local! {
        static COUNT: Cell<usize> = const { Cell::new(0) };
    }
    pub(crate) fn reset() {
        COUNT.with(|count| count.set(0));
    }
    pub(crate) fn get() -> usize {
        COUNT.with(Cell::get)
    }
    pub(crate) fn bump() {
        COUNT.with(|count| count.set(count.get() + 1));
    }
}

/// How a removal attempt ended. The sync's removal walk NEVER uses a recursive
/// `remove_dir_all`: every directory leaf is removed with a NON-RECURSIVE rmdir
/// (see [`Applier::remove_subtree`]), and the per-child walk of the directory
/// is iterative (an explicit heap stack). A directory that still holds reserved
/// (residue) entries is left in place, and the callers must know
/// whether the subtree is actually gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Removal {
    /// The entry and every descendant is gone.
    Removed,
    /// The entry was left in place because its subtree still holds residue. The
    /// residue paths are recorded and still exist.
    ResidueLeft,
    /// The entry was left in place because its own path (or an ancestor) is a
    /// path a conflict forbids destroying, which is off-limits to deletion.
    Blocked,
}

/// Where a rename whose call reported an error actually left the entry. A
/// failed rename is not assumed to have done nothing: the far side performs the
/// move with a single atomic `rename(2)` (perl, after `mkdir -p parent`), so a
/// PARTIAL move is not possible — but the command may have EXECUTED and the
/// connection DROPPED before its outcome was observed, leaving the entry at
/// either spelling. The entry's location is therefore read back and the report
/// is reconciled against the disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RenamedEntryLocation {
    /// The entry is present at the rename's destination: the move LANDED.
    Destination,
    /// The entry is present at the rename's source: the move did NOT land.
    Source,
    /// Neither spelling could be confirmed present (or a probe failed): the
    /// location is unknown, so neither path is named.
    Unknown,
}

/// How much of a directory a mutation needs before it can write into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParentNeed {
    /// The mutation writes a new entry into the directory. A local durable
    /// write additionally chmods the immediate parent private, so the local
    /// target is `0o700`.
    Private,
    /// The mutation unlinks an entry from the directory and needs only owner
    /// write + traverse.
    Writable,
    /// The mutation never writes into the directory; it only has to REACH an
    /// entry below it (a chmod of the child on a directory-over-directory mode
    /// change). It needs owner traverse, never owner write.
    Traverse,
}

/// The mode to move a directory to for `current`/`need`, or `current` when no
/// change is needed. `immediate` is the directory the mutation writes into;
/// every other candidate is an ancestor that only needs traversing.
fn widen_target(current: Mode, immediate: bool, need: ParentNeed, confined: bool) -> Mode {
    if immediate {
        match (need, confined) {
            // The confined local write path chmods the immediate parent to
            // `0o700` on its way to the child, so that is the exact target.
            (ParentNeed::Private, true) => OWNER_RWX,
            // A remote (or a local transport) write only needs owner write and
            // traverse on the parent.
            (ParentNeed::Private, false) | (ParentNeed::Writable, _) => {
                current | OWNER_WRITE | OWNER_TRAVERSE
            }
            // A traverse-only need never writes into the immediate parent.
            (ParentNeed::Traverse, _) => current | OWNER_TRAVERSE,
        }
    } else {
        current | OWNER_TRAVERSE
    }
}

/// The directory permissions a transfer of `kind` OVER `dest_kind` needs from
/// the directory it writes into. A DIRECTORY over an EXISTING directory is a
/// mode-only change: `transfer_dir` queues the child's mode and `finalize`
/// chmods the CHILD, so it writes nothing into the parent and needs only
/// traverse. Creating a directory over a stale non-directory unlinks/creates an
/// entry (owner write + traverse). A file or symlink install goes through a
/// durable write path that also chmods its immediate parent private.
fn parent_need(kind: EntryKind, dest_kind: Option<EntryKind>) -> ParentNeed {
    match (kind, dest_kind) {
        (EntryKind::Dir, Some(EntryKind::Dir)) => ParentNeed::Traverse,
        (EntryKind::Dir, _) => ParentNeed::Writable,
        (EntryKind::File | EntryKind::Symlink, _) => ParentNeed::Private,
    }
}

fn run(
    source: &Side<'_>,
    dest: &Side<'_>,
    policy: &dyn Policy,
    extraneous: Extraneous,
    ownership: DestinationOwnership,
) -> SyncResult {
    // Hold the destination's operation lock for the WHOLE run: `_lock` lives
    // until this function returns, so the flock is released only after the last
    // mutation, the verification, and the source-quiescence re-read.
    let _lock = match ownership {
        DestinationOwnership::Locked(lock) => Some(lock),
        DestinationOwnership::Unowned => None,
    };
    let source_meta = match source.manifest() {
        Ok(meta) => meta,
        Err(error) => return Err(SyncError::from(error)),
    };
    // The RAW source manifest the plan is made against, kept for the
    // SOURCE-quiescence check at the END of the run. It must be the manifest
    // BEFORE the reserved-namespace strip below, so a change to a reserved
    // spelling is not hidden from the comparison.
    let source_plan = source_meta.clone();
    let dest_meta = match dest.manifest() {
        Ok(meta) => meta,
        Err(error) => return Err(SyncError::from(error)),
    };
    // The reserved claim-aside namespace is bookkeeping, never content. Strip it
    // from BOTH manifests BEFORE the diff, so residue is never classified as
    // source content (transferred) or destination content (removed), and carry
    // the source-side collisions and the destination-side residue in the
    // report. A source collision is a `ReservedName` conflict, not a silent
    // skip; it is NOT also residue, because residue is the abandoned
    // destination state (a path left in place that must still be restored),
    // and a source collision is neither left in place by this sync nor a
    // destination path at all.
    let source_reserved = match reserved_entries(&source_meta) {
        Ok(entries) => entries,
        Err(error) => return Err(SyncError::from(error)),
    };
    let dest_residue = reserved_paths(&dest_meta);
    let source_meta = strip_reserved(source_meta);
    let dest_meta = strip_reserved(dest_meta);
    let diff = diff_trees(&source_meta, &dest_meta);
    let mut applier = Applier {
        source,
        dest,
        policy,
        extraneous_policy: extraneous,
        diff: &diff,
        outcomes: BTreeMap::new(),
        conflicts: BTreeMap::new(),
        extraneous: BTreeSet::new(),
        verify: Vec::new(),
        verified: BTreeSet::new(),
        verify_failures: BTreeSet::new(),
        indeterminate: BTreeMap::new(),
        pending_final: BTreeMap::new(),
        journal: ModeJournal::default(),
        removed: BTreeSet::new(),
        claim_failures: Vec::new(),
        unconfirmed_moves: Vec::new(),
        source_reserved,
        dest_residue,
        aliased_dest: BTreeMap::new(),
        dest_case_insensitive: None,
        // The destination ROOT is verified like any other directory the run
        // TOUCHED: the run always examines it (and creates it when absent), so
        // an unplanned entry AT the root — not only under a transferred
        // parent — is caught. A directory the run did not transfer into still
        // needs no listing check, so this does not turn an all-`Same` sync
        // into an O(tree) listing pass beyond the root itself.
        touched_dirs: BTreeSet::from([String::new()]),
        listings: RefCell::new(BTreeMap::new()),
        ancestry_dirs: RefCell::new(BTreeSet::new()),
        transfers: 0,
    };
    let result = applier.run();
    // ENFORCE THE SOURCE-QUIESCENCE PRECONDITION, as far as the crate can
    // observe it. The caller owes a source that does not move during the run
    // and the crate cannot lock it, so rather than trust the obligation the
    // crate VERIFIES it: re-read the source manifest and compare it to the one
    // the plan was made against, turning a silent plan/transfer skew into a
    // LOUD failure that names the paths that moved. A source read that cannot
    // be repeated is itself a failure — an unconfirmed quiescence is not
    // quiescence.
    match source.manifest() {
        Ok(current) if current == source_plan => result,
        Ok(current) => {
            let error = source_changed_error(&source_plan, &current);
            Err(match result {
                Ok(report) => SyncError {
                    error,
                    report: Box::new(report),
                    restore_failures: Vec::new(),
                },
                Err(mut failure) => {
                    failure.restore_failures.push(error.to_string());
                    failure
                }
            })
        }
        Err(probe) => {
            let error = Error::integrity(format!(
                "the run could not confirm the SOURCE was quiescent: re-reading the source manifest after the transfer failed: {probe}"
            ));
            Err(match result {
                Ok(report) => SyncError {
                    error,
                    report: Box::new(report),
                    restore_failures: Vec::new(),
                },
                Err(mut failure) => {
                    failure.restore_failures.push(error.to_string());
                    failure
                }
            })
        }
    }
}

/// Describe a SOURCE-quiescence violation: the source manifest re-read at the
/// end of the run differs from the one the transfer was planned against. The
/// paths that ADDED, DISAPPEARED, or CHANGED are named so the caller can see
/// exactly what moved underneath the run. Only called on the failure path, so
/// the extra comparison costs nothing on a clean run.
fn source_changed_error(planned: &TreeMetadata, current: &TreeMetadata) -> Error {
    let diff = diff_trees(planned, current);
    let mut changed: Vec<String> = Vec::new();
    for entry in &planned.entries {
        if diff.classify(&entry.path) != Some(EntryDiff::Same) {
            changed.push(entry.path.clone());
        }
    }
    for entry in &current.entries {
        if diff.classify(&entry.path) == Some(EntryDiff::Extraneous) {
            changed.push(entry.path.clone());
        }
    }
    changed.sort();
    changed.dedup();
    Error::integrity(format!(
        "the SOURCE changed during the run, violating the caller's quiescence precondition: the destination was planned against source digest {}, but the source now digests to {}; changed paths: {}",
        planned.tree_sha256,
        current.tree_sha256,
        if changed.is_empty() {
            "(none identifiable)".to_string()
        } else {
            changed.join(", ")
        },
    ))
}

struct Applier<'a, 'b> {
    source: &'b Side<'a>,
    dest: &'b Side<'a>,
    policy: &'b dyn Policy,
    extraneous_policy: Extraneous,
    diff: &'b TreeDiff,
    /// Per-source-entry outcome, keyed by path (a `BTreeMap` so iteration and
    /// the derived report are path-ordered and a path cannot be recorded
    /// twice).
    outcomes: BTreeMap<String, Outcome>,
    /// Conflicts keyed by path. This record is the ONE source of the deletion
    /// prohibition: [`ConflictReason::forbids_destruction`] decides, per
    /// conflict, whether the path it names is off-limits (see
    /// [`Applier::is_prohibited`]). There is no parallel `blocked` set, so a
    /// conflict site cannot forget to block.
    conflicts: BTreeMap<String, Conflict>,
    /// Every destination-only path (whether or not it is removed). A path whose
    /// removal a conflict blocked is reported in `conflicts` instead (see
    /// `derive_report`).
    extraneous: BTreeSet<String>,
    /// Entries whose written bytes must be verified.
    verify: Vec<VerifyItem>,
    /// Paths whose content/target has been verified this run.
    verified: BTreeSet<String>,
    /// Paths whose post-transfer verification FAILED (content hash, symlink
    /// target, final mode, or restored mode). Reported in
    /// [`SyncReport::verify_failures`], never in `applied`.
    verify_failures: BTreeSet<String>,
    /// Paths with a mutating call in flight, keyed by the KIND of mutation
    /// attempted: [`Applier::begin_mutation`] inserts the path and counts the
    /// transfer BEFORE the call runs, and [`Applier::commit_mutation`] decrements
    /// the count when a call of the SAME kind reports `Ok`. A path still here
    /// when the report is derived had an attempt error, so it may or may not have
    /// landed; it is reported in [`SyncReport::indeterminate`]. A CONTENT attempt
    /// is never downgraded to a MODE one, so the mode restore in
    /// [`Applier::restore`] cannot make a failed write or removal look resolved.
    /// Counts are PER KIND and only a successful call of that kind decrements
    /// them, so a later successful mutation at the same path cannot erase an
    /// earlier failed attempt.
    /// [`Applier::reconcile_residue`] also inserts a residue candidate whose
    /// presence could not be confirmed: its location is unknown, and an unknown
    /// location is exactly what this map records.
    indeterminate: BTreeMap<String, PendingMutations>,
    /// Directories whose final mode must be applied after every child is in
    /// place (path -> intended mode). Applied deepest-first.
    pending_final: BTreeMap<String, Mode>,
    /// THE mode record.
    journal: ModeJournal,
    /// Paths already removed this run, so a descendant of a removed directory
    /// is not removed again (ancestry via `Path`, never a literal separator).
    removed: BTreeSet<String>,
    /// Failures restoring a CLAIMED entry after a failed install (a
    /// claim-by-rename rollback that itself failed). Merged into the
    /// [`SyncError`]'s restore failures.
    claim_failures: Vec<String>,
    /// RENAMES whose call reported failure and whose landed-or-not could not be
    /// confirmed: the entry may be at EITHER spelling. Consumed by
    /// [`Applier::reconcile_residue`], which never names an unconfirmed path as
    /// residue but names BOTH possible spellings in `restore_failures`.
    unconfirmed_moves: Vec<UnconfirmedMove>,
    /// SOURCE entries whose name is in the reserved claim-aside namespace,
    /// with their kind. They are reported as [`ConflictReason::ReservedName`]
    /// and never transferred.
    source_reserved: BTreeMap<String, EntryKind>,
    /// DESTINATION entries in the reserved claim-aside namespace (from the RAW
    /// destination manifest, plus any discovered while removing a claimed
    /// subtree and any aside left by a failed rollback). A claimed subtree that
    /// holds residue is never recursively removed, so every path here still
    /// exists. This set is derived from the RAW manifests and the removal walk;
    /// the deletion prohibition itself is derived from [`Applier::conflicts`].
    dest_residue: BTreeSet<String>,
    /// Destination on-disk spellings that an installed (or skipped) SOURCE
    /// entry aliases on an aliasing filesystem: keyed by the name the
    /// destination actually contains, valued by the source manifest path it
    /// really names. Populated by the pre-transfer alias check and by
    /// [`Applier::verify_names`]. It is what makes the removal of such a
    /// spelling — and of everything below it — a conflict instead of a
    /// destruction: the sanctioned [`Extraneous::Delete`] removal is keyed on a
    /// spelling that aliases another file.
    aliased_dest: BTreeMap<String, String>,
    /// The destination filesystem's case sensitivity, probed at most ONCE per
    /// run and only when a source entry could case-fold onto another entry
    /// (see [`Applier::refuse_unrepresentable_case_aliases`]). `None` until
    /// probed, or when the destination root is absent (the probe would create
    /// it) and the per-directory name verification is left to catch the fold.
    dest_case_insensitive: Option<bool>,
    /// The manifest paths of the destination DIRECTORIES this run TOUCHED:
    /// installed into, created, or removed from — ALWAYS including the
    /// destination ROOT (`""`), which the run examines on every path. A
    /// non-root directory nothing was written into needs no such check, so
    /// this set keeps an all-`Same` sync from paying for a full-tree listing.
    /// [`Applier::verify`] reads each one's LIVE listing and compares it
    /// BYTE-IDENTICALLY against the names the run expected there, and verifies
    /// the content and KIND of the entries it claims to have left alone. A
    /// directory this run REMOVED stays in the set (the removal pass inserts a
    /// removed entry's parent), but every consumer SKIPS a path for which
    /// [`Applier::is_already_gone`] holds: re-listing an absent directory would
    /// otherwise raise a missing-ancestor error for a correctly deleted
    /// subtree. The `touched_dirs` set is therefore "every directory the
    /// verification MUST still find", not "every directory it may probe".
    touched_dirs: BTreeSet<String>,
    /// THE run-scoped listing cache: for every destination directory this run
    /// has enumerated (keyed by its manifest path, `""` for the root), the
    /// listing read from the destination. It is the ONLY place a listing can
    /// be fetched, so every consumer ([`Applier::verify_names`],
    /// [`Applier::verify_directory_listings`],
    /// [`Applier::verify_claimed_untouched`],
    /// [`Applier::refuse_address_folded_onto_another_name`], and
    /// [`Applier::remove_extraneous`]) shares ONE read per directory instead of
    /// re-listing the parent once per entry (the O(N^2) enumeration defect).
    ///
    /// FRESHNESS is re-established by CLEARING the cache at the start of every
    /// [`Applier::verify`] pass: the verify passes are the only consumers whose
    /// verdict must reflect the destination as it stands AFTER the transfers
    /// (and, for the post-`remove_extraneous` pass, after the removals), and no
    /// destination mutation runs inside a verify pass, so a directory is read
    /// ONCE per pass and that read is exact. The transfer-time fold gate and
    /// the removal-time name check use a listing that may predate later
    /// mutations of OTHER entries in the same directory; that is safe because
    /// each asks only about the byte spelling and KIND of the ONE path it
    /// names, and no sibling mutation changes those (every content/kind claim
    /// is re-confirmed live, not from the listing). [`RefCell`] because the
    /// read is logically pure at every call site but must fill the cache.
    listings: RefCell<BTreeMap<String, CachedListing>>,
    /// THE run-scoped ANCESTRY memo for [`Applier::guard_destination`]: the
    /// manifest spelling of every destination path CONFIRMED (by `kind_opt`,
    /// `lstat`, never `stat`) to be a real DIRECTORY. A hit is exactly the
    /// `Some(EntryKind::Dir)` arm of the guard's per-component probe, so it
    /// replaces that one `kind_opt` with a set lookup.
    ///
    /// SCOPED TO CONFINED DESTINATIONS — A PROPERTY OF THE SIDE AND THE
    /// PLATFORM, ENFORCED AT THE USE SITE. The memo is populated and consulted
    /// ONLY while [`Side::is_confined_local`] holds: a [`Side::Local`]
    /// destination on a platform whose `_fd` primitives resolve components with
    /// `O_NOFOLLOW` ([`crate::atomic::COMPONENT_CONFINED`]), so every mutation
    /// and probe is resolved component-wise through `crate::atomic`. On a
    /// PATH-BASED [`Side::Remote`] destination — and equally on a [`Side::Local`]
    /// one where the platform's primitives are path-based — the preflight is
    /// the confinement (see "Destination-component confinement" on the module),
    /// so the applier caches NOTHING there and probes live on every operation.
    /// The condition is structural — the destination KIND together with the
    /// platform primitive property, checked at the point of use — never a
    /// comment assuming a guarantee that only holds on some of the paths the
    /// applier serves.
    ///
    /// WHY IT IS SOUND ON A CONFINED DESTINATION. A memo hit can skip only a
    /// REDUNDANT preflight; it can never skip the confinement. Even if a
    /// non-cooperating writer turns a memoized directory into a symlink, the
    /// mutation itself goes through the component-wise `O_NOFOLLOW` primitive in
    /// `crate::atomic`, which refuses the swapped component — so the memo widens
    /// no window through which a mutation could land outside the root.
    ///
    /// WHAT IT RESTS ON, STATED AT THE POINT OF USE. The memo additionally rests
    /// on the exclusive-ownership PRECONDITION the lock establishes: under it,
    /// the run itself is the only writer, so a confirmed `Dir` fact stays true
    /// and the run converts a directory ONLY by (a) renaming it aside in
    /// [`Applier::claim_aside`]/[`Applier::rename_back`] and installing a
    /// different kind at the same manifest spelling, or (b) removing it in
    /// [`Applier::remove_subtree`]. Both are CONTENT mutations, and
    /// [`Applier::begin_mutation`] DROPS the memo entry for the mutated path, so
    /// the next guard at or below it re-probes the LIVE object. A MODE mutation
    /// (a widen or restore) does not invalidate a kind fact. ABSENCE is never
    /// memoized: a directory the run creates was not a directory before, and
    /// re-probing an absent component is what keeps a `MustExist` refusal (and a
    /// `MayCreate` pass) exact after a create; only the positive `Dir` fact is
    /// stable enough to reuse. A stale entry for a DESCENDANT of a converted
    /// directory is masked by its converted ancestor, which the top-down prefix
    /// walk re-probes first. A writer that VIOLATES the precondition is still
    /// handled: every `verify_*` pass re-reads LIVE listings and re-probes kinds,
    /// so a swapped component it leaves behind is DETECTED and the run FAILS
    /// CLOSED rather than silently applied.
    ancestry_dirs: RefCell<BTreeSet<String>>,
    transfers: usize,
}

impl Applier<'_, '_> {
    fn run(&mut self) -> SyncResult {
        let result = self.run_steps();
        // THE one settle site: it runs on the success and the failure path.
        let (settle_failures, verify_error) = self.settle();
        // THE final reconciliation: confirm every residue candidate against the
        // disk BEFORE the report is derived, so "every named path still EXISTS"
        // holds by construction for every branch, present and future.
        self.reconcile_residue();
        let report = self.derive_report();
        // Claim-rollback failures happened during the transfer; merge them with
        // the settle failures so a failed rollback is never swallowed.
        let mut restore_failures = std::mem::take(&mut self.claim_failures);
        restore_failures.extend(settle_failures);
        match result {
            Ok(()) => match verify_error {
                None if restore_failures.is_empty() => Ok(report),
                verify_error => {
                    let error = verify_error.unwrap_or_else(|| {
                        // The failure is a cleanup failure, not a mode restore:
                        // name every recorded failure rather than misreporting
                        // a leaked aside as a transient mode.
                        Error::integrity(format!(
                            "{} failure(s) left the destination in a state that could not be cleaned up: {}",
                            restore_failures.len(),
                            restore_failures.join("; ")
                        ))
                    });
                    Err(SyncError {
                        error,
                        report: Box::new(report),
                        restore_failures,
                    })
                }
            },
            Err(error) => {
                let mut failures = restore_failures;
                if let Some(verify_error) = verify_error {
                    failures.push(format!("post-settle verification: {verify_error}"));
                }
                Err(SyncError {
                    error,
                    report: Box::new(report),
                    restore_failures: failures,
                })
            }
        }
    }

    fn run_steps(&mut self) -> Result<()> {
        self.report_extraneous();
        self.transfer()?;
        self.finalize()?;
        // Verification gates removal: everything written and every final mode
        // is checked BEFORE anything is destroyed. The restored-mode half of
        // verification runs after settle.
        self.verify(false)?;
        self.remove_extraneous()?;
        Ok(())
    }

    /// The ONE place a restore runs. It does not drain the journal; the report
    /// still derives from it.
    fn settle(&mut self) -> (Vec<String>, Option<Error>) {
        let failures = self.restore();
        let verify_error = self.verify(true).err();
        (failures, verify_error)
    }

    /// Derive the report from the outcome record and the mode journal. Nothing
    /// is pushed ad hoc during the transfer.
    ///
    /// The lists PARTITION under ONE explicit precedence, documented here and
    /// asserted by the tests:
    ///
    /// > indeterminate > conflicts > residue > applied > skipped > extraneous >
    /// > verify_failures
    ///
    /// A path claimed by a higher list is omitted from every lower one. On the
    /// merits: `indeterminate` is the LEAST certain claim (a failed mutation may
    /// have landed or not), so it subsumes the rest; `conflicts` is the caller's
    /// decision surface and must never be hidden; `residue` still EXISTS and must
    /// be recovered by hand, so it wins over the verification bookkeeping in
    /// `verify_failures` (whose failure is also carried in
    /// [`SyncError::restore_failures`]); `applied`/`skipped`/`extraneous` are the
    /// outcome of a known mutation; `verify_failures` is the catch-all for a
    /// mutation that did not reach a passed final state.
    ///
    /// `transient_dirs` is deliberately NOT in that partition: it MAY share a
    /// path with `applied` and `verify_failures` (a widened `Changed` directory
    /// that was also applied, or whose verification failed), but it is disjoint
    /// from `indeterminate`, `conflicts`, `residue`, `skipped`, and
    /// `extraneous`.
    fn derive_report(&self) -> SyncReport {
        // The raw candidate claims, before the precedence filter.
        let indeterminate: BTreeSet<String> = self.indeterminate.keys().cloned().collect();
        let mut applied: BTreeSet<String> = BTreeSet::new();
        let mut skipped: BTreeSet<String> = BTreeSet::new();
        // A `Transferred` path that did not reach a verified final state is NOT
        // dropped from every list: it is named in `verify_failures`. This is what
        // makes the report account for every path the run MUTATED on the failure
        // path too — a directory created by `transfer_dir` whose `finalize` never
        // ran is still named, instead of vanishing (its final mode did not land).
        let mut verify_failures: BTreeSet<String> = self.verify_failures.clone();
        for (path, outcome) in &self.outcomes {
            match outcome {
                Outcome::Transferred => {
                    if self.verified.contains(path) && self.journal.final_applied(path) {
                        applied.insert(path.clone());
                    } else {
                        verify_failures.insert(path.clone());
                    }
                }
                Outcome::Skipped => {
                    // A path whose mode the journal touched is NOT truthfully
                    // skipped: it is named in `transient_dirs`. The
                    // re-confirmation inside a TOUCHED parent is scoped by
                    // `verify_claimed_untouched`; a `Skipped` path whose parent
                    // was never touched is reported on the manifest alone, as
                    // [`SyncReport::skipped`] documents.
                    if !self.journal.is_widened(path) {
                        skipped.insert(path.clone());
                    }
                }
            }
        }
        let mut conflicts: Vec<Conflict> = self.conflicts.values().cloned().collect();
        let mut residue: BTreeSet<String> =
            reserved_roots(&self.dest_residue).into_iter().collect();
        let mut extraneous: BTreeSet<String> = self.extraneous.iter().cloned().collect();

        // ONE authority for "a path whose FINAL verification could not complete
        // is never reported as a verified outcome". `verify_failures` here is
        // the derived failure set (every recorded verification failure PLUS
        // every `Transferred` path that did not reach a verified final state),
        // and a path in it is excluded from EVERY verified-outcome list
        // REGARDLESS of which pass recorded the failure or what the per-path
        // outcome is. This is what stops a `Skipped` path whose verification
        // COULD NOT RUN (an unenumerable directory, a kind swap) from being
        // advertised as `skipped` just because the failure happened to be
        // recorded in a set that `apply_precedence` ranks below `skipped`: the
        // recorded FAILURE decides membership, not the outcome.
        for path in &verify_failures {
            applied.remove(path);
            skipped.remove(path);
            extraneous.remove(path);
        }

        // ONE explicit precedence so the lists partition. The filter is a pure
        // function (see `apply_precedence`) so the partition is unit-testable
        // with an arbitrary overlap.
        apply_precedence(
            &indeterminate,
            &mut conflicts,
            &mut residue,
            &mut applied,
            &mut skipped,
            &mut extraneous,
            &mut verify_failures,
        );

        // Outside the partition (may share with `applied`/`verify_failures`),
        // but still disjoint from the lists above.
        let transient_dirs: Vec<String> = self
            .journal
            .widened_paths()
            .into_iter()
            .filter(|path| {
                !indeterminate.contains(path)
                    && !self.conflicts.contains_key(path)
                    && !self.dest_residue.contains(path)
                    && !self.extraneous.contains(path)
            })
            .collect();
        SyncReport {
            applied: applied.into_iter().collect(),
            skipped: skipped.into_iter().collect(),
            conflicts,
            // A destination-only path whose sanctioned removal a conflict
            // blocked is reported in `conflicts` (reason `ParentRefused`)
            // instead of being duplicated here: the lists are mutually
            // exclusive under the precedence above.
            extraneous: extraneous.into_iter().collect(),
            transient_dirs,
            residue: residue.into_iter().collect(),
            verify_failures: verify_failures.into_iter().collect(),
            indeterminate: indeterminate.into_iter().collect(),
            transfers: self.transfers,
        }
    }

    /// Record that a `kind` mutating call on `path` is ABOUT to run. This is the
    /// "record the attempt FIRST" discipline: the transfer is counted up front,
    /// so `transfers == 0` stays a valid "nothing was mutated" oracle even when
    /// the call later fails after partially applying, and the path is
    /// INDETERMINATE until a call of the SAME kind reports success. On `Ok` the
    /// caller calls [`Applier::commit_mutation`]; on `Err` the path is left here
    /// and named in [`SyncReport::indeterminate`].
    ///
    /// A CONTENT attempt outranks a MODE attempt: once the path's content may
    /// have changed, a later mode attempt on the same path must not overwrite
    /// that record, or [`Applier::restore`]'s confirming chmod could silently
    /// resolve a failed write.
    fn begin_mutation(&mut self, path: &str, kind: MutationKind) {
        // A CONTENT mutation can change the KIND of `path`: a create, a write, a
        // rename (claim/rollback), or a removal. Any memoized "this path is a
        // real directory" fact is therefore no longer trustworthy AT this
        // spelling, so it is dropped here (the ONE mutation choke point) and the
        // next guard re-probes the LIVE object. A MODE mutation leaves the kind
        // untouched and keeps the fact. The memo exists only for a confined
        // destination (see [`Applier::ancestry_dirs`]); on a path-based one the
        // set is never filled, so this drop is a harmless no-op there.
        if kind == MutationKind::Content {
            self.ancestry_dirs.borrow_mut().remove(path);
        }
        self.transfers += 1;
        let pending = self.indeterminate.entry(path.to_string()).or_default();
        match kind {
            MutationKind::Content => pending.content += 1,
            MutationKind::Mode => pending.mode += 1,
        }
    }

    /// The `kind` mutating call on `path` returned `Ok`: THAT attempt landed, so
    /// it is resolved. A count is decremented only for the SAME kind — a
    /// successful restore of a path's mode says nothing about whether a failed
    /// CONTENT mutation landed — and only by one, so a PRIOR failed attempt of
    /// the same kind keeps the path indeterminate.
    fn commit_mutation(&mut self, path: &str, kind: MutationKind) {
        let Some(pending) = self.indeterminate.get_mut(path) else {
            return;
        };
        let slot = match kind {
            MutationKind::Content => &mut pending.content,
            MutationKind::Mode => &mut pending.mode,
        };
        *slot = slot.saturating_sub(1);
        if pending.is_empty() {
            self.indeterminate.remove(path);
        }
    }

    /// Record a path's intended final mode, reading the LIVE mode immediately
    /// after the operation that was supposed to apply it. A mode the transport
    /// never applied leaves `final_applied = false`, so the restore targets the
    /// original and verification still demands the intended mode.
    fn note_final(&mut self, path: &str, intended: Mode, kind: EntryKind) -> Result<()> {
        let rel = rooted(path)?;
        let live = self.dest.mode_opt(&rel, kind)?;
        self.journal.mark_final_mode(path, intended, live);
        Ok(())
    }

    fn conflict(
        &mut self,
        path: &str,
        kind: EntryKind,
        policy: EntryPolicy,
        reason: ConflictReason,
    ) {
        self.conflicts.insert(
            path.to_string(),
            Conflict {
                path: path.to_string(),
                kind,
                policy,
                reason,
                on_disk: None,
            },
        );
    }

    /// Report a [`ConflictReason::NameNotFaithful`] conflict naming the
    /// destination's actual on-disk spelling when it could be read.
    fn name_conflict(&mut self, path: &str, kind: EntryKind, on_disk: Option<String>) {
        let policy = self.policy.for_path(path, kind);
        self.conflicts.insert(
            path.to_string(),
            Conflict {
                path: path.to_string(),
                kind,
                policy,
                reason: ConflictReason::NameNotFaithful,
                on_disk,
            },
        );
    }

    /// Whether `path` (or an ancestor) is a destination spelling an installed
    /// source entry aliases, so removing it would destroy that entry.
    fn is_aliased_dest(&self, path: &str) -> bool {
        self.aliased_dest.contains_key(path)
            || ancestor_paths(path)
                .into_iter()
                .any(|ancestor| self.aliased_dest.contains_key(&ancestor))
    }

    /// The on-disk NAME of the topmost aliased destination spelling at or above
    /// `path`, for naming in a [`ConflictReason::NameNotFaithful`] conflict.
    fn aliased_dest_root(&self, path: &str) -> Option<String> {
        let full = if self.aliased_dest.contains_key(path) {
            path.to_string()
        } else {
            ancestor_paths(path)
                .into_iter()
                .find(|ancestor| self.aliased_dest.contains_key(ancestor))?
        };
        Path::new(&full)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
    }

    /// Report every destination-only entry. Removal happens later, only after
    /// the transfers and verification succeed.
    fn report_extraneous(&mut self) {
        for entry in &self.diff.dest.entries {
            if self.diff.classify(&entry.path) == Some(EntryDiff::Extraneous) {
                self.extraneous.insert(entry.path.clone());
            }
        }
    }

    /// The destination manifest entry at `path`, if any.
    fn dest_entry_at(&self, path: &str) -> Option<&TreeEntry> {
        let entries = &self.diff.dest.entries;
        let index = entries
            .binary_search_by(|e| e.path.as_str().cmp(path))
            .ok()?;
        Some(&entries[index])
    }

    /// Whether the conflict at `path` itself forbids destroying `path`.
    ///
    /// Derived from the conflict record through the ONE definition
    /// ([`ConflictReason::forbids_destruction`]); there is no parallel set.
    fn is_directly_prohibited(&self, path: &str) -> bool {
        self.conflicts
            .get(path)
            .is_some_and(|conflict| conflict.reason.forbids_destruction())
    }

    /// Whether `path` is (or is below) a path a conflict forbids destroying.
    /// This is the deletion prohibition: mode-INDEPENDENT, so a WRITABLE
    /// conflicted directory protects its destination-only children too.
    fn is_prohibited(&self, path: &str) -> bool {
        self.is_directly_prohibited(path)
            || ancestor_paths(path)
                .into_iter()
                .any(|ancestor| self.is_directly_prohibited(&ancestor))
    }

    /// Whether `path` may be destroyed under `sanction`. This is
    /// proof-carrying: the caller passes WHY the path is the sync's to destroy,
    /// so the guard can neither over-block the sync's own bookkeeping nor
    /// under-block caller data.
    fn may_delete(&self, path: &str, sanction: Sanction<'_>) -> bool {
        match sanction {
            // The sync's own claim aside: the caller holds the `Claim`, so the
            // path was renamed aside by THIS sync and is not caller data. The
            // ancestry test is necessary but NOT sufficient: the claim was
            // taken when the directory held exactly the manifest-described
            // entries, and a concurrent writer may have added a child since.
            // `remove_subtree` therefore re-establishes the sanction against
            // the LIVE listing ([`Applier::claim_child_is_addressed`]) before
            // it destroys anything under an `OwnClaim` directory — the
            // ancestry test alone is exactly what let a stale claim delete a
            // writer-created child.
            Sanction::OwnClaim(claim) => {
                is_same_or_descendant(path, &manifest_spelling(&claim.rel))
            }
            // The sync's own partial creation during a rollback. It carries
            // the SAME `Claim` as `OwnClaim`, because the call site only ever
            // reaches it after `claim_aside` renamed the ORIGINAL at
            // `claim.original` aside: the live path is the real path the claim
            // was taken from, so anything there is this sync's own partial
            // (never caller data) and is deletable ONLY within that claim's
            // range.
            Sanction::OwnPartial(claim) => {
                is_same_or_descendant(path, &manifest_spelling(&claim.original))
            }
            // Caller data: only a destination-only entry absent from the source
            // manifest, and still refused for any path the conflict-derived
            // prohibition covers.
            //
            // DELIBERATE DEFENSE IN DEPTH. `remove_extraneous` already refuses a
            // prohibited path with `ParentRefused` BEFORE any widen, so this
            // clause is not reached through the walk: the walk
            // descends only into children of an EXTraneous (destination-only)
            // directory, whose subtree by construction holds no source entry and
            // therefore cannot carry a conflict — the prohibition is DERIVED
            // from the conflict record, and a conflict is recorded only for a
            // source entry, a source reserved name, or an extraneous path the
            // top-level pass already refused. It is kept rather than relying on
            // that reachability argument, so a future caller (or a diff that
            // admits a conflicted path below an extraneous directory) still
            // cannot destroy a protected path. There is no test that fails when
            // it is deleted, because no reachable state reaches it.
            Sanction::ExtraneousFlag => {
                self.diff.classify(path) == Some(EntryDiff::Extraneous) && !self.is_prohibited(path)
            }
        }
    }

    /// Whether an ancestor of `path` forbids its installation. An ancestor
    /// forbids when a conflict left it alone (the prohibition derived from the
    /// conflict record) AND either it is not an existing destination DIRECTORY
    /// or installing the child would need its mode widened for `need` — which
    /// the prohibition forbids. The rule is uniform ("a prohibited directory is
    /// never widened"); whether a particular child would need the widen depends
    /// on this direction's write path (see [`ConflictReason::ParentRefused`]).
    fn forbidden_ancestor_blocks_write(&self, path: &str, need: ParentNeed) -> Result<bool> {
        for ancestor in ancestor_paths(path) {
            if !self.is_directly_prohibited(&ancestor) {
                continue;
            }
            let Some(entry) = self.dest_entry_at(&ancestor) else {
                return Ok(true);
            };
            if entry.entry_type != EntryKind::Dir.as_str() {
                return Ok(true);
            }
            // The ancestor IS an existing directory. It blocks only when
            // installing the child would need its mode widened, which the
            // conflict forbids.
            let immediate =
                Path::new(path).parent().and_then(Path::to_str) == Some(ancestor.as_str());
            let rel = rooted(&ancestor)?;
            let current = self.dest.mode(&rel, EntryKind::Dir)?;
            let target = widen_target(current, immediate, need, self.dest.is_confined_local());
            if target != current {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether a destination directory at `path` may be removed to make room
    /// for a non-directory: only when it has no descendants, or when the caller
    /// explicitly sanctioned removing extraneous entries. Every descendant of a
    /// directory the source replaces with a file/symlink is necessarily
    /// destination-only, so removing the directory would destroy entries the
    /// caller never sanctioned. Descendants are determined with
    /// `Path::strip_prefix` (component-wise), so a sibling whose name merely
    /// shares a prefix is not a descendant.
    ///
    /// The diff's destination manifest is STRIPPED of the reserved namespace, so
    /// a directory whose only child is an aside would look childless; the RAW
    /// residue set is therefore consulted too, so a directory holding residue is
    /// NOT sanctioned by the EMPTINESS test alone. [`Extraneous::Delete`] DOES
    /// sanction it (the early return below consults no residue set), and that is
    /// safe: the replacement claims the directory aside and then removes it
    /// through the ONE removal walk, which stops at the reserved child and
    /// leaves the holding directory in place ([`Removal::ResidueLeft`]), so the
    /// residue survives even a sanctioned replacement.
    fn dir_replace_is_sanctioned(&self, path: &str) -> bool {
        if self.extraneous_policy == Extraneous::Delete {
            return true;
        }
        if self
            .dest_residue
            .iter()
            .any(|residue| is_strict_descendant(residue, path))
        {
            return false;
        }
        !self
            .diff
            .dest
            .entries
            .iter()
            .any(|entry| is_strict_descendant(&entry.path, path))
    }

    /// The ONE widen choke point. Every mutation kind that writes into a
    /// directory calls this first: a directory create, a regular-file write, an
    /// append write, a symlink create, and a removal (which additionally widens
    /// the target directory of a subtree removal). The decision is read from
    /// each directory's CURRENT mode, never the source's and never a cached
    /// "already widened" bit — a directory can need widening again after
    /// `finalize` reinstated a read-only final mode.
    fn widen_ancestors(&mut self, path: &str, need: ParentNeed) -> Result<()> {
        let ancestors = ancestor_paths(path);
        let last = ancestors.len().checked_sub(1);
        // The directories this operation may widen: manifest entries that exist
        // as directories. `dest_entry_at` reads the SNAPSHOT; whether each is
        // LIVE is established by the ONE ancestry verification below.
        let mut candidates: Vec<(usize, String, RootedRelativePath)> = Vec::new();
        for (index, dir) in ancestors.iter().enumerate() {
            // A path whose OWN entry a conflict forbids must never be widened
            // (its mode is left exactly as it was found).
            if self.is_directly_prohibited(dir) {
                continue;
            }
            // Only a directory that already EXISTS in the destination manifest
            // can need widening: a directory this sync creates is created
            // writable, and a non-directory ancestor is resolved (or blocked)
            // by the entry that owns it.
            let Some(existing_kind) = self.dest_entry_at(dir).map(EntryKind::of).transpose()?
            else {
                continue;
            };
            if existing_kind != EntryKind::Dir {
                continue;
            }
            candidates.push((index, dir.clone(), rooted(dir)?));
        }
        // ONE live ancestry verification for the WHOLE widen. The DEEPEST
        // candidate's strict ancestors are exactly this path's strict ancestors
        // (top-down), so guarding it once checks every prefix — and, because it
        // demands a final DIRECTORY, the deepest candidate itself. The loop
        // below performs no ancestry walk of its own, which is what removes the
        // per-ancestor x per-prefix multiplication (a depth-D widen used to cost
        // O(D^2) probes, and O(D^3) `openat`). Nothing is remembered across
        // operations: this fact lives for exactly this call.
        if let Some((_, _, deepest)) = candidates.last() {
            self.guard_destination(deepest, AncestorPolicy::MustExist, FinalPolicy::Directory)?;
        }
        for (index, dir, rel) in candidates {
            let immediate = last == Some(index);
            self.widen_dir_verified(&dir, &rel, need, immediate)?;
        }
        Ok(())
    }

    /// THE single destination-confinement preflight: every destination mutation
    /// consults it before it runs. Using `kind_opt` (`lstat`, never
    /// `stat`/`exists`) it verifies that
    ///
    /// * every STRICT ancestor component of `rel` is a REAL directory (a
    ///   symlink, a regular file, or — when `ancestors` requires existence — a
    ///   missing component is refused), and
    /// * the FINAL component satisfies `final_component` (a symlink is refused
    ///   whenever the operation would follow it; a real directory is required
    ///   for a directory operation).
    ///
    /// This is what keeps a destination mutation inside the destination root:
    /// the path-based [`Remote`] implementation follows a symlink in ANY
    /// component, so without this check a symlink at a directory position
    /// redirects a write, a chmod, a rename, a removal, or a listing OUTSIDE the
    /// root. It complements — and for the fd-confined local destination
    /// duplicates — the component-wise `O_NOFOLLOW` resolution of
    /// `crate::atomic`: there the window is closed entirely, while here it is a
    /// check-then-act window (the residual race documented on the module). A
    /// refusal is an [`Err`] the call site surfaces; it is NEVER silently
    /// skipped, so no refused path is claimed `applied`/`skipped`/`extraneous`.
    fn guard_destination(
        &self,
        rel: &RootedRelativePath,
        ancestors: AncestorPolicy,
        final_component: FinalPolicy,
    ) -> Result<()> {
        // An ABSENT destination root: no component can be a symlink, so a
        // creating operation proceeds (it creates the real parent chain) and a
        // requiring one refuses. `kind_opt` would otherwise open the root and
        // fail for a path the operation is about to create.
        if !self.dest.root_present() {
            return match ancestors {
                AncestorPolicy::MayCreate => Ok(()),
                AncestorPolicy::MustExist => {
                    Err(missing_destination_ancestor_error(&manifest_spelling(rel)))
                }
            };
        }
        // Strict ancestors TOP-DOWN (nearest to the root first), so the
        // nearest-to-root refusal is named and a symlink is never resolved by a
        // deeper check.
        //
        // The ancestry memo is consulted ONLY where the destination's own
        // primitives enforce component-wise confinement
        // ([`Side::is_confined_local`], which conjoins the side kind with
        // [`crate::atomic::COMPONENT_CONFINED`]); on a path-based destination
        // the preflight IS the confinement, so every operation probes live and
        // nothing is cached (see [`Applier::ancestry_dirs`]).
        let memo_ancestry = self.dest.is_confined_local();
        let mut prefixes: Vec<RootedRelativePath> = Vec::new();
        let mut current = rel.parent();
        while let Some(ancestor) = current {
            current = ancestor.parent();
            prefixes.push(ancestor);
        }
        for ancestor in prefixes.into_iter().rev() {
            let spelling = manifest_spelling(&ancestor);
            // A prefix the run already CONFIRMED as a real directory is a
            // reusable fact on a confined destination (see
            // [`Applier::ancestry_dirs`]); only a MISS reaches the live probe.
            if memo_ancestry && self.ancestry_dirs.borrow().contains(&spelling) {
                continue;
            }
            match self.dest.kind_opt(&ancestor)? {
                Some(EntryKind::Dir) => {
                    if memo_ancestry {
                        self.ancestry_dirs.borrow_mut().insert(spelling);
                    }
                }
                Some(other) => {
                    return Err(non_directory_destination_error(&spelling, other));
                }
                None if ancestors == AncestorPolicy::MayCreate => {}
                None => {
                    return Err(missing_destination_ancestor_error(&spelling));
                }
            }
        }
        match final_component {
            FinalPolicy::Unresolved => {}
            policy => {
                // A confirmed directory satisfies EVERY `FinalPolicy` (it is not
                // a symlink and, where the policy demands a directory, it is
                // one), so a hit skips the probe; a `File`/`Symlink`/absence is
                // never memoized. Only a confined destination may reuse the hit.
                let spelling = manifest_spelling(rel);
                if memo_ancestry && self.ancestry_dirs.borrow().contains(&spelling) {
                    return Ok(());
                }
                match self.dest.kind_opt(rel)? {
                    None => {}
                    Some(EntryKind::Dir) => {
                        if memo_ancestry {
                            self.ancestry_dirs.borrow_mut().insert(spelling);
                        }
                    }
                    Some(EntryKind::Symlink) => {
                        return Err(non_directory_destination_error(
                            &manifest_spelling(rel),
                            EntryKind::Symlink,
                        ));
                    }
                    Some(EntryKind::File) if policy == FinalPolicy::Directory => {
                        return Err(non_directory_destination_error(
                            &manifest_spelling(rel),
                            EntryKind::File,
                        ));
                    }
                    Some(EntryKind::File) => {}
                }
            }
        }
        Ok(())
    }

    /// The manifest spelling a LIVE path must have for `sanction` to cover it,
    /// or `None` when the sanction's proof does not REACH the live path at all.
    /// THIS IS THE ONE AUTHORITY for the live re-establishment, and it is TOTAL
    /// by construction: every arm must NAME a manifest root (or deny reach), so
    /// no arm can authorize destruction by returning a constant.
    /// `remove_subtree` then asks the diff ONE question
    /// ([`TreeDiff::classify`]) of the returned spelling — `None`, or a
    /// spelling the manifest does not address, preserves and names the live
    /// entry.
    ///
    /// * [`Sanction::ExtraneousFlag`] names the live path itself: the caller
    ///   already established `classify(path) == Extraneous` at the top, and every
    ///   child of an extraneous directory is an extraneous manifest entry.
    /// * [`Sanction::OwnClaim`] re-roots the live path from the ASIDE spelling
    ///   ([`Claim::rel`]) back to the manifest spelling ([`Claim::original`])
    ///   the aside holds.
    /// * [`Sanction::OwnPartial`] reaches ONLY the single entry at the claim's
    ///   real path: the sync's own partial creation is `create_dir_all`'s EMPTY
    ///   directory or one file/symlink, so NOTHING strictly below it was written
    ///   by this sync. A live descendant is therefore outside the proof and is
    ///   `None` — preserved and named — whatever any manifest says.
    fn live_entry_manifest_spelling(
        &self,
        live_path: &str,
        sanction: Sanction<'_>,
    ) -> Option<String> {
        match sanction {
            Sanction::ExtraneousFlag => Some(live_path.to_string()),
            Sanction::OwnClaim(claim) => Some(re_root_path(
                &manifest_spelling(&claim.original),
                live_path,
                &manifest_spelling(&claim.rel),
            )),
            Sanction::OwnPartial(claim) => {
                let original = manifest_spelling(&claim.original);
                (live_path == original).then_some(original)
            }
        }
    }

    /// Whether a LIVE child of a path being destroyed is one the sanction
    /// actually covers, re-established against the LIVE listing rather than
    /// against the manifest SNAPSHOT the sanction was taken from. The spelling
    /// comes from the ONE authority ([`Applier::live_entry_manifest_spelling`])
    /// and the diff is consulted ONCE, so every variant — `ExtraneousFlag`,
    /// `OwnClaim`, and `OwnPartial` — is measured by the identical rule: a live
    /// entry no manifest spelling addresses is NOT this sync's to destroy.
    fn live_entry_is_addressed(&self, live_path: &str, sanction: Sanction<'_>) -> bool {
        self.live_entry_manifest_spelling(live_path, sanction)
            .is_some_and(|spelling| self.diff.classify(&spelling).is_some())
    }

    /// Widen the directory at `path`/`rel` when its CURRENT mode falls short of
    /// `need`. Idempotent by construction: when the current mode already
    /// satisfies `need` the target equals it and no chmod runs, so a second
    /// widen of the same directory in the same state is a no-op. The journal
    /// records the original ONCE per identity, so a widen after a `finalize`
    /// still restores the true original.
    ///
    /// NO ANCESTRY WALK OF ITS OWN. The caller has ALREADY verified, in this
    /// SAME operation, that `rel` is a live real directory and that every strict
    /// ancestor of it is a real directory — [`Applier::widen_ancestors`] does it
    /// once for the whole ancestor chain, and [`Applier::remove_subtree`] does
    /// it immediately before widening the directory it is about to empty.
    /// Re-walking the prefixes here would multiply the work by the prefix
    /// length; the verified fact lives for exactly one operation and is never
    /// cached across one.
    fn widen_dir_verified(
        &mut self,
        path: &str,
        rel: &RootedRelativePath,
        need: ParentNeed,
        immediate: bool,
    ) -> Result<()> {
        if self.is_directly_prohibited(path) {
            return Ok(());
        }
        let current = self.dest.mode(rel, EntryKind::Dir)?;
        let target = widen_target(current, immediate, need, self.dest.is_confined_local());
        if target == current {
            return Ok(());
        }
        self.journal
            .note_first_touch(path, EntryKind::Dir, Some(current));
        self.begin_mutation(path, MutationKind::Mode);
        match self.dest.set_mode(rel, target, EntryKind::Dir) {
            Ok(()) => {
                self.journal.mark_widened(path);
                self.commit_mutation(path, MutationKind::Mode);
                Ok(())
            }
            Err(error) => {
                // The chmod may or may not have landed. Record the widen so the
                // single settle still tries to restore the original (and so the
                // path is named); the path stays in `indeterminate`.
                self.journal.mark_widened(path);
                Err(error)
            }
        }
    }

    /// THE removal implementation: remove `rel` (whose live kind is `kind`)
    /// deepest-first, widening every directory it must unlink from and counting
    /// each mutation. Both the extraneous pass and every kind-changing claim
    /// (`drop_claim`, a failed install's `discard_partial`) call THIS, so there
    /// is exactly one removal path: a claimed subtree and an extraneous subtree
    /// are removed by the same code, and a read-only directory nested anywhere
    /// inside either one is widened before its own children are unlinked.
    ///
    /// A reserved (residue) descendant is NEVER removed: it is recorded and the
    /// directory holding it is LEFT IN PLACE (returning [`Removal::ResidueLeft`])
    /// instead of being handed to a RECURSIVE removal, which would
    /// delete the very entry that was skipped. The `sanction` is the PROOF the
    /// caller holds for why this path is the sync's to destroy; a path the
    /// conflict-derived prohibition covers is left in place
    /// ([`Removal::Blocked`]) unless the sanction is the sync's own bookkeeping
    /// ([`Sanction::OwnClaim`] / [`Sanction::OwnPartial`]).
    ///
    /// THE LIVE KIND. There is no `kind` parameter: the kind that selects the
    /// removal primitive — and, crucially, whether the live object is walked at
    /// all — is read from the LIVE destination object HERE, at the single
    /// removal entry point. No caller (a manifest snapshot, a [`Claim`], the
    /// mode journal, or the live `list` that produced a child's kind) can
    /// supply one, so a kind observed at an earlier moment cannot route around
    /// the authority in the `Dir` arm by presenting a stale non-`Dir` kind.
    /// The tree walk lives ONLY here, in this `Dir` arm, where the per-child
    /// authority ([`Applier::live_entry_is_addressed`]) runs; the leaf arms are
    /// single, non-recursive removals with no descendants to authorize.
    ///
    /// THE WALK IS ITERATIVE, over an explicit heap stack, not a recursive
    /// call: one level of destination depth is one `DirFrame`, never one Rust
    /// stack frame. A deep destination tree therefore cannot exhaust the thread
    /// stack (which would call the overflow handler and `SIGABRT` the host
    /// process on libtest's 2 MiB thread stack or an async runtime's). The DFS
    /// order and every per-entry step are IDENTICAL to the recursive form: a
    /// frame is pushed when a directory is entered, its children are visited in
    /// listing order depth-first, and the frame is finished (emptiness re-list,
    /// then the non-recursive `rmdir`) only after every child has been folded
    /// back. The one property the explicit stack must not lose is the point of
    /// that non-recursive leaf removal: the directory's OWN removal must not
    /// delete an unenumerated name. It is preserved because the FINAL removal is
    /// still [`Side::remove_dir`] (rmdir semantics) after an explicit emptiness
    /// re-list — never a recursive removal — so a child a writer adds after the
    /// last enumeration makes the removal fail `ENOTEMPTY` and be NAMED, exactly
    /// as before; the leaf primitives ([`Side::remove_file`], [`Side::remove_dir`])
    /// are untouched by the conversion.
    fn remove_subtree(
        &mut self,
        path: &str,
        rel: &RootedRelativePath,
        sanction: Sanction<'_>,
    ) -> Result<Removal> {
        /// One destination DIRECTORY the walk has entered and whose children are
        /// still being visited. The frame owns the listing snapshot taken at
        /// entry and the outcome of the children folded back so far, so the
        /// walk's state lives on the HEAP (`stack`) rather than on the call
        /// stack. `outcome` is the recursive form's `outcome` local.
        struct DirFrame {
            /// The manifest spelling of the directory.
            path: String,
            /// The descriptor-relative address of the directory.
            rel: RootedRelativePath,
            /// The listing taken when the walk entered the directory.
            children: Vec<(OsString, EntryKind)>,
            /// Index of the next child of `children` to visit.
            next: usize,
            /// The outcome of the children visited so far.
            outcome: Removal,
        }

        // `pending` is the single entry whose own removal is next to attempt;
        // `completed` is the outcome of the entry/subtree just finished, waiting
        // to be folded into the frame it belongs to; `stack` holds the directory
        // frames still being walked. `pending` and `completed` are never both
        // set. The ENTRY phase below is the recursive body verbatim; the only
        // changes are the push instead of the recursive call and the fold of the
        // return value into the top frame.
        let mut stack: Vec<DirFrame> = Vec::new();
        let mut pending: Option<(String, RootedRelativePath)> =
            Some((path.to_string(), rel.clone()));
        let mut completed: Option<Removal> = None;

        loop {
            if let Some((entry_path, entry_rel)) = pending.take() {
                // ---- ENTRY: attempt the removal of one entry. ----
                if !self.may_delete(&entry_path, sanction) {
                    completed = Some(Removal::Blocked);
                } else if let Some(kind) = self.dest.kind_opt(&entry_rel)? {
                    // The LIVE kind, not a snapshot/claim/journal kind.
                    self.guard_destination(
                        &entry_rel,
                        AncestorPolicy::MustExist,
                        if kind == EntryKind::Dir {
                            FinalPolicy::Directory
                        } else {
                            FinalPolicy::Unresolved
                        },
                    )?;
                    match kind {
                        EntryKind::Dir => {
                            // A read-only directory cannot have its children
                            // unlinked; widen it first (journaled, so a failed
                            // removal is restorable).
                            self.widen_dir_verified(
                                &entry_path,
                                &entry_rel,
                                ParentNeed::Writable,
                                true,
                            )?;
                            let children = self.dest.list(&entry_rel)?;
                            stack.push(DirFrame {
                                path: entry_path,
                                rel: entry_rel,
                                children,
                                next: 0,
                                outcome: Removal::Removed,
                            });
                        }
                        EntryKind::File | EntryKind::Symlink => {
                            // A single, NON-RECURSIVE unlink. The live kind was
                            // just read, and `Side::remove_file` is `unlinkat`
                            // (never `AT_REMOVEDIR`), so the leaf has no
                            // descendants the sync walks and needs no per-child
                            // authority.
                            self.begin_mutation(&entry_path, MutationKind::Content);
                            match self.dest.remove_file(&entry_rel) {
                                Ok(()) => {
                                    self.commit_mutation(&entry_path, MutationKind::Content);
                                    completed = Some(Removal::Removed);
                                }
                                Err(error) => return Err(error),
                            }
                        }
                    }
                } else {
                    // An entry that is absent has nothing to remove.
                    completed = Some(Removal::Removed);
                }
                continue;
            }

            if let Some(outcome) = completed.take() {
                // ---- FOLD: hand a finished entry/subtree to its parent. ----
                match stack.last_mut() {
                    // No enclosing frame: this was the entry the call started
                    // with, so the whole removal is done.
                    None => return Ok(outcome),
                    Some(frame) => match outcome {
                        Removal::Removed => {}
                        Removal::Blocked => {
                            if frame.outcome == Removal::Removed {
                                frame.outcome = Removal::Blocked;
                            }
                        }
                        Removal::ResidueLeft => frame.outcome = Removal::ResidueLeft,
                    },
                }
            }

            // ---- ADVANCE: visit the top frame's next child, or finish it. ----
            'advance: loop {
                let last = stack
                    .len()
                    .checked_sub(1)
                    .expect("the walk reaches ADVANCE only with an open frame");
                let next = stack[last].next;
                if next < stack[last].children.len() {
                    // Clone the name out FIRST so no borrow of the frame is held
                    // across the calls below.
                    let name = stack[last].children[next].0.clone();
                    stack[last].next += 1;
                    let child_path = join_manifest_path(&stack[last].path, &name);
                    if is_reserved_name(&name) {
                        self.note_residue(&child_path);
                        stack[last].outcome = Removal::ResidueLeft;
                        continue 'advance;
                    }
                    // An `OwnClaim`/`OwnPartial` sanction rested on the
                    // directory holding exactly what the manifest described (a
                    // claim), or on nothing below it at all (a partial).
                    // Re-establish it against the LIVE listing: under `OwnClaim`
                    // a child no manifest spelling addresses appeared after the
                    // claim was taken, and under `OwnPartial` ANY child is
                    // outside the proof (the sync created only the empty
                    // directory), so leave it and name it as residue instead of
                    // descending into it.
                    if !self.live_entry_is_addressed(&child_path, sanction) {
                        self.note_residue(&child_path);
                        stack[last].outcome = Removal::ResidueLeft;
                        continue 'advance;
                    }
                    let child_rel = stack[last].rel.join(&name)?;
                    pending = Some((child_path, child_rel));
                    break 'advance;
                }

                // Every child of the frame has been visited: FINISH it.
                let frame = stack.pop().expect("the frame was just borrowed");
                if frame.outcome != Removal::Removed {
                    // The directory is non-empty by construction: do NOT rmdir
                    // it (and never a RECURSIVE remove, which would delete the
                    // residue we just skipped).
                    completed = Some(frame.outcome);
                    break 'advance;
                }
                // Re-establish EMPTINESS against the LIVE listing before the
                // leaf removal. The walk above destroyed exactly the children
                // the authority addressed; a child a writer added after the
                // walk is NOT the sync's to destroy, so a non-empty directory is
                // LEFT IN PLACE (and named) rather than handed to a removal that
                // could delete it.
                let live = self.dest.list(&frame.rel)?;
                if !live.is_empty() {
                    for (name, _) in live {
                        self.note_residue(&join_manifest_path(&frame.path, &name));
                    }
                    completed = Some(Removal::ResidueLeft);
                    break 'advance;
                }
                self.begin_mutation(&frame.path, MutationKind::Content);
                // THE FINAL DIRECTORY REMOVAL IS NON-RECURSIVE: `Side::remove_dir`
                // maps to rmdir semantics, which fails with
                // ENOTEMPTY/EEXIST when the directory is not empty. That makes
                // the run's claim — every entry under this directory was
                // enumerated and sanctioned — TRUE AT THE MOMENT OF REMOVAL,
                // not merely at enumeration time: a child a writer creates in
                // the window after this walk's last listing makes the removal
                // fail LOUDLY instead of being destroyed unnamed. This is the
                // only removal primitive the walk removes a directory with; the
                // per-entry authority is re-run for every child in ADVANCE.
                match self.dest.remove_dir(&frame.rel) {
                    Ok(()) => {
                        self.commit_mutation(&frame.path, MutationKind::Content);
                        self.journal.mark_removed(&frame.path);
                        self.removed.insert(frame.path.clone());
                        completed = Some(Removal::Removed);
                    }
                    Err(error) => {
                        // The directory was not empty at removal time (or the
                        // removal failed): NAME every child that is there now —
                        // it was never enumerated, so it was never authorized,
                        // and it must not vanish from the report. A best-effort
                        // re-list; a failed probe simply names nothing extra.
                        if let Ok(live) = self.dest.list(&frame.rel) {
                            for (name, _) in live {
                                self.note_residue(&join_manifest_path(&frame.path, &name));
                            }
                        }
                        return Err(error);
                    }
                }
                break 'advance;
            }
        }
    }

    /// Remove whatever this sync just installed at `rel` while rolling back a
    /// failed kind-changing replacement. The claim moved the ORIGINAL away, so
    /// the entry now at `rel` is this sync's own partial creation and is safe to
    /// discard under [`Sanction::OwnPartial`] (never a deletion of caller data)
    /// — but ONLY that single entry: the sync's own creation is
    /// `create_dir_all`'s EMPTY directory or one file/symlink, so a live child
    /// under a partial DIRECTORY is preserved and named as residue by the ONE
    /// live re-establishment ([`Applier::live_entry_manifest_spelling`]), which
    /// for `OwnPartial` reaches the root entry and nothing below it. This is
    /// what lets the aside be renamed back even when the failed install was
    /// `create_dir_all` creating the directory and then failing: a partial
    /// directory would otherwise block the rollback.
    fn discard_partial(&mut self, rel: &RootedRelativePath, claim: &Claim) -> Result<Removal> {
        match self.dest.kind_opt(rel)? {
            None => Ok(Removal::Removed),
            Some(_live) => {
                let path = manifest_spelling(rel);
                // No kind is passed: `remove_subtree` reads the LIVE kind at its
                // own entry, so the probe above only decides whether there is
                // anything to discard at all.
                let outcome = self.remove_subtree(&path, rel, Sanction::OwnPartial(claim))?;
                if outcome == Removal::Removed {
                    // The original is about to be renamed back to `rel`; it is
                    // no longer "already gone".
                    self.removed.remove(&path);
                }
                Ok(outcome)
            }
        }
    }

    /// Read the source entry and install it as a regular file. Split out so a
    /// source read failure during a kind-changing replacement triggers the
    /// same claim rollback as a write failure.
    ///
    /// The mutating call is the destination WRITE, not the source READ: the
    /// attempt is recorded only once the bytes to install are in hand, so a
    /// source read failure does not wrongly mark the destination indeterminate.
    /// A transport whose write publishes the entry and THEN fails (a chmod,
    /// fsync, or durability check) leaves the path in `indeterminate`, which is
    /// the honest accounting of an entry that may be visible.
    fn install_file(&mut self, path: &str, rel: &RootedRelativePath, mode: Mode) -> Result<()> {
        let bytes = self.source.read(rel)?;
        self.guard_destination(rel, AncestorPolicy::MayCreate, FinalPolicy::NotSymlink)?;
        self.begin_mutation(path, MutationKind::Content);
        match self.dest.write_file(rel, &bytes, mode) {
            Ok(()) => {
                self.commit_mutation(path, MutationKind::Content);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// CLAIM the destination entry at `rel` by renaming it ASIDE to a unique
    /// hidden sibling, returning the aside. The caller installs the new entry
    /// at the real name and then either `drop_claim`s or `rollback_claim`s.
    /// Renaming (not removing) first is what makes a failed kind-changing
    /// replacement leave the destination byte-identical.
    ///
    /// A claim records no kind: the aside's kind is read from the LIVE object
    /// when it is removed, so nothing a claim stores can select a removal
    /// primitive (see [`Claim`]).
    fn claim_aside(&mut self, rel: &RootedRelativePath) -> Result<Claim> {
        // The aside name is hidden and unique per process+counter; skip any
        // name that already exists (belt-and-suspenders against a collision).
        let aside = loop {
            let candidate = rel.with_file_name(aside_name())?;
            if !self.dest.exists(&candidate)? {
                break candidate;
            }
        };
        // The rename's source path is the one that may have moved (its new
        // location is the aside); record the attempt against `rel`.
        let path = manifest_spelling(rel);
        self.guard_destination(rel, AncestorPolicy::MustExist, FinalPolicy::Unresolved)?;
        self.begin_mutation(&path, MutationKind::Content);
        match self.dest.rename(rel, &aside) {
            Ok(()) => self.commit_mutation(&path, MutationKind::Content),
            Err(error) => {
                // A rename that REPORTS an error may still have LANDED: the far
                // side performs the move with a single atomic `rename(2)`
                // (perl, after `mkdir -p parent`), and the connection may drop
                // after the command executed but before its outcome is
                // observed here. Read back where the entry actually is and
                // reconcile the report with the disk BEFORE naming anything.
                let location = self.locate_after_failed_rename(rel, &aside);
                if location == RenamedEntryLocation::Destination {
                    // The subtree may have held residue; keep the reported
                    // paths naming its CURRENT (aside) location.
                    self.re_root_residue(rel, &aside);
                }
                // ONE decision point: `record_stranded_entry` names the aside
                // as residue ONLY when the entry is CONFIRMED to still be there.
                // A move that did not land (Source) and a move whose location
                // could not be confirmed (Unknown) both reach its false branch
                // and record nothing.
                self.record_stranded_entry(
                    &aside,
                    &format!("the claim of {path} reported failure: {error}"),
                );
                if location == RenamedEntryLocation::Unknown {
                    // The location could not be confirmed: assert NOTHING. The
                    // final reconciliation drops every unconfirmable residue
                    // candidate and names BOTH possible spellings of each in
                    // `restore_failures`.
                    self.unconfirmed_moves.push(UnconfirmedMove {
                        from: manifest_spelling(rel),
                        to: manifest_spelling(&aside),
                    });
                }
                return Err(error);
            }
        }
        // The claimed subtree may hold residue; keep the reported paths naming
        // its CURRENT location (the old spelling no longer exists).
        self.re_root_residue(rel, &aside);
        Ok(Claim {
            original: rel.clone(),
            rel: aside,
        })
    }

    /// Where a rename whose call reported an error actually left the entry.
    /// A rename is not necessarily all-or-nothing as OBSERVED: the move may
    /// have landed and the failure only surfaced afterwards, so the report is
    /// reconciled against the live tree instead of assuming the move failed.
    fn locate_after_failed_rename(
        &self,
        from: &RootedRelativePath,
        to: &RootedRelativePath,
    ) -> RenamedEntryLocation {
        match self.dest.kind_opt(to) {
            Ok(Some(_)) => RenamedEntryLocation::Destination,
            Ok(None) => match self.dest.kind_opt(from) {
                Ok(Some(_)) => RenamedEntryLocation::Source,
                // Absent from both spellings (or the probe failed): the
                // location cannot be confirmed, so nothing is named.
                Ok(None) | Err(_) => RenamedEntryLocation::Unknown,
            },
            Err(_) => RenamedEntryLocation::Unknown,
        }
    }

    /// Record `aside` as leftover destination residue and report a failure,
    /// reading its presence back FIRST. This is what makes "every path named in
    /// `residue` still EXISTS" true by construction rather than by inspection:
    /// the location is read back through the fd-confined kind primitive
    /// (locally) or the transport's typed metadata (remotely) before anything
    /// is named, so a rollback whose rename landed cannot leave the report
    /// naming a non-existent aside.
    ///
    /// There are THREE branches, mirroring [`Applier::record_leftover_aside`]:
    ///
    /// * CONFIRMED present — it is residue, and the message may say the original
    ///   is still there;
    /// * CONFIRMED gone — nothing is stranded, so nothing is named;
    /// * the probe itself FAILED — presence cannot be confirmed HERE, so the
    ///   aside is recorded as a residue CANDIDATE and the message DESCRIBES the
    ///   uncertainty without asserting existence or spelling the aside path.
    ///   [`Applier::reconcile_residue`] then confirms the candidate at report
    ///   time (keeping it as `residue`) or downgrades it to the possibility
    ///   channel: `indeterminate` plus a restore failure explicitly marked
    ///   unconfirmed. This is the ONE place an unconfirmable location is
    ///   reported; without it a stranded aside holding the caller's only copy
    ///   would be named NOWHERE.
    fn record_stranded_entry(&mut self, aside: &RootedRelativePath, cause: &str) {
        let aside_path = manifest_spelling(aside);
        match self.dest.kind_opt(aside) {
            // CONFIRMED present: it is residue, and the message may say the
            // original is still there.
            Ok(Some(_)) => {
                self.note_residue(&aside_path);
                self.claim_failures.push(format!(
                    "{cause}; the original is still at {aside_path} and must be recovered by hand"
                ));
            }
            // CONFIRMED gone: no aside holds the original, so nothing is
            // stranded and no path is named.
            Ok(None) => {}
            // The probe itself failed: presence cannot be confirmed HERE, so
            // record the candidate for the report-time reconciliation (which
            // confirms or downgrades it) and DESCRIBE the uncertainty without
            // asserting existence or spelling the aside path.
            Err(probe) => {
                self.note_residue(&aside_path);
                self.claim_failures.push(format!(
                    "{cause}; the original may be stranded at this sync's claimed aside, whose presence could not be confirmed: the read-back probe also failed: {probe}"
                ));
            }
        }
    }

    /// Delete the aside after a SUCCESSFUL install, deepest-first with widening
    /// (the ONE removal implementation). A reserved child of the aside is never
    /// removed: the directory holding it is LEFT IN PLACE and this returns an
    /// error the caller turns into machine-readable residue. Deletion is
    /// sanctioned by the [`Claim`] itself ([`Sanction::OwnClaim`]): the path was
    /// renamed aside by THIS sync, so it is not caller data, and the sync's own
    /// cleanup cannot strand residue under a conflicted writable ancestor. The
    /// claim is NOT a licence to destroy a child that appeared after it was
    /// taken: `remove_subtree` re-establishes the sanction against the LIVE
    /// listing and leaves an unaddressed child as residue.
    fn drop_claim(&mut self, claim: &Claim) -> Result<()> {
        // Whether the claimed subtree took a directory off the real path is
        // decided from the LIVE kind of the aside, never a stored one: a stale
        // kind here would mark (or fail to mark) the real path's descendants as
        // gone incorrectly.
        if self.dest.kind_opt(&claim.rel)? == Some(EntryKind::Dir) {
            // The claimed subtree no longer exists at the real path, so a later
            // extraneous removal must not re-attempt one of its descendants.
            self.removed.insert(manifest_spelling(&claim.original));
        }
        let path = manifest_spelling(&claim.rel);
        // No kind parameter: `remove_subtree` reads the LIVE kind and, for a
        // live directory, walks it under the per-child authority.
        match self.remove_subtree(&path, &claim.rel, Sanction::OwnClaim(claim))? {
            Removal::Removed => Ok(()),
            Removal::ResidueLeft => Err(Error::store(format!(
                "the claimed aside {path} still holds residue and was left in place"
            ))),
            Removal::Blocked => Err(Error::store(format!(
                "the claimed aside {path} is under a path a conflict blocked and was left in place"
            ))),
        }
    }

    /// Record a claim whose deletion failed AFTER the new entry was installed:
    /// the installed entry is correct and (elsewhere) reported `applied`, while
    /// a leftover aside that still holds the original becomes machine-readable
    /// `residue` AND a reported restore failure (so a caller checking neither
    /// can still see it).
    ///
    /// Whether the aside actually still holds the original is READ BACK, never
    /// asserted: the removal may have LANDED and then reported failure (the
    /// shape of a transport whose `rm`/unlink succeeds before the runner
    /// observes an error), in which case the destination is correct and there
    /// is no path to recover. The LISTS assert existence (a `residue` entry is
    /// confirmed present by [`Applier::reconcile_residue`]); the MESSAGES
    /// describe. A message therefore names the aside ONLY when the read-back
    /// CONFIRMS it is present, so
    /// `assert_restore_failures_name_existing_asides` holds for removals too,
    /// not only renames.
    ///
    /// What the message may CLAIM about a present aside depends on its kind. A
    /// present FILE or SYMLINK aside IS the claimed original, so its presence
    /// confirms the original is there. A present DIRECTORY aside is confirmed
    /// only to EXIST: `drop_claim` removes a claimed subtree deepest-first, so a
    /// descendant unlink can LAND and then fail, leaving the directory in place
    /// with part of its content already gone. Asserting such a directory "still
    /// holds the original" would state content the read-back never confirmed.
    fn record_leftover_aside(&mut self, path: &str, claim: &Claim, error: Error) {
        let aside = manifest_spelling(&claim.rel);
        match self.dest.kind_opt(&claim.rel) {
            // CONFIRMED present: it is residue. The message distinguishes an
            // aside whose presence IS the original (a file or symlink) from one
            // whose presence only proves the directory exists.
            Ok(Some(kind)) => {
                self.note_residue(&aside);
                // The wording is chosen from the LIVE kind just read, never a
                // kind stored on the claim.
                let state = match kind {
                    EntryKind::Dir => {
                        "still exists, though it may no longer hold every original entry"
                    }
                    EntryKind::File | EntryKind::Symlink => "still holds the original",
                };
                self.claim_failures.push(format!(
                    "the entry {path} was installed, but its claimed aside {aside} could not be removed and {state}: {error}"
                ));
            }
            // CONFIRMED gone: the removal landed. The destination is correct,
            // there is nothing to recover, and NO message names the absent
            // aside. The failed call stays in `indeterminate` (attempt-first).
            Ok(None) => {
                self.claim_failures.push(format!(
                    "the entry {path} was installed; removing its claimed aside reported failure, but a read-back confirms the aside is GONE, so the destination is correct: {error}"
                ));
            }
            // The probe itself failed: presence cannot be confirmed HERE. Record
            // the candidate so the report-time reconciliation confirms it (and
            // routes an unconfirmable one to the possibility channel), and
            // DESCRIBE the uncertainty without asserting existence or spelling
            // the aside path.
            Err(probe) => {
                self.note_residue(&aside);
                self.claim_failures.push(format!(
                    "the entry {path} was installed; removing its claimed aside reported failure and the aside's presence could not be confirmed: {error}; the read-back probe also failed: {probe}"
                ));
            }
        }
    }

    /// Rename a claimed aside BACK after a FAILED install. Any partial entry
    /// this sync created at `rel` is removed FIRST, so the rename cannot be
    /// blocked by our own leftover (a `create_dir_all` that created the
    /// directory and then failed). Whether the original is still at the aside
    /// is READ BACK, never assumed: a rename that reports failure may have
    /// landed (the far side's single atomic `rename(2)` can execute and the
    /// connection drop before its outcome is observed here), and the report
    /// must name the aside only when the entry is confirmed to be there.
    fn rollback_claim(&mut self, rel: &RootedRelativePath, claim: Claim) {
        let rel_path = manifest_spelling(rel);
        match self.discard_partial(rel, &claim) {
            Ok(Removal::Removed) => {}
            Ok(outcome) => {
                self.record_stranded_entry(
                    &claim.rel,
                    &format!(
                        "the partial replacement at {rel_path} could not be fully discarded ({outcome:?}) before restoring the original"
                    ),
                );
                return;
            }
            Err(error) => {
                self.record_stranded_entry(
                    &claim.rel,
                    &format!(
                        "the partial replacement at {rel_path} could not be discarded before restoring the original: {error}"
                    ),
                );
                return;
            }
        }
        if let Err(error) = self.rename_back(&claim.rel, rel) {
            match self.locate_after_failed_rename(&claim.rel, rel) {
                // The rollback did NOT land: the original really is stranded
                // at the aside (which is confirmed to exist).
                RenamedEntryLocation::Source => self.record_stranded_entry(
                    &claim.rel,
                    &format!(
                        "the replaced entry {rel_path} could not be restored after a failed install: {error}"
                    ),
                ),
                // The rollback LANDED despite reporting its failure: the entry
                // is back at `rel` and the aside no longer exists, so NOTHING
                // is stranded (and asserting "remains stranded at the aside"
                // would name a path that is gone).
                RenamedEntryLocation::Destination => self.re_root_residue(&claim.rel, rel),
                RenamedEntryLocation::Unknown => {
                    // The rollback may or may not have landed: assert NOTHING
                    // about location. The reconciliation names both possible
                    // spellings for every affected residue path.
                    self.unconfirmed_moves.push(UnconfirmedMove {
                        from: manifest_spelling(&claim.rel),
                        to: rel_path.clone(),
                    });
                }
            }
        } else {
            // The original is back at `rel`; re-root any residue it holds.
            self.re_root_residue(&claim.rel, rel);
        }
        // Whether the entry restored at `rel` is a directory is decided from the
        // LIVE kind there, never a kind stored on the claim. A file or symlink
        // is NOT the directory the attempted transfer touched, so there are no
        // directory entries under it to verify and the touch is dropped rather
        // than letting `verify_directory_listings` refuse to list a
        // non-directory.
        let restored_is_dir = matches!(self.dest.kind_opt(rel), Ok(Some(EntryKind::Dir)));
        if !restored_is_dir {
            self.touched_dirs.remove(&rel_path);
        }
    }

    /// Rename the claimed aside back to its original path, recording the
    /// attempt first: a rename that fails may have moved the entry part-way, so
    /// the path is left INDETERMINATE. The caller then READS BACK the entry's
    /// location: the aside is reported as residue and as a restore failure only
    /// when it is CONFIRMED to still hold the entry (see [`Applier::rollback_-
    /// claim`]).
    fn rename_back(&mut self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
        let path = manifest_spelling(to);
        self.guard_destination(from, AncestorPolicy::MustExist, FinalPolicy::Unresolved)?;
        self.guard_destination(to, AncestorPolicy::MustExist, FinalPolicy::Unresolved)?;
        // THE ROLLBACK TARGET MUST BE ABSENT. `discard_partial` just removed
        // this sync's own partial, so the run EXPECTS `to` to be free. A live
        // entry there is a writer's, created in the window since the claim; a
        // plain `renameat` replaces the final directory entry, so without this
        // check the rollback would silently DISPLACE an entry the run did not
        // create. Preserve and NAME it instead (the caller's read-back then
        // names the stranded aside too). This is the same check-then-act shape
        // as `guard_destination`, whose residual component-swap race the module
        // documents as not closed for the far side.
        if let Some(kind) = self.dest.kind_opt(to)? {
            self.note_residue(&path);
            return Err(Error::store(format!(
                "the rollback of {path} found a live {kind:?} entry there that this run did not create; refusing to displace it"
            )));
        }
        self.begin_mutation(&path, MutationKind::Content);
        match self.dest.rename(from, to) {
            Ok(()) => {
                self.commit_mutation(&path, MutationKind::Content);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    /// Record `path` as destination residue: it is deliberately LEFT IN PLACE.
    /// The mode journal records the path as ABANDONED, not removed — it still
    /// exists, so a transient widen of it must still be restored, but it is no
    /// longer a live subject of the transfer, so it is never reported in
    /// `transient_dirs`.
    fn note_residue(&mut self, path: &str) {
        self.dest_residue.insert(path.to_string());
        self.journal.mark_abandoned(path);
    }

    /// Re-root every recorded destination-residue path that is `from` or a
    /// descendant of `from` onto `to`. When a claim-by-rename moves a subtree
    /// that holds residue, the report must keep naming the residue's CURRENT
    /// location (and the old spelling may no longer exist).
    fn re_root_residue(&mut self, from: &RootedRelativePath, to: &RootedRelativePath) {
        let from = manifest_spelling(from);
        let to = manifest_spelling(to);
        let moved: Vec<String> = self
            .dest_residue
            .iter()
            .filter(|path| is_same_or_descendant(path, &from))
            .cloned()
            .collect();
        for path in moved {
            self.dest_residue.remove(&path);
            let relocated = re_root_path(&to, &path, &from);
            self.dest_residue.insert(relocated);
        }
    }

    /// THE final reconciliation that makes
    ///
    /// > every path named in `residue` still EXISTS afterward
    ///
    /// true by CONSTRUCTION for every branch, present and future. Each residue
    /// candidate is confirmed present at REPORT time (after the last mutation
    /// and the last restore). A candidate that is gone — or whose presence
    /// cannot be confirmed because the probe itself fails — is REMOVED from the
    /// residue set and therefore never named as residue. It is routed through a
    /// channel that asserts NOTHING about its location: the candidate is named
    /// in [`SyncReport::indeterminate`] (the highest-precedence list) and a
    /// restore failure names BOTH possible spellings — the candidate itself and,
    /// when an unconfirmed claim/rollback rename moved its subtree, the
    /// re-rooted spelling — explicitly marked as unconfirmed.
    ///
    /// This is also the ONE place the POSSIBILITY channel is surfaced, and the
    /// surfacing is UNCONDITIONAL. Every [`UnconfirmedMove`] is iterated in its
    /// OWN right — never as a side effect of the residue loop below — so a move
    /// of a RESIDUE-FREE subtree is surfaced too. Each such move contributes (a)
    /// both possible spellings to `indeterminate` (a list that asserts no
    /// location) and (b) a restore failure naming both spellings as
    /// possibilities. Surfacing is therefore NEVER conditional on a residue
    /// candidate falling under the move.
    ///
    /// The two rules this enforces:
    ///
    /// > the LISTS assert EXISTENCE and contain only CONFIRMED paths;
    /// > the possibility channel asserts NOTHING and is COMPLETE.
    fn reconcile_residue(&mut self) {
        // (1) THE possibility channel: every rename whose landed-or-not could
        // not be confirmed, in its own right. Cloned first so the loop does not
        // borrow `self.unconfirmed_moves` across the `&mut self` insertions.
        let moves: Vec<(String, String)> = self
            .unconfirmed_moves
            .iter()
            .map(|moved| (moved.from.clone(), moved.to.clone()))
            .collect();
        for (from, to) in &moves {
            // (a) A list that asserts NO location: either spelling is possible.
            self.note_indeterminate(from);
            self.note_indeterminate(to);
            // (b) A restore failure naming BOTH spellings, explicitly marked
            // unconfirmed. "could not be confirmed" is the marker the
            // `assert_aside_only_named_as_possible` test helper checks.
            self.claim_failures.push(format!(
                "the rename of {from} to {to} reported an error and the entry's location could not be confirmed; it may be at {from} or {to} and must be checked by hand"
            ));
        }
        // (2) Confirm every residue candidate present at report time; a
        // candidate that is gone (or whose probe fails) stops being residue and
        // becomes an unconfirmed possibility instead.
        let mut candidates: Vec<String> = self.dest_residue.iter().cloned().collect();
        candidates.sort();
        for path in candidates {
            let confirmed = match rooted(&path) {
                Ok(rel) => matches!(self.dest.exists(&rel), Ok(true)),
                Err(_) => false,
            };
            if confirmed {
                continue;
            }
            self.dest_residue.remove(&path);
            // Every spelling the caller must check: the candidate itself, plus
            // the re-rooted spelling under each move whose location could not be
            // confirmed.
            let mut locations: BTreeSet<String> = BTreeSet::new();
            locations.insert(path.clone());
            for (from, to) in &moves {
                if is_same_or_descendant(&path, from) {
                    locations.insert(re_root_path(to, &path, from));
                }
            }
            self.note_indeterminate(&path);
            self.claim_failures.push(format!(
                "the residue at {path} could not be confirmed present: its location is unknown and it may be at {}, which must be checked by hand",
                locations.into_iter().collect::<Vec<_>>().join(" or ")
            ));
        }
    }

    /// Record `path` in [`SyncReport::indeterminate`] WITHOUT an in-flight
    /// attempt: the residue reconciliation uses it for a location that could not
    /// be confirmed. A list that asserts NO location is exactly what
    /// `indeterminate` means, and the count is permanent (nothing commits it),
    /// so a later probe cannot silently drop it.
    fn note_indeterminate(&mut self, path: &str) {
        self.indeterminate
            .entry(path.to_string())
            .or_default()
            .content += 1;
    }

    /// Whether `path` or an ancestor was already removed this run. Ancestry is
    /// component-wise (`Path`), never a literal-separator split.
    fn is_already_gone(&self, path: &str) -> bool {
        if self.removed.contains(path) {
            return true;
        }
        let mut current = Path::new(path).parent();
        while let Some(parent) = current {
            let Some(parent) = parent.to_str() else {
                break;
            };
            if self.removed.contains(parent) {
                return true;
            }
            current = Path::new(parent).parent();
        }
        false
    }

    fn transfer(&mut self) -> Result<()> {
        // A SOURCE name in the reserved claim-aside namespace collides with this
        // crate's own bookkeeping: report it as a conflict (never transfer it,
        // never silently skip it) so nothing widens around it. The conflict is
        // the prohibition; there is no separate set to update.
        for (path, kind) in self.source_reserved.clone() {
            let policy = self.policy.for_path(&path, kind);
            self.conflict(&path, kind, policy, ConflictReason::ReservedName);
        }
        // A SOURCE pair that differs only by case cannot both exist on a
        // case-insensitive destination. Detect it BEFORE any mutation (using a
        // case-sensitivity probe of the destination) and report the member(s)
        // that cannot be represented, so the sync never silently loses one and
        // never destroys the entry the other aliases.
        self.refuse_unrepresentable_case_aliases()?;
        // Owned copies so the loop does not borrow `self.diff` across the
        // `&mut self` transfer methods.
        let source_entries: Vec<TreeEntry> = self.diff.source.entries.clone();
        let dest_entries: BTreeMap<String, TreeEntry> = self
            .diff
            .dest
            .entries
            .iter()
            .map(|e| (e.path.clone(), e.clone()))
            .collect();
        for entry in &source_entries {
            let path = entry.path.as_str();
            // A path already conflicted (an unrepresentable case alias, or a
            // reserved-name collision) is left exactly as found: a conflict is
            // the prohibition, so it is not transferred.
            if self.conflicts.contains_key(path) {
                continue;
            }
            match self.diff.classify(path) {
                Some(EntryDiff::Same) => {
                    self.outcomes.insert(path.to_string(), Outcome::Skipped);
                    continue;
                }
                Some(EntryDiff::Missing) | Some(EntryDiff::Changed) => {}
                Some(EntryDiff::Extraneous) | None => {
                    return Err(Error::integrity(format!(
                        "source entry {path:?} has no destination classification"
                    )));
                }
            }
            let kind = EntryKind::of(entry)?;
            let policy = self.policy.for_path(path, kind);
            if policy == EntryPolicy::Refuse {
                // The conflict is the prohibition: the entry's OWN mode is left
                // untouched, and it is never widened, created, finalized, or
                // removed (there is no separate set to update).
                self.conflict(path, kind, policy, ConflictReason::Refused);
                continue;
            }
            if policy == EntryPolicy::AppendTail && kind != EntryKind::File {
                // A non-file cannot be appended to. The `AppendNotAFile`
                // conflict forbids DESTRUCTION of the path it names for EVERY
                // non-file kind, so a source DIRECTORY, a source FILE over a
                // destination directory, and a source SYMLINK over a
                // destination directory all protect the destination subtree
                // uniformly (previously only the first two remembered to).
                self.conflict(path, kind, policy, ConflictReason::AppendNotAFile);
                continue;
            }
            // An `AppendTail` file may need NO parent write at all (the source
            // is a prefix of the destination), and a `Replace` over a file
            // with identical content is a MODE-only change — neither writes
            // into the parent, so neither is blocked. A DIRECTORY over an
            // EXISTING destination directory is ALSO a mode-only change: it
            // queues `pending_final` and `finalize` chmods the CHILD, so it
            // needs traverse on the parent, never write. An append that does
            // write is blocked inside `append_write`; every other transfer
            // writes into the parent.
            let defers_to_append = kind == EntryKind::File && policy == EntryPolicy::AppendTail;
            let mode_only_replace = kind == EntryKind::File
                && policy == EntryPolicy::Replace
                && dest_entries.get(path).is_some_and(|dest| {
                    dest.entry_type == EntryKind::File.as_str()
                        && dest.content_sha256.as_deref() == entry.content_sha256.as_deref()
                });
            // The need is derived from what the transfer will ACTUALLY do
            // against the destination kind, so a directory-over-directory mode
            // change is not blocked by a refused directory that only had to be
            // traversable (its own mode is never widened).
            let dest_kind = match dest_entries.get(path) {
                Some(entry) => Some(EntryKind::of(entry)?),
                None => None,
            };
            if !defers_to_append
                && !mode_only_replace
                && self.forbidden_ancestor_blocks_write(path, parent_need(kind, dest_kind))?
            {
                // Nothing was created for the forbidden ancestor, so this entry
                // cannot be installed. Nothing is mutated; the conflict names
                // the child.
                self.conflict(path, kind, policy, ConflictReason::ParentRefused);
                continue;
            }
            let rel = rooted(path)?;
            // STRUCTURAL FOLD GATE: a manifest path is an ADDRESS, and an
            // aliasing destination filesystem can resolve it to a
            // DIFFERENTLY-SPELLED entry (macOS APFS folds `Straße.txt` onto
            // `STRASSE.txt`, `ﬁ.txt` onto `fi.txt`, `ς` onto `σ`, … — a
            // `to_lowercase` model cannot enumerate those rules). Installing the
            // manifest spelling would then mutate the folded target, which may
            // be a `Same`/`Skipped` or destination-only entry the report claims
            // to leave alone. Refuse the install and name the fold; the
            // per-directory listing check below is the backstop.
            if self.refuse_address_folded_onto_another_name(path, kind, &rel)? {
                continue;
            }
            // The run is about to install into (or create) this directory, so
            // its listing is verified against the run's intent by
            // [`Applier::verify_directory_listings`] and
            // [`Applier::verify_claimed_untouched`].
            self.touched_dirs.insert(parent_manifest(path));
            if kind == EntryKind::Dir {
                self.touched_dirs.insert(path.to_string());
            }
            let dest_entry = dest_entries.get(path);
            match kind {
                EntryKind::Dir => self.transfer_dir(entry, &rel, dest_kind)?,
                EntryKind::File => {
                    self.transfer_file(entry, dest_entry, &rel, dest_kind, policy)?
                }
                EntryKind::Symlink => self.transfer_symlink(entry, &rel, dest_kind)?,
            }
        }
        Ok(())
    }

    /// THE live-kind probe a mutation-dispatch site uses IN PLACE OF a
    /// manifest/claim/journal kind. `snapshot_present` is whether the manifest
    /// described an entry at `rel`; when it did not, the run must not probe (the
    /// destination root may not exist yet) and the live kind is `None`. The only
    /// other constructor of the value this returns is [`Side::kind_opt`], so a
    /// kind observed at an earlier moment cannot be passed to it.
    fn live_dest_kind(
        &self,
        rel: &RootedRelativePath,
        snapshot_present: bool,
    ) -> Result<Option<EntryKind>> {
        if snapshot_present {
            self.dest.kind_opt(rel)
        } else {
            Ok(None)
        }
    }

    fn transfer_dir(
        &mut self,
        entry: &TreeEntry,
        rel: &RootedRelativePath,
        dest_kind: Option<EntryKind>,
    ) -> Result<()> {
        let mode = parse_mode(&entry.mode)?;
        // The snapshot `dest_kind` selects the ROUTE (mode-only over an
        // existing directory, or a kind-changing claim+create). It is NOT a
        // destructive dispatch: a CLAIM carries no kind and the removal
        // ([`Applier::remove_subtree`]) reads the LIVE kind at its own entry,
        // so a stale non-`Dir` snapshot can no longer route a live directory
        // into the non-recursive leaf arm and bypass the authority. A snapshot
        // `Dir` whose live object is not a directory follows the mode-only
        // route, where the live guards refuse the chmod/install (never a
        // follow), preserving the NON-RACY
        // `a_preexisting_directory_symlink_is_refused_for_install` contract.
        match dest_kind {
            // Mode-only change over an existing directory: its children are
            // their own entries, and its mode is finalized below.
            Some(EntryKind::Dir) => {}
            Some(_stale) => {
                // A directory create needs owner write + traverse on its
                // parent (the local create path chmods the NEW directory, not
                // its parent).
                self.widen_ancestors(&entry.path, ParentNeed::Writable)?;
                let claim = self.claim_aside(rel)?;
                self.guard_destination(rel, AncestorPolicy::MayCreate, FinalPolicy::NotSymlink)?;
                self.begin_mutation(&entry.path, MutationKind::Content);
                match self.dest.create_dir_all(rel) {
                    Ok(()) => {
                        self.commit_mutation(&entry.path, MutationKind::Content);
                        if let Err(error) = self.drop_claim(&claim) {
                            self.record_leftover_aside(&entry.path, &claim, error);
                        }
                    }
                    Err(error) => {
                        self.rollback_claim(rel, claim);
                        return Err(error);
                    }
                }
                self.journal
                    .note_first_touch(&entry.path, EntryKind::Dir, None);
            }
            None => {
                self.widen_ancestors(&entry.path, ParentNeed::Writable)?;
                self.guard_destination(rel, AncestorPolicy::MayCreate, FinalPolicy::NotSymlink)?;
                self.begin_mutation(&entry.path, MutationKind::Content);
                match self.dest.create_dir_all(rel) {
                    Ok(()) => self.commit_mutation(&entry.path, MutationKind::Content),
                    // The directory may have been CREATED before the failure
                    // (the local create chmods and the transport may sync); do
                    // not roll back our OWN root-relative creation, and leave
                    // the path named in `indeterminate`.
                    Err(error) => return Err(error),
                }
                self.journal
                    .note_first_touch(&entry.path, EntryKind::Dir, None);
            }
        }
        self.pending_final.insert(entry.path.clone(), mode);
        self.outcomes
            .insert(entry.path.clone(), Outcome::Transferred);
        // A created or changed directory is a `Transferred` outcome: its KIND
        // must be re-read like a file's bytes, so a directory a concurrent
        // writer replaced with a regular file (the name stays present) is not
        // reported `applied`.
        self.verify.push(VerifyItem {
            path: entry.path.clone(),
            kind: EntryKind::Dir,
            expected_sha256: String::new(),
        });
        Ok(())
    }

    fn transfer_file(
        &mut self,
        entry: &TreeEntry,
        dest_entry: Option<&TreeEntry>,
        rel: &RootedRelativePath,
        dest_kind: Option<EntryKind>,
        policy: EntryPolicy,
    ) -> Result<()> {
        let expected = require_hash(entry)?.to_string();
        match policy {
            EntryPolicy::Replace => {
                // THE LIVE KIND DECIDES THE ROUTE ([`Applier::live_dest_kind`]).
                // The manifest `dest_kind` is a snapshot read before the run; a
                // concurrent writer can swap the kind under it, and the
                // claim/verify window is long enough for exactly that. When the
                // snapshot says an entry EXISTS, re-read the live kind and shadow
                // the snapshot with it, so (a) the mode-only short-circuit below
                // can only be taken for a LIVE regular FILE — a live directory
                // is never chmodded as if it were the snapshot's file — and (b)
                // a kind-changing replacement always acts on the LIVE kind. A
                // snapshot `None` (Missing) has nothing to gate and must not
                // probe: the destination root may not exist yet.
                let dest_kind = self.live_dest_kind(rel, dest_kind.is_some())?;
                // A mode-only change: the content already matches, so no bytes
                // are transferred — only the mode. A chmod does not write into
                // the parent, so no widen is needed.
                if let (Some(dest), Some(EntryKind::File)) = (dest_entry, dest_kind)
                    && dest.content_sha256.as_deref() == Some(expected.as_str())
                {
                    let mode = parse_mode(&entry.mode)?;
                    let original = self
                        .dest
                        .mode_opt(rel, EntryKind::File)?
                        .unwrap_or(parse_mode(&dest.mode)?);
                    self.journal
                        .note_first_touch(&entry.path, EntryKind::File, Some(original));
                    self.guard_destination(
                        rel,
                        AncestorPolicy::MustExist,
                        FinalPolicy::NotSymlink,
                    )?;
                    self.begin_mutation(&entry.path, MutationKind::Mode);
                    match self.dest.set_mode(rel, mode, EntryKind::File) {
                        Ok(()) => {
                            self.commit_mutation(&entry.path, MutationKind::Mode);
                            // Record the outcome BEFORE the fallible mode READ
                            // (`note_final`): if that read fails, the chmod
                            // already landed and the path must be named, not
                            // dropped from every list.
                            self.outcomes
                                .insert(entry.path.clone(), Outcome::Transferred);
                            self.note_final(&entry.path, mode, EntryKind::File)?;
                            // A mode-only transfer MUTATES the path (the
                            // chmod), so its CONTENT is re-read exactly like a
                            // byte transfer: `applied` must not name a path
                            // whose bytes a concurrent writer changed between
                            // the decision and the verification.
                            self.verify.push(VerifyItem {
                                path: entry.path.clone(),
                                kind: EntryKind::File,
                                expected_sha256: expected,
                            });
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    }
                }
                if dest_kind == Some(EntryKind::Dir) && !self.dir_replace_is_sanctioned(&entry.path)
                {
                    self.conflict(
                        &entry.path,
                        EntryKind::File,
                        policy,
                        ConflictReason::ExtraneousBelow,
                    );
                    return Ok(());
                }
                self.widen_ancestors(&entry.path, ParentNeed::Private)?;
                // Parse the source mode BEFORE the claim window opens: a
                // malformed manifest mode must not strand the claimed aside
                // with no rollback (a fallible call inside the window would
                // otherwise exit without restoring the original).
                let mode = parse_mode(&entry.mode)?;
                // A KIND-CHANGING replacement claims the stale entry by
                // renaming it aside, installs the new entry at the real name,
                // and only then deletes the aside. Removing first would destroy
                // the stale subtree before the install could fail.
                let claim = match dest_kind {
                    Some(EntryKind::Dir | EntryKind::Symlink) => Some(self.claim_aside(rel)?),
                    Some(EntryKind::File) | None => None,
                };
                let original = match dest_kind {
                    Some(EntryKind::File) => self.dest.mode_opt(rel, EntryKind::File)?,
                    _ => None,
                };
                self.journal
                    .note_first_touch(&entry.path, EntryKind::File, original);
                self.make_overwritable(&entry.path, rel)?;
                let install = self.install_file(&entry.path, rel, mode);
                match (install, claim) {
                    (Ok(()), None) => {}
                    // The destination is correct; a leftover aside is recorded
                    // as machine-readable residue and a reported failure (loud),
                    // never swallowed — and the entry is still verified and
                    // reported `applied`, because it WAS installed.
                    (Ok(()), Some(claim)) => {
                        if let Err(error) = self.drop_claim(&claim) {
                            self.record_leftover_aside(&entry.path, &claim, error);
                        }
                    }
                    (Err(error), None) => return Err(error),
                    (Err(error), Some(claim)) => {
                        self.rollback_claim(rel, claim);
                        return Err(error);
                    }
                }
                // The write landed; record the outcome BEFORE the fallible mode
                // READ, so a read failure names the path instead of dropping it.
                self.outcomes
                    .insert(entry.path.clone(), Outcome::Transferred);
                self.note_final(&entry.path, mode, EntryKind::File)?;
                self.verify.push(VerifyItem {
                    path: entry.path.clone(),
                    kind: EntryKind::File,
                    expected_sha256: expected,
                });
            }
            EntryPolicy::AppendTail => {
                self.append_tail(entry, dest_entry, rel, dest_kind, &expected)?;
            }
            EntryPolicy::Refuse => {
                return Err(Error::integrity(format!(
                    "internal: Refuse reached the transfer for {:?}",
                    entry.path
                )));
            }
        }
        Ok(())
    }

    /// Make an existing destination regular file owner-writable before a
    /// REMOTE overwrite. The local durable path publishes by atomic rename, so
    /// the target's own mode is irrelevant there; a remote write needs write
    /// permission on the file itself. The transient widen is recorded and
    /// restored (or superseded by the write's final mode).
    fn make_overwritable(&mut self, path: &str, rel: &RootedRelativePath) -> Result<()> {
        if self.dest.is_confined_local() {
            return Ok(());
        }
        // THE LIVE KIND, never a snapshot: a stale `File` from the manifest would
        // otherwise let this chmod a live directory. The decision uses the
        // live kind and the file's CURRENT mode, never the manifest's values.
        if self.dest.kind_opt(rel)? != Some(EntryKind::File) {
            return Ok(());
        }
        let Some(current) = self.dest.mode_opt(rel, EntryKind::File)? else {
            return Ok(());
        };
        if current & OWNER_WRITE != 0 {
            return Ok(());
        }
        // The decision is the LIVE mode just read (a cached "already widened"
        // bit would be stale after any later mode change and is deliberately
        // not consulted).
        self.journal
            .note_first_touch(path, EntryKind::File, Some(current));
        self.guard_destination(rel, AncestorPolicy::MustExist, FinalPolicy::NotSymlink)?;
        self.begin_mutation(path, MutationKind::Mode);
        match self
            .dest
            .set_mode(rel, current | OWNER_WRITE, EntryKind::File)
        {
            Ok(()) => {
                self.journal.mark_widened(path);
                self.commit_mutation(path, MutationKind::Mode);
                Ok(())
            }
            Err(error) => {
                // The chmod may or may not have landed; keep the widen recorded
                // so settle still restores the original, and leave the path
                // indeterminate.
                self.journal.mark_widened(path);
                Err(error)
            }
        }
    }

    /// The append-only rule. A manifest carries hashes, not bytes, so BOTH
    /// sides' bytes are read to test the prefix relation.
    fn append_tail(
        &mut self,
        entry: &TreeEntry,
        dest_entry: Option<&TreeEntry>,
        rel: &RootedRelativePath,
        dest_kind: Option<EntryKind>,
        expected: &str,
    ) -> Result<()> {
        // THE LIVE KIND DECIDES THE APPEND ROUTE ([`Applier::live_dest_kind`]),
        // never the snapshot: a destination the snapshot called a FILE but that
        // is now a DIRECTORY or SYMLINK takes the non-file arm (a conflict)
        // rather than being read and then chmodded as a file.
        let dest_kind = self.live_dest_kind(rel, dest_kind.is_some())?;
        let dest_bytes = match dest_kind {
            // A MISSING destination is always written — including a zero-length
            // source. Branching on the entry diff (not on comparing bytes) is
            // what makes `src = b""` against an absent destination create the
            // empty file instead of reporting it skipped.
            None => {
                let source_bytes = self.source.read(rel)?;
                return self.append_write(entry, rel, dest_kind, &source_bytes, expected);
            }
            Some(EntryKind::File) => self.dest.read(rel)?,
            Some(_) => {
                // A source FILE over a destination DIRECTORY is `AppendNotAFile`.
                // The conflict itself forbids destruction of the directory (its
                // `forbids_destruction` is exhaustive and uniform), so its
                // destination-only children are `ParentRefused` and survive a
                // [`Extraneous::Delete`] pass instead of being destroyed under a
                // conflict that claimed to leave the path alone.
                self.conflict(
                    &entry.path,
                    EntryKind::File,
                    EntryPolicy::AppendTail,
                    ConflictReason::AppendNotAFile,
                );
                return Ok(());
            }
        };
        let source_bytes = self.source.read(rel)?;
        if dest_bytes == source_bytes {
            // Identical bytes: the append-only rule writes nothing. A differing
            // mode is still applied — the rule constrains BYTES, not modes.
            self.append_settle_mode(entry, dest_entry, rel, &dest_bytes)
        } else if source_bytes.starts_with(&dest_bytes) {
            // The destination is a prefix: write the whole source through the
            // durable replace primitive (same observable result as appending
            // the tail, never a truncation).
            self.append_write(entry, rel, dest_kind, &source_bytes, expected)
        } else if dest_bytes.starts_with(&source_bytes) {
            // The source is a prefix: append-only writes NO BYTES, but a
            // differing mode is still applied.
            self.append_settle_mode(entry, dest_entry, rel, &dest_bytes)
        } else {
            self.conflict(
                &entry.path,
                EntryKind::File,
                EntryPolicy::AppendTail,
                ConflictReason::Diverged,
            );
            Ok(())
        }
    }

    /// Nothing to append (or the destination already holds a prefix-equal
    /// stream): leave the bytes untouched, but apply a differing mode.
    ///
    /// `observed_bytes` are the destination bytes read for the append rule, so
    /// the mode-only `Transferred` outcome can be CONTENT-verified against the
    /// bytes this run actually saw: the path is mutated (chmod), and `applied`
    /// must not name it if a concurrent writer changed those bytes in the
    /// window before verification.
    fn append_settle_mode(
        &mut self,
        entry: &TreeEntry,
        dest_entry: Option<&TreeEntry>,
        rel: &RootedRelativePath,
        observed_bytes: &[u8],
    ) -> Result<()> {
        let mode = parse_mode(&entry.mode)?;
        let Some(dest) = dest_entry else {
            self.outcomes.insert(entry.path.clone(), Outcome::Skipped);
            return Ok(());
        };
        // Re-establish the LIVE kind after the byte read: the append rule
        // constrains a LIVE regular FILE, and applying a file mode to a live
        // directory is the stale-kind class. A non-file live kind is refused and
        // named, never chmodded.
        if self.dest.kind_opt(rel)? != Some(EntryKind::File) {
            self.conflict(
                &entry.path,
                EntryKind::File,
                EntryPolicy::AppendTail,
                ConflictReason::AppendNotAFile,
            );
            return Ok(());
        }
        // The decision uses the file's CURRENT mode, not the (possibly stale)
        // manifest value.
        let current = self
            .dest
            .mode_opt(rel, EntryKind::File)?
            .unwrap_or(parse_mode(&dest.mode)?);
        if current == mode {
            self.outcomes.insert(entry.path.clone(), Outcome::Skipped);
            return Ok(());
        }
        self.journal
            .note_first_touch(&entry.path, EntryKind::File, Some(current));
        self.guard_destination(rel, AncestorPolicy::MustExist, FinalPolicy::NotSymlink)?;
        self.begin_mutation(&entry.path, MutationKind::Mode);
        match self.dest.set_mode(rel, mode, EntryKind::File) {
            Ok(()) => {
                self.commit_mutation(&entry.path, MutationKind::Mode);
                self.outcomes
                    .insert(entry.path.clone(), Outcome::Transferred);
                self.note_final(&entry.path, mode, EntryKind::File)?;
                // The mode was applied; re-read the CONTENT the append rule
                // left alone and require it to equal the bytes observed before
                // the chmod, so a writer that changed them is never reported as
                // `applied`.
                self.verify.push(VerifyItem {
                    path: entry.path.clone(),
                    kind: EntryKind::File,
                    expected_sha256: crate::digest::sha256_bytes(observed_bytes),
                });
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn append_write(
        &mut self,
        entry: &TreeEntry,
        rel: &RootedRelativePath,
        dest_kind: Option<EntryKind>,
        source_bytes: &[u8],
        expected: &str,
    ) -> Result<()> {
        // This append DOES write into the parent, so the block applies here
        // (it is deferred out of `transfer` because a no-write append of the
        // same path must not be blocked).
        if self.forbidden_ancestor_blocks_write(&entry.path, ParentNeed::Private)? {
            self.conflict(
                &entry.path,
                EntryKind::File,
                EntryPolicy::AppendTail,
                ConflictReason::ParentRefused,
            );
            return Ok(());
        }
        let mode = parse_mode(&entry.mode)?;
        self.widen_ancestors(&entry.path, ParentNeed::Private)?;
        let original = match dest_kind {
            Some(EntryKind::File) => self.dest.mode_opt(rel, EntryKind::File)?,
            _ => None,
        };
        self.journal
            .note_first_touch(&entry.path, EntryKind::File, original);
        self.make_overwritable(&entry.path, rel)?;
        self.guard_destination(rel, AncestorPolicy::MayCreate, FinalPolicy::NotSymlink)?;
        self.begin_mutation(&entry.path, MutationKind::Content);
        match self.dest.write_file(rel, source_bytes, mode) {
            Ok(()) => {
                self.commit_mutation(&entry.path, MutationKind::Content);
                // Record the outcome BEFORE the fallible mode READ, so a read
                // failure names the path.
                self.outcomes
                    .insert(entry.path.clone(), Outcome::Transferred);
                self.note_final(&entry.path, mode, EntryKind::File)?;
                self.verify.push(VerifyItem {
                    path: entry.path.clone(),
                    kind: EntryKind::File,
                    expected_sha256: expected.to_string(),
                });
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn transfer_symlink(
        &mut self,
        entry: &TreeEntry,
        rel: &RootedRelativePath,
        dest_kind: Option<EntryKind>,
    ) -> Result<()> {
        let target = entry.symlink_target.as_deref().ok_or_else(|| {
            Error::integrity(format!(
                "manifest symlink entry {} has no target",
                entry.path
            ))
        })?;
        let expected = require_hash(entry)?.to_string();
        // The snapshot `dest_kind` selects the route here too; the claim and the
        // removal read the LIVE kind, so this is a gate/route decision, never a
        // destructive dispatch.
        if dest_kind == Some(EntryKind::Dir) && !self.dir_replace_is_sanctioned(&entry.path) {
            self.conflict(
                &entry.path,
                EntryKind::Symlink,
                EntryPolicy::Replace,
                ConflictReason::ExtraneousBelow,
            );
            return Ok(());
        }
        self.widen_ancestors(&entry.path, ParentNeed::Private)?;
        // A stale file, symlink, or directory is CLAIMED by renaming it aside
        // (a symlink at the destination is moved, never followed); the link is
        // created at the real name; only then is the aside deleted. If the
        // create fails the aside is renamed back.
        let claim = match dest_kind {
            Some(_) => Some(self.claim_aside(rel)?),
            None => None,
        };
        self.guard_destination(rel, AncestorPolicy::MayCreate, FinalPolicy::NotSymlink)?;
        self.begin_mutation(&entry.path, MutationKind::Content);
        // `Path::new` over the manifest's target string is a BYTE-FAITHFUL
        // constructor: it splits on the platform separator but never resolves
        // `.`/`..`, never normalizes, and never consults the filesystem, so
        // `symlink(2)` stores exactly the source's target. No guard belongs
        // here: the manifest is the ONE validator of what a target may be
        // (absolute, escaping, and — per the manifest's round-trip contract —
        // any byte sequence the wire cannot carry are refused there), and a
        // second, disagreeing rule here would let a `TreeEntry` from a
        // divergent producer through one of the two.
        let install = self.dest.symlink(Path::new(target), rel);
        match (install, claim) {
            (Ok(()), None) => {
                self.commit_mutation(&entry.path, MutationKind::Content);
            }
            (Ok(()), Some(claim)) => {
                self.commit_mutation(&entry.path, MutationKind::Content);
                if let Err(error) = self.drop_claim(&claim) {
                    self.record_leftover_aside(&entry.path, &claim, error);
                }
            }
            (Err(error), None) => return Err(error),
            (Err(error), Some(claim)) => {
                self.rollback_claim(rel, claim);
                return Err(error);
            }
        }
        // Restart the journal identity: a symlink replacing a directory must
        // not inherit the removed directory's record (which would drop the
        // entry from every report list). A symlink has no mode step, so
        // `final_applied` treats it as settled; its identity is the target,
        // which verification checks.
        self.journal
            .note_first_touch(&entry.path, EntryKind::Symlink, None);
        self.verify.push(VerifyItem {
            path: entry.path.clone(),
            kind: EntryKind::Symlink,
            expected_sha256: expected,
        });
        self.outcomes
            .insert(entry.path.clone(), Outcome::Transferred);
        Ok(())
    }

    /// Apply the intended final mode of every directory this sync created or
    /// changed, deepest-first so a read-only parent is finalized only after its
    /// children. A mode already in place is not chmodded again (no redundant
    /// chmod, no transfer counted).
    fn finalize(&mut self) -> Result<()> {
        let mut dirs: Vec<(String, Mode)> = std::mem::take(&mut self.pending_final)
            .into_iter()
            .collect();
        dirs.sort_by(|a, b| {
            let da = Path::new(&a.0).components().count();
            let db = Path::new(&b.0).components().count();
            db.cmp(&da).then_with(|| a.0.cmp(&b.0))
        });
        for (path, mode) in dirs {
            let rel = rooted(&path)?;
            let current = self.dest.mode(&rel, EntryKind::Dir)?;
            // First touch only: a directory already widened keeps its original
            // (pre-widen) value.
            self.journal
                .note_first_touch(&path, EntryKind::Dir, Some(current));
            if current == mode {
                // The intended mode is already in place.
                self.journal.mark_final_mode(&path, mode, Some(current));
                continue;
            }
            self.guard_destination(&rel, AncestorPolicy::MustExist, FinalPolicy::Directory)?;
            self.begin_mutation(&path, MutationKind::Mode);
            match self.dest.set_mode(&rel, mode, EntryKind::Dir) {
                Ok(()) => {
                    self.commit_mutation(&path, MutationKind::Mode);
                    self.note_final(&path, mode, EntryKind::Dir)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Restore every mode this sync widened and did not supersede, deepest
    /// first. Idempotent (a path already at its target is left alone),
    /// best-effort (a failure is collected, never masking the original error),
    /// and it COUNTS each chmod it performs and re-reads the result.
    ///
    /// THE LIVE KIND, not the journal's recorded kind, selects the primitive.
    /// The journal records the kind of the identity the sync touched; a
    /// concurrent writer can replace that identity (a file swapped for a
    /// directory). The journal's kind is used ONLY to detect the change: a LIVE
    /// kind the journal never recorded is REFUSED and NAMED, never silently
    /// chmodded with a mode meant for a different kind. `mode_opt`/`set_mode`
    /// then receive the LIVE kind, so even without the refusal the wrong mode
    /// could not be applied.
    fn restore(&mut self) -> Vec<String> {
        let plan = self.journal.restore_plan();
        let mut failures = Vec::new();
        for (path, recorded_kind, target) in plan {
            let rel = match rooted(&path) {
                Ok(rel) => rel,
                Err(error) => {
                    failures.push(format!("restore mode {target:04o} of {path}: {error}"));
                    continue;
                }
            };
            let live = match self.dest.kind_opt(&rel) {
                Ok(Some(live)) => live,
                // The path was removed (by this sync or as part of a removed
                // ancestor): there is no mode left to restore.
                Ok(None) => continue,
                Err(error) => {
                    failures.push(format!("restore mode {target:04o} of {path}: {error}"));
                    continue;
                }
            };
            if live != recorded_kind {
                failures.push(format!(
                    "restore mode {target:04o} of {path}: this sync recorded a {recorded_kind:?} but the live entry is a {live:?}; refusing to apply a mode to an entry it never recorded"
                ));
                continue;
            }
            let current = match self.dest.mode_opt(&rel, live) {
                Ok(Some(mode)) => mode,
                Ok(None) => continue,
                Err(error) => {
                    failures.push(format!("restore mode {target:04o} of {path}: {error}"));
                    continue;
                }
            };
            if current == target {
                // The live mode already matches the target, so the path's mode
                // is KNOWN; clear a pending MODE attempt (never a CONTENT one —
                // a failed write/removal is not resolved by a mode restore).
                self.commit_mutation(&path, MutationKind::Mode);
                continue;
            }
            if let Err(error) = self.guard_destination(
                &rel,
                AncestorPolicy::MustExist,
                if live == EntryKind::Dir {
                    FinalPolicy::Directory
                } else {
                    FinalPolicy::NotSymlink
                },
            ) {
                failures.push(format!("restore mode {target:04o} of {path}: {error}"));
                continue;
            }
            self.begin_mutation(&path, MutationKind::Mode);
            if let Err(error) = self.dest.set_mode(&rel, target, live) {
                failures.push(format!("restore mode {target:04o} of {path}: {error}"));
                continue;
            }
            self.commit_mutation(&path, MutationKind::Mode);
            // A dropped restore is never a silent success.
            match self.dest.mode_opt(&rel, live) {
                Ok(Some(mode)) if mode == target => {}
                Ok(Some(mode)) => failures.push(format!(
                    "restore mode {target:04o} of {path}: destination has {mode:04o}"
                )),
                Ok(None) => failures.push(format!(
                    "restore mode {target:04o} of {path}: the path disappeared"
                )),
                Err(error) => failures.push(format!("verify restored mode of {path}: {error}")),
            }
        }
        failures
    }

    /// Re-read every written entry (file hash, symlink target) and check the
    /// MODE of every path the journal touched: a mode-only file change, a
    /// directory's final mode, and — when `include_restored` is set — the mode
    /// a restore wrote back.
    fn verify(&mut self, include_restored: bool) -> Result<()> {
        // THE freshness point for the listing cache: this pass verifies the
        // destination as it stands NOW. Everything the transfers installed and
        // (on the post-removal pass) everything `remove_extraneous` removed
        // must be visible to the checks below, so no cached listing may outlive
        // the mutations it predates. No destination mutation runs inside this
        // pass, so from here on one read per directory is exact.
        self.clear_listings();
        // A path is committed to `verified` only after EVERY check this pass
        // makes for it has passed: the loops collect failures instead of
        // returning immediately, and a path that failed any check is removed
        // before the merge. This makes `verified` mean content AND mode
        // verified, so a path whose content matched but whose mode check then
        // failed is never admitted to `applied` (the report is derived after
        // this returns, even on the error path), while a fully-passed peer is
        // still credited.
        let mut verified_now: BTreeSet<String> = BTreeSet::new();
        let mut failed: BTreeSet<String> = BTreeSet::new();
        let mut first_error: Option<Error> = None;
        let items: Vec<(String, EntryKind, String)> = self
            .verify
            .iter()
            .map(|item| (item.path.clone(), item.kind, item.expected_sha256.clone()))
            .collect();
        for (path, kind, expected) in items {
            let result = (|| -> Result<()> {
                let rel = rooted(&path)?;
                // The KIND is verified FIRST: the content and mode checks below
                // resolve through the address, so a path whose NAME is present
                // while the entry at it changed KIND (a directory replaced by a
                // regular file, say) would otherwise pass — `applied` would
                // name a kind the destination does not hold.
                match self.dest.kind_opt(&rel)? {
                    Some(actual) if actual == kind => {}
                    Some(actual) => {
                        return Err(Error::integrity(format!(
                            "post-transfer verification failed for {path}: the destination holds a {} where a {} was expected",
                            actual.as_str(),
                            kind.as_str()
                        )));
                    }
                    None => {
                        return Err(Error::integrity(format!(
                            "post-transfer verification failed for {path}: the path is absent (a {} was expected)",
                            kind.as_str()
                        )));
                    }
                }
                let actual = match kind {
                    EntryKind::File => crate::digest::sha256_bytes(&self.dest.read(&rel)?),
                    EntryKind::Symlink => {
                        let target = self.dest.read_link(&rel)?;
                        crate::digest::sha256_bytes(target.as_os_str().as_encoded_bytes())
                    }
                    EntryKind::Dir => return Ok(()),
                };
                if actual != expected {
                    return Err(Error::integrity(format!(
                        "post-transfer verification failed for {path}: expected {expected}, destination hashes {actual}"
                    )));
                }
                Ok(())
            })();
            match result {
                Ok(()) => {
                    verified_now.insert(path);
                }
                Err(error) => {
                    failed.insert(path);
                    first_error = first_error.or(Some(error));
                }
            }
        }
        for (path, kind, target) in self.journal.mode_targets(include_restored) {
            let result = (|| -> Result<()> {
                let rel = rooted(&path)?;
                match self.dest.mode_opt(&rel, kind)? {
                    Some(mode) if mode == target => Ok(()),
                    Some(mode) => Err(Error::integrity(format!(
                        "post-transfer verification failed for {path}: expected mode {target:04o}, destination has {mode:04o}"
                    ))),
                    None => Err(Error::integrity(format!(
                        "post-transfer verification failed for {path}: the path is absent (expected mode {target:04o})"
                    ))),
                }
            })();
            match result {
                Ok(()) => {
                    verified_now.insert(path);
                }
                Err(error) => {
                    failed.insert(path);
                    first_error = first_error.or(Some(error));
                }
            }
        }
        // The NAME check is the third leg of the SAME pass: a manifest entry is
        // an ADDRESS, so its spelling must BE the on-disk name. It runs after
        // the content and mode checks so that one pass derives the whole report.
        self.verify_names(&mut failed, &mut first_error);
        // The STRUCTURAL per-directory backstop and the coverage of entries the
        // report claims to have left alone. Both run in the SAME pass as the
        // content/mode checks (and therefore BEFORE `remove_extraneous`), so a
        // path either finds unfaithful can still be excluded from every
        // removal. Any of the three name passes can raise the pass's first
        // error: an unplanned on-disk name no manifest spelling addresses, or a
        // directory that cannot be enumerated faithfully (against which no
        // verification is possible).
        self.verify_directory_listings(&mut failed, &mut first_error);
        self.verify_claimed_untouched(&mut failed, &mut first_error);
        for path in &failed {
            verified_now.remove(path);
        }
        // A path whose verification failed is mutated but NOT applied; name it
        // machine-readably in the report, not only in the error string.
        self.verify_failures.extend(failed.iter().cloned());
        // ... and remove it from the CUMULATIVE `verified` set. The set must mean
        // "passed the LATEST verification pass", or a path that passed the
        // pre-settle pass and then FAILED the post-settle one (a dropped restore)
        // would still satisfy `derive_report`'s `applied` gate, and the
        // `applied > verify_failures` precedence would delete the genuine
        // failure. `applied` must require the FINAL post-settle verification.
        self.verified.retain(|path| !failed.contains(path));
        self.verified.extend(verified_now);
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Remove every destination-only entry (only when the caller asked and only
    /// after transfers and verification succeeded), deepest-first so a parent
    /// is removed only after its children. Each removal widens its read-only
    /// parent through the ONE choke point; the widenings are reverted by the
    /// single settle.
    fn remove_extraneous(&mut self) -> Result<()> {
        if self.extraneous_policy == Extraneous::Keep {
            return Ok(());
        }
        /// One parent directory's listing for the WHOLE removal pass. `names`
        /// keeps the raw `(name, kind)` pairs so an on-disk alias that is not
        /// byte-identical to the manifest spelling can still be NAMED; `index`
        /// is the name -> kind lookup the per-entry faithful test uses. Built
        /// ONCE per parent, so k extraneous entries in one directory cost ONE
        /// listing and k log-k lookups, not k listing clones and O(k^2) scans.
        struct PassListing {
            names: DirListing,
            index: BTreeMap<Vec<u8>, EntryKind>,
        }
        let mut entries: Vec<(String, EntryKind)> = Vec::new();
        for entry in &self.diff.dest.entries {
            if self.diff.classify(&entry.path) == Some(EntryDiff::Extraneous) {
                entries.push((entry.path.clone(), EntryKind::of(entry)?));
            }
        }
        entries.sort_by(|a, b| {
            let da = Path::new(&a.0).components().count();
            let db = Path::new(&b.0).components().count();
            db.cmp(&da).then_with(|| a.0.cmp(&b.0))
        });
        // ONE parent listing for the whole pass. This is SOUND given the pass's
        // own removals because the per-entry question below is exactly "is THIS
        // entry's own manifest name, with THIS entry's kind, present in its
        // parent" — a SIBLING removal changes neither this entry's name nor its
        // kind, and the pass never removes an ANCESTOR of a path it has not
        // already folded past: entries are sorted DEEPEST-FIRST, so a child is
        // processed before its parent, and a path whose ancestor a TRANSFER
        // already took is caught by [`Applier::is_already_gone`] first. The
        // snapshot is also the SAME one the pre-fix code consumed: `self.listing`
        // caches per directory until the next `verify` pass clears it, and no
        // verify pass runs inside this loop, so hoisting the fetch removes the
        // per-entry clone/scan WITHOUT changing which listing is observed.
        let mut pass_listings: BTreeMap<String, PassListing> = BTreeMap::new();
        // A destination-only subtree that CONTAINS residue must not be removed:
        // destroying it would destroy the stranded original the residue holds.
        // Refuse the topmost such directory (and everything under it) and report
        // it as `ResidueBelow` — nothing inside is touched.
        let residue_guards = self.residue_guards(&entries);
        for (path, kind) in entries {
            if self.is_already_gone(&path) {
                // A transfer already took this path with an ancestor directory.
                continue;
            }
            // The parent's listing changes if this removal lands, so it is
            // verified against the run's intent in the settle pass.
            self.touched_dirs.insert(parent_manifest(&path));
            if is_guarded(&path, &residue_guards) {
                let policy = self.policy.for_path(&path, kind);
                self.conflict(&path, kind, policy, ConflictReason::ResidueBelow);
                continue;
            }
            // A path whose own entry (or an ancestor) a conflict left alone is
            // off-limits to DELETION, mode-INDEPENDENTLY: a writable conflicted
            // directory must not have its children deleted either. The
            // prohibition is DERIVED from the conflict record, and the deletion
            // itself carries [`Sanction::ExtraneousFlag`] as proof. The check
            // runs BEFORE any widen, so no mode under a prohibited subtree is
            // touched. (The transfer path keeps the narrower
            // [`Applier::forbidden_ancestor_blocks_write`] rule.)
            if self.is_prohibited(&path) {
                let policy = self.policy.for_path(&path, kind);
                self.conflict(&path, kind, policy, ConflictReason::ParentRefused);
                continue;
            }
            // IDENTITY-AWARE REMOVAL. The caller's [`Extraneous::Delete`] sanctions
            // destroying THIS destination-only path, not a spelling that aliases
            // another file. An on-disk spelling an installed (or skipped) source
            // entry aliases is off-limits: removing it would destroy the entry
            // just transferred through the fold (case B).
            if self.is_aliased_dest(&path) {
                let on_disk = self.aliased_dest_root(&path);
                self.name_conflict(&path, kind, on_disk);
                continue;
            }
            // The entry must EXIST under the manifest spelling in its parent's
            // listing (read byte-identically), not merely resolve through the
            // address: a filesystem that folded an install onto a different
            // spelling leaves the manifest spelling naming an entry that is not
            // there, so the sanction for THIS path covers nothing again.
            //
            // A parent the run cannot enumerate faithfully is a HARD ERROR
            // before any widen or remove: no entry in a directory it could not
            // read may be destroyed, and the sanction for THIS path cannot be
            // confirmed at all.
            let expected = file_name_bytes(&path);
            let parent = parent_manifest(&path);
            if !pass_listings.contains_key(&parent) {
                let names = match self.listing(&parent) {
                    Ok(names) => names,
                    Err(error) => {
                        return Err(unenumerable_directory_error(&parent, error.as_ref()));
                    }
                };
                let index = names.iter().cloned().collect();
                pass_listings.insert(parent.clone(), PassListing { names, index });
            }
            let listing = &pass_listings[&parent];
            let faithful = match &expected {
                Some(expected) => listing.index.get(expected) == Some(&kind),
                None => false,
            };
            if !faithful {
                let on_disk = expected
                    .as_deref()
                    .and_then(|expected| alias_in(&listing.names, expected));
                self.name_conflict(&path, kind, on_disk);
                continue;
            }
            self.widen_ancestors(&path, ParentNeed::Writable)?;
            let rel = rooted(&path)?;
            match self.remove_subtree(&path, &rel, Sanction::ExtraneousFlag)? {
                Removal::Removed => {}
                Removal::Blocked => {
                    let policy = self.policy.for_path(&path, kind);
                    self.conflict(&path, kind, policy, ConflictReason::ParentRefused);
                }
                Removal::ResidueLeft => {
                    let policy = self.policy.for_path(&path, kind);
                    self.conflict(&path, kind, policy, ConflictReason::ResidueBelow);
                }
            }
        }
        Ok(())
    }

    /// POST-INSTALL NAME VERIFICATION, the third leg of the one verification
    /// pass (content hash, symlink target, mode — and the on-disk name).
    ///
    /// A manifest path is used as an ADDRESS, but on an aliasing destination
    /// filesystem installing the manifest spelling can land on a pre-existing,
    /// differently-spelled entry: the address then names something other than
    /// what the sync thinks. The check therefore reads each installed entry's
    /// PARENT DIRECTORY and compares the entry's final component
    /// BYTE-IDENTICALLY against the listing — never by resolving the manifest
    /// spelling, which the filesystem folds.
    ///
    /// A mismatch is a [`ConflictReason::NameNotFaithful`] conflict naming the
    /// on-disk spelling; the path is marked failed (so it is never `applied`),
    /// and the on-disk spelling is recorded in [`Applier::aliased_dest`] so it
    /// and its subtree can never be removed. A parent that cannot be listed is
    /// a RUN-LEVEL ERROR ([`unenumerable_directory_error`]): a directory the run
    /// cannot enumerate faithfully is one against which it cannot verify its
    /// result at all, so the path is named in `verify_failures` and the pass
    /// fails closed instead of fabricating a per-path conflict. An entry under
    /// an ancestor whose own name
    /// is not faithful is conflicted too, because its true location is under the
    /// ancestor's folded spelling.
    ///
    /// EVERY ancestor COMPONENT is verified, top-down, against ITS OWN parent's
    /// live listing (byte-identically), not only the final component: a fold in
    /// a parent component makes the parent listing below it resolve through the
    /// fold, so the final-component check alone would pass while the installed
    /// path names a spelling the destination does not hold. The ancestor check
    /// also runs for a parent that is NOT a source manifest entry, which is what
    /// makes an installed path under a folded ancestor a conflict instead of a
    /// false `applied` even if a crafted manifest reaches this point.
    fn verify_names(&mut self, failed: &mut BTreeSet<String>, first_error: &mut Option<Error>) {
        // SCOPE: every source entry whose outcome is `Transferred`, AND every
        // source entry the report would call `Skipped` whose parent directory
        // this run TOUCHED. The second class is what covers a destination entry
        // the run claims to have left alone: a fold from another install can
        // rename or displace it, and the run must not report the result as
        // no-mutation.
        let entries: Vec<(String, EntryKind)> = self
            .diff
            .source
            .entries
            .iter()
            .filter(|entry| match self.outcomes.get(&entry.path) {
                Some(Outcome::Transferred) => true,
                Some(Outcome::Skipped) => self.touched_dirs.contains(&parent_manifest(&entry.path)),
                None => false,
            })
            .filter_map(|entry| {
                EntryKind::of(entry)
                    .ok()
                    .map(|kind| (entry.path.clone(), kind))
            })
            .collect();
        // One listing per parent directory, no matter how many children it
        // holds: the check is derived from ONE pass over the destinations, and
        // the SHARED cache ([`Applier::listing`]) is what makes that one read.
        for (path, kind) in entries {
            if self
                .conflicts
                .get(&path)
                .is_some_and(|conflict| conflict.reason == ConflictReason::NameNotFaithful)
            {
                failed.insert(path);
                continue;
            }
            if let Some(ancestor) = ancestor_paths(&path).into_iter().find(|ancestor| {
                self.conflicts
                    .get(ancestor)
                    .is_some_and(|conflict| conflict.reason == ConflictReason::NameNotFaithful)
            }) {
                let on_disk = self
                    .conflicts
                    .get(&ancestor)
                    .and_then(|conflict| conflict.on_disk.clone());
                self.name_conflict(&path, kind, on_disk);
                failed.insert(path);
                continue;
            }
            // Verify EVERY ancestor COMPONENT of the manifest path against ITS
            // OWN parent's live listing, BYTE-IDENTICALLY, exactly as the final
            // component is verified below. A fold in a parent component makes
            // every manifestation below it an address to a differently-spelled
            // entry, and the final-component check alone cannot see it: the
            // parent listing is obtained THROUGH the folded parent, so it names
            // the entry the fold resolves to. Checking each component top-down
            // is what keeps an installed path from being reported `applied` for
            // a spelling the destination does not hold (and keeps one on-disk
            // entry from being reported under two spellings).
            let mut ancestor_failed = false;
            for ancestor in ancestor_paths(&path) {
                let ancestor_conflict = self
                    .conflicts
                    .get(&ancestor)
                    .filter(|conflict| conflict.reason == ConflictReason::NameNotFaithful)
                    .and_then(|conflict| conflict.on_disk.clone());
                if let Some(on_disk) = ancestor_conflict {
                    self.name_conflict(&path, kind, Some(on_disk));
                    failed.insert(path.clone());
                    ancestor_failed = true;
                    break;
                }
                let Some(ancestor_name) = file_name_bytes(&ancestor) else {
                    continue;
                };
                let ancestor_parent = parent_manifest(&ancestor);
                let listing = self.listing(&ancestor_parent);
                match listing {
                    Ok(names) if names.iter().any(|(name, _)| name == &ancestor_name) => {}
                    Ok(names) => {
                        let on_disk = alias_in(&names, &ancestor_name);
                        self.name_conflict(&ancestor, EntryKind::Dir, on_disk.clone());
                        match on_disk {
                            Some(on_disk) => {
                                let dest_path =
                                    join_manifest_path(&ancestor_parent, OsStr::new(&on_disk));
                                self.aliased_dest
                                    .entry(dest_path)
                                    .or_insert_with(|| path.clone());
                            }
                            None => self.protect_extraneous_siblings(
                                &ancestor_parent,
                                &path,
                                &ancestor_name,
                            ),
                        }
                        failed.insert(path.clone());
                        ancestor_failed = true;
                        break;
                    }
                    Err(error) => {
                        note_listing_failure(first_error, &ancestor_parent, error.as_ref());
                        failed.insert(path.clone());
                        ancestor_failed = true;
                        break;
                    }
                }
            }
            if ancestor_failed {
                continue;
            }
            let Some(expected) = file_name_bytes(&path) else {
                continue;
            };
            let parent = parent_manifest(&path);
            let listing = self.listing(&parent);
            match listing {
                Ok(names) if names.iter().any(|(name, _)| name == &expected) => {}
                Ok(names) => {
                    let on_disk = alias_in(&names, &expected);
                    self.name_conflict(&path, kind, on_disk.clone());
                    match on_disk {
                        // The destination's actual spelling is named: protect it
                        // (and its subtree) from removal by construction.
                        Some(on_disk) => {
                            let dest_path = join_manifest_path(&parent, OsStr::new(&on_disk));
                            self.aliased_dest.insert(dest_path, path.clone());
                        }
                        // A folding this crate's `to_lowercase` does not model
                        // (so the on-disk name cannot be NAMED): fall back to
                        // protecting every destination-only entry in the same
                        // directory, so the folded target can never be removed
                        // even though it cannot be named.
                        None => self.protect_extraneous_siblings(&parent, &path, &expected),
                    }
                    failed.insert(path);
                }
                Err(error) => {
                    // The directory could not be read, so identity could not be
                    // confirmed at all: a run-level error carrying the cause,
                    // never a per-path `NameNotFaithful` conflict. The path is
                    // still named so the report accounts for it.
                    note_listing_failure(first_error, &parent, error.as_ref());
                    failed.insert(path);
                }
            }
        }
    }

    /// THE structural per-directory backstop: for every destination directory
    /// the run TOUCHED (installed into, created, or removed from), compare the
    /// LIVE listing BYTE-IDENTICALLY against the names the run expected there —
    /// the manifest spellings of the source entries it intended to install or
    /// leave (`Transferred`/`Skipped`, never a conflicted one), plus every
    /// destination entry it knows about that is still present (destination-only
    /// and residue).
    ///
    /// An expected name that is ABSENT (a fold swallowed an install) is a
    /// [`ConflictReason::NameNotFaithful`] conflict naming the two spellings,
    /// and an unplanned on-disk name that ALIASES a source entry is the same
    /// conflict; the affected paths are excluded from `applied`, `skipped`, and
    /// removal (through [`Applier::aliased_dest`]). This holds for EVERY
    /// filesystem, including folds [`alias_in`] cannot name: the comparison is
    /// on the raw listing bytes of the touched directory itself.
    ///
    /// The `unexpected` branch for a name NO manifest spelling addresses, in a
    /// directory the run TOUCHED (always including the destination ROOT, which
    /// every run examines), is an ERROR, not a report entry on an `Ok` run: it
    /// is a mutation the sync did not make (a concurrent or mirrored writer), it
    /// has no conflict entry for the caller to act on, and it would otherwise
    /// live only in [`SyncReport::verify_failures`]. `first_error` carries it
    /// out of this pass so the run fails loudly; the path is still named in
    /// `verify_failures` and protected from removal through
    /// [`Applier::aliased_dest`]. A directory the run did NOT touch (a
    /// subdirectory not installed into, created, or removed from) is not
    /// listed, so an unplanned entry there is not detected by this pass. A
    /// directory that cannot be enumerated at all is likewise a run-level
    /// error: no claim about it can be confirmed.
    fn verify_directory_listings(
        &mut self,
        failed: &mut BTreeSet<String>,
        first_error: &mut Option<Error>,
    ) {
        let dirs: Vec<String> = self.touched_dirs.iter().cloned().collect();
        for dir in dirs {
            // A directory the RUN REMOVED (or that lies UNDER one it removed) no
            // longer exists, so re-listing it would be a false failure: on a
            // confined destination an absent ANCESTOR raises `openat ENOENT`
            // for a directory the removal walk already verified and deleted
            // (the `Remove`/`Delete` pass of an all-extraneous nested chain,
            // e.g. `d/d/f`). The fail-closed behaviour below is untouched for a
            // directory that EXISTS but cannot be enumerated: this skips only a
            // path this run itself removed.
            if self.is_already_gone(&dir) {
                continue;
            }
            let live = match self.listing(&dir) {
                Ok(entries) => entries,
                // A directory the run cannot enumerate faithfully: it cannot
                // verify the run's result against it, so the pass fails closed
                // with the underlying cause rather than silently skipping the
                // check.
                Err(error) => {
                    note_listing_failure(first_error, &dir, error.as_ref());
                    continue;
                }
            };
            // NAME -> LIVE KIND, so an expected entry whose NAME is present at
            // a DIFFERENT kind (a symlink where the manifest says `Dir`) is a
            // mismatch, not an intact entry: a name-only comparison is what let
            // a live symlink at a directory position pass as a directory.
            let live_kinds: BTreeMap<Vec<u8>, EntryKind> = live.iter().cloned().collect();
            // (a) The source entries the run intends to be present, by manifest
            // spelling. A CONFLICTED path is excluded: the run deliberately did
            // not install it, so its absence is not a fidelity failure.
            let mut source_expected: Vec<(String, EntryKind, Vec<u8>)> = Vec::new();
            for entry in &self.diff.source.entries {
                if parent_manifest(&entry.path) != dir || self.conflicts.contains_key(&entry.path) {
                    continue;
                }
                if !matches!(
                    self.outcomes.get(&entry.path),
                    Some(Outcome::Transferred) | Some(Outcome::Skipped)
                ) {
                    continue;
                }
                let Ok(kind) = EntryKind::of(entry) else {
                    continue;
                };
                let Some(name) = file_name_bytes(&entry.path) else {
                    continue;
                };
                source_expected.push((entry.path.clone(), kind, name));
            }
            for (path, kind, expected) in &source_expected {
                match live_kinds.get(expected) {
                    // Present under the manifest kind: intact.
                    Some(live_kind) if live_kind == kind => continue,
                    // Present under a DIFFERENT kind: no fold explains it (the
                    // name is byte-identical), so it is NOT an intact
                    // directory/entry. Mark it a verification failure and
                    // protect the live spelling from removal; never treat it as
                    // present-and-correct. (A `Transferred`/`Skipped` source
                    // entry is ALSO checked by the content/KIND passes; this is
                    // the structural backstop that sees the kind swap even when
                    // an outcome-driven check would not.)
                    Some(_live_kind) => {
                        let dest_path = join_manifest_path(
                            &dir,
                            OsStr::new(String::from_utf8_lossy(expected).as_ref()),
                        );
                        self.aliased_dest
                            .entry(dest_path)
                            .or_insert_with(|| path.clone());
                        failed.insert(path.clone());
                        continue;
                    }
                    // Absent: fall through to the existing absent-name
                    // handling (a fold may have swallowed the install).
                    None => {}
                }
                let on_disk = self.name_the_alias(&dir, path, *kind, &live);
                self.name_conflict(path, *kind, on_disk.clone());
                match on_disk {
                    Some(on_disk) => {
                        let dest_path = join_manifest_path(&dir, OsStr::new(&on_disk));
                        self.aliased_dest
                            .entry(dest_path)
                            .or_insert_with(|| path.clone());
                    }
                    None => self.protect_extraneous_siblings(&dir, path, expected),
                }
                failed.insert(path.clone());
            }
            // (b) The names the run DID intend in this directory: the source
            // spellings above, plus every destination manifest name that is
            // still live (kept destination-only entries and residue). Any live
            // name outside that set was created under a spelling no list
            // expects.
            let mut intended: BTreeSet<Vec<u8>> = source_expected
                .iter()
                .map(|(_, _, name)| name.clone())
                .collect();
            for entry in &self.diff.dest.entries {
                if parent_manifest(&entry.path) == dir
                    && let Some(name) = file_name_bytes(&entry.path)
                    && live_kinds.contains_key(&name)
                {
                    intended.insert(name);
                }
            }
            for residue in &self.dest_residue {
                if parent_manifest(residue) == dir
                    && let Some(name) = file_name_bytes(residue)
                    && live_kinds.contains_key(&name)
                {
                    intended.insert(name);
                }
            }
            let mut unexpected: Vec<String> = Vec::new();
            for (name, _kind) in &live {
                let name_text = String::from_utf8_lossy(name);
                if is_reserved_name(OsStr::new(name_text.as_ref())) {
                    continue;
                }
                if intended.contains(name) {
                    continue;
                }
                unexpected.push(name_text.into_owned());
            }
            for on_disk in unexpected {
                // Attribute it to the source entry it aliases, if any, so the
                // conflict names a manifest path; otherwise record the on-disk
                // path itself as protected and unverified rather than invent a
                // source claim.
                let mut named = false;
                for (path, kind, expected) in &source_expected {
                    if String::from_utf8_lossy(expected) == on_disk.as_str() {
                        continue;
                    }
                    if self.name_the_alias(&dir, path, *kind, &live).as_deref()
                        == Some(on_disk.as_str())
                    {
                        self.name_conflict(path, *kind, Some(on_disk.clone()));
                        failed.insert(path.clone());
                        named = true;
                    }
                }
                if !named {
                    let on_disk_path = join_manifest_path(&dir, OsStr::new(&on_disk));
                    self.aliased_dest
                        .entry(on_disk_path.clone())
                        .or_insert_with(|| on_disk_path.clone());
                    failed.insert(on_disk_path.clone());
                    if first_error.is_none() {
                        *first_error = Some(Error::integrity(format!(
                            "post-transfer verification failed: {} holds the unplanned entry {on_disk_path}, which no manifest spelling addresses; reporting an error rather than claiming the directory was left as intended",
                            destination_dir_subject(&dir)
                        )));
                    }
                }
            }
        }
    }

    /// Verify the KIND and the CONTENT/TARGET of every entry the report would
    /// call `Skipped` (or leave as a kept destination-only entry) inside a
    /// TOUCHED directory.
    ///
    /// A fold can mutate one of these entries without the run ever naming it:
    /// the install lands THROUGH the fold and the victim is not a source entry
    /// whose outcome is `Transferred`, so the ordinary verification pass never
    /// looks at it. A content/target change OR a KIND change here is exactly the
    /// defect — the run claims no mutation while the entry changed — and the
    /// entry is excluded from `skipped` (and named in `verify_failures`)
    /// instead of being reported as no-mutation. The KIND check is what catches
    /// a `Same` directory a writer replaced with a regular file, which keeps the
    /// name and so passes every name-only check.
    fn verify_claimed_untouched(
        &mut self,
        failed: &mut BTreeSet<String>,
        first_error: &mut Option<Error>,
    ) {
        // Clone the claims first: the mutable bookkeeping below must not fight
        // the borrow of `self.diff`.
        let mut candidates: Vec<(String, EntryKind, Option<String>)> = Vec::new();
        for entry in &self.diff.dest.entries {
            let dir = parent_manifest(&entry.path);
            if !self.touched_dirs.contains(&dir) || is_reserved_path(&entry.path) {
                continue;
            }
            // A path the run REMOVED (or that lies under a removed ancestor) is
            // gone BY DESIGN; it is not a "left alone" claim, so it is not
            // listed here. Re-probing it would raise a missing-ancestor error
            // on a confined destination for an entry the run correctly
            // deleted (see [`Applier::verify_directory_listings`]).
            if self.is_already_gone(&entry.path) {
                continue;
            }
            let claimed = match self.outcomes.get(&entry.path) {
                Some(Outcome::Transferred) => false,
                Some(Outcome::Skipped) | None => true,
            };
            if !claimed {
                continue;
            }
            let Ok(kind) = EntryKind::of(entry) else {
                continue;
            };
            candidates.push((entry.path.clone(), kind, entry.content_sha256.clone()));
        }
        for (path, kind, expected_hash) in candidates {
            let Ok(rel) = rooted(&path) else {
                continue;
            };
            // Only a path STILL PRESENT under its exact spelling is a "left
            // alone" claim; a removed entry is gone by design. The listing (not
            // the folded address) keeps this exact.
            let parent = parent_manifest(&path);
            let present = match file_name_bytes(&path) {
                Some(name) => match self.listing(&parent) {
                    Ok(names) => names.iter().any(|(live_name, _)| live_name == &name),
                    // The directory could not be enumerated, so the
                    // no-mutation claim cannot be confirmed: fail closed and
                    // name the path, never silently skip the check.
                    Err(error) => {
                        note_listing_failure(first_error, &parent, error.as_ref());
                        failed.insert(path);
                        continue;
                    }
                },
                None => false,
            };
            if !present {
                continue;
            }
            // The KIND is checked FIRST: a name that is still present under its
            // exact spelling says nothing about the entry AT it. A `Same`
            // directory the writer replaced with a regular file (or any other
            // kind swap) keeps the name, so the name-only checks cannot see it;
            // the run must not call the result "left alone". An unreadable or
            // unsupported kind is likewise not confirmed.
            let intact = match self.dest.kind_opt(&rel) {
                Ok(Some(actual)) if actual == kind => match (kind, expected_hash.as_deref()) {
                    (EntryKind::File, Some(expected)) => self
                        .dest
                        .read(&rel)
                        .map(|bytes| crate::digest::sha256_bytes(&bytes) == expected)
                        .unwrap_or(false),
                    (EntryKind::Symlink, Some(expected)) => self
                        .dest
                        .read_link(&rel)
                        .map(|target| {
                            crate::digest::sha256_bytes(target.as_os_str().as_encoded_bytes())
                                == expected
                        })
                        .unwrap_or(false),
                    // A directory has no content of its own, and a manifest
                    // entry with no recorded hash makes no content claim.
                    _ => true,
                },
                // Absent, a different kind, or a probe that failed: the
                // no-mutation claim is not confirmed.
                _ => false,
            };
            if !intact {
                self.outcomes.remove(&path);
                failed.insert(path);
            }
        }
    }

    /// Protect every destination-only entry in `parent` whose spelling is not
    /// `expected`, because a name mismatch the on-disk target of which could not
    /// be identified may have folded the installed entry onto any of them. A
    /// conservative over-approximation, used only when a fold is already a
    /// reported conflict: over-protecting a sibling is a conflict, never a
    /// destruction.
    fn protect_extraneous_siblings(&mut self, parent: &str, source: &str, expected: &[u8]) {
        let siblings: Vec<String> = self
            .diff
            .dest
            .entries
            .iter()
            .filter(|entry| {
                parent_manifest(&entry.path) == parent
                    && self.diff.classify(&entry.path) == Some(EntryDiff::Extraneous)
                    && file_name_bytes(&entry.path).is_some_and(|name| name != expected)
            })
            .map(|entry| entry.path.clone())
            .collect();
        for sibling in siblings {
            self.aliased_dest
                .entry(sibling)
                .or_insert_with(|| source.to_string());
        }
    }

    /// THE structural fold gate, run BEFORE an install mutates anything.
    ///
    /// A manifest path is an ADDRESS. The destination filesystem may resolve
    /// that address to a DIFFERENTLY-SPELLED existing entry (macOS APFS folds
    /// `Straße.txt` onto `STRASSE.txt`, `ﬁ.txt` onto `fi.txt`, `ς` onto `σ`, …;
    /// a `to_lowercase` model cannot enumerate those rules). Installing the
    /// manifest spelling then mutates the folded target — a path that may be a
    /// `Same`/`Skipped` or destination-only entry the report claims to leave
    /// alone.
    ///
    /// The check is NOT a fold model: it asks the DESTINATION two questions
    /// that are exact on any filesystem. (1) Is the manifest spelling present
    /// BYTE-IDENTICALLY in its parent directory's live listing? (2) Does the
    /// address nevertheless RESOLVE? Yes to (2) and no to (1) means the
    /// filesystem folded the address onto some other spelling; the install is
    /// refused, the on-disk spelling is named in the conflict when it can be
    /// identified, and it is recorded in [`Applier::aliased_dest`] so no
    /// removal can destroy it. An ABSENT address (a genuine create) and an
    /// exact-name entry (a legitimate replace) both pass.
    ///
    /// A listing that cannot be READ is itself a run-level error: a directory
    /// the run cannot enumerate faithfully is one it cannot verify at all, so
    /// the gate fails closed (carrying the cause) rather than proceeding to
    /// install through a listing it could not check.
    fn refuse_address_folded_onto_another_name(
        &mut self,
        path: &str,
        kind: EntryKind,
        rel: &RootedRelativePath,
    ) -> Result<bool> {
        let Some(expected) = file_name_bytes(path) else {
            return Ok(false);
        };
        let parent = parent_manifest(path);
        let listing = match self.listing(&parent) {
            Ok(names) => names,
            Err(error) => return Err(unenumerable_directory_error(&parent, error.as_ref())),
        };
        if listing.iter().any(|(name, _)| name == &expected) {
            return Ok(false);
        }
        if !self.dest.root_present() || !self.dest.exists(rel)? {
            return Ok(false);
        }
        let on_disk = self.name_the_alias(&parent, path, kind, &listing);
        self.name_conflict(path, kind, on_disk.clone());
        match on_disk {
            Some(on_disk) => {
                let dest_path = join_manifest_path(&parent, OsStr::new(&on_disk));
                self.aliased_dest
                    .entry(dest_path)
                    .or_insert_with(|| path.to_string());
            }
            None => self.protect_extraneous_siblings(&parent, path, &expected),
        }
        Ok(true)
    }

    /// The destination's actual on-disk spelling of the entry the manifest
    /// `path` addresses, when the filesystem folded the spelling onto a
    /// DIFFERENTLY-SPELLED entry. `None` when no listing entry aliases it, or
    /// when the alias cannot be identified unambiguously.
    ///
    /// The first attempt is the cheap `to_lowercase` NAME match ([`alias_in`]);
    /// it names the common case-folding filesystems. When that does not model
    /// the fold (a Unicode special case such as `ß`/`ss`), the fallback
    /// compares the entry the address RESOLVES to against each candidate
    /// listing entry by IDENTITY (file bytes, or a symlink target). This is NOT
    /// a better fold table: detection is the exact `exists` + listing test in
    /// the callers; this only NAMES the target, and an unnameable target
    /// degrades to a conservative sibling protection. The caller passes the
    /// listing it ALREADY read (and whose failure it already propagated), so
    /// this helper never swallows a listing error of its own.
    fn name_the_alias(
        &self,
        parent: &str,
        path: &str,
        kind: EntryKind,
        names: &[(Vec<u8>, EntryKind)],
    ) -> Option<String> {
        let expected = file_name_bytes(path)?;
        if let Some(name) = alias_in(names, &expected) {
            return Some(name);
        }
        if kind == EntryKind::Dir {
            // A directory has no content identity to compare; a single
            // byte-different on-disk entry is the only safe inference.
            let mut candidates = names
                .iter()
                .filter(|(name, _)| **name != expected)
                .map(|(name, _)| String::from_utf8_lossy(name).into_owned());
            let first = candidates.next()?;
            return candidates.next().is_none().then_some(first);
        }
        let identity = self.alias_identity(path, kind)?;
        let mut found: Option<String> = None;
        for (name, _) in names.iter().filter(|(name, _)| **name != expected) {
            let candidate_name = String::from_utf8_lossy(name);
            let candidate = join_manifest_path(parent, OsStr::new(candidate_name.as_ref()));
            if self.alias_identity(&candidate, kind).as_deref() == Some(identity.as_slice()) {
                if found.is_some() {
                    // Ambiguous: another candidate has the same identity, so
                    // naming either spelling would be a guess.
                    return None;
                }
                found = Some(candidate_name.into_owned());
            }
        }
        found
    }

    /// The identity of the entry at `path` for naming a fold target: file
    /// bytes, or a symlink's target bytes. `None` for a directory or an
    /// unreadable entry.
    fn alias_identity(&self, path: &str, kind: EntryKind) -> Option<Vec<u8>> {
        let rel = rooted(path).ok()?;
        match kind {
            EntryKind::File => self.dest.read(&rel).ok(),
            EntryKind::Symlink => self
                .dest
                .read_link(&rel)
                .ok()
                .map(|target| target.as_os_str().as_encoded_bytes().to_vec()),
            EntryKind::Dir => None,
        }
    }

    /// THE one cached listing authority for the whole run: return `parent`'s
    /// listing from the run-scoped cache, reading it from the destination via
    /// [`Applier::dir_listing`] (the ONLY place that touches the destination
    /// for a listing) on the first request for that directory. Every consumer
    /// goes through here, so a directory with N entries is enumerated ONCE per
    /// verify pass, not once per entry. The cached `Result` (success OR failure)
    /// is reused: within a pass no destination mutation runs, so a second read
    /// of the same directory could only reproduce the same failure.
    fn listing(&self, parent: &str) -> std::result::Result<DirListing, std::rc::Rc<Error>> {
        #[cfg(test)]
        listing_reads::bump();
        if let Some(cached) = self.listings.borrow().get(parent) {
            return cached.clone();
        }
        let fresh = self.dir_listing(parent).map_err(std::rc::Rc::new);
        self.listings
            .borrow_mut()
            .insert(parent.to_string(), fresh.clone());
        fresh
    }

    /// Drop every cached listing. THE freshness point: called at the start of
    /// each [`Applier::verify`] pass, so a verification verdict can never be
    /// sourced from a listing that predates a destination mutation it is meant
    /// to check (a `Some` mutation the run made, or a removal it performed in
    /// [`Applier::remove_extraneous`]). The next `listing` call re-reads.
    fn clear_listings(&self) {
        self.listings.borrow_mut().clear();
    }

    /// The destination directory `parent` (the manifest spelling of a parent,
    /// `""` for the destination ROOT), as `(name, kind)` pairs: the exact
    /// on-disk NAME bytes plus the LIVE kind, so a caller can compare KIND as
    /// well as NAME. An ABSENT directory is enumerated faithfully as EMPTY (it
    /// holds no directory entries). A path that EXISTS but is NOT a real
    /// directory — a symlink, or a regular file — is an [`Err`], NEVER an empty
    /// listing: a path-based `list` would FOLLOW a symlink there and enumerate
    /// the target, which is exactly the escape this refusal closes. The kind is
    /// read with `kind_opt` (lstat, never `stat`/`exists`), so a
    /// symlink-to-directory is [`EntryKind::Symlink`], not a directory.
    ///
    /// This is the RAW fetch: it is reached only through [`Applier::listing`],
    /// which caches it, so it is the single place the destination is listed.
    fn dir_listing(&self, parent: &str) -> Result<DirListing> {
        let entries = if parent.is_empty() {
            match self.dest.list_root() {
                Ok(entries) => entries,
                // An ABSENT destination root has no entries: it is enumerated
                // faithfully as empty, never reported as unenumerable. Only a
                // root that EXISTS yet cannot be read is a listing failure.
                Err(_) if !self.dest.root_present() => return Ok(Vec::new()),
                Err(error) => return Err(error),
            }
        } else {
            let rel = rooted(parent)?;
            // An ABSENT destination root has no child directories: every path
            // enumerates faithfully as empty rather than failing on a root that
            // the operation may be about to create. `kind_opt` below would open
            // the root and fail when it does not exist.
            if !self.dest.root_present() {
                return Ok(Vec::new());
            }
            // The path must be a REAL directory before it may be listed: an
            // existing symlink or file is refused (never followed), and only a
            // CONFIRMED absent path enumerates as empty. A path-based
            // `list` would resolve a symlink here and enumerate whatever it
            // points at, so the refusal is what keeps a listing inside the
            // destination root.
            match self.dest.kind_opt(&rel)? {
                None => return Ok(Vec::new()),
                Some(EntryKind::Dir) => {}
                Some(other) => return Err(non_directory_destination_error(parent, other)),
            }
            self.dest.list(&rel)?
        };
        Ok(entries
            .into_iter()
            .map(|(name, kind)| (name.as_encoded_bytes().to_vec(), kind))
            .collect())
    }

    /// Detect a SOURCE pair that differs only by case when the destination
    /// filesystem is case-insensitive, and report the member(s) that cannot be
    /// represented.
    ///
    /// The destination's case sensitivity is ASKED OF THE FILESYSTEM with a
    /// probe ([`Applier::dest_case_insensitive`]), never assumed from a
    /// platform. The probe runs only when a source entry could fold onto
    /// another source entry or onto an existing destination entry, so an
    /// ordinary sync pays nothing. On a case-SENSITIVE destination nothing is
    /// refused: the pair is legitimate and both entries transfer.
    ///
    /// Within a fold group the lexicographically-first spelling is kept (it is
    /// representable) and every other eligible member is conflicted with the
    /// kept spelling as its on-disk name. A kept spelling that itself aliases an
    /// existing destination entry is conflicted too, and that destination
    /// spelling is recorded in [`Applier::aliased_dest`] so the `delete_-
    /// extraneous` pass cannot destroy it.
    fn refuse_unrepresentable_case_aliases(&mut self) -> Result<()> {
        // (parent, case-folded name) -> members.
        let mut source_groups: BTreeMap<(String, String), Vec<CaseMember>> = BTreeMap::new();
        for entry in &self.diff.source.entries {
            let Some(name) = Path::new(&entry.path).file_name().and_then(OsStr::to_str) else {
                continue;
            };
            let member = CaseMember {
                path: entry.path.clone(),
                name: name.to_string(),
                kind: EntryKind::of(entry)?,
                eligible: matches!(
                    self.diff.classify(&entry.path),
                    Some(EntryDiff::Missing) | Some(EntryDiff::Changed)
                ),
            };
            source_groups
                .entry((parent_manifest(&entry.path), name.to_lowercase()))
                .or_default()
                .push(member);
        }
        let mut dest_groups: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        for entry in &self.diff.dest.entries {
            let Some(name) = Path::new(&entry.path).file_name().and_then(OsStr::to_str) else {
                continue;
            };
            dest_groups
                .entry((parent_manifest(&entry.path), name.to_lowercase()))
                .or_default()
                .push(name.to_string());
        }
        let needs_probe = source_groups.iter().any(|(key, members)| {
            if !members.iter().any(|member| member.eligible) {
                return false;
            }
            let distinct: BTreeSet<&str> =
                members.iter().map(|member| member.name.as_str()).collect();
            if distinct.len() > 1 {
                return true;
            }
            dest_groups.get(key).is_some_and(|dest_names| {
                members.iter().any(|member| {
                    member.eligible && dest_names.iter().any(|dest| dest.as_str() != member.name)
                })
            })
        });
        if !needs_probe {
            return Ok(());
        }
        // An ABSENT destination root cannot be probed without CREATING it, and a
        // run that refuses every entry must not create it. The destination
        // therefore cannot be told apart from a case-insensitive one BEFORE the
        // first mutation; conservatively refuse the members a case-insensitive
        // destination cannot represent. A case-sensitive destination would have
        // represented them, so this can weaken a capability for a destination
        // that does not exist YET — it never loses data, and an existing
        // destination (the common case) still asks the filesystem with the
        // probe below. Without this, the refusal was skipped entirely and the
        // pair folded during the transfer, one member silently overwriting the
        // other.
        if self.dest.root_present() && !self.dest_case_insensitive()? {
            return Ok(());
        }
        for (key, members) in &source_groups {
            if !members.iter().any(|member| member.eligible) {
                continue;
            }
            let kept = members
                .iter()
                .map(|member| member.name.as_str())
                .min()
                .unwrap_or_default()
                .to_string();
            let dest_names = dest_groups.get(key);
            let dest_alias = dest_names
                .and_then(|names| names.iter().find(|dest| dest.as_str() != kept).cloned());
            for member in members {
                if !member.eligible || (member.name == kept && dest_alias.is_none()) {
                    continue;
                }
                let on_disk = if member.name == kept {
                    dest_alias.clone().unwrap_or_else(|| kept.clone())
                } else {
                    kept.clone()
                };
                self.name_conflict(&member.path, member.kind, Some(on_disk.clone()));
                if dest_names.is_some_and(|names| names.iter().any(|dest| dest == &on_disk)) {
                    let dest_path = join_manifest_path(&key.0, OsStr::new(&on_disk));
                    self.aliased_dest.insert(dest_path, member.path.clone());
                }
            }
        }
        Ok(())
    }

    /// Probe the destination filesystem's case sensitivity: create a unique
    /// mixed-case probe DIRECTORY in the destination root, look it up with the
    /// case of every ASCII letter flipped, and remove the probe.
    ///
    /// Where it lives: the probe name is in the RESERVED `.sync-aside.`
    /// namespace, so an interrupted probe is residue the next run reports and
    /// never transfers or destroys. What it costs: a `create_dir_all`, an
    /// existence lookup of the flipped spelling (plus the collision lookup and
    /// the cleanup `remove`) against the destination root — every one a remote
    /// round trip on an SSH transport — and it is probed at most ONCE per run.
    /// Its mutations ARE counted in [`SyncReport::transfers`] (the attempt-first
    /// accounting is uniform) and its own failures are named in
    /// [`SyncReport::indeterminate`] — so `transfers == 0` still means no
    /// mutation was attempted. The result is cached for the run.
    fn dest_case_insensitive(&mut self) -> Result<bool> {
        if let Some(probed) = self.dest_case_insensitive {
            return Ok(probed);
        }
        let (name, flipped) = loop {
            let candidate = case_probe_name();
            let flipped = flip_ascii_case(&candidate);
            let rel = RootedRelativePath::parse(Path::new(&candidate))?;
            let flipped_rel = RootedRelativePath::parse(Path::new(&flipped))?;
            // Neither spelling may already name an entry: on a case-SENSITIVE
            // filesystem an unrelated entry at the flipped spelling would
            // otherwise make the probe report a false "case-insensitive".
            if !self.dest.exists(&rel)? && !self.dest.exists(&flipped_rel)? {
                break (candidate, flipped);
            }
        };
        let rel = RootedRelativePath::parse(Path::new(&name))?;
        let flipped_rel = RootedRelativePath::parse(Path::new(&flipped))?;
        self.guard_destination(&rel, AncestorPolicy::MayCreate, FinalPolicy::NotSymlink)?;
        self.begin_mutation(&name, MutationKind::Content);
        match self.dest.create_dir_all(&rel) {
            Ok(()) => self.commit_mutation(&name, MutationKind::Content),
            Err(error) => return Err(error),
        }
        let insensitive = match self.dest.exists(&flipped_rel) {
            Ok(value) => value,
            Err(error) => {
                let _ = self.remove_probe(&rel);
                return Err(error);
            }
        };
        self.remove_probe(&rel)?;
        self.dest_case_insensitive = Some(insensitive);
        Ok(insensitive)
    }

    /// Remove the case-sensitivity probe directory, recording a leftover as
    /// residue (it still exists, so its transient state is reported rather than
    /// silently leaked).
    fn remove_probe(&mut self, rel: &RootedRelativePath) -> Result<()> {
        let path = manifest_spelling(rel);
        self.guard_destination(rel, AncestorPolicy::MustExist, FinalPolicy::Directory)?;
        self.begin_mutation(&path, MutationKind::Content);
        match self.dest.remove_dir(rel) {
            Ok(()) => {
                self.commit_mutation(&path, MutationKind::Content);
                Ok(())
            }
            Err(error) => {
                self.note_residue(&path);
                Err(error)
            }
        }
    }

    /// The extraneous directories whose subtree contains residue, plus every
    /// extraneous ancestor of one: removing any of them would strand (or
    /// destroy) the residue below. `is_guarded` then covers the whole guarded
    /// subtree, so nothing under a residue-holding directory is touched.
    fn residue_guards(&self, entries: &[(String, EntryKind)]) -> BTreeSet<String> {
        let extraneous: BTreeSet<&str> = entries.iter().map(|(p, _)| p.as_str()).collect();
        let mut guards = BTreeSet::new();
        for residue in &self.dest_residue {
            for ancestor in ancestor_paths(residue) {
                if extraneous.contains(ancestor.as_str()) {
                    guards.insert(ancestor);
                }
            }
        }
        guards
    }
}

/// A unique, hidden sibling name for a claim aside. Dot-prefixed and carrying
/// the process id and a process-scoped counter, so concurrent syncs on one
/// destination stay collision-free; `claim_aside` also checks the destination
/// for an existing entry and skips a collision. The prefix is the RESERVED
/// [`ASIDE_PREFIX`] namespace: every name this function returns is excluded
/// from both manifests before the diff.
fn aside_name() -> OsString {
    use std::sync::atomic::{AtomicU64, Ordering};
    static ASIDE_COUNTER: AtomicU64 = AtomicU64::new(0);
    OsString::from(format!(
        "{ASIDE_PREFIX}{}.{}",
        std::process::id(),
        ASIDE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Whether a single file name is in the RESERVED claim-aside namespace
/// ([`ASIDE_PREFIX`]).
fn is_reserved_name(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.starts_with(ASIDE_PREFIX))
}

/// Whether ANY component of a canonical manifest path is reserved. A reserved
/// DIRECTORY makes every entry below it reserved too (the aside holds the whole
/// stranded subtree).
fn is_reserved_path(path: &str) -> bool {
    Path::new(path)
        .components()
        .any(|component| match component {
            Component::Normal(name) => is_reserved_name(name),
            _ => false,
        })
}

/// Join a manifest-style parent path and a child name into a manifest-style
/// path, using `/` on every platform (the spelling `canonicalize_tree` uses).
/// An EMPTY name returns the parent unchanged: a manifest spelling never ends
/// in a separator, so `re_root_residue` re-rooting a path onto itself must not
/// emit a trailing `/`.
fn join_manifest_path(parent: &str, name: &OsStr) -> String {
    let name = name.to_string_lossy();
    if name.is_empty() {
        parent.to_string()
    } else if parent.is_empty() {
        name.into_owned()
    } else {
        format!("{parent}/{name}")
    }
}

/// The canonical manifest spelling of a rooted relative path: its components
/// joined with `/` on EVERY platform, matching `canonicalize_tree`. Used for
/// every bookkeeping key (`residue`, `removed`, the journal), so the `/`-spelled
/// manifest paths and the `Path`-derived ones cannot fail to compare on Windows.
fn manifest_spelling(rel: &RootedRelativePath) -> String {
    let mut out = String::new();
    for component in rel.as_path().components() {
        if let Component::Normal(name) = component {
            if !out.is_empty() {
                out.push('/');
            }
            out.push_str(&name.to_string_lossy());
        }
    }
    out
}

/// The manifest spelling of `path`'s parent directory, `""` for the root (a
/// manifest does not name the root). Ancestry is component-wise via
/// `Path::parent`, never a literal-separator split.
fn parent_manifest(path: &str) -> String {
    Path::new(path)
        .parent()
        .and_then(Path::to_str)
        .unwrap_or("")
        .to_string()
}

/// The final component of a manifest path, as raw bytes so a byte-identical
/// comparison against a directory listing is possible.
fn file_name_bytes(path: &str) -> Option<Vec<u8>> {
    Path::new(path)
        .file_name()
        .map(|name| name.as_encoded_bytes().to_vec())
}

/// The ONE run-level error for a destination directory the run could not
/// enumerate faithfully (the transport's listing recognises and refuses a name
/// that is not valid UTF-8 rather than handing out a lossy view). A directory
/// that cannot be listed is one against which the run cannot verify its own
/// result, so the failure is raised at the run level — never re-classified as a
/// per-path [`ConflictReason::NameNotFaithful`] conflict — carrying the
/// underlying cause.
fn unenumerable_directory_error(dir: &str, cause: &Error) -> Error {
    let label = destination_path_label(dir);
    Error::integrity(format!(
        "the destination directory {label} could not be enumerated faithfully, so the run cannot verify the destination against it: {cause}"
    ))
}

/// The ONE run-level refusal for a destination path that exists but is not a
/// real directory. Such a path can neither be enumerated as a directory nor
/// have a child installed, renamed, chmodded, or removed under it: a symlink
/// there resolves every one of those operations OUTSIDE the destination root.
/// The refusal names the live KIND so the caller can act, and it is deliberately
/// a run-level error rather than a per-path `NameNotFaithful` conflict, exactly
/// like [`unenumerable_directory_error`].
fn non_directory_destination_error(path: &str, kind: EntryKind) -> Error {
    let label = destination_path_label(path);
    Error::integrity(format!(
        "the destination path {label} is a {} where a directory was required; refusing to follow it (a symlink there would resolve outside the destination root)",
        kind.as_str()
    ))
}

/// The ONE run-level refusal for a strict ancestor of a destination path that
/// is absent where the operation requires it to exist.
fn missing_destination_ancestor_error(path: &str) -> Error {
    let label = destination_path_label(path);
    Error::integrity(format!(
        "the destination directory {label} does not exist, so the path below it cannot be mutated safely"
    ))
}

/// The label a message uses for a destination path whose spelling may be the
/// EMPTY root spelling. The root has no name of its own, so an empty path is
/// named explicitly rather than interpolated as an empty string — which would
/// leave a doubled space and read as if the name were missing.
fn destination_path_label(path: &str) -> &str {
    if path.is_empty() {
        "<destination root>"
    } else {
        path
    }
}

/// The SUBJECT a message names for a destination directory that may be the
/// root: the bare root has no name, so it is named as "the destination root"
/// rather than interpolated empty (which rendered the unplanned-entry error as
/// `the directory  holds ...`).
fn destination_dir_subject(dir: &str) -> String {
    if dir.is_empty() {
        "the destination root".to_string()
    } else {
        format!("the directory {dir}")
    }
}

/// Record `dir`'s listing failure as the verification pass's FIRST error,
/// keeping the underlying cause. Later failures in the same pass are subsumed:
/// the pass fails once, with the cause the caller can act on.
fn note_listing_failure(first_error: &mut Option<Error>, dir: &str, cause: &Error) {
    if first_error.is_none() {
        *first_error = Some(unenumerable_directory_error(dir, cause));
    }
}

/// The name in `names` that case-folds to `expected` without being
/// byte-identical to it: the destination's actual on-disk spelling of an entry
/// the manifest addressed by `expected`. `None` when no listing entry aliases
/// it (the entry is simply absent). The fold is `str::to_lowercase`; a folding
/// it does not model (a Unicode special case) is still caught as a mismatch,
/// only the on-disk spelling then cannot be named.
fn alias_in(names: &[(Vec<u8>, EntryKind)], expected: &[u8]) -> Option<String> {
    let expected_fold = String::from_utf8_lossy(expected).to_lowercase();
    names.iter().find_map(|(name, _)| {
        let text = String::from_utf8_lossy(name);
        (text.to_lowercase() == expected_fold).then(|| text.into_owned())
    })
}

/// One source entry considered by the unrepresentable-case-pair check
/// ([`Applier::refuse_unrepresentable_case_aliases`]): its manifest path, its
/// final component, its kind, and whether it is ELIGIBLE for a transfer (only a
/// `Missing`/`Changed` entry would be installed).
struct CaseMember {
    path: String,
    name: String,
    kind: EntryKind,
    eligible: bool,
}

/// A unique, hidden, MIXED-CASE probe name for the destination
/// case-sensitivity probe ([`Applier::dest_case_insensitive`]). It carries the
/// process id and a process-scoped counter so concurrent syncs cannot collide,
/// and it lives in the RESERVED [`ASIDE_PREFIX`] namespace, so a probe
/// interrupted between creation and cleanup is residue the next run reports and
/// never transfers or destroys.
fn case_probe_name() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CASE_PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{ASIDE_PREFIX}case-probe.{}.{}",
        std::process::id(),
        CASE_PROBE_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Flip the case of every ASCII letter in `name`, leaving every other byte
/// alone. The result is a different byte string with the same case fold, so it
/// resolves to the probe entry exactly when the destination filesystem is
/// case-insensitive.
fn flip_ascii_case(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else {
                c
            }
        })
        .collect()
}

/// The reserved entries of a manifest, with their kind (a source-side
/// collision must be reported with a kind, like every conflict).
fn reserved_entries(meta: &TreeMetadata) -> Result<BTreeMap<String, EntryKind>> {
    let mut reserved = BTreeMap::new();
    for entry in &meta.entries {
        if is_reserved_path(&entry.path) {
            reserved.insert(entry.path.clone(), EntryKind::of(entry)?);
        }
    }
    Ok(reserved)
}

/// The reserved paths of a manifest (kind-agnostic), used for destination
/// residue.
fn reserved_paths(meta: &TreeMetadata) -> BTreeSet<String> {
    meta.entries
        .iter()
        .filter(|entry| is_reserved_path(&entry.path))
        .map(|entry| entry.path.clone())
        .collect()
}

/// Apply the report's ONE documented precedence to the raw candidate claims:
///
/// > `indeterminate` > `conflicts` > `residue` > `applied` > `skipped` >
/// > `extraneous` > `verify_failures`
///
/// A path named by a higher-precedence list is removed from EVERY lower one, so
/// the lists partition. `indeterminate` is the least-certain claim (an attempted
/// mutation may or may not have landed), so it subsumes the rest — including a
/// path that is ALSO a conflict. Pure, so the partition (the
/// `indeterminate` > `conflicts` edge in particular) is unit-testable with an
/// arbitrary overlap even though the two lists are unreachable together through
/// the public API today: a conflict leaves a path alone while `indeterminate`
/// means a mutation on it was attempted and failed.
fn apply_precedence(
    indeterminate: &BTreeSet<String>,
    conflicts: &mut Vec<Conflict>,
    residue: &mut BTreeSet<String>,
    applied: &mut BTreeSet<String>,
    skipped: &mut BTreeSet<String>,
    extraneous: &mut BTreeSet<String>,
    verify_failures: &mut BTreeSet<String>,
) {
    let mut claimed: BTreeSet<String> = indeterminate.clone();
    // `indeterminate` wins over `conflicts`.
    conflicts.retain(|conflict| !claimed.contains(&conflict.path));
    claimed.extend(conflicts.iter().map(|conflict| conflict.path.clone()));
    residue.retain(|path| !claimed.contains(path));
    claimed.extend(residue.iter().cloned());
    applied.retain(|path| !claimed.contains(path));
    claimed.extend(applied.iter().cloned());
    skipped.retain(|path| !claimed.contains(path));
    claimed.extend(skipped.iter().cloned());
    extraneous.retain(|path| !claimed.contains(path));
    claimed.extend(extraneous.iter().cloned());
    verify_failures.retain(|path| !claimed.contains(path));
}

/// Re-root a manifest-spelled `path` from the `from` domain onto the `to`
/// domain, component-wise. `path` is expected to be `from` or a descendant of
/// it, and every caller guards with an ancestry test
/// (`is_same_or_descendant`); when it is NOT, the failed `strip_prefix` yields
/// an EMPTY suffix, so the result is `to` itself — the empty path joined onto
/// `to`, NOT `path` unchanged. Ancestry is interpreted with
/// `Path::strip_prefix`, never by splitting on a literal separator.
fn re_root_path(to: &str, path: &str, from: &str) -> String {
    let suffix = Path::new(path)
        .strip_prefix(Path::new(from))
        .unwrap_or_else(|_| Path::new(""));
    join_manifest_path(to, suffix.as_os_str())
}

/// Reduce a set of reserved paths to the TOPMOST ones: a path with a reserved
/// ancestor is part of that ancestor's stranded subtree, so reporting the
/// ancestor is enough for the caller to act on.
fn reserved_roots(paths: &BTreeSet<String>) -> Vec<String> {
    paths
        .iter()
        .filter(|path| {
            !ancestor_paths(path)
                .into_iter()
                .any(|ancestor| paths.contains(&ancestor))
        })
        .cloned()
        .collect()
}

/// Strip every reserved entry from a manifest, recomputing the tree digest so
/// the manifest stays self-consistent. Reserved names are bookkeeping, never
/// content: the diff is computed as if they did not exist. `compute_tree_digest`
/// hashes the serialized metadata INCLUDING `tree_sha256`, so the field is
/// BLANKED before recomputing: otherwise the new digest would hash the old one
/// in and depend on the pre-strip value (non-canonical, non-idempotent). Every
/// other producer of a tree digest blanks the field first.
fn strip_reserved(mut meta: TreeMetadata) -> TreeMetadata {
    meta.entries.retain(|entry| !is_reserved_path(&entry.path));
    meta.tree_sha256 = String::new();
    meta.tree_sha256 = compute_tree_digest(&meta);
    meta
}

/// Whether `path` is (or is below) a residue-guarded directory, so removing it
/// would strand or destroy residue.
fn is_guarded(path: &str, guards: &BTreeSet<String>) -> bool {
    if guards.contains(path) {
        return true;
    }
    ancestor_paths(path)
        .into_iter()
        .any(|ancestor| guards.contains(&ancestor))
}

/// Whether `path` is a STRICT descendant of `dir`, component-wise: `px` is not
/// under `p`, and a separator is required. Uses `Path::strip_prefix`, so it is
/// correct whether the manifest spells paths with `/` or with the platform
/// separator — a literal-separator check makes a source file replacing a
/// directory look "sanctioned" (and would delete unsanctioned children).
fn is_strict_descendant(path: &str, dir: &str) -> bool {
    Path::new(path)
        .strip_prefix(Path::new(dir))
        .is_ok_and(|rest| !rest.as_os_str().is_empty())
}

/// Whether `path` is `dir` itself or a strict descendant of it (component-wise).
fn is_same_or_descendant(path: &str, dir: &str) -> bool {
    path == dir || is_strict_descendant(path, dir)
}

/// Every ancestor directory of a canonical manifest `path`, from the top-level
/// component down to the immediate parent. Excludes the path itself and the
/// root (a manifest does not describe the root). Ancestry is interpreted with
/// `Path::parent`, never by splitting on a literal separator.
fn ancestor_paths(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Path::new(path).parent();
    while let Some(parent) = current {
        match parent.to_str() {
            Some(text) if !text.is_empty() => out.push(text.to_string()),
            _ => break,
        }
        current = parent.parent();
    }
    out.reverse();
    out
}

/// Convert a canonical manifest path into the validated relative path a
/// transport accepts. The caller passes a path the canonicalizer produced (a
/// manifest entry's path, or a bookkeeping key derived from one), which is
/// already the on-disk name — NFC, UTF-8, `/`-joined — so this is a direct
/// address, never a re-normalization (see "Manifest paths are addresses" on the
/// module). A path the transport refuses is REPORTED (an error), not skipped
/// silently.
fn rooted(path: &str) -> Result<RootedRelativePath> {
    RootedRelativePath::parse(Path::new(path)).map_err(|e| {
        Error::path(format!(
            "manifest path {path:?} cannot address the transport: {e}"
        ))
    })
}

fn require_hash(entry: &TreeEntry) -> Result<&str> {
    entry.content_sha256.as_deref().ok_or_else(|| {
        Error::integrity(format!(
            "manifest entry {} ({}) has no content hash",
            entry.path, entry.entry_type
        ))
    })
}

fn parse_mode(mode: &str) -> Result<Mode> {
    u32::from_str_radix(mode, 8)
        .map(|mode| mode & 0o7777)
        .map_err(|_| Error::integrity(format!("invalid manifest mode {mode:?}")))
}

/// Normalize a local root spelling ONCE: drop trailing separators (and collapse
/// doubled ones) so `root` and `root/` name the same tree. `/` stays `/`, and an
/// empty path stays empty.
fn normalize_root(root_path: &Path) -> PathBuf {
    root_path.components().collect()
}

/// Canonicalize `path`, resolving every symlink in its LONGEST EXISTING PREFIX
/// and appending the not-yet-created tail unchanged. A root that does not exist
/// yet (a destination the sync creates lazily) has no other spelling to resolve
/// to, and the tail is exactly the tree the sync would create, so this is the
/// canonical form to compare roots against. An existing path is canonicalized
/// whole.
fn canonicalize_with_missing_tail(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| Error::materialization(format!("resolve current dir: {e}")))?
            .join(path)
    };
    if let Ok(canonical) = std::fs::canonicalize(&absolute) {
        return Ok(canonical);
    }
    // The not-yet-created tail accumulates file names; `prefix` steps up one
    // component at a time until a component RESOLVES. The check comes FIRST so
    // the filesystem root itself is tried: a path whose only existing ancestor
    // is `/` must still resolve (`/a` with only `/` present).
    let mut prefix = absolute.as_path();
    let mut tail: Vec<OsString> = Vec::new();
    loop {
        if let Ok(mut canonical) = std::fs::canonicalize(prefix) {
            for name in tail.iter().rev() {
                canonical.push(name);
            }
            return Ok(canonical);
        }
        let Some(parent) = prefix.parent() else {
            break;
        };
        if let Some(name) = prefix.file_name() {
            tail.push(name.to_os_string());
        } else {
            break;
        }
        prefix = parent;
    }
    Err(Error::materialization(format!(
        "cannot resolve {}: no existing ancestor directory",
        path.display()
    )))
}

/// Refuse a pair of sync roots where ONE is a STRICT ancestor of the other (see
/// [`sync`]'s "the two roots must be disjoint" section). Equal canonical roots
/// are allowed: the diff is empty and the run is an idempotent no-op. The
/// comparison is [`crate::root::roots_overlap`], the SAME rule
/// [`crate::root::OwnedRoot::parse`] uses, applied to the canonical paths, so
/// this is not a second definition of overlap.
///
/// UNDECIDABLE CASE: this computes nothing when `remote.is_local()` is false.
/// The remote root then names a path on ANOTHER host, and this host cannot
/// resolve it — the far-side path may coincide with, contain, or be contained
/// by the local root (a bind mount, a shared filesystem, or an `ssh` target
/// that is this very host). No refusal is possible, and none is fabricated; the
/// caller co-locating the two roots must ensure disjointness itself. The module
/// docs state this residual.
fn refuse_overlapping_roots(local: &LocalSide, remote: &dyn Remote) -> Result<()> {
    if !remote.is_local() {
        return Ok(());
    }
    let local_canonical = canonicalize_with_missing_tail(&local.root_path)?;
    let remote_canonical = canonicalize_with_missing_tail(remote.root())?;
    if local_canonical == remote_canonical {
        return Ok(());
    }
    if crate::root::roots_overlap(&local_canonical, &remote_canonical) {
        let (outer, inner) = if local_canonical.starts_with(&remote_canonical) {
            (remote.root(), local.root_path.as_path())
        } else {
            (local.root_path.as_path(), remote.root())
        };
        return Err(Error::materialization(format!(
            "refusing to sync {} and {}: the root {} is an ancestor of {}, so the run would copy a tree into its own subtree (and, with Extraneous::Delete, destroy the source); the two roots must be disjoint",
            local.root_path.display(),
            remote.root().display(),
            outer.display(),
            inner.display(),
        )));
    }
    Ok(())
}

/// One side of a transfer: the local tree (addressed through the fd-confined
/// durable primitives) or the remote (addressed through [`Remote`]).
enum Side<'a> {
    Local(&'a LocalSide),
    Remote(&'a dyn Remote),
}

impl Side<'_> {
    /// Whether this side is the fd-confined LOCAL implementation ON THIS
    /// PLATFORM: a [`Side::Local`] AND a platform whose `_fd` primitives
    /// resolve components without following symlinks
    /// ([`crate::atomic::COMPONENT_CONFINED`]).
    ///
    /// The side kind alone is not the property the name claims. A
    /// [`Side::Local`] routes its mutations through `crate::atomic`, but on a
    /// path-based port those primitives follow a symlinked component, so a
    /// local destination there is NOT confined and no caller may skip a live
    /// preflight on its account. The platform half is single-sourced next to
    /// the primitives, so this answer cannot drift from what `crate::atomic`
    /// actually enforces.
    ///
    /// A local transport is a [`Side::Remote`] with `is_local()` true, but its
    /// writes are path-based and need different widening; it is unconfined
    /// here regardless of platform.
    fn is_confined_local(&self) -> bool {
        crate::atomic::COMPONENT_CONFINED && matches!(self, Side::Local(_))
    }

    fn manifest(&self) -> Result<TreeMetadata> {
        match self {
            Side::Local(local) => local.manifest(),
            Side::Remote(remote) => remote_manifest(*remote),
        }
    }

    /// The current mode of an existing entry.
    fn mode(&self, rel: &RootedRelativePath, kind: EntryKind) -> Result<Mode> {
        match self {
            Side::Local(local) => local.mode(rel, kind),
            Side::Remote(remote) => Ok(remote.metadata(rel)?.mode & 0o7777),
        }
    }

    /// The current mode of an existing entry, or `None` when it is absent.
    fn mode_opt(&self, rel: &RootedRelativePath, kind: EntryKind) -> Result<Option<Mode>> {
        match self {
            Side::Local(local) => local.mode_opt(rel, kind),
            Side::Remote(remote) => Ok(remote.metadata_opt(rel)?.map(|m| m.mode & 0o7777)),
        }
    }

    fn read(&self, rel: &RootedRelativePath) -> Result<Vec<u8>> {
        match self {
            Side::Local(local) => local.read(rel),
            Side::Remote(remote) => remote.read(rel),
        }
    }

    fn read_link(&self, rel: &RootedRelativePath) -> Result<PathBuf> {
        match self {
            Side::Local(local) => local.read_link(rel),
            Side::Remote(remote) => remote.read_link(rel),
        }
    }

    fn create_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
        match self {
            Side::Local(local) => local.create_dir_all(rel),
            Side::Remote(remote) => remote.create_dir_all(rel),
        }
    }

    fn write_file(&self, rel: &RootedRelativePath, bytes: &[u8], mode: Mode) -> Result<()> {
        match self {
            Side::Local(local) => local.write_file(rel, bytes, mode),
            Side::Remote(remote) => remote.write(rel, bytes, mode),
        }
    }

    fn symlink(&self, target: &Path, rel: &RootedRelativePath) -> Result<()> {
        match self {
            Side::Local(local) => local.symlink(target, rel),
            Side::Remote(remote) => remote.symlink(target, rel),
        }
    }

    fn set_mode(&self, rel: &RootedRelativePath, mode: Mode, kind: EntryKind) -> Result<()> {
        match self {
            Side::Local(local) => local.set_mode(rel, mode, kind),
            Side::Remote(remote) => remote.set_mode(rel, mode),
        }
    }

    /// Remove the entry at `rel` with the primitive for `kind`. The `kind` is
    /// the LIVE kind the caller ([`Applier::remove_subtree`]) just read from the
    /// destination object; the local arm honors it exactly rather than
    /// re-deriving a directory and walking it, so a leaf removal can never turn
    /// into the tree walk the removal authority gates.
    fn remove_file(&self, rel: &RootedRelativePath) -> Result<()> {
        match self {
            Side::Local(local) => local.remove_file(rel),
            Side::Remote(remote) => remote.remove_file(rel),
        }
    }

    /// Remove the DIRECTORY at `rel` NON-RECURSIVELY (rmdir semantics). The
    /// caller ([`Applier::remove_subtree`]'s `Dir` arm) has already removed
    /// every child it enumerated and authorized, so the directory must be
    /// EMPTY; a child that appeared after the enumeration makes this fail with
    /// `ENOTEMPTY` — LOUDLY, never destroyed unnamed. Both arms are
    /// non-recursive: the confined local primitive is a descriptor-relative
    /// `unlinkat(AT_REMOVEDIR)`, and the transport primitive is `rmdir` (a
    /// confined `unlinkat(AT_REMOVEDIR)` for a local transport, `rmdir` through
    /// the exec seam for a remote one).
    fn remove_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        match self {
            Side::Local(local) => local.remove_dir(rel),
            Side::Remote(remote) => remote.remove_dir(rel),
        }
    }

    /// Whether any destination entry exists at `rel` (kind-agnostic, so a
    /// symlink counts).
    fn exists(&self, rel: &RootedRelativePath) -> Result<bool> {
        match self {
            Side::Local(local) => local.exists(rel),
            Side::Remote(remote) => Ok(remote.metadata_opt(rel)?.is_some()),
        }
    }

    /// The LIVE kind of the destination entry at `rel`, classified WITHOUT
    /// following a final-component symlink, or `None` when it is absent. Used
    /// by the unified removal to walk a claimed subtree that is not in the
    /// manifest and to classify every entry it meets. An entry that is not a
    /// regular file, directory, or symlink is refused (an error), never
    /// silently treated as one of them.
    fn kind_opt(&self, rel: &RootedRelativePath) -> Result<Option<EntryKind>> {
        match self {
            Side::Local(local) => local.kind_opt(rel),
            Side::Remote(remote) => Ok(remote.metadata_opt(rel)?.map(|meta| {
                if meta.is_dir {
                    EntryKind::Dir
                } else if meta.is_symlink {
                    EntryKind::Symlink
                } else {
                    EntryKind::File
                }
            })),
        }
    }

    /// The direct children of the destination directory at `rel`, as
    /// `(name, kind)` pairs. The kind is classified without following a symlink
    /// (a symlink to a directory is a symlink, so a recursive removal unlinks it
    /// rather than descending into its target).
    fn list(&self, rel: &RootedRelativePath) -> Result<Vec<(OsString, EntryKind)>> {
        match self {
            Side::Local(local) => local.list(rel),
            Side::Remote(remote) => Ok(remote
                .list(rel)?
                .into_iter()
                .map(|entry| {
                    let kind = if entry.is_dir {
                        EntryKind::Dir
                    } else if entry.is_symlink {
                        EntryKind::Symlink
                    } else {
                        EntryKind::File
                    };
                    (OsString::from(entry.name), kind)
                })
                .collect()),
        }
    }

    /// The names of the destination ROOT directory. The root is not itself a
    /// manifest entry, so it is addressed with the EMPTY rooted relative path:
    /// the local primitive lists the pinned root, and a transport joins the
    /// empty path onto its root untouched.
    fn list_root(&self) -> Result<Vec<(OsString, EntryKind)>> {
        self.list(&root_relative_path())
    }

    /// Whether the destination root EXISTS. The case-sensitivity probe must not
    /// create it (a fully-refused pull leaves an absent root absent), so it runs
    /// only when the root is already there.
    fn root_present(&self) -> bool {
        match self {
            Side::Local(local) => local.root_present(),
            // `manifest()` succeeded before any transfer, and a remote root that
            // does not exist is an error there, so the root is present.
            Side::Remote(_) => true,
        }
    }

    /// Rename a destination entry within the tree (the claim-by-rename
    /// primitive). A symlink or directory is moved as the entry itself, never
    /// followed.
    fn rename(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
        match self {
            Side::Local(local) => local.rename(from, to),
            Side::Remote(remote) => remote.rename(from, to),
        }
    }
}

/// The EMPTY rooted relative path, naming the destination root for a listing.
/// It is a private bookkeeping spelling, never a manifest address: manifest
/// paths are non-empty, and the transport joins it onto its root untouched.
fn root_relative_path() -> RootedRelativePath {
    RootedRelativePath::from_validated(PathBuf::new())
}

/// The local tree.
///
/// The root PATH is normalized ONCE at construction (a trailing separator is
/// dropped), so `root` and `root/` name the same tree and a symlinked root is
/// refused identically for both spellings. When the root exists at construction
/// its descriptor is opened IMMEDIATELY, before any manifest is read, and every
/// `_fd` read and mutation reuses it, so two operations cannot resolve
/// different inodes. The manifest is produced by the path-based canonicalizer;
/// on Unix the walk is confirmed to have described the pinned inode (see the
/// module's root-pinning notes). For a destination the directory is CREATED
/// just before the first mutation, so a sync whose every entry is refused
/// creates nothing.
struct LocalSide {
    root_path: PathBuf,
    /// Whether this side is the local DESTINATION. Only a destination may have
    /// a missing root created, and only at the first mutation; a missing
    /// SOURCE root is an error.
    ensure: bool,
    /// The pinned root descriptor, opened at construction when the root exists
    /// and otherwise on the first mutation that needs it.
    root: OnceCell<crate::atomic::RootDir>,
}

impl LocalSide {
    /// Construct the local side and PIN the root descriptor when it exists.
    fn open(root_path: &Path, ensure: bool) -> Result<LocalSide> {
        let side = LocalSide {
            root_path: normalize_root(root_path),
            ensure,
            root: OnceCell::new(),
        };
        match std::fs::symlink_metadata(&side.root_path) {
            Ok(meta) if meta.is_dir() => {
                let root = crate::atomic::RootDir::open(&side.root_path)?;
                let _ = side.root.set(root);
            }
            // A destination that does not exist yet is created lazily; a
            // missing source is reported by `manifest`.
            Ok(_) => {
                return Err(Error::materialization(format!(
                    "local tree root {} is not a directory",
                    side.root_path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(Error::materialization(format!(
                    "local tree root {} cannot be described: {error}",
                    side.root_path.display()
                )));
            }
        }
        Ok(side)
    }

    /// The manifest of the local tree.
    ///
    /// A DESTINATION that does not exist yet is the EMPTY tree. This is the
    /// local destination, not a far side: there is no host ambiguity and no
    /// risk of describing a different tree, and treating the absent
    /// destination as empty is what lets a fully-refused pull leave the root
    /// absent. (An absent REMOTE root is an error — see `remote_manifest`.)
    /// A non-directory root is always an error, and a missing SOURCE root is an
    /// error, never `empty`.
    fn manifest(&self) -> Result<TreeMetadata> {
        match std::fs::symlink_metadata(&self.root_path) {
            Ok(meta) if meta.is_dir() => {
                let manifest = canonicalize_tree(&self.root_path)?;
                self.confirm_pinned_root()?;
                Ok(manifest)
            }
            Ok(_) => Err(Error::materialization(format!(
                "local tree root {} is not a directory",
                self.root_path.display()
            ))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && self.ensure => {
                // A destination that was ABSENT when this side was opened is the
                // empty tree. But if a descriptor was already pinned, the path
                // named a real directory at open and has since disappeared:
                // describing it as empty would diff against one tree and mutate
                // another, so refuse instead.
                if self.root.get().is_some() {
                    return Err(Error::materialization(format!(
                        "local tree root {} disappeared after its descriptor was pinned; refusing to describe it as an empty tree",
                        self.root_path.display()
                    )));
                }
                Ok(Self::empty_tree())
            }
            Err(error) => Err(Error::materialization(format!(
                "local tree root {} does not exist: {error}",
                self.root_path.display()
            ))),
        }
    }

    /// Confirm that the path the manifest walk just described is the inode the
    /// pinned descriptor holds. Closes the pin/manifest swap window on Unix;
    /// the Windows port has no descriptor, so the documented weaker guarantee
    /// applies (see the module docs).
    #[cfg(unix)]
    fn confirm_pinned_root(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let Some(root) = self.root.get() else {
            return Ok(());
        };
        let pinned = std::fs::File::from(
            root.as_fd()
                .try_clone()
                .map_err(|e| Error::store(format!("dup root dir: {e}")))?,
        )
        .metadata()
        .map_err(|e| Error::store(format!("fstat root: {e}")))?;
        let described = std::fs::symlink_metadata(&self.root_path).map_err(|e| {
            Error::materialization(format!(
                "local tree root {} cannot be re-described: {e}",
                self.root_path.display()
            ))
        })?;
        if pinned.dev() != described.dev() || pinned.ino() != described.ino() {
            return Err(Error::materialization(format!(
                "local tree root {} changed identity while it was being described; refusing to diff one inode and mutate another",
                self.root_path.display()
            )));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn confirm_pinned_root(&self) -> Result<()> {
        Ok(())
    }

    /// The canonical EMPTY tree: no entries, with the digest computed exactly
    /// as `canonicalize_tree` computes it for an empty directory.
    fn empty_tree() -> TreeMetadata {
        let mut manifest = TreeMetadata {
            tree_schema_version: TREE_SCHEMA_VERSION,
            hash_algorithm: "sha256".to_string(),
            tree_sha256: String::new(),
            entries: Vec::new(),
        };
        manifest.tree_sha256 = compute_tree_digest(&manifest);
        manifest
    }

    /// The pinned root descriptor, opened on first use (never creating the
    /// root).
    fn root_dir(&self) -> Result<&crate::atomic::RootDir> {
        if let Some(root) = self.root.get() {
            return Ok(root);
        }
        let root = crate::atomic::RootDir::open(&self.root_path)?;
        let _ = self.root.set(root);
        self.root
            .get()
            .ok_or_else(|| Error::store("local root descriptor was not initialized"))
    }

    /// The pinned root descriptor, creating the directory first when this is
    /// the DESTINATION. Nothing is created until this runs, so a sync whose
    /// every entry is refused creates no root.
    ///
    /// When the root was ABSENT when this side was opened, the diff was
    /// computed against the EMPTY tree. If a directory has appeared at the path
    /// since, adopting it would silently ignore its entries (they are neither
    /// reported nor removed), so a NON-EMPTY one is refused. An empty directory
    /// is exactly what this would have created, so it is adopted.
    fn root_for_mutation(&self) -> Result<&crate::atomic::RootDir> {
        if self.root.get().is_none() && self.ensure {
            if self.root_path.exists() {
                let mut entries = std::fs::read_dir(&self.root_path).map_err(|e| {
                    Error::store(format!("read local root {}: {e}", self.root_path.display()))
                })?;
                if entries.next().is_some() {
                    return Err(Error::materialization(format!(
                        "local destination root {} appeared after it was described as absent and is not empty; refusing to adopt it",
                        self.root_path.display()
                    )));
                }
            } else {
                std::fs::create_dir_all(&self.root_path).map_err(|e| {
                    Error::store(format!(
                        "create local root {}: {e}",
                        self.root_path.display()
                    ))
                })?;
            }
        }
        self.root_dir()
    }

    /// The current mode of an existing entry.
    fn mode(&self, rel: &RootedRelativePath, kind: EntryKind) -> Result<Mode> {
        match kind {
            EntryKind::Dir => self.dir_mode(rel),
            EntryKind::File => self.file_mode(rel),
            // A symlink's mode is the fixed `0777` and is never chmodded; it is
            // reported for completeness and never used as a widen target.
            EntryKind::Symlink => crate::platform::file_mode(&self.root_path.join(rel.as_path()))
                .map(|mode| mode & 0o7777)
                .map_err(|e| Error::store(format!("stat {}: {e}", rel.display()))),
        }
    }

    /// The current mode of an entry, or `None` when it is absent.
    fn mode_opt(&self, rel: &RootedRelativePath, kind: EntryKind) -> Result<Option<Mode>> {
        if !crate::atomic::path_state_fd(self.root_dir()?, rel.as_path())? {
            return Ok(None);
        }
        Ok(Some(self.mode(rel, kind)?))
    }

    fn read(&self, rel: &RootedRelativePath) -> Result<Vec<u8>> {
        crate::atomic::read_fd(self.root_dir()?, rel.as_path())
    }

    fn read_link(&self, rel: &RootedRelativePath) -> Result<PathBuf> {
        crate::atomic::read_link_fd(self.root_dir()?, rel.as_path())
    }

    fn create_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
        crate::atomic::ensure_private_dir_fd(self.root_for_mutation()?, rel.as_path())
    }

    fn write_file(&self, rel: &RootedRelativePath, bytes: &[u8], mode: Mode) -> Result<()> {
        match crate::atomic::write_atomic_replace_fd(
            self.root_for_mutation()?,
            rel.as_path(),
            bytes,
            &mut |_| None,
        )? {
            ReplaceOutcome::ReplacedDurable => {}
            ReplaceOutcome::ReplacedDurabilityUnknown { error } => {
                return Err(Error::store(format!(
                    "write {}: the entry is visible but its durability is unconfirmed: {error}",
                    rel.display()
                )));
            }
        }
        self.set_mode(rel, mode, EntryKind::File)
    }

    fn set_mode(&self, rel: &RootedRelativePath, mode: Mode, kind: EntryKind) -> Result<()> {
        set_local_mode(self.root_for_mutation()?, &self.root_path, rel, mode, kind)
    }

    /// The current mode of an existing local directory, resolved
    /// descriptor-relative with `O_NOFOLLOW`.
    #[cfg(unix)]
    fn dir_mode(&self, rel: &RootedRelativePath) -> Result<Mode> {
        let fd = crate::atomic::openat_no_follow(
            self.root_dir()?.as_fd(),
            rel.as_path(),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?;
        let meta = std::fs::File::from(fd)
            .metadata()
            .map_err(|e| Error::store(format!("fstat {}: {e}", rel.display())))?;
        Ok(crate::platform::metadata_mode(&meta) & 0o7777)
    }

    #[cfg(not(unix))]
    fn dir_mode(&self, rel: &RootedRelativePath) -> Result<Mode> {
        crate::platform::file_mode(&self.root_path.join(rel.as_path()))
            .map(|mode| mode & 0o7777)
            .map_err(|e| Error::store(format!("stat {}: {e}", rel.display())))
    }

    /// The current mode of an existing local regular file, resolved
    /// descriptor-relative with `O_NOFOLLOW` (a symlink is refused, never
    /// followed).
    #[cfg(unix)]
    fn file_mode(&self, rel: &RootedRelativePath) -> Result<Mode> {
        let fd = crate::atomic::openat_no_follow(
            self.root_dir()?.as_fd(),
            rel.as_path(),
            libc::O_RDONLY,
            0,
        )?;
        let meta = std::fs::File::from(fd)
            .metadata()
            .map_err(|e| Error::store(format!("fstat {}: {e}", rel.display())))?;
        Ok(crate::platform::metadata_mode(&meta) & 0o7777)
    }

    #[cfg(not(unix))]
    fn file_mode(&self, rel: &RootedRelativePath) -> Result<Mode> {
        crate::platform::file_mode(&self.root_path.join(rel.as_path()))
            .map(|mode| mode & 0o7777)
            .map_err(|e| Error::store(format!("stat {}: {e}", rel.display())))
    }

    fn symlink(&self, target: &Path, rel: &RootedRelativePath) -> Result<()> {
        symlink_local(self.root_for_mutation()?, &self.root_path, target, rel)
    }

    /// Remove the FILE (or SYMLINK) at `rel`, classified by the caller's live
    /// kind WITHOUT FOLLOWING a final-component symlink. `unlinkat` removes
    /// exactly one entry (never `AT_REMOVEDIR`), so an entry that changed to a
    /// directory between the caller's probe and this call is REFUSED by the
    /// filesystem, never recursively destroyed. A confirmed absence is success.
    fn remove_file(&self, rel: &RootedRelativePath) -> Result<()> {
        match crate::atomic::remove_file_fd(self.root_dir()?, rel.as_path()) {
            Ok(()) => Ok(()),
            // A race may have removed the entry between the caller's live probe
            // and this call; a CONFIRMED absence is the contract's success.
            Err(error) => match crate::atomic::path_kind_fd(self.root_dir()?, rel.as_path())? {
                None => Ok(()),
                Some(_) => Err(error),
            },
        }
    }

    /// Remove the DIRECTORY at `rel` NON-RECURSIVELY: a descriptor-relative
    /// `unlinkat(AT_REMOVEDIR)` (rmdir semantics) that fails with `ENOTEMPTY`
    /// when the directory holds anything. The caller
    /// ([`Applier::remove_subtree`]'s `Dir` arm) has already removed and
    /// authorized every child it enumerated, so a child created after the
    /// enumeration makes this REFUSE LOUDLY instead of being destroyed
    /// unnamed. A confirmed absence is success (a race may have removed it).
    #[cfg(unix)]
    fn remove_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        use std::os::fd::AsRawFd;
        let root = self.root_dir()?;
        let parent_rel = rel.as_path().parent().unwrap_or(Path::new(""));
        let parent_fd = if parent_rel.as_os_str().is_empty() {
            root.as_fd()
                .try_clone()
                .map_err(|e| Error::store(format!("dup root dir: {e}")))?
        } else {
            crate::atomic::openat_no_follow(
                root.as_fd(),
                parent_rel,
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?
        };
        let name = rel
            .as_path()
            .file_name()
            .ok_or_else(|| Error::store(format!("{} has no file name", rel.display())))?;
        let name_c = std::ffi::CString::new(name.as_encoded_bytes())
            .map_err(|_| Error::store("rmdir name with NUL"))?;
        let r =
            unsafe { libc::unlinkat(parent_fd.as_raw_fd(), name_c.as_ptr(), libc::AT_REMOVEDIR) };
        if r < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound
                && crate::atomic::path_kind_fd(self.root_dir()?, rel.as_path())?.is_none()
            {
                return Ok(());
            }
            return Err(Error::store(format!("rmdir {}: {error}", rel.display())));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn remove_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        let path = self.root_path.join(rel.as_path());
        std::fs::remove_dir(&path)
            .map_err(|e| Error::store(format!("rmdir {}: {e}", path.display())))
    }

    /// Whether any entry exists at `rel` (kind-agnostic, so a symlink counts
    /// and a non-file/dir/symlink entry still counts as present).
    fn exists(&self, rel: &RootedRelativePath) -> Result<bool> {
        Ok(crate::atomic::path_kind_fd(self.root_dir()?, rel.as_path())?.is_some())
    }

    /// The live kind of the entry at `rel`, classified WITHOUT following a
    /// final-component symlink.
    fn kind_opt(&self, rel: &RootedRelativePath) -> Result<Option<EntryKind>> {
        match crate::atomic::path_kind_fd(self.root_dir()?, rel.as_path())? {
            None => Ok(None),
            Some(crate::atomic::PathKind::File) => Ok(Some(EntryKind::File)),
            Some(crate::atomic::PathKind::Dir) => Ok(Some(EntryKind::Dir)),
            Some(crate::atomic::PathKind::Symlink) => Ok(Some(EntryKind::Symlink)),
            Some(crate::atomic::PathKind::Other) => Err(Error::store(format!(
                "destination entry {} has an unsupported kind (not a regular file, a directory, or a symlink)",
                rel.display()
            ))),
        }
    }

    /// The direct children of the local directory at `rel`, classified WITHOUT
    /// following a final-component symlink.
    ///
    /// A NON-directory child is reported as [`EntryKind::File`], so a symlink
    /// is reported as a file. That is deliberate and SAFE because the kind this
    /// method returns never SELECTS a removal primitive: the one caller
    /// ([`Applier::remove_subtree`]) uses the listing only to decide whether to
    /// DESCEND (a `Dir`, from the authoritative `is_dir` that
    /// `atomic::read_dir_fd` derived with `fstatat(AT_SYMLINK_NOFOLLOW)`), and
    /// the walk re-reads the LIVE kind at its own entry before choosing a
    /// primitive. `atomic::read_dir_fd`'s `DirEntry` exposes only `is_dir`, so
    /// recovering the symlink kind here would need a second descriptor walk; a
    /// caller that needs the exact kind MUST read it with
    /// [`LocalSide::kind_opt`] rather than trust this value.
    fn list(&self, rel: &RootedRelativePath) -> Result<Vec<(OsString, EntryKind)>> {
        if rel.as_path().as_os_str().is_empty() {
            // The destination ROOT itself: `atomic::read_dir_fd` refuses the
            // empty path (it must name at least one normal component), so the
            // root is listed here. This is the ONE name read that is not
            // descriptor-relative (the pinned root path is read directly): the
            // manifest walk is path-based too, and the residual root-swap race
            // is the one the module already documents.
            return self.list_pinned_root();
        }
        // `read_dir_fd` reports only DIR-vs-non-dir (`is_dir` from
        // `fstatat(AT_SYMLINK_NOFOLLOW)`); the exact kind is resolved per entry
        // with `path_kind_fd`, so a SYMLINK is reported as a symlink, never
        // silently as a regular file. The listing now CARRIES kinds, so a
        // name-only kind would make `verify_directory_listings` see a symlink
        // where the manifest says `File` and report a spurious mismatch.
        let root = self.root_dir()?;
        let entries = crate::atomic::read_dir_fd(root, rel.as_path())?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            if entry.is_dir {
                out.push((entry.name, EntryKind::Dir));
                continue;
            }
            let child = rel.join(&entry.name)?;
            let kind = match crate::atomic::path_kind_fd(root, child.as_path())? {
                Some(crate::atomic::PathKind::Symlink) => EntryKind::Symlink,
                Some(crate::atomic::PathKind::File) => EntryKind::File,
                Some(crate::atomic::PathKind::Dir) => EntryKind::Dir,
                // The entry vanished between the directory read and the
                // classification: it is no longer a live child.
                None => continue,
                Some(crate::atomic::PathKind::Other) => {
                    return Err(Error::store(format!(
                        "destination entry {} has an unsupported kind (not a regular file, a directory, or a symlink)",
                        child.display()
                    )));
                }
            };
            out.push((entry.name, kind));
        }
        Ok(out)
    }

    /// List the pinned ROOT directory by its path. Only [`LocalSide::list`] with
    /// the EMPTY rooted relative path reaches here.
    fn list_pinned_root(&self) -> Result<Vec<(OsString, EntryKind)>> {
        let entries = std::fs::read_dir(&self.root_path).map_err(|e| {
            Error::store(format!("read local root {}: {e}", self.root_path.display()))
        })?;
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| Error::store(format!("read local root entry: {e}")))?;
            // `symlink_metadata` (lstat) so a symlink is reported as a symlink,
            // never as a regular file: the listing carries kinds.
            let meta = std::fs::symlink_metadata(entry.path()).map_err(|e| {
                Error::store(format!(
                    "classify local root entry {}: {e}",
                    entry.path().display()
                ))
            })?;
            let kind = if meta.is_dir() {
                EntryKind::Dir
            } else if meta.file_type().is_symlink() {
                EntryKind::Symlink
            } else {
                EntryKind::File
            };
            out.push((entry.file_name(), kind));
        }
        Ok(out)
    }

    /// Whether the local root exists as a directory. The case-sensitivity probe
    /// consults this so it never CREATES an absent destination root.
    fn root_present(&self) -> bool {
        self.root.get().is_some()
            || std::fs::symlink_metadata(&self.root_path)
                .map(|meta| meta.is_dir())
                .unwrap_or(false)
    }

    /// Rename an entry within the tree, component-wise with `O_NOFOLLOW` on
    /// both sides, so a symlink in any path component is refused and the final
    /// component is moved (never followed).
    fn rename(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
        crate::atomic::renameat_paths(self.root_dir()?, from.as_path(), to.as_path())
    }
}

/// Apply a mode to an existing local entry through a component-wise,
/// `O_NOFOLLOW`-resolved descriptor: a symlink in any path component (or at the
/// final component) is refused, never followed.
#[cfg(unix)]
fn set_local_mode(
    root: &crate::atomic::RootDir,
    _root_path: &Path,
    rel: &RootedRelativePath,
    mode: Mode,
    kind: EntryKind,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let flags = match kind {
        EntryKind::Dir => libc::O_RDONLY | libc::O_DIRECTORY,
        EntryKind::File | EntryKind::Symlink => libc::O_RDONLY,
    };
    let fd = crate::atomic::openat_no_follow(root.as_fd(), rel.as_path(), flags, 0)?;
    std::fs::File::from(fd)
        .set_permissions(std::fs::Permissions::from_mode(mode & 0o7777))
        .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))
}

/// The Windows port has no directory descriptors and no Unix mode bits: the
/// mode is applied path-based (a no-op), with the documented weaker
/// confinement guarantee of the store's Windows implementation.
#[cfg(not(unix))]
fn set_local_mode(
    _root: &crate::atomic::RootDir,
    root_path: &Path,
    rel: &RootedRelativePath,
    mode: Mode,
    _kind: EntryKind,
) -> Result<()> {
    crate::platform::chmod(&root_path.join(rel.as_path()), mode & 0o7777)
        .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))
}

/// Create a local symlink through the parent directory's descriptor: the
/// target is NOT resolved (it is a link target, legitimately relative and
/// possibly `..`-bearing), the link path is opened component-wise with
/// `O_NOFOLLOW`, and an existing entry at the link path is unlinked first
/// (never followed). The parent directory is synced so the new entry is
/// durable.
#[cfg(unix)]
fn symlink_local(
    root: &crate::atomic::RootDir,
    _root_path: &Path,
    target: &Path,
    rel: &RootedRelativePath,
) -> Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    let parent_rel = rel.as_path().parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(parent) = parent_rel {
        crate::atomic::ensure_private_dir_fd(root, parent)?;
    }
    let parent_fd = match parent_rel {
        Some(parent) => crate::atomic::openat_no_follow(
            root.as_fd(),
            parent,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?,
        None => root
            .as_fd()
            .try_clone()
            .map_err(|e| Error::store(format!("dup root dir: {e}")))?,
    };
    let name = rel
        .file_name()
        .ok_or_else(|| Error::store(format!("symlink {}: no file name", rel.display())))?;
    let name_c =
        CString::new(name.as_bytes()).map_err(|_| Error::store("symlink name with NUL"))?;
    let target_c = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| Error::store("symlink target with NUL"))?;
    let r = unsafe { libc::unlinkat(parent_fd.as_raw_fd(), name_c.as_ptr(), 0) };
    if r < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(Error::store(format!("unlink {}: {e}", rel.display())));
        }
    }
    let r = unsafe { libc::symlinkat(target_c.as_ptr(), parent_fd.as_raw_fd(), name_c.as_ptr()) };
    if r < 0 {
        return Err(Error::store(format!(
            "symlinkat {}: {}",
            rel.display(),
            std::io::Error::last_os_error()
        )));
    }
    crate::atomic::sync_parent_dir_fd(root, rel.as_path())
}

/// The Windows port's best-effort symlink creation (the platform helper
/// requires admin/developer mode; a failure propagates).
#[cfg(not(unix))]
fn symlink_local(
    _root: &crate::atomic::RootDir,
    root_path: &Path,
    target: &Path,
    rel: &RootedRelativePath,
) -> Result<()> {
    let link = root_path.join(rel.as_path());
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::store(format!("mkdir {}: {e}", parent.display())))?;
    }
    match std::fs::remove_file(&link) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::store(format!("remove {}: {e}", rel.display()))),
    }
    crate::platform::symlink(target, &link)
        .map_err(|e| Error::store(format!("symlink {}: {e}", rel.display())))
}

#[cfg(test)]
mod tests;
