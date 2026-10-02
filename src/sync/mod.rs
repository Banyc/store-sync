//! Push and pull a tree between two hosts, transferring only what differs and
//! never destroying a destination entry the caller did not sanction.
//!
//! The module is split along the one boundary that keeps the decision separate
//! from the mutation:
//!
//! * [`diff`] — describe each side as a manifest
//!   ([`crate::manifest::TreeMetadata`]) and classify every path. It mutates
//!   nothing.
//! * [`apply`] — move the eligible entries in the caller's
//!   [`apply::Direction`], under a caller-supplied [`apply::Policy`], and
//!   verify what was written.
//!
//! A manifest carries path, kind, mode, content hash, and symlink target per
//! entry — hashes, never bytes — so the comparison part of a transfer never
//! ships content. Bytes cross the link only for entries that actually differ.
//!
//! # The destruction invariant
//!
//! > A path may be destroyed only when the sync holds an explicit sanction for
//! > that path; every conflict that leaves a path alone also forbids destroying
//! > it, derived from ONE definition rather than a parallel set; and a path left
//! > in place is restored, never mistaken for a path that is gone.
//!
//! [`apply`] states how each clause is realized: the prohibition is the conflict
//! record read through the exhaustive [`apply::ConflictReason`] decision (there
//! is no parallel blocked set), deletion requires the `Sanction` the caller
//! holds, and a residue path is an explicit abandoned state distinct from
//! `removed` (so it is reported, never deleted, and still restored).
//!
//! # The mode-record invariant
//!
//! Installing a child into a read-only parent directory requires transiently
//! widening the parent and restoring it afterwards. That bookkeeping is the
//! one mechanism [`apply`]'s mode journal owns, and it enforces exactly:
//!
//! > Every mode the sync changes is recorded ONCE, with its original value, at
//! > the single place that changes it; every recorded path is restored unless
//! > its final intended mode was successfully applied; and the report is
//! > derived from that record, never from bookkeeping that has been drained or
//! > overwritten.
//!
//! [`apply`] states how each clause of the invariant is realized (one journal
//! entry per path; the one widen choke point every mutation kind calls; a
//! single idempotent restore on the success and failure path; a report derived
//! from the journal and the per-entry outcome record).
//!
//! # Two contracts a caller must know
//!
//! * **The destination is exclusively owned for the run, and the source must be
//!   quiescent.** [`apply::sync`] TAKES the destination's operation lock (a
//!   [`crate::lock::FileLock`] on the record named by
//!   [`apply::destination_lock_path`]) and holds it for the WHOLE run, from
//!   before the destination manifest is read until after the final
//!   verification pass and any removal phase. Two preconditions follow: (a) the
//!   destination is exclusively owned for the duration — cooperating writers
//!   must hold the SAME lock, which the crate takes for you; (b) the SOURCE is
//!   quiescent — the crate cannot lock the source (a remote tree for a PULL, the
//!   caller's tree for a PUSH), so a concurrent source write is OUTSIDE the
//!   contract. A COOPERATING writer is refused at acquisition; a
//!   NON-cooperating writer is still caught by the existing post-transfer
//!   verification, which is retained unchanged as a best-effort tripwire that
//!   fails closed. The crate takes NO lock for a REMOTE destination (a far-side
//!   lock cannot be held across the run with the existing machinery); see
//!   [`apply`]'s "The lock discipline" section for that gap and the exact
//!   failure mode.
//! * **The two roots must be disjoint.** Neither the local root nor the remote
//!   root may be an ancestor of the other; [`apply::sync`] refuses a strict
//!   nesting before any mutation because a nested destination makes the run
//!   copy a tree into its own subtree and a nested source makes the
//!   destination manifest enumerate (and an extraneous removal destroy) the
//!   source. EQUAL roots are allowed: the diff is empty and the run is an
//!   idempotent no-op. The refusal reuses the crate's ONE overlap authority
//!   ([`crate::root::roots_overlap`], the rule [`crate::root::OwnedRoot::parse`]
//!   enforces). For a REMOTE
//!   ([`crate::transport::SshTransport`]) root the relationship is undecidable
//!   from this host, so no refusal is computed — and none is implied; a caller
//!   co-locating the two roots must ensure disjointness itself. See
//!   [`apply`]'s "the two roots must be disjoint" section.

pub mod apply;
pub mod diff;

pub use apply::{
    Conflict, ConflictReason, Direction, EntryPolicy, Policy, ReplaceAll, SyncError, SyncReport,
    SyncResult, destination_lock_path, pull, push, sync,
};
pub use diff::{
    EntryDiff, EntryKind, REMOTE_MANIFEST_TIMEOUT, TreeDiff, diff_trees, local_manifest,
    remote_manifest,
};
