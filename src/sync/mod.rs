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
//! * **`sync` takes NO lock.** Its concurrency posture is detection and
//!   fail-closed (post-transfer verification reads every written entry and
//!   touched directory back, and an `Ok` run is not a claim that the
//!   destination is clean), NOT serialisation. A caller that needs to
//!   serialise against a concurrent push or checkpoint must hold the crate's
//!   push lock itself ([`crate::lock::FileLock`] on the operation-lock record
//!   named by [`crate::transport::Layout::lock`]). See [`apply`]'s "the lock
//!   discipline" section.

pub mod apply;
pub mod diff;

pub use apply::{
    Conflict, ConflictReason, Direction, EntryPolicy, Policy, ReplaceAll, SyncError, SyncReport,
    SyncResult, pull, push, sync,
};
pub use diff::{
    EntryDiff, EntryKind, REMOTE_MANIFEST_TIMEOUT, TreeDiff, diff_trees, local_manifest,
    remote_manifest,
};
