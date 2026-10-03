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
//! # The contract, and how the crate enforces it
//!
//! * **The transport's host identity is prepared before the first remote
//!   request of a run.** The entry points call
//!   [`crate::transport::Remote::prepare_identity`] themselves — before the
//!   destination lock record is created — rather than asking the caller for an
//!   undocumented extra call. The default is a no-op (and
//!   [`crate::transport::LocalTransport`] does not override it), so a local
//!   destination is unaffected; for [`crate::transport::SshTransport`] it
//!   creates the control-socket directory and pins the verified host key. The
//!   caller still supplies the identity MATERIAL at construction; the crate
//!   does not trust-on-first-use.
//! * **The destination is exclusively owned, and the source is quiescent.**
//!   These are CONDITIONS THE CALLER MUST UPHOLD for the run to be
//!   well-defined, and the crate ENFORCES as much of them as it can rather than
//!   asking.
//!
//!   (a) **The destination is exclusively owned for the run.** The ONE entry
//!   point [`apply::sync`] HOLDS the destination's operation lock (a
//!   [`crate::lock::FileLock`] on the record named by
//!   [`apply::destination_lock_path`]) for the WHOLE run via the unforgeable
//!   [`apply::DestinationOwnership::Locked`] token produced by
//!   [`apply::DestinationOwnership::lock`]. That acquisition runs before the
//!   destination manifest is read and the token is held for the WHOLE run, so a
//!   cooperating writer that tries to acquire the same record is refused at
//!   acquisition. That record is a SIBLING of the destination root and is a
//!   DIFFERENT file from the in-root [`crate::transport::Layout::lock`], so the
//!   two locks do NOT exclude each other (see
//!   [`apply::destination_lock_path`]). A destination whose lock the crate
//!   CANNOT take — a REMOTE (far-side) one, or a root with no sibling record
//!   location — is REFUSED by the acquiring constructor rather than run
//!   unowned. The weaker path is the [`apply::DestinationOwnership::Unowned`]
//!   value written at the call site, so the weaker choice is stated in the TYPE
//!   and cannot be made by omission.
//!
//!   (b) **The SOURCE is quiescent.** The crate cannot lock the source (a
//!   remote tree for a PULL, the caller's tree for a PUSH), so it VERIFIES
//!   instead: the run re-reads the source manifest at the end and FAILS CLOSED,
//!   naming the paths that moved, if it differs from the plan. An ABA that
//!   changes back between the two reads is beyond what two samples can catch.
//!
//!   (c) **A writer using a DIFFERENT version of this tool, or a different tool
//!   sharing the store, is a NON-COOPERATING writer** unless it takes the same
//!   lock — the ownership claim is only as strong as the ecosystem's discipline,
//!   and the crate cannot force another program to take the record.
//!
//!   A non-cooperating write is NOT permission to lose data: the post-transfer
//!   verification is retained UNCHANGED, so an out-of-band write it observes is
//!   REPORTED (a conflict, a [`apply::SyncReport::verify_failures`] entry, or a
//!   hard error naming the unplanned path) and the run does not return a clean
//!   `Ok`. Its coverage is the paths the run reads, so it is not total. See
//!   [`apply`]'s "The lock discipline" section, including the far-side
//!   limitation: for a remote destination NEITHER the lock NOR any far-side
//!   exclusion is available, and only the explicitly-named
//!   [`apply::DestinationOwnership::Unowned`] value reaches it.
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
pub mod residue;

pub use residue::Residue;

pub use apply::{
    Conflict, ConflictReason, DestinationOwnership, Direction, EntryPolicy, Extraneous,
    LockedDestination, Policy, ReplaceAll, RetireOutcome, SyncError, SyncReport, SyncResult,
    UnsupportedDestination, destination_lock_path, retire_destination_lock, sync,
};
pub use diff::{
    EntryDiff, EntryKind, REMOTE_MANIFEST_TIMEOUT, TreeDiff, apply_manifests, diff_trees,
    local_manifest, remote_manifest,
};
