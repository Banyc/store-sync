//! Push and pull a tree between two hosts, transferring only what differs and
//! never destroying a destination entry the caller did not sanction.
//!
//! The module is split along the one boundary that keeps the decision separate
//! from the mutation:
//!
//! * [`diff`] — describe each side as a manifest
//!   ([`crate::manifest::TreeMetadata`]) and classify every path. It mutates
//!   nothing.
//! * `apply` — move the eligible entries in the caller's `Direction`, under a
//!   caller-supplied `Policy`, and verify what was written. (This change lands
//!   the comparison half; the transfer half follows.)
//!
//! A manifest carries path, kind, mode, content hash, and symlink target per
//! entry — hashes, never bytes — so the comparison part of a transfer never
//! ships content. Bytes cross the link only for entries that actually differ.

pub mod diff;

pub use diff::{
    EntryDiff, EntryKind, REMOTE_MANIFEST_TIMEOUT, TreeDiff, diff_trees, local_manifest,
    remote_manifest,
};
