//! A durable, symlink-confined local store, and the transport that moves a
//! tree of it between hosts.
//!
//! Two halves, one crate:
//!
//! * the **store substrate** — a directory tree the process owns, with
//!   descriptor-relative path resolution that refuses a symlink injected into
//!   any PARENT component and the FINAL component on the open/create-new/read
//!   paths (the atomic replace instead REPLACES the final entry and never
//!   follows it, so it cannot escape), durable atomic writes with explicit
//!   commit points, an
//!   advisory lock, and the validated-identifier machinery for the names of
//!   the things stored in it ([`atomic`], [`root`], [`lock`], [`id`]);
//! * the **transport** — the [`transport::Remote`] trait and its two
//!   realizations (an in-process [`transport::LocalTransport`] and an
//!   [`transport::SshTransport`] over `ssh`), plus the [`manifest`] machinery
//!   that describes a tree by content hash so two hosts can agree on what
//!   differs without shipping the bytes ([`sync`]).
//!
//! [`env`], [`digest`], [`platform`], and [`trace`] are the small shared
//! helpers the rest of the crate is built on.
//!
//! The crate is deliberately free of any application's domain model: no
//! deployment, release, ledger, or record-book concept appears here. A store
//! is a root directory; a name is a validated string; a transfer is a
//! comparison of two manifests.

pub mod atomic;
pub mod digest;
pub mod env;
pub mod error;
pub mod id;
pub mod lock;
pub mod manifest;
pub mod platform;
pub mod root;
pub mod sync;
pub mod trace;
pub mod transport;

#[cfg(test)]
pub(crate) mod test_support;

pub use error::{Error, Result};
