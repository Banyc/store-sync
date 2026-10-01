//! Durable atomic filesystem I/O for the store.
//!
//! The atomic-replace protocol this module implements is the store's
//! durability machinery: write a UNIQUE temp file in the same directory,
//! chmod it private (0o600) BEFORE it can become visible under its final
//! name, fsync it, rename it into place (atomic on POSIX — a reader never
//! sees a torn record), then fsync the parent directory. The replace has
//! TWO DISTINCT COMMIT POINTS and `write_atomic_replace` reports them
//! EXPLICITLY ([`ReplaceOutcome`]): the RENAME is commit point 1 (the new
//! content becomes VISIBLE under its final name), and the PARENT-DIRECTORY
//! FSYNC is commit point 2 (the rename becomes DURABLE across power loss).
//! A failure before the rename is an `Err` — the OLD content is still
//! visible. A failure of the parent-directory open/fsync AFTER the rename
//! is [`ReplaceOutcome::ReplacedDurabilityUnknown`] — the NEW content IS
//! visible but its durability is UNCONFIRMED — never a bare `Err` (a bare
//! `Err` would conflate "the rename never happened" with "the rename
//! happened but the durability commit could not be verified"). The
//! durability of these writes is the checkpoint's ordering guarantee — the
//! floor marker must be durable BEFORE the compaction deletes anything, so
//! an interrupted compaction can never expose history below the floor; the
//! checkpoint's per-stage sequence (the transactional ADVANCE and its
//! restore) lives in `crate::retention::history_floor` on top of these
//! primitives.
//!
//! The helpers here are the shared plumbing — `pub` free functions
//! imported by `crate::store::local` and `crate::retention::history_floor`:
//! the tri-state existence check (`path_state`), the fail-closed
//! parent-dir fsync (`sync_parent_dir`), unique temp naming
//! (`temp_name_for`), the atomic marker/JSONL rewrites
//! (`write_atomic_replace`, `write_jsonl_atomic`), private permissions
//! (`set_private`, `ensure_private_dir`), the tree-object directory
//! copy (`copy_dir_recursive`), and the JSON readers.
//!
//! Parse-sensitive marker reads: a PRESENT-but-malformed marker CONTENT is
//! semantic CORRUPTION and maps to [`Error::integrity`] via
//! `read_json_marker` (the file exists, it is just not a valid marker),
//! while a mechanical filesystem I/O failure (open/read/rename/fsync)
//! stays [`Error::store`] — the class split a caller can always
//! distinguish "this marker is corrupt" from "disk read failed".
//! `read_json` folds both into [`Error::store`], which is correct for
//! its non-marker callers (observed.json, retention-debt.json, tree
//! metadata, ...); callers of `read_json_marker` must still perform
//! their own schema-version check after a successful parse (also
//! [`Error::integrity`]): an unsupported `schema_version` is a
//! marker-format violation, not an I/O failure.
//!
//! # The platform split (ONE cfg switch at the module boundary)
//!
//! The platform-dependent primitives — private permissions, the atomic
//! replace's rename/fsync semantics, and the owned-root confinement — live
//! in the [`unix`] / [`windows`] submodules, selected by the TWO `mod`
//! declarations below (the single cfg switch point). [`unix`] is the
//! descriptor-relative implementation (`openat`/`renameat`/`linkat`/
//! `unlinkat`/`mkdirat` with `O_NOFOLLOW` — the symlink-refusing
//! confinement, plus the POSIX parent-directory fsync durability).
//! [`windows`] is the path-based implementation with documented weaker
//! guarantees: no directory descriptors (the root is a path), no
//! parent-directory fsync durability, a non-atomic replace (Windows
//! `rename` does not overwrite), and no Unix mode bits. The rest of the
//! crate calls the re-exported surface below and never sees the switch.

use crate::error::{Error, Result};
#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
pub use windows::*;

/// The path-based JSON reader — TEST-ONLY (the crash-consistency assertions
/// read a REOPENED store's files directly to verify the on-disk state). The
/// store's OWN record reads route through [`read_json_fd`]
/// (descriptor-relative, symlink-refusing); no production caller uses the
/// raw-path reader, so it is `#[cfg(test)]`-gated (no `#[allow(dead_code)]`
/// band-aid).
#[cfg(test)]
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes =
        std::fs::read(path).map_err(|e| Error::store(format!("read {}: {e}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::store(format!("deserialize {}: {e}", path.display())))
}
/// TRI-STATE existence check for marker/backup/log DISCOVERY: is `path`
/// present? A genuine [`std::io::ErrorKind::NotFound`] from
/// [`std::fs::symlink_metadata`] is the ONE outcome that reads as ABSENCE
/// (`Ok(false)`); EVERY other filesystem error (EACCES, EIO, ENOTDIR, ...)
/// is a real failure → [`Error::store`], NEVER treated as absence. This is
/// the fail-closed replacement for the boolean `.exists()` checks that
/// silently read a permission/I/O error on the marker directory as "no
/// floor" / "no pending cleanup" / "no backups".
///
/// The store's WRITE-path open-or-create checks (`append_attempt`,
/// `append_snapshot`, `write_atomic_cas`) are deliberately NOT converted:
/// there a swallowed `exists()` error lands in the subsequent open/create
/// call, which fails and propagates anyway — no silent absence is possible.
///
/// Under `#[cfg(test)]` the check routes through the injectable
/// `MarkerIoOps` seam when a test installed one, so the tri-state
/// property can force each outcome on the marker path.
pub fn path_state(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) => absent_or_store(e, path),
    }
}

/// Classify a metadata error tri-state: ONLY a genuine
/// [`std::io::ErrorKind::NotFound`] is absence (`Ok(false)`); any other io
/// error is [`Error::store`] (a permission/read failure is never "no
/// marker").
fn absent_or_store(e: std::io::Error, path: &Path) -> Result<bool> {
    if e.kind() == std::io::ErrorKind::NotFound {
        Ok(false)
    } else {
        Err(Error::store(format!("stat {}: {e}", path.display())))
    }
}

/// Unique temp-file name for an atomic replace of `path`: same directory,
/// hidden dot-prefixed name carrying the process id and a process-scoped
/// counter, so concurrent atomic writes on one store stay collision-free.
pub fn temp_name_for(path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    path.with_file_name(format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default(),
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
    ))
}

/// The unique temp FILE NAME for an atomic replace of a file named
/// `file_name`: hidden dot-prefixed, carrying the process id and a
/// process-scoped counter (the same naming as [`temp_name_for`], but for
/// the descriptor-relative writers that need just the name). Unix-only
/// (the Windows `_fd` writers use the path-based replace's own temp
/// naming).
#[cfg(unix)]
pub fn temp_file_name(file_name: &OsStr) -> std::ffi::OsString {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    std::ffi::OsString::from(format!(
        ".{}.tmp.{}.{}",
        file_name.to_string_lossy(),
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
    ))
}

/// The explicit outcome of an atomic replace: the two commit points
/// (the rename — new content VISIBLE — and the parent-directory fsync —
/// new content DURABLE) are reported distinctly, so a caller can always
/// tell "the rename never happened" from "the rename happened but
/// durability is unconfirmed" (see `write_atomic_replace`).
#[derive(Debug)]
pub enum ReplaceOutcome {
    /// BOTH commit points confirmed: the new content is visible under its
    /// final name AND the parent-directory fsync succeeded — the replace
    /// is durable across power loss.
    ReplacedDurable,
    /// ONLY the rename (commit point 1) is confirmed: the new content IS
    /// visible under its final name, but the parent-directory open/fsync
    /// (commit point 2) failed AFTER the rename — durability is
    /// UNCONFIRMED and the failure is carried. NEVER a bare `Err`: `Err`
    /// means the rename never happened (the old content is still visible).
    ReplacedDurabilityUnknown { error: Error },
}

/// The [`write_atomic_replace`] stage a test-injected fault fires at. The
/// hook is [`write_atomic_replace`]'s own `fault` parameter, so a
/// per-fixture registry can fault each atomic-replacement stage exactly as
/// the append path's `FaultKind::AppendWrite` family does; production
/// passes a no-op hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplaceStage {
    /// The temp-file CREATE/WRITE stage (before any I/O on the temp): the
    /// visible target is wholly OLD; a fault here is an `Err`.
    Write,
    /// The temp-file FSYNC stage (after the write, before the chmod): an
    /// invisible dot-prefixed temp exists; the visible target is wholly
    /// OLD; a fault here is an `Err`.
    Sync,
    /// The RENAME stage (after the chmod, before the atomic rename): the
    /// visible target is wholly OLD; a fault here is an `Err`.
    Rename,
    /// The PARENT-DIRECTORY open/fsync stage, AFTER the rename: the new
    /// content IS visible under its final name but its durability is
    /// unconfirmed — reported as
    /// [`ReplaceOutcome::ReplacedDurabilityUnknown`], never an `Err`.
    DirSync,
}

/// One entry of a descriptor-relative directory read.
pub struct DirEntry {
    /// The entry's file name (never `.` or `..`).
    pub name: std::ffi::OsString,
    /// Whether the entry is a directory (classified with
    /// `fstatat(AT_SYMLINK_NOFOLLOW)` — a symlink entry is reported as a
    /// non-directory, never followed).
    pub is_dir: bool,
}

// =====================================================================
// THE OWNED ROOT (the store's mutation anchor)
// ---------------------------------------------------------------------
// Unix: an open directory descriptor (`O_DIRECTORY | O_NOFOLLOW |
// O_CLOEXEC`) — every mutation resolves component-wise with
// `openat(O_NOFOLLOW)`, so a symlink injected into a path component can
// never redirect a mutation outside the owned root. Windows: the root
// PATH (no directory descriptors); mutations resolve path-based with
// documented weaker guarantees — Windows symlinks require
// admin/developer mode (a smaller symlink-injection attack surface), and
// there is no parent-directory fsync durability.
// =====================================================================
#[cfg(unix)]
pub struct RootDir(OwnedFd);
#[cfg(windows)]
pub struct RootDir(PathBuf);

impl RootDir {
    /// Open the owned root: `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` on
    /// Unix (the descriptor pins the root); the canonical path on Windows.
    pub fn open(base: &Path) -> Result<RootDir> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.read(true);
            opts.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let f = opts
                .open(base)
                .map_err(|e| Error::store(format!("open root {}: {e}", base.display())))?;
            Ok(RootDir(f.into()))
        }
        #[cfg(windows)]
        {
            Ok(RootDir(base.to_path_buf()))
        }
    }

    #[cfg(unix)]
    pub fn as_fd(&self) -> &OwnedFd {
        &self.0
    }

    #[cfg(windows)]
    pub fn path(&self) -> &Path {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{ReplaceOutcome, ReplaceStage, write_atomic_replace};
    use crate::error::Error;
    use crate::test_support::{fixture_env, fixture_tmpdir, proptest_cases, slow_tests_enabled};
    use proptest::prelude::*;

    fn marker_path() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = fixture_tmpdir(&fixture_env()).unwrap();
        let path = dir.path().join("marker.json");
        (dir, path)
    }

    /// COMMIT POINT 1 (the rename): a fault at the rename stage is a
    /// PRE-RENAME failure — `write_atomic_replace` returns a bare `Err`
    /// and the OLD content stays visible under the final name.
    #[test]
    fn pre_rename_failure_leaves_old_content_visible() {
        let (_dir, path) = marker_path();
        std::fs::write(&path, b"OLD").unwrap();
        let err = write_atomic_replace(&path, b"NEW", &mut |stage| {
            (stage == ReplaceStage::Rename).then(|| Error::store("injected rename fault"))
        })
        .unwrap_err();
        assert!(matches!(err, Error::Store(_)));
        assert_eq!(std::fs::read(&path).unwrap(), b"OLD".to_vec());
    }

    /// COMMIT POINT 2 (the parent-directory fsync): a fault AFTER the rename
    /// leaves the NEW content visible and reports
    /// [`ReplaceOutcome::ReplacedDurabilityUnknown`] — NEVER a bare `Err`.
    #[test]
    fn post_rename_parent_fsync_failure_reports_durability_unknown() {
        let (_dir, path) = marker_path();
        std::fs::write(&path, b"OLD").unwrap();
        let outcome = write_atomic_replace(&path, b"NEW", &mut |stage| {
            (stage == ReplaceStage::DirSync).then(|| Error::store("injected dir fsync fault"))
        })
        .unwrap();
        assert!(matches!(
            outcome,
            ReplaceOutcome::ReplacedDurabilityUnknown {
                error: Error::Store(_)
            }
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"NEW".to_vec());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(proptest_cases(64)))]
        /// The no-op hook is the production path: both commit points are
        /// confirmed and the new bytes are what a reader sees.
        #[test]
        fn successful_replace_roundtrips_arbitrary_bytes(old: Vec<u8>, new: Vec<u8>) {
            let (_dir, path) = marker_path();
            std::fs::write(&path, &old).unwrap();
            let outcome = write_atomic_replace(&path, &new, &mut |_stage| None).unwrap();
            prop_assert!(matches!(outcome, ReplaceOutcome::ReplacedDurable));
            prop_assert_eq!(std::fs::read(&path).unwrap(), new);
        }
    }

    /// The exhaustive per-stage sweep — the full suite runs it under
    /// `STORE_SYNC_FULL_TESTS`; the two commit-point tests above always run.
    /// EVERY pre-rename stage leaves the OLD content visible behind an
    /// `Err`; the post-rename stage leaves the NEW content visible behind
    /// `ReplacedDurabilityUnknown`, never an `Err`.
    #[test]
    fn exhaustive_stage_sweep() {
        if !slow_tests_enabled() {
            return;
        }
        for stage in [
            ReplaceStage::Write,
            ReplaceStage::Sync,
            ReplaceStage::Rename,
        ] {
            let (_dir, path) = marker_path();
            std::fs::write(&path, b"OLD").unwrap();
            let err = write_atomic_replace(&path, b"NEW", &mut |s| {
                (s == stage).then(|| Error::store("injected fault"))
            })
            .unwrap_err();
            assert!(matches!(err, Error::Store(_)));
            assert_eq!(std::fs::read(&path).unwrap(), b"OLD".to_vec());
        }
        let (_dir, path) = marker_path();
        std::fs::write(&path, b"OLD").unwrap();
        let outcome = write_atomic_replace(&path, b"NEW", &mut |s| {
            (s == ReplaceStage::DirSync).then(|| Error::store("injected fault"))
        })
        .unwrap();
        assert!(matches!(
            outcome,
            ReplaceOutcome::ReplacedDurabilityUnknown { .. }
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"NEW".to_vec());
    }
}
