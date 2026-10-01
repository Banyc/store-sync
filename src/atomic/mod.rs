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
//! visible, and the temp file the replace wrote is UNLINKED before the call
//! returns, so a failed replace leaves the directory exactly as it found it
//! (no stray temp entry). The best-effort unlink is never silent: if it
//! itself fails, the error carries both the original failure and the cleanup
//! failure. A failure of the parent-directory open/fsync AFTER the rename
//! is [`ReplaceOutcome::ReplacedDurabilityUnknown`] — the NEW content IS
//! visible but its durability is UNCONFIRMED — never a bare `Err` (a bare
//! `Err` would conflate "the rename never happened" with "the rename
//! happened but the durability commit could not be verified"). The
//! durability of these writes is the ordering guarantee the rest of the
//! crate builds on: [`ReplaceOutcome::ReplacedDurable`] means the new bytes
//! are visible AND durable BEFORE the caller proceeds, while
//! [`ReplaceOutcome::ReplacedDurabilityUnknown`] tells the caller the
//! content is visible but its durability is unconfirmed — so a caller's
//! recovery step can always tell "this write committed durably" from "this
//! write is visible but may be lost". The per-operation sequencing on top
//! of these primitives belongs to the caller, not to this module.
//!
//! The helpers here are the shared plumbing — the `pub` free functions this
//! crate exports as its durable-I/O layer:
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
//! `unlinkat`/`mkdirat` with `O_NOFOLLOW` — every PARENT component is
//! refused as a symlink, and the open/create-new helpers refuse the FINAL
//! component too, while the atomic replace installs with `renameat` and
//! replaces the final entry without ever following it; see [`unix`]'s
//! module docs — plus the POSIX parent-directory fsync durability).
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
/// (descriptor-relative: a symlink in any component, final included, is
/// refused); no production caller uses the
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

/// Best-effort removal of a FAILED atomic replace's temp file.
///
/// `original` is the failure that triggered the cleanup. The unlink is
/// best-effort — the caller is already receiving a failure — but it is NEVER
/// silent: when the unlink itself fails, the returned error carries BOTH the
/// original failure and the cleanup failure, so the caller can see that a
/// stray temp entry may remain. On success the original error is returned
/// unchanged (same class, same message).
///
/// NEVER called after a successful rename: the temp name no longer exists (it
/// IS the destination), so an unlink would remove the committed content. The
/// post-rename parent-fsync failure ([`ReplaceOutcome::ReplacedDurabilityUnknown`])
/// is therefore NOT a cleanup point.
fn discard_temp(original: Error, tmp: &Path) -> Error {
    match std::fs::remove_file(tmp) {
        Ok(()) => original,
        Err(e) => original.with_context(format!(
            "additionally failed to unlink the failed replace's temp {}: {e}",
            tmp.display()
        )),
    }
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
    /// The temp-file FSYNC stage (after the write, before the chmod): a
    /// dot-prefixed temp exists and is unlinked before the `Err` is
    /// returned; the visible target is wholly OLD; a fault here is an
    /// `Err`.
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

/// The kind of a directory entry, classified WITHOUT following a symlink.
///
/// [`path_kind_fd`] returns this for the entry at a root-relative path. The
/// classification is deliberately independent of the entry's target: a
/// symlink whose TARGET is a directory is [`PathKind::Symlink`], never
/// [`PathKind::Dir`] — exactly the distinction [`DirEntry::is_dir`] cannot
/// make, and the answer [`path_state_fd`] cannot report (its `O_NOFOLLOW`
/// open raises `ELOOP` for a symlink instead of answering "this entry
/// exists and is a symlink").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathKind {
    /// A regular file (`S_IFREG`).
    File,
    /// A directory (`S_IFDIR`).
    Dir,
    /// A symbolic link (`S_IFLNK`), whatever its target's kind.
    Symlink,
    /// Any other entry kind (FIFO, socket, device, ...).
    Other,
}

// =====================================================================
// THE OWNED ROOT (the store's mutation anchor)
// ---------------------------------------------------------------------
// Unix: an open directory descriptor (`O_DIRECTORY | O_NOFOLLOW |
// O_CLOEXEC`) — every mutation resolves component-wise with
// `openat(O_NOFOLLOW)`: a symlink at any parent component is refused and
// the atomic replace replaces the final entry with `renameat` without
// following it, so a symlink injected into a path component can never
// redirect a mutation outside the owned root. Windows: the root
// PATH (no directory descriptors); mutations resolve path-based with
// documented weaker guarantees — Windows symlinks require
// admin/developer mode (a smaller symlink-injection attack surface), and
// there is no parent-directory fsync durability.
// =====================================================================
#[cfg(unix)]
pub struct RootDir(OwnedFd);
#[cfg(windows)]
pub struct RootDir(PathBuf);

/// Normalize the spelling of an owned-root path so two spellings that name
/// the same directory open the same root. Trailing path separators are
/// stripped, along with repeated separators and non-leading `.`
/// components that [`Path::components`] erases anyway (all of these name
/// the same directory). The filesystem root is preserved: `/` normalizes
/// to `/`, never to the empty path.
///
/// The strip is load-bearing, not cosmetic. A trailing separator DEFEATS
/// `O_DIRECTORY | O_NOFOLLOW`, because POSIX resolves `link/` by following
/// `link` as an INTERMEDIATE component (the final component is empty), so
/// the symlink-refusing open never sees the link — while the same root
/// spelled `link` is refused. Normalizing before the open makes both
/// spellings take the same path. A `..` in the root is the caller's own
/// trusted base and is left intact; a `..` in a ROOT-RELATIVE entry path
/// is refused by [`validate_rel`].
fn normalize_root(base: &Path) -> PathBuf {
    base.components().collect()
}

/// Validate that `path` is a ROOT-RELATIVE entry path, refusing every
/// spelling that could resolve outside the owned root. Only
/// [`std::path::Component::Normal`] components are admitted:
///
/// * an absolute path contributes a `RootDir`/`Prefix` component, and
///   `openat` IGNORES the root descriptor for an absolute path (on the
///   Windows port `Path::join` REPLACES the root instead), so the
///   operation would resolve against the real filesystem root — a
///   confinement escape;
/// * a `..` (`ParentDir`) component walks ABOVE the root;
/// * `.` (`CurDir`) and the empty path name the root directory itself,
///   never an entry under it.
///
/// Trailing and repeated separators are NOT refused: [`Path`] erases them,
/// so `a/b/` and `a//b` are the same components as `a/b` and the spellings
/// keep resolving identically. Every refusal is an
/// [`std::io::ErrorKind::InvalidInput`] so each caller folds it into its
/// own path-contextual store error (fail-closed: a path error, never an
/// interesting resolution).
fn validate_rel(path: &Path) -> std::io::Result<()> {
    let mut names_an_entry = false;
    for component in path.components() {
        match component {
            std::path::Component::Normal(_) => names_an_entry = true,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "a root-relative path may contain only normal components \
                     (no absolute path, no `..`, no `.`)",
                ));
            }
        }
    }
    if !names_an_entry {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "a root-relative path must name at least one normal component \
             (the empty path is refused)",
        ));
    }
    Ok(())
}

impl RootDir {
    /// Open the owned root.
    ///
    /// The path is normalized first ([`normalize_root`]): trailing path
    /// separators are stripped, so `dir/` and `dir` open the SAME root. On
    /// Unix the open is `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, so the
    /// descriptor pins the root and a real directory opens, a
    /// symlink-to-directory is refused (`ENOTDIR`/`ELOOP`), and a regular
    /// file is refused (`ENOTDIR`) — IDENTICALLY for both spellings.
    ///
    /// Windows (the path-based port) stores the normalized path, so both
    /// spellings name the same root for every later mutation. It does NOT
    /// guarantee the same refusal: there is no directory descriptor and no
    /// `O_NOFOLLOW` equivalent here, so a symlink root (which on Windows
    /// requires admin/developer mode) is not refused at open — the
    /// documented weaker guarantee of the Windows port.
    pub fn open(base: &Path) -> Result<RootDir> {
        let base = normalize_root(base);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.read(true);
            opts.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let f = opts
                .open(&base)
                .map_err(|e| Error::store(format!("open root {}: {e}", base.display())))?;
            Ok(RootDir(f.into()))
        }
        #[cfg(windows)]
        {
            Ok(RootDir(base))
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
    use super::{ReplaceOutcome, ReplaceStage, normalize_root, validate_rel, write_atomic_replace};
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

    /// The root spelling is NORMALIZED: a trailing separator, a repeated
    /// separator, and a non-leading `.` all name the same root as the plain
    /// spelling, while the filesystem root itself is preserved (`/` never
    /// becomes the empty path).
    #[test]
    fn normalize_root_strips_trailing_separators_and_preserves_the_root() {
        use std::path::{Path, PathBuf};
        for (spelling, want) in [
            ("a/b", "a/b"),
            ("a/b/", "a/b"),
            ("a/b//", "a/b"),
            ("a//b", "a/b"),
            ("a/./b", "a/b"),
            ("a/b///", "a/b"),
        ] {
            assert_eq!(
                normalize_root(Path::new(spelling)),
                PathBuf::from(want),
                "{spelling:?} must normalize to {want:?}"
            );
        }
        assert_eq!(normalize_root(Path::new("/")), PathBuf::from("/"));
        assert_eq!(normalize_root(Path::new("//")), PathBuf::from("/"));
    }

    /// The root-relative path guard: trailing and repeated separators are
    /// accepted (they name the same components), while an absolute path, a
    /// `..` walk, a `.`, and the empty path are refused as path errors.
    #[test]
    fn validate_rel_accepts_normal_spellings_and_refuses_escapes() {
        use std::path::Path;
        for ok in ["a", "a/b", "a/b/", "a//b", "a/./b", "a/b/c/"] {
            assert!(
                validate_rel(Path::new(ok)).is_ok(),
                "{ok:?} must be accepted"
            );
        }
        for bad in ["", ".", "./", "..", "../b", "a/../b", "a/..", "/b", "/"] {
            let err = validate_rel(Path::new(bad))
                .expect_err("an escaping or empty spelling must be refused");
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::InvalidInput,
                "{bad:?} must be an invalid-input path error"
            );
        }
    }
}
