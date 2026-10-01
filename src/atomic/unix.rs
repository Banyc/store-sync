//! The Unix implementation of the store atomic I/O: the descriptor-relative
//! owned-root confinement (`openat`/`renameat`/`linkat`/`unlinkat`/`mkdirat`
//! with `O_NOFOLLOW`) plus the POSIX durability protocol (temp fsync, atomic
//! rename, parent-directory fsync). Selected by the single `#[cfg(unix)]`
//! `mod` declaration in [`super`].
//!
//! # Which path SPELLINGS are refused
//!
//! Every path this module resolves is validated as ROOT-RELATIVE first
//! ([`validate_rel`]): only normal components are admitted, so an ABSOLUTE
//! path (whose `RootDir`/`Prefix` component makes `openat` ignore the root
//! descriptor) and a `..` component (which walks ABOVE the root) are
//! refused as path errors, as are `.` and the empty path (they name the
//! root, not an entry under it). Trailing and repeated separators are NOT
//! refused — [`Path::components`] erases them, so `a/b/` and `a//b` name
//! the same entry as `a/b` and resolve identically. The owned root itself
//! is normalized the same way before it is opened
//! ([`super::normalize_root`]), so `dir/` and `dir` are one root.
//!
//! # Which path components are refused
//!
//! Every PARENT component is resolved with component-wise
//! `openat(O_NOFOLLOW)` and a symlink there is REFUSED (ELOOP) — for every
//! primitive, reads included.
//!
//! The OPEN / CREATE-NEW helpers — [`openat_no_follow`], [`write_file_fd`],
//! [`write_atomic_cas_fd`] — also open the FINAL component with
//! `O_NOFOLLOW`, so a symlink there is refused too.
//!
//! The atomic REPLACE path — [`write_atomic_replace_fd`] — is the exception.
//! It installs with `renameat` into the descriptor-relative parent, and
//! `renameat` replaces the final directory entry WITHOUT opening it, so
//! there is no final `O_NOFOLLOW` open to raise ELOOP. A final-component
//! symlink is therefore NOT refused; it is REPLACED by a regular file at the
//! link's own in-root path, and the link's former target is left untouched.
//! That is still confinement-safe and race-free (the rename can never follow
//! the link, so it cannot escape the root), but it is "replace, never
//! follow" rather than "refuse". A caller that must REFUSE a foreign final
//! entry instead of overwriting it uses one of the open/create-new helpers
//! above — [`openat_no_follow`], [`write_file_fd`], [`write_atomic_cas_fd`],
//! or the read-side [`read_fd`] / [`path_state_fd`], all of which open the
//! final component with `O_NOFOLLOW` and so genuinely refuse it.

use super::*;
use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;

pub fn set_private(path: &Path) -> Result<()> {
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .map_err(|e| Error::store(format!("chmod {}: {e}", path.display())))
}
/// The path-based durable atomic replace: write a UNIQUE hidden temp in the
/// target's directory, fsync it, chmod it 0o600, rename it into place
/// (COMMIT POINT 1), then fsync the parent directory (COMMIT POINT 2). A
/// failure BEFORE the rename is an `Err`, leaves the OLD content visible, and
/// UNLINKS the temp (best-effort — a cleanup failure is reported together
/// with the original failure, never swallowed); see [`ReplaceOutcome`] for
/// the two commit points.
pub fn write_atomic_replace(
    path: &Path,
    bytes: &[u8],
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<ReplaceOutcome> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::store(format!("mkdir {}: {e}", parent.display())))?;
    }
    let tmp = temp_name_for(path);
    // Stage 1: the temp create/write. A failure (or an injected
    // [`ReplaceStage::Write`] fault) is a PRE-RENAME `Err`: the visible
    // target is wholly OLD.
    if let Some(e) = fault(ReplaceStage::Write) {
        return Err(e);
    }
    let mut tmp_file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
    {
        Ok(f) => f,
        // A failed CREATE means the temp was never created (or the name
        // belongs to another writer): nothing to clean up.
        Err(e) => return Err(Error::store(format!("create {}: {e}", tmp.display()))),
    };
    if let Err(e) = tmp_file.write_all(bytes) {
        // Close the temp before unlinking (Windows cannot delete an open
        // file) and remove the stray the failed write left behind.
        drop(tmp_file);
        return Err(discard_temp(
            Error::store(format!("write {}: {e}", tmp.display())),
            &tmp,
        ));
    }
    drop(tmp_file);
    // Stage 2: the temp fsync. A failure (or an injected
    // [`ReplaceStage::Sync`] fault) is a PRE-RENAME `Err`: the dot-prefixed
    // temp the replace wrote is unlinked before the `Err` returns, so no
    // stray entry survives.
    if let Some(e) = fault(ReplaceStage::Sync) {
        return Err(discard_temp(e, &tmp));
    }
    let tmp_file = match std::fs::File::open(&tmp) {
        Ok(f) => f,
        Err(e) => {
            return Err(discard_temp(
                Error::store(format!("open {}: {e}", tmp.display())),
                &tmp,
            ));
        }
    };
    if let Err(e) = tmp_file.sync_all() {
        drop(tmp_file);
        return Err(discard_temp(
            Error::store(format!("fsync {}: {e}", tmp.display())),
            &tmp,
        ));
    }
    drop(tmp_file);
    // Private BEFORE visible: the temp carries 0o600 before the rename, so
    // no reader ever observes the marker with default permissions.
    if let Err(e) = set_private(&tmp) {
        return Err(discard_temp(e, &tmp));
    }
    // Stage 3: the atomic rename — COMMIT POINT 1. A failure (or an
    // injected [`ReplaceStage::Rename`] fault) is a PRE-RENAME `Err`: the
    // visible target is wholly OLD and the temp is unlinked.
    if let Some(e) = fault(ReplaceStage::Rename) {
        return Err(discard_temp(e, &tmp));
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        return Err(discard_temp(
            Error::store(format!("rename {}: {e}", path.display())),
            &tmp,
        ));
    }
    // Stage 4: the parent-directory open + fsync — COMMIT POINT 2, AFTER
    // the rename. FAIL-CLOSED but EXPLICIT: a failed open, a failed sync,
    // or an injected [`ReplaceStage::DirSync`] fault means the NEW content
    // is visible but its durability is unconfirmed — returned as
    // [`ReplaceOutcome::ReplacedDurabilityUnknown`] carrying the original
    // error, NEVER a bare `Err` (an `Err` would falsely report that the
    // rename never happened, while the ledger commit visibly stands).
    if let Some(e) = fault(ReplaceStage::DirSync) {
        return Ok(ReplaceOutcome::ReplacedDurabilityUnknown { error: e });
    }
    if let Some(parent) = path.parent() {
        let dir = match std::fs::File::open(parent) {
            Ok(dir) => dir,
            Err(e) => {
                return Ok(ReplaceOutcome::ReplacedDurabilityUnknown {
                    error: Error::store(format!("open dir {}: {e}", parent.display())),
                });
            }
        };
        if let Err(e) = dir.sync_all() {
            return Ok(ReplaceOutcome::ReplacedDurabilityUnknown {
                error: Error::store(format!("fsync dir {}: {e}", parent.display())),
            });
        }
    }
    Ok(ReplaceOutcome::ReplacedDurable)
}
/// Durable directory sync: fsync the parent directory of `path` so a
/// rename/removal inside it survives power loss. Errors PROPAGATE (a
/// failed dir sync means the change may not be durable).
pub fn sync_parent_dir(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::store(format!("sync parent of {}: no parent", path.display())))?;
    let dir = std::fs::File::open(parent)
        .map_err(|e| Error::store(format!("open parent dir {}: {e}", parent.display())))?;
    dir.sync_all()
        .map_err(|e| Error::store(format!("fsync parent dir {}: {e}", parent.display())))
}

pub fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| Error::store(format!("mkdir {}: {e}", path.display())))?;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms)
        .map_err(|e| Error::store(format!("chmod {}: {e}", path.display())))
}

/// DURABLE private directory creation: create `path` (and every missing
/// ancestor) with the same private chmod as [`ensure_private_dir`], then make
/// EVERY newly created directory entry durable BEFORE the call returns — fsync
/// the parent directory of each component this call created (deepest first), and
/// then the parent of the new path's own parent (the entry that names the
/// directory HOLDING the new path). The store case this exists for is the FIRST
/// ledger append on a NEW target: the walk creates `targets/<target>/` while
/// `targets/` itself was already created (UNSYNCED) by the store open's
/// [`ensure_private_dir`], so the append must fsync BOTH the `targets/<target>/`
/// entry (inside `targets/`) AND the `targets/` entry (inside the base) before
/// it reports success — otherwise a power loss could lose the directories while
/// the reported ledger survives.
///
/// The helper knows what it created by creating COMPONENT-BY-COMPONENT (walk
/// up from `path` to the deepest existing ancestor, create the missing chain
/// top-down, chmod each) instead of `create_dir_all`, which cannot report what
/// it created. Syncing an already-existing ancestor is always safe (the fsync
/// only forces the entries created below it), so the extra parent-of-parent
/// sync is the harmless, conservative "sync the ancestor chain" choice.
///
/// Returns `true` when this call created at least one directory (and therefore
/// ran the syncs), `false` when everything already existed (the fast path of
/// every later append: nothing created, nothing to sync).
pub fn ensure_private_dir_durable(path: &Path) -> Result<bool> {
    // Walk from `path` up to the deepest ancestor that already exists,
    // collecting the MISSING chain (pushed deepest-first).
    let mut missing: Vec<PathBuf> = Vec::new();
    let mut cur: &Path = path;
    loop {
        match std::fs::symlink_metadata(cur) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cur.to_path_buf());
                match cur.parent() {
                    Some(parent) if !parent.as_os_str().is_empty() => cur = parent,
                    _ => break,
                }
            }
            Err(e) => return Err(Error::store(format!("stat {}: {e}", cur.display()))),
        }
    }
    if missing.is_empty() {
        return Ok(false);
    }
    // Create the chain TOP-DOWN (parents before their children) with the
    // private 0o700 chmod, exactly as `create_dir_all` + `ensure_private_dir`
    // would — one component at a time so the caller knows what was created. A
    // racing creation of an ancestor is tolerated (it exists; the chmod is
    // idempotent). NOTE: the chmod must be 0o700 (never [`set_private`]'s
    // 0o600) — a directory without its execute bit denies every subsequent
    // stat of its children.
    for component in missing.iter().rev() {
        match std::fs::create_dir(component) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(Error::store(format!("mkdir {}: {e}", component.display())));
            }
        }
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(component, perms)
            .map_err(|e| Error::store(format!("chmod {}: {e}", component.display())))?;
    }
    // Durable commit of every NEW directory entry: fsync the parent of each
    // created component (deepest first — the new dir's own entry), and then
    // the parent of the new path's PARENT — the `targets/` entry inside the
    // base — which an earlier UNSYNCED creation (the store open) may have
    // made: the first append is the first chance to make it durable.
    for component in missing.iter().rev() {
        sync_parent_dir(component)?;
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        sync_parent_dir(parent)?;
    }
    Ok(true)
}

/// TEST-ONLY path-based recursive tree copy: the store's OWN object staging
/// now uses the descriptor-relative [`copy_dir_recursive_fd`]; this path
/// variant survives for the retention checkpoint's test-only store clone
/// (which copies a whole store base to a fresh path and holds no root
/// descriptor).
#[cfg(test)]
pub fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)
        .map_err(|e| Error::store(format!("mkdir {}: {e}", dst.display())))?;
    for entry in std::fs::read_dir(src)
        .map_err(|e| Error::store(format!("read_dir {}: {e}", src.display())))?
    {
        let entry = entry.map_err(|e| Error::store(format!("entry: {e}")))?;
        let path = entry.path();
        let ft = entry
            .file_type()
            .map_err(|e| Error::store(format!("file_type: {e}")))?;
        let target = dst.join(entry.file_name());
        if ft.is_dir() {
            copy_dir_recursive(&path, &target)?;
        } else if ft.is_symlink() {
            let link = std::fs::read_link(&path)
                .map_err(|e| Error::store(format!("readlink {}: {e}", path.display())))?;
            let _ = std::fs::remove_file(&target);
            std::os::unix::fs::symlink(&link, &target)
                .map_err(|e| Error::store(format!("symlink {}: {e}", target.display())))?;
        } else {
            std::fs::copy(&path, &target)
                .map_err(|e| Error::store(format!("copy {}: {e}", path.display())))?;
        }
    }
    Ok(())
}

// =====================================================================
// DESCRIPTOR-RELATIVE I/O (the owned-root confinement)
// ---------------------------------------------------------------------
// The store's mutations resolve paths relative to the owned root's open
// directory descriptor, COMPONENT-WISE with `openat(O_NOFOLLOW)`: every
// intermediate component is opened as a directory with `O_DIRECTORY |
// O_NOFOLLOW` (a symlink at any PARENT component → ELOOP → refused). The
// open/create-new helpers also open the FINAL component with
// `O_NOFOLLOW`, so a symlink there is refused as well; the atomic REPLACE
// path does not open the final entry at all — it installs with `renameat`,
// which replaces that directory entry and cannot follow it (see
// [`write_atomic_replace_fd`]). Either way a symlink injected into a path
// component can never redirect a mutation outside the owned root — the
// descriptor pins the root, and no component is ever followed. The
// path-based free functions above stay for the retention machinery (which
// operates on paths under a store base it does not hold a descriptor
// for); the store's OWN mutations route through the `_fd` variants below.
// =====================================================================

/// Split a ROOT-RELATIVE path into its components, refusing every spelling
/// that could resolve outside the owned root (see [`validate_rel`]) and
/// returning the remaining components as raw bytes for the `openat`/
/// `mkdirat` loops. [`Path::components`] has already erased trailing and
/// repeated separators, so `a/b/` and `a//b` yield the same `a`, `b` as
/// `a/b` and keep resolving identically.
fn rel_components(rel: &Path) -> std::io::Result<Vec<&[u8]>> {
    validate_rel(rel)?;
    Ok(rel.components().map(|c| c.as_os_str().as_bytes()).collect())
}

/// Open `rel` relative to `dir_fd` COMPONENT-WISE with `O_NOFOLLOW`: every
/// intermediate component is opened as a directory (`O_RDONLY | O_DIRECTORY
/// | O_NOFOLLOW | O_CLOEXEC`), and the final component is opened with
/// `flags` plus `O_NOFOLLOW | O_CLOEXEC`. Every component, INCLUDING the
/// final one, is therefore refused (ELOOP) if it is a symlink — a mutation
/// can never be redirected outside the root the descriptor pins. `rel` is
/// validated as ROOT-RELATIVE first ([`rel_components`]): an absolute path,
/// a `..`, a `.`, or the empty path is refused before any `openat`, so the
/// spelling can never move the resolution off the root. `mode` is
/// used only when `flags` includes `O_CREAT`. The raw `_io` variant returns
/// the underlying io error (so a caller can distinguish a genuine NotFound
/// from a symlink refusal); [`openat_no_follow`] wraps it with the path
/// context.
pub fn openat_no_follow_io(
    dir_fd: &OwnedFd,
    rel: &Path,
    flags: i32,
    mode: u32,
) -> std::io::Result<OwnedFd> {
    let mut cur: OwnedFd = dir_fd.try_clone()?;
    let comps = rel_components(rel)?;
    for (i, comp) in comps.iter().enumerate() {
        let is_last = i == comps.len() - 1;
        let f = if is_last {
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
        };
        let c = CString::new(*comp).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path component with NUL")
        })?;
        let fd = unsafe { libc::openat(cur.as_raw_fd(), c.as_ptr(), f, mode) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        cur = unsafe { OwnedFd::from_raw_fd(fd) };
    }
    Ok(cur)
}

/// [`openat_no_follow_io`] with the path context folded into the store
/// error.
pub fn openat_no_follow(dir_fd: &OwnedFd, rel: &Path, flags: i32, mode: u32) -> Result<OwnedFd> {
    openat_no_follow_io(dir_fd, rel, flags, mode)
        .map_err(|e| Error::store(format!("openat {}: {e}", rel.display())))
}

/// Open the parent directory of `rel` relative to `root` (component-wise
/// with O_NOFOLLOW), returning the parent fd and the final file name. The
/// full `rel` is validated as ROOT-RELATIVE FIRST ([`rel_components`]):
/// without that guard `rel.parent()` alone would let `/b` (whose parent is
/// `/`) and `a/../b` (whose parent is `a/..`) resolve an OUTSIDE directory.
fn parent_fd_of<'a>(root: &OwnedFd, rel: &'a Path) -> Result<(OwnedFd, &'a OsStr)> {
    if let Err(e) = rel_components(rel) {
        return Err(Error::store(format!(
            "refusing path {}: {e}",
            rel.display()
        )));
    }
    let parent_rel = rel.parent().unwrap_or(Path::new(""));
    let parent_fd = if parent_rel.as_os_str().is_empty() {
        root.try_clone()
            .map_err(|e| Error::store(format!("dup root dir: {e}")))?
    } else {
        openat_no_follow(root, parent_rel, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
    };
    let file_name = rel
        .file_name()
        .ok_or_else(|| Error::store(format!("{} has no file name", rel.display())))?;
    Ok((parent_fd, file_name))
}

/// fsync a directory fd (the descriptor-relative parent-dir sync).
pub fn fsync_dir_fd(fd: &OwnedFd) -> Result<()> {
    let f = std::fs::File::from(
        fd.try_clone()
            .map_err(|e| Error::store(format!("dup dir: {e}")))?,
    );
    f.sync_all()
        .map_err(|e| Error::store(format!("fsync dir: {e}")))
}

/// renameat between two names in (possibly different) directory fds.
pub fn renameat_fd(dir_fd: &OwnedFd, from: &OsStr, to_dir: &OwnedFd, to: &OsStr) -> Result<()> {
    let from_c =
        CString::new(from.as_bytes()).map_err(|_| Error::store("rename source with NUL"))?;
    let to_c = CString::new(to.as_bytes()).map_err(|_| Error::store("rename target with NUL"))?;
    let r = unsafe {
        libc::renameat(
            dir_fd.as_raw_fd(),
            from_c.as_ptr(),
            to_dir.as_raw_fd(),
            to_c.as_ptr(),
        )
    };
    if r < 0 {
        return Err(Error::store(format!(
            "renameat: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// linkat (no AT_SYMLINK_FOLLOW — a hard link to the entry itself, never
/// to a symlink's target). Returns the raw io error so a caller can
/// distinguish the EEXIST race from a real failure.
fn linkat_fd(dir_fd: &OwnedFd, from: &OsStr, to_dir: &OwnedFd, to: &OsStr) -> std::io::Result<()> {
    let from_c = CString::new(from.as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "link source with NUL")
    })?;
    let to_c = CString::new(to.as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "link target with NUL")
    })?;
    let r = unsafe {
        libc::linkat(
            dir_fd.as_raw_fd(),
            from_c.as_ptr(),
            to_dir.as_raw_fd(),
            to_c.as_ptr(),
            0,
        )
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// unlinkat (no AT_REMOVEDIR — a file or symlink; the symlink itself is
/// removed, never its target).
fn unlinkat_fd(dir_fd: &OwnedFd, name: &OsStr) -> Result<()> {
    let c = CString::new(name.as_bytes()).map_err(|_| Error::store("unlink name with NUL"))?;
    let r = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c.as_ptr(), 0) };
    if r < 0 {
        return Err(Error::store(format!(
            "unlinkat: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Open-or-create a directory component relative to `cur` (O_DIRECTORY |
/// O_NOFOLLOW; created with 0o700 when missing, tolerating a racing
/// creation). A symlink at the component is refused (ELOOP); a
/// non-directory is refused (ENOTDIR).
fn open_or_create_dir(cur: &OwnedFd, comp: &[u8]) -> Result<OwnedFd> {
    let c = CString::new(comp).map_err(|_| Error::store("path component with NUL"))?;
    let fd = unsafe {
        libc::openat(
            cur.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if fd >= 0 {
        return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
    }
    let e = std::io::Error::last_os_error();
    if e.kind() != std::io::ErrorKind::NotFound {
        return Err(Error::store(format!("openat: {e}")));
    }
    let r = unsafe { libc::mkdirat(cur.as_raw_fd(), c.as_ptr(), 0o700) };
    if r < 0 {
        let e2 = std::io::Error::last_os_error();
        if e2.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(Error::store(format!("mkdirat: {e2}")));
        }
    }
    let fd2 = unsafe {
        libc::openat(
            cur.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
        )
    };
    if fd2 < 0 {
        return Err(Error::store(format!(
            "openat: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd2) })
}

/// Read a whole file through an already-open descriptor.
fn read_fd_to_end(fd: &OwnedFd) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::from(
        fd.try_clone()
            .map_err(|e| Error::store(format!("dup fd: {e}")))?,
    );
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .map_err(|e| Error::store(format!("read: {e}")))?;
    Ok(buf)
}

/// Iterate the entries of the directory `dir_fd` (via `fdopendir`),
/// calling `f` with each entry's name (excluding `.` and `..`). The fd is
/// NOT consumed (a clone is passed to fdopendir).
fn for_each_dir_entry(dir_fd: &OwnedFd, mut f: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
    // `fdopendir` TAKES OWNERSHIP of the fd: transfer the clone's raw fd
    // (never drop the OwnedFd — that would double-close the fd the
    // directory stream owns).
    let clone = dir_fd
        .try_clone()
        .map_err(|e| Error::store(format!("dup dir: {e}")))?;
    let dir = unsafe { libc::fdopendir(clone.into_raw_fd()) };
    if dir.is_null() {
        return Err(Error::store(format!(
            "fdopendir: {}",
            std::io::Error::last_os_error()
        )));
    }
    loop {
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let name = name.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        f(name)?;
    }
    unsafe { libc::closedir(dir) };
    Ok(())
}

/// Best-effort unlink of a FAILED descriptor-relative atomic replace's temp
/// (the [`discard_temp`] contract, expressed with `unlinkat` against the
/// parent fd): on success the original error is returned unchanged; when the
/// unlink itself fails the returned error carries BOTH failures, never a
/// swallowed cleanup failure. NEVER called after a successful rename (the
/// temp name no longer exists).
fn discard_temp_fd(original: Error, parent_fd: &OwnedFd, tmp_name: &OsStr) -> Error {
    match unlinkat_fd(parent_fd, tmp_name) {
        Ok(()) => original,
        Err(e) => original.with_context(format!(
            "additionally failed to unlink the failed replace's temp {}: {e}",
            tmp_name.to_string_lossy()
        )),
    }
}

/// The descriptor-relative atomic replace: the same four-stage protocol as
/// [`write_atomic_replace`], but the path resolves COMPONENT-WISE relative
/// to `root` with `openat(O_NOFOLLOW)`. Every PARENT component is refused
/// (ELOOP) if it is a symlink; the FINAL entry is NOT opened — the install
/// is a `renameat` into the descriptor-relative parent, which replaces the
/// final directory entry and so cannot follow it. A final-component symlink
/// is therefore REPLACED by a regular file at the link's own in-root path
/// (the link's former target is left untouched) rather than refused; the
/// replace still cannot escape the root, race-free. A caller that must
/// REFUSE a foreign final entry instead of overwriting it uses one of the
/// open/create-new primitives — [`openat_no_follow`], [`write_file_fd`],
/// [`write_atomic_cas_fd`], [`read_fd`], or [`path_state_fd`]. The parent
/// directory is created via [`ensure_private_dir_fd`] if missing. A failure
/// BEFORE the rename UNLINKS the temp before the `Err` returns (best-effort,
/// the cleanup failure carried with the original one), so a failed replace
/// leaves no stray temp; the post-rename parent-fsync failure is NOT a
/// cleanup point (the temp name no longer exists).
pub fn write_atomic_replace_fd(
    root: &RootDir,
    rel: &Path,
    bytes: &[u8],
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<ReplaceOutcome> {
    // The parent directory is created if missing — the same
    // `create_dir_all(parent)` the path-based protocol runs first —
    // component-wise with O_NOFOLLOW (a symlink injected into any parent
    // component is refused).
    let parent_rel = rel.parent().unwrap_or(Path::new(""));
    if !parent_rel.as_os_str().is_empty() {
        ensure_private_dir_fd(root, parent_rel)?;
    }
    let (parent_fd, file_name) = parent_fd_of(root.as_fd(), rel)?;
    let tmp_name = temp_file_name(file_name);
    // Stage 1: the temp create/write. A failure (or an injected
    // [`ReplaceStage::Write`] fault) is a PRE-RENAME `Err`: the visible
    // target is wholly OLD.
    if let Some(e) = fault(ReplaceStage::Write) {
        return Err(e);
    }
    // A failed CREATE means the temp was never created (or the name belongs
    // to another writer): nothing to clean up, so the error propagates as-is.
    let tmp_fd = openat_no_follow(
        &parent_fd,
        Path::new(&tmp_name),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    let mut f = std::fs::File::from(tmp_fd);
    if let Err(e) = f.write_all(bytes) {
        drop(f);
        return Err(discard_temp_fd(
            Error::store(format!("write {}: {e}", rel.display())),
            &parent_fd,
            &tmp_name,
        ));
    }
    drop(f);
    // Stage 2: the temp fsync. A failure (or an injected
    // [`ReplaceStage::Sync`] fault) is a PRE-RENAME `Err`: the dot-prefixed
    // temp the replace wrote is unlinked before the `Err` returns, so no
    // stray entry survives.
    if let Some(e) = fault(ReplaceStage::Sync) {
        return Err(discard_temp_fd(e, &parent_fd, &tmp_name));
    }
    let f = match openat_no_follow(&parent_fd, Path::new(&tmp_name), libc::O_RDONLY, 0) {
        Ok(fd) => std::fs::File::from(fd),
        Err(e) => return Err(discard_temp_fd(e, &parent_fd, &tmp_name)),
    };
    if let Err(e) = f.sync_all() {
        drop(f);
        return Err(discard_temp_fd(
            Error::store(format!("fsync {}: {e}", rel.display())),
            &parent_fd,
            &tmp_name,
        ));
    }
    drop(f);
    // Private BEFORE visible: the temp carries 0o600 before the rename, so
    // no reader ever observes the marker with default permissions.
    let f = match openat_no_follow(&parent_fd, Path::new(&tmp_name), libc::O_RDONLY, 0) {
        Ok(fd) => std::fs::File::from(fd),
        Err(e) => return Err(discard_temp_fd(e, &parent_fd, &tmp_name)),
    };
    if let Err(e) = f.set_permissions(std::fs::Permissions::from_mode(0o600)) {
        drop(f);
        return Err(discard_temp_fd(
            Error::store(format!("chmod {}: {e}", rel.display())),
            &parent_fd,
            &tmp_name,
        ));
    }
    drop(f);
    // Stage 3: the atomic rename — COMMIT POINT 1. A failure (or an
    // injected [`ReplaceStage::Rename`] fault) is a PRE-RENAME `Err`: the
    // visible target is wholly OLD and the temp is unlinked.
    if let Some(e) = fault(ReplaceStage::Rename) {
        return Err(discard_temp_fd(e, &parent_fd, &tmp_name));
    }
    if let Err(e) = renameat_fd(&parent_fd, &tmp_name, &parent_fd, file_name) {
        return Err(discard_temp_fd(e, &parent_fd, &tmp_name));
    }
    // Stage 4: the parent-directory open + fsync — COMMIT POINT 2, AFTER
    // the rename. FAIL-CLOSED but EXPLICIT (see [`write_atomic_replace`]).
    if let Some(e) = fault(ReplaceStage::DirSync) {
        return Ok(ReplaceOutcome::ReplacedDurabilityUnknown { error: e });
    }
    if let Err(e) = fsync_dir_fd(&parent_fd) {
        return Ok(ReplaceOutcome::ReplacedDurabilityUnknown { error: e });
    }
    Ok(ReplaceOutcome::ReplacedDurable)
}

/// The descriptor-relative create-or-compare CAS: the same protocol as
/// [`write_atomic_cas`], but every path resolves COMPONENT-WISE relative to
/// `root` with `openat(O_NOFOLLOW)`. A symlink injected at the final
/// component is REFUSED (ELOOP) — never followed, never compared against
/// its target.
pub fn write_atomic_cas_fd(root: &RootDir, rel: &Path, bytes: &[u8]) -> Result<()> {
    let (parent_fd, file_name) = parent_fd_of(root.as_fd(), rel)?;
    // If the file exists, its content must be byte-identical (an identical
    // rewrite is an idempotent success; a symlink at the final component is
    // refused by the O_NOFOLLOW open — never followed).
    match openat_no_follow_io(&parent_fd, Path::new(file_name), libc::O_RDONLY, 0) {
        Ok(f) => {
            let existing = read_fd_to_end(&f)?;
            if existing == bytes {
                return Ok(());
            }
            return Err(Error::store(format!(
                "refusing to replace existing {} with different content",
                rel.display()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(Error::store(format!("open {}: {e}", rel.display())));
        }
    }
    // The file is absent: write a unique temp, install WITHOUT replacement
    // (linkat fails on EEXIST, so a racing loser can never clobber a winner
    // and no reader ever sees a torn record), unlink the temp name, then
    // fsync the parent directory.
    let tmp_name = temp_file_name(file_name);
    // A failed CREATE means the temp was never created (or the name belongs
    // to another writer): nothing to clean up, so the error propagates as-is.
    let tmp_fd = openat_no_follow(
        &parent_fd,
        Path::new(&tmp_name),
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    let mut f = std::fs::File::from(tmp_fd);
    if let Err(e) = f.write_all(bytes) {
        drop(f);
        return Err(discard_temp_fd(
            Error::store(format!("write {}: {e}", rel.display())),
            &parent_fd,
            &tmp_name,
        ));
    }
    if let Err(e) = f.sync_all() {
        drop(f);
        return Err(discard_temp_fd(
            Error::store(format!("fsync {}: {e}", rel.display())),
            &parent_fd,
            &tmp_name,
        ));
    }
    drop(f);
    let installed = match linkat_fd(&parent_fd, &tmp_name, &parent_fd, file_name) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => {
            return Err(discard_temp_fd(
                Error::store(format!("install {}: {e}", rel.display())),
                &parent_fd,
                &tmp_name,
            ));
        }
    };
    // The install is done (our content, or the racing winner's): removing the
    // temp name is the protocol's own bookkeeping, so a failure there must NOT
    // turn a committed CAS into an error — best-effort, as before.
    let _ = unlinkat_fd(&parent_fd, &tmp_name);
    if !installed {
        // Lost the race: the winner's content must match ours or refuse.
        let f = openat_no_follow(&parent_fd, Path::new(file_name), libc::O_RDONLY, 0)?;
        let existing = read_fd_to_end(&f)?;
        if existing != bytes {
            return Err(Error::store(format!(
                "refusing to replace existing {} with different content",
                rel.display()
            )));
        }
        return Ok(());
    }
    // Private BEFORE visible: chmod the installed file, then fsync the
    // parent directory (THE DURABILITY COMMIT POINT — fail closed, see
    // [`write_atomic_cas`]).
    {
        let f = std::fs::File::from(openat_no_follow(
            &parent_fd,
            Path::new(file_name),
            libc::O_RDONLY,
            0,
        )?);
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))?;
    }
    fsync_dir_fd(&parent_fd)?;
    Ok(())
}

/// The descriptor-relative private-directory creation: create `rel` (and
/// every missing ancestor) component-wise relative to `root` with
/// `mkdirat`/`openat(O_NOFOLLOW)`, chmodding the FINAL directory to 0o700
/// (the same contract as [`ensure_private_dir`]). A symlink at any
/// component is refused (ELOOP) — never followed.
pub fn ensure_private_dir_fd(root: &RootDir, rel: &Path) -> Result<()> {
    let comps = rel_components(rel)
        .map_err(|e| Error::store(format!("refusing path {}: {e}", rel.display())))?;
    let mut cur: OwnedFd = root
        .as_fd()
        .try_clone()
        .map_err(|e| Error::store(format!("dup root dir: {e}")))?;
    for (i, comp) in comps.iter().enumerate() {
        let is_last = i == comps.len() - 1;
        let dir = open_or_create_dir(&cur, comp)?;
        if is_last {
            let f = std::fs::File::from(
                dir.try_clone()
                    .map_err(|e| Error::store(format!("dup dir: {e}")))?,
            );
            f.set_permissions(std::fs::Permissions::from_mode(0o700))
                .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))?;
        }
        cur = dir;
    }
    Ok(())
}

/// The descriptor-relative DURABLE private-directory creation: the same
/// component-by-component creation + per-component 0o700 chmod as
/// [`ensure_private_dir_durable`], then the same durable commit — fsync the
/// parent of each created component (deepest first), then the parent of the
/// new path's own parent — all through directory fds. Returns `true` when
/// this call created at least one directory.
pub fn ensure_private_dir_durable_fd(root: &RootDir, rel: &Path) -> Result<bool> {
    let comps = rel_components(rel)
        .map_err(|e| Error::store(format!("refusing path {}: {e}", rel.display())))?;
    let mut dirs: Vec<OwnedFd> = Vec::with_capacity(comps.len());
    let mut cur: OwnedFd = root
        .as_fd()
        .try_clone()
        .map_err(|e| Error::store(format!("dup root dir: {e}")))?;
    let mut created: Vec<usize> = Vec::new();
    for (i, comp) in comps.iter().enumerate() {
        let c = CString::new(*comp).map_err(|_| Error::store("path component with NUL"))?;
        let fd = unsafe {
            libc::openat(
                cur.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            )
        };
        if fd >= 0 {
            cur = unsafe { OwnedFd::from_raw_fd(fd) };
        } else {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(Error::store(format!("openat {}: {e}", rel.display())));
            }
            let r = unsafe { libc::mkdirat(cur.as_raw_fd(), c.as_ptr(), 0o700) };
            if r < 0 {
                let e2 = std::io::Error::last_os_error();
                if e2.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(Error::store(format!("mkdirat {}: {e2}", rel.display())));
                }
            }
            let fd2 = unsafe {
                libc::openat(
                    cur.as_raw_fd(),
                    c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0,
                )
            };
            if fd2 < 0 {
                return Err(Error::store(format!(
                    "openat {}: {}",
                    rel.display(),
                    std::io::Error::last_os_error()
                )));
            }
            let dir = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd2) });
            dir.set_permissions(std::fs::Permissions::from_mode(0o700))
                .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))?;
            cur = dir.into();
            created.push(i);
        }
        dirs.push(
            cur.try_clone()
                .map_err(|e| Error::store(format!("dup dir: {e}")))?,
        );
    }
    if created.is_empty() {
        return Ok(false);
    }
    // Durable commit of every NEW directory entry: fsync the parent of each
    // created component (deepest first), then the parent of the new path's
    // own parent (the entry that names the directory HOLDING the new path).
    for &i in created.iter().rev() {
        if i == 0 {
            fsync_dir_fd(root.as_fd())?;
        } else {
            fsync_dir_fd(&dirs[i - 1])?;
        }
    }
    if comps.len() >= 2 {
        if comps.len() >= 3 {
            fsync_dir_fd(&dirs[comps.len() - 3])?;
        } else {
            fsync_dir_fd(root.as_fd())?;
        }
    }
    Ok(true)
}

/// The descriptor-relative parent-directory fsync: fsync the directory
/// holding `rel` (the durability commit of a rename/removal inside it).
pub fn sync_parent_dir_fd(root: &RootDir, rel: &Path) -> Result<()> {
    let parent_rel = rel.parent().unwrap_or(Path::new(""));
    let parent_fd = if parent_rel.as_os_str().is_empty() {
        root.as_fd()
            .try_clone()
            .map_err(|e| Error::store(format!("dup root dir: {e}")))?
    } else {
        openat_no_follow(
            root.as_fd(),
            parent_rel,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?
    };
    fsync_dir_fd(&parent_fd)
}

/// The descriptor-relative private chmod (0o600) of a file under the root.
pub fn set_private_fd(root: &RootDir, rel: &Path) -> Result<()> {
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    let f = std::fs::File::from(openat_no_follow(
        &parent_fd,
        Path::new(name),
        libc::O_RDONLY,
        0,
    )?);
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))
}

/// The descriptor-relative remove of a single file (or symlink — the
/// symlink itself is removed, never its target).
pub fn remove_file_fd(root: &RootDir, rel: &Path) -> Result<()> {
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    unlinkat_fd(&parent_fd, name)
}

/// The descriptor-relative rename of a path under the root to another path
/// under the root (both parents resolved component-wise with O_NOFOLLOW).
pub fn renameat_paths(root: &RootDir, from: &Path, to: &Path) -> Result<()> {
    let (from_fd, from_name) = parent_fd_of(root.as_fd(), from)?;
    let (to_fd, to_name) = parent_fd_of(root.as_fd(), to)?;
    renameat_fd(&from_fd, from_name, &to_fd, to_name)
}

/// The descriptor-relative recursive removal of a directory tree: every
/// entry is classified with `fstatat(AT_SYMLINK_NOFOLLOW)` (a symlink is
/// removed as the entry itself, never followed), subdirectories are
/// recursed into, and the tree root is removed last. A symlink injected at
/// any component is refused (ELOOP) — never followed.
pub fn remove_dir_all_fd(root: &RootDir, rel: &Path) -> Result<()> {
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    let dir_fd = openat_no_follow(
        &parent_fd,
        Path::new(name),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    remove_dir_contents_fd(&dir_fd, rel)?;
    let c = CString::new(name.as_bytes()).map_err(|_| Error::store("rmdir name with NUL"))?;
    let r = unsafe { libc::unlinkat(parent_fd.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) };
    if r < 0 {
        return Err(Error::store(format!(
            "rmdir {}: {}",
            rel.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Remove the CONTENTS of the directory `dir_fd` (recursively), leaving the
/// directory itself in place.
fn remove_dir_contents_fd(dir_fd: &OwnedFd, rel: &Path) -> Result<()> {
    for_each_dir_entry(dir_fd, |name| {
        let child_rel = rel.join(Path::new(std::ffi::OsStr::from_bytes(name)));
        let c = CString::new(name).map_err(|_| Error::store("path component with NUL"))?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if r < 0 {
            return Err(Error::store(format!(
                "fstatat {}: {}",
                child_rel.display(),
                std::io::Error::last_os_error()
            )));
        }
        if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            let sub = openat_no_follow(
                dir_fd,
                Path::new(std::ffi::OsStr::from_bytes(name)),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
            remove_dir_contents_fd(&sub, &child_rel)?;
            let r = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) };
            if r < 0 {
                return Err(Error::store(format!(
                    "rmdir {}: {}",
                    child_rel.display(),
                    std::io::Error::last_os_error()
                )));
            }
        } else {
            // A file or symlink: unlinkat removes the entry itself (a
            // symlink is removed, never its target).
            unlinkat_fd(dir_fd, std::ffi::OsStr::from_bytes(name))?;
        }
        Ok(())
    })
}

/// The descriptor-relative recursive tree copy: the DESTINATION resolves
/// component-wise relative to `root` with O_NOFOLLOW (a symlink injected
/// into a destination component is refused); the SOURCE is read from its
/// absolute path (a read, never a mutation). Directory and file modes are
/// copied EXACTLY from the source (the tree digest includes modes — a
/// mode-shifted copy would fail the staged-object verification).
pub fn copy_dir_recursive_fd(root: &RootDir, src: &Path, dst_rel: &Path) -> Result<()> {
    // Create the destination directory with the SOURCE directory's mode
    // (the digest includes modes; the copy must preserve them exactly).
    let src_mode = std::fs::metadata(src)
        .map_err(|e| Error::store(format!("stat {}: {e}", src.display())))?
        .permissions()
        .mode();
    create_dir_chain_fd(root.as_fd(), dst_rel, src_mode)?;
    let dst_fd = openat_no_follow(root.as_fd(), dst_rel, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    for entry in std::fs::read_dir(src)
        .map_err(|e| Error::store(format!("read_dir {}: {e}", src.display())))?
    {
        let entry = entry.map_err(|e| Error::store(format!("entry: {e}")))?;
        let name = entry.file_name();
        let ft = entry
            .file_type()
            .map_err(|e| Error::store(format!("file_type: {e}")))?;
        let child_rel = dst_rel.join(&name);
        if ft.is_dir() {
            copy_dir_recursive_fd(root, &entry.path(), &child_rel)?;
        } else if ft.is_symlink() {
            let link = std::fs::read_link(entry.path())
                .map_err(|e| Error::store(format!("readlink {}: {e}", entry.path().display())))?;
            // Remove any existing entry at the target (the original removes
            // the target before symlinking), then symlinkat.
            let _ = unlinkat_fd(&dst_fd, &name);
            let name_c =
                CString::new(name.as_bytes()).map_err(|_| Error::store("symlink name with NUL"))?;
            let target_c = CString::new(link.as_os_str().as_bytes())
                .map_err(|_| Error::store("symlink target with NUL"))?;
            let r =
                unsafe { libc::symlinkat(target_c.as_ptr(), dst_fd.as_raw_fd(), name_c.as_ptr()) };
            if r < 0 {
                return Err(Error::store(format!(
                    "symlinkat {}: {}",
                    child_rel.display(),
                    std::io::Error::last_os_error()
                )));
            }
        } else {
            let src_f = std::fs::File::open(entry.path())
                .map_err(|e| Error::store(format!("open {}: {e}", entry.path().display())))?;
            let mode = src_f
                .metadata()
                .map_err(|e| Error::store(format!("fstat {}: {e}", entry.path().display())))?
                .permissions()
                .mode();
            let dst_f = openat_no_follow(
                &dst_fd,
                Path::new(&name),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                mode,
            )?;
            let mut dst_f = std::fs::File::from(dst_f);
            std::io::copy(&mut &src_f, &mut dst_f)
                .map_err(|e| Error::store(format!("copy {}: {e}", entry.path().display())))?;
            dst_f
                .set_permissions(std::fs::Permissions::from_mode(mode))
                .map_err(|e| Error::store(format!("chmod {}: {e}", child_rel.display())))?;
        }
    }
    Ok(())
}

/// Create the directory chain `rel` relative to `root` component-wise with
/// O_NOFOLLOW, chmodding the FINAL directory to `mode` (the intermediate
/// components are outside the tree root, so their modes do not affect the
/// tree digest).
fn create_dir_chain_fd(root: &OwnedFd, rel: &Path, mode: u32) -> Result<()> {
    let comps = rel_components(rel)
        .map_err(|e| Error::store(format!("refusing path {}: {e}", rel.display())))?;
    let mut cur: OwnedFd = root
        .try_clone()
        .map_err(|e| Error::store(format!("dup root dir: {e}")))?;
    for (i, comp) in comps.iter().enumerate() {
        let is_last = i == comps.len() - 1;
        let dir = open_or_create_dir(&cur, comp)?;
        if is_last {
            let f = std::fs::File::from(
                dir.try_clone()
                    .map_err(|e| Error::store(format!("dup dir: {e}")))?,
            );
            f.set_permissions(std::fs::Permissions::from_mode(mode))
                .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))?;
        }
        cur = dir;
    }
    Ok(())
}

/// The descriptor-relative recursive tree fsync: the same deepest-first
/// protocol as [`fsync_tree_recursive`], but every entry is classified with
/// `fstatat(AT_SYMLINK_NOFOLLOW)` and opened relative to the root's
/// descriptor — a symlink injected into any component is refused (ELOOP),
/// never followed. Symlinks are SKIPPED (their durability is their
/// directory entry, covered by the parent-dir fsync).
pub fn fsync_tree_recursive_fd(root: &RootDir, rel: &Path) -> Result<()> {
    let dir_fd = openat_no_follow(root.as_fd(), rel, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    for_each_dir_entry(&dir_fd, |name| {
        let child_rel = rel.join(Path::new(std::ffi::OsStr::from_bytes(name)));
        let c = CString::new(name).map_err(|_| Error::store("path component with NUL"))?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if r < 0 {
            return Err(Error::store(format!(
                "fstatat {}: {}",
                child_rel.display(),
                std::io::Error::last_os_error()
            )));
        }
        if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            fsync_tree_recursive_fd(root, &child_rel)?;
        } else if (st.st_mode & libc::S_IFMT) == libc::S_IFREG {
            let f = std::fs::File::from(openat_no_follow(
                &dir_fd,
                Path::new(std::ffi::OsStr::from_bytes(name)),
                libc::O_RDONLY | libc::O_NOFOLLOW,
                0,
            )?);
            f.sync_all()
                .map_err(|e| Error::store(format!("fsync {}: {e}", child_rel.display())))?;
        }
        // Symlinks and other entries are SKIPPED (their durability is their
        // directory entry, covered by the parent-dir fsync).
        Ok(())
    })?;
    fsync_dir_fd(&dir_fd)
}

/// The descriptor-relative plain file write (create-or-truncate, 0o600):
/// used for the staged object's `tree.json` metadata (the staged tree is
/// fsynced as a whole by [`fsync_tree_recursive_fd`] before the publish).
pub fn write_file_fd(root: &RootDir, rel: &Path, bytes: &[u8]) -> Result<()> {
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    let f = openat_no_follow(
        &parent_fd,
        Path::new(name),
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
        0o600,
    )?;
    let mut f = std::fs::File::from(f);
    f.write_all(bytes)
        .map_err(|e| Error::store(format!("write {}: {e}", rel.display())))
}

// =====================================================================
// DESCRIPTOR-RELATIVE READS (the owned-root confinement, read side)
// ---------------------------------------------------------------------
// The store's READS resolve paths relative to the owned root's open
// directory descriptor, COMPONENT-WISE with `openat(O_NOFOLLOW)` — every
// PARENT component is refused and, unlike the atomic REPLACE path, the
// FINAL component is opened with `O_NOFOLLOW` and so is refused too: a
// symlink injected into ANY path component of a read is refused (ELOOP),
// never followed, so a read can never be redirected outside the owned
// root. The path-based free functions above
// (`read_json`, `path_state`) stay for the retention machinery (which
// operates on paths under a store base it does not hold a descriptor
// for); the store's OWN reads route through the `_fd` variants below.
// =====================================================================

/// Read the whole file at `rel` relative to `dir_fd`, resolved
/// COMPONENT-WISE with `openat(O_NOFOLLOW)`: every intermediate component
/// is opened as a directory (`O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
/// O_CLOEXEC`) and the final component is opened with
/// `O_RDONLY | O_NOFOLLOW | O_CLOEXEC`. A symlink injected at ANY
/// component is refused (ELOOP) — a read can never be redirected outside
/// the root the descriptor pins.
pub fn read_fd(root: &RootDir, rel: &Path) -> Result<Vec<u8>> {
    let f = openat_no_follow(root.as_fd(), rel, libc::O_RDONLY, 0)?;
    read_fd_to_end(&f)
}

/// Read the target of the symlink at `rel` relative to `root`, the fd-confined
/// counterpart of the path-based `std::fs::read_link`. The PARENT is resolved
/// COMPONENT-WISE with `openat(O_NOFOLLOW)` (a symlink injected into any parent
/// component is refused — ELOOP — never followed), and the target itself is
/// read with `readlinkat` without following it. A final component that is not a
/// symlink is an error, and a missing entry is the same [`Error::store`] class
/// the other `_fd` primitives report.
pub fn read_link_fd(root: &RootDir, rel: &Path) -> Result<PathBuf> {
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    let c = CString::new(name.as_bytes())
        .map_err(|_| Error::store("readlink path component with NUL"))?;
    let mut buf: Vec<u8> = vec![0; 256];
    loop {
        let n = unsafe {
            libc::readlinkat(
                parent_fd.as_raw_fd(),
                c.as_ptr(),
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
            )
        };
        if n < 0 {
            return Err(Error::store(format!(
                "readlinkat {}: {}",
                rel.display(),
                std::io::Error::last_os_error()
            )));
        }
        let n = n as usize;
        if n < buf.len() {
            buf.truncate(n);
            return Ok(PathBuf::from(std::ffi::OsString::from_vec(buf)));
        }
        buf.resize(buf.len() * 2, 0);
    }
}

/// [`read_fd`] + JSON deserialization (the descriptor-relative mirror of
/// [`read_json`] for the store's own record reads).
pub fn read_json_fd<T: serde::de::DeserializeOwned>(root: &RootDir, rel: &Path) -> Result<T> {
    let bytes = read_fd(root, rel)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::store(format!("deserialize {}: {e}", rel.display())))
}

/// The descriptor-relative TRI-STATE existence check (the mirror of
/// [`path_state`] for the store's own reads): resolve `rel` component-wise
/// with `O_NOFOLLOW` and `fstat` the final component. A symlink at ANY
/// component is REFUSED (ELOOP — never followed); a genuine NotFound of
/// the final component is ABSENCE (`Ok(false)`); EVERY other filesystem
/// error is a real failure → [`Error::store`], NEVER treated as absence.
pub fn path_state_fd(root: &RootDir, rel: &Path) -> Result<bool> {
    match openat_no_follow_io(root.as_fd(), rel, libc::O_RDONLY, 0) {
        Ok(fd) => {
            let f = std::fs::File::from(fd);
            f.metadata()
                .map_err(|e| Error::store(format!("fstat {}: {e}", rel.display())))?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::store(format!("openat {}: {e}", rel.display()))),
    }
}

/// The KIND of the entry at `rel` relative to `root`, classified WITHOUT
/// following a final-component symlink — the companion of [`path_state_fd`]
/// for callers that must HANDLE a symlink rather than refuse it (a sync
/// that replaces or removes a symlink destination).
///
/// The PARENT is resolved component-wise with [`parent_fd_of`]
/// (`openat(O_NOFOLLOW)`), so a symlink injected at any parent component is
/// REFUSED (ELOOP), never followed, and `rel` is validated as
/// ROOT-RELATIVE first, so an absolute path, a `..`, a `.`, and the empty
/// path are refused before any `openat` — the same guards as every other
/// `_fd` primitive. The final component is then classified with
/// `fstatat(parent_fd, name, AT_SYMLINK_NOFOLLOW)` from the mode's
/// `S_IFMT`, so a symlink whose TARGET is a directory is
/// [`PathKind::Symlink`], never [`PathKind::Dir`]. A missing entry is
/// ABSENCE (`Ok(None)`); every other filesystem error is a real failure →
/// [`Error::store`].
///
/// [`parent_fd_of`]: super::parent_fd_of
pub fn path_kind_fd(root: &RootDir, rel: &Path) -> Result<Option<PathKind>> {
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    let c = CString::new(name.as_bytes()).map_err(|_| Error::store("path component with NUL"))?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let r = unsafe {
        libc::fstatat(
            parent_fd.as_raw_fd(),
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(Error::store(format!("fstatat {}: {e}", rel.display())));
    }
    Ok(Some(kind_from_mode(st.st_mode)))
}

/// Classify an entry kind from a POSIX `S_IFMT` mode (`stat`'s
/// `st_mode`), WITHOUT consulting any symlink target (the mode is the
/// link's own mode because the caller passed `AT_SYMLINK_NOFOLLOW`).
fn kind_from_mode(mode: libc::mode_t) -> PathKind {
    match mode & libc::S_IFMT {
        libc::S_IFREG => PathKind::File,
        libc::S_IFDIR => PathKind::Dir,
        libc::S_IFLNK => PathKind::Symlink,
        _ => PathKind::Other,
    }
}

/// Read the entries of the directory at `rel` relative to `dir_fd`,
/// resolved COMPONENT-WISE with `openat(O_NOFOLLOW)` (a symlink injected
/// at any component is refused — ELOOP — never followed). Each entry is
/// classified with `fstatat(AT_SYMLINK_NOFOLLOW)` (a symlink entry is
/// reported as a non-directory, never followed).
pub fn read_dir_fd(root: &RootDir, rel: &Path) -> Result<Vec<DirEntry>> {
    let dir_fd = openat_no_follow(root.as_fd(), rel, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    let mut out = Vec::new();
    for_each_dir_entry(&dir_fd, |name| {
        let c = CString::new(name).map_err(|_| Error::store("path component with NUL"))?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::fstatat(
                dir_fd.as_raw_fd(),
                c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if r < 0 {
            return Err(Error::store(format!(
                "fstatat {}: {}",
                rel.join(Path::new(std::ffi::OsStr::from_bytes(name)))
                    .display(),
                std::io::Error::last_os_error()
            )));
        }
        out.push(DirEntry {
            name: std::ffi::OsStr::from_bytes(name).to_os_string(),
            is_dir: (st.st_mode & libc::S_IFMT) == libc::S_IFDIR,
        });
        Ok(())
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        Error, PathKind, ReplaceOutcome, ReplaceStage, RootDir, path_kind_fd, read_dir_fd, read_fd,
        read_link_fd, write_atomic_cas_fd, write_atomic_replace, write_atomic_replace_fd,
    };
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    /// The entry names DIRECTLY under the path-based directory `dir`, sorted:
    /// a failed replace must leave NOTHING but the names the test seeded.
    fn entry_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// The entry names directly under the descriptor-relative directory `rel`
    /// (through the module's own walk), sorted.
    fn dir_names_fd(root: &RootDir, rel: &Path) -> Vec<String> {
        let mut names: Vec<String> = read_dir_fd(root, rel)
            .unwrap()
            .into_iter()
            .map(|e| e.name.to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn only(path: &str) -> Vec<String> {
        vec![path.to_string()]
    }

    fn owned_root() -> (tempfile::TempDir, RootDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = RootDir::open(dir.path()).expect("open the owned root");
        (dir, root)
    }

    /// The same path spelled with a TRAILING separator.
    fn with_trailing_separator(path: &Path) -> PathBuf {
        let mut spelled = path.as_os_str().to_os_string();
        spelled.push("/");
        PathBuf::from(spelled)
    }

    /// Open a root that must be refused, returning the refusal.
    fn open_must_fail(path: &Path) -> Error {
        match RootDir::open(path) {
            Ok(_) => panic!("RootDir::open({}) must be refused", path.display()),
            Err(e) => e,
        }
    }

    /// `(device, inode)` of the directory an owned root descriptor pins: two
    /// descriptors with the same pair name the same directory.
    fn dir_identity(root: &RootDir) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let f = std::fs::File::from(root.as_fd().try_clone().unwrap());
        let md = f.metadata().unwrap();
        (md.dev(), md.ino())
    }

    /// A normal symlink resolves to its stored target through the fd path.
    #[test]
    fn read_link_fd_returns_a_symlink_target() {
        let (dir, root) = owned_root();
        std::os::unix::fs::symlink("target.txt", dir.path().join("link")).unwrap();
        assert_eq!(
            read_link_fd(&root, Path::new("link")).unwrap(),
            PathBuf::from("target.txt")
        );
    }

    /// A symlink injected at a PARENT component is refused by the
    /// component-wise open, and the outside link is never read.
    #[test]
    fn read_link_fd_refuses_a_parent_component_symlink() {
        let (dir, root) = owned_root();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink("OUTSIDE-TARGET", outside.join("secret")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join("sub")).unwrap();

        let err = read_link_fd(&root, Path::new("sub/secret"))
            .expect_err("a read through a symlink-injected parent must be refused");
        assert!(
            matches!(err, Error::Store(_)),
            "the refusal must be a store error, got: {err:?}"
        );
        let text = err.to_string();
        assert!(
            text.contains("openat"),
            "the refusal must name the component-wise open, got: {text}"
        );
        assert!(
            !text.contains("OUTSIDE-TARGET"),
            "the outside link's target must never be read, got: {text}"
        );
        assert_eq!(
            std::fs::read_link(outside.join("secret")).unwrap(),
            PathBuf::from("OUTSIDE-TARGET"),
            "the outside link must be untouched"
        );
    }

    /// A final component that is not a symlink is an error, never a
    /// fabricated target.
    #[test]
    fn read_link_fd_errors_when_the_final_component_is_not_a_symlink() {
        let (dir, root) = owned_root();
        std::fs::write(dir.path().join("plain.txt"), b"x").unwrap();
        let err = read_link_fd(&root, Path::new("plain.txt"))
            .expect_err("a non-symlink final component must be an error");
        assert!(matches!(err, Error::Store(_)), "got: {err:?}");
        assert!(
            err.to_string().contains("readlinkat"),
            "the error must come from readlinkat, got: {err}"
        );
    }

    /// A missing entry is the same store-error class the other `_fd`
    /// primitives report for a missing path.
    #[test]
    fn read_link_fd_reports_a_missing_entry_as_a_store_error() {
        let (_dir, root) = owned_root();
        let err =
            read_link_fd(&root, Path::new("missing")).expect_err("a missing entry must error");
        assert!(matches!(err, Error::Store(_)), "got: {err:?}");
    }

    /// Every entry kind is classified from the entry's OWN mode:
    /// a regular file is `File`, a directory is `Dir`, a symlink is
    /// `Symlink` — INCLUDING a symlink whose TARGET is a directory (the
    /// whole point: it must never read as `Dir`) — a FIFO is `Other`, and
    /// a missing path is `Ok(None)`.
    #[test]
    fn path_kind_fd_classifies_without_following_a_symlink() {
        let (dir, root) = owned_root();
        std::fs::write(dir.path().join("file"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("dir")).unwrap();
        std::os::unix::fs::symlink("file", dir.path().join("link")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("dir"), dir.path().join("dirlink")).unwrap();

        let fifo = dir.path().join("fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) },
            0,
            "mkfifo must succeed"
        );

        assert_eq!(
            path_kind_fd(&root, Path::new("file")).unwrap(),
            Some(PathKind::File),
            "a regular file is File"
        );
        assert_eq!(
            path_kind_fd(&root, Path::new("dir")).unwrap(),
            Some(PathKind::Dir),
            "a directory is Dir"
        );
        assert_eq!(
            path_kind_fd(&root, Path::new("link")).unwrap(),
            Some(PathKind::Symlink),
            "a symlink is Symlink, never its target's kind"
        );
        assert_eq!(
            path_kind_fd(&root, Path::new("dirlink")).unwrap(),
            Some(PathKind::Symlink),
            "a symlink TO A DIRECTORY must still be Symlink, never Dir"
        );
        assert_eq!(
            path_kind_fd(&root, Path::new("fifo")).unwrap(),
            Some(PathKind::Other),
            "a FIFO is Other"
        );
        assert_eq!(
            path_kind_fd(&root, Path::new("missing")).unwrap(),
            None,
            "a missing path is absence"
        );
    }

    /// A symlink injected at a PARENT component is refused by the
    /// component-wise `openat(O_NOFOLLOW)` guard, never followed — the
    /// outside directory is not even stat'd for the entry.
    #[test]
    fn path_kind_fd_refuses_a_parent_component_symlink() {
        let (dir, root) = owned_root();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"OUTSIDE").unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join("sub")).unwrap();

        let err = path_kind_fd(&root, Path::new("sub/secret"))
            .expect_err("a parent-component symlink must be refused, not followed");
        assert!(matches!(err, Error::Store(_)), "got: {err:?}");
        assert!(
            err.to_string().contains("openat"),
            "the refusal must name the component-wise open, got: {err}"
        );
    }

    /// An absolute path, a `..` walk, a `.`, and the empty path are refused
    /// by the ROOT-RELATIVE guard — before any `fstatat` — exactly as the
    /// other `_fd` primitives refuse them.
    #[test]
    fn path_kind_fd_refuses_escaping_spellings() {
        let (dir, root) = owned_root();
        let absolute = dir.path().join("outside").as_os_str().to_os_string();
        for spelling in [
            PathBuf::from("/etc"),
            PathBuf::from(&absolute),
            PathBuf::from(".."),
            PathBuf::from("../secret"),
            PathBuf::from("a/../secret"),
            PathBuf::from("."),
            PathBuf::new(),
        ] {
            let err = path_kind_fd(&root, &spelling)
                .expect_err("an escaping or empty spelling must be refused");
            assert!(
                matches!(err, Error::Store(_)) && err.to_string().contains("normal component"),
                "{spelling:?} must be refused by the root-relative guard, got: {err}"
            );
        }
    }

    /// A real directory opens with and without a trailing slash, and both
    /// descriptors pin the SAME directory inode: `dir/` is one root with
    /// `dir`, never a different (or symlink-followed) resolution.
    #[test]
    fn root_dir_open_normalizes_a_trailing_separator_to_the_same_directory() {
        let dir = tempfile::tempdir().unwrap();
        let plain = RootDir::open(dir.path()).expect("the plain spelling opens");
        let spelled = RootDir::open(&with_trailing_separator(dir.path()))
            .expect("the trailing-separator spelling opens the same directory");
        assert_eq!(
            dir_identity(&plain),
            dir_identity(&spelled),
            "`dir/` and `dir` must pin the same directory inode"
        );
    }

    /// A symlink-to-directory root is REFUSED with and without a trailing
    /// slash: normalization strips the separator, so the `O_NOFOLLOW` open
    /// sees the link (ELOOP/ENOTDIR) instead of following it as an
    /// intermediate component.
    #[test]
    fn root_dir_open_refuses_a_symlink_root_with_and_without_a_trailing_separator() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        for spelling in [link.clone(), with_trailing_separator(&link)] {
            let err = open_must_fail(&spelling);
            assert!(matches!(err, Error::Store(_)), "got: {err:?}");
            assert!(
                err.to_string().contains("open root"),
                "the refusal must come from the root open, got: {err}"
            );
        }
    }

    /// A regular-file root is REFUSED with and without a trailing slash
    /// (`O_DIRECTORY`): the two spellings agree.
    #[test]
    fn root_dir_open_refuses_a_regular_file_with_and_without_a_trailing_separator() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"not a directory").unwrap();
        for spelling in [file.clone(), with_trailing_separator(&file)] {
            let err = open_must_fail(&spelling);
            assert!(matches!(err, Error::Store(_)), "got: {err:?}");
            assert!(
                err.to_string().contains("open root"),
                "the refusal must come from the root open, got: {err}"
            );
        }
    }

    /// The root-relative spelling rule, pinned: trailing and repeated
    /// separators name the SAME in-root entry, while an absolute path, a
    /// `..` walk, `.`, and the empty path are refused by the ROOT-RELATIVE
    /// GUARD — not incidentally by a missing or symlinked outside entry —
    /// and so can never resolve to an outside entry.
    #[test]
    fn relative_path_spelling_resolves_identically_or_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let root_path = tmp.path().join("root");
        std::fs::create_dir(&root_path).unwrap();
        let root = RootDir::open(&root_path).expect("open the owned root");
        std::fs::create_dir_all(root_path.join("a")).unwrap();
        std::fs::write(root_path.join("a/b"), b"IN-ROOT").unwrap();
        for spelling in ["a/b", "a/b/", "a//b", "a/./b"] {
            assert_eq!(
                read_fd(&root, Path::new(spelling)).unwrap(),
                b"IN-ROOT".to_vec(),
                "{spelling:?} must name the same entry as a/b"
            );
        }

        // A real OUTSIDE file a `..` walk would reach if it were resolved:
        // the root lives one level down, so `../outside-secret` is a real
        // sibling. Without the guard the read would SUCCEED and leak it.
        let outside = tmp.path().join("outside-secret");
        std::fs::write(&outside, b"OUTSIDE-SECRET").unwrap();
        let absolute = outside.as_os_str().to_os_string();
        for spelling in [
            PathBuf::from("/b"),
            PathBuf::from(".."),
            PathBuf::from("../outside-secret"),
            PathBuf::from("a/../../outside-secret"),
            PathBuf::from("a/../b"),
            PathBuf::from("."),
            PathBuf::new(),
            Path::new(&absolute).to_path_buf(),
        ] {
            let err = read_fd(&root, &spelling)
                .expect_err("an escaping or empty spelling must be refused");
            let text = err.to_string();
            assert!(
                matches!(err, Error::Store(_)) && text.contains("normal component"),
                "{spelling:?} must be refused by the root-relative guard, got: {text}"
            );
        }

        // A mutation spelling is refused the same way: nothing lands outside.
        let err = super::write_file_fd(&root, Path::new("../outside-secret"), b"NOPE")
            .expect_err("a `..` mutation spelling must be refused");
        assert!(err.to_string().contains("normal component"), "got: {err}");
        assert_eq!(
            std::fs::read(&outside).unwrap().as_slice(),
            b"OUTSIDE-SECRET",
            "the outside file must be untouched and its bytes never returned"
        );
    }

    // =================================================================
    // TEMP CLEANUP ON A FAILED ATOMIC REPLACE
    // ----------------------------------------------------------------
    // Every pre-rename failure (and even a COMPLETED rename) must leave no
    // stray dot-prefixed temp behind, while the two commit points keep the
    // OLD content visible before the rename and the NEW content after it.
    // =================================================================

    /// A fault at EACH PRE-RENAME stage leaves the OLD content visible and the
    /// directory holding ONLY the seeded destination — the failed replace's
    /// temp is unlinked before the `Err` is returned.
    #[test]
    fn failed_path_replace_at_each_pre_rename_stage_leaves_no_temp_and_old_content() {
        for stage in [
            ReplaceStage::Write,
            ReplaceStage::Sync,
            ReplaceStage::Rename,
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("marker.json");
            std::fs::write(&path, b"OLD").unwrap();
            let err = write_atomic_replace(&path, b"NEW", &mut |s| {
                (s == stage).then(|| Error::store(format!("injected {stage:?} fault")))
            })
            .unwrap_err();
            assert!(matches!(err, Error::Store(_)), "{stage:?}: got {err:?}");
            assert_eq!(
                std::fs::read(&path).unwrap(),
                b"OLD".to_vec(),
                "{stage:?}: the OLD content must stay visible"
            );
            assert_eq!(
                entry_names(dir.path()),
                only("marker.json"),
                "{stage:?}: a failed replace must leave no stray temp"
            );
        }
    }

    /// The descriptor-relative replace obeys the same cleanup contract: a
    /// fault at each pre-rename stage leaves the OLD content visible and NO
    /// temp entry in the parent directory.
    #[test]
    fn failed_fd_replace_at_each_pre_rename_stage_leaves_no_temp_and_old_content() {
        let rel = Path::new("sub/marker.json");
        for stage in [
            ReplaceStage::Write,
            ReplaceStage::Sync,
            ReplaceStage::Rename,
        ] {
            let (dir, root) = owned_root();
            std::fs::create_dir_all(dir.path().join("sub")).unwrap();
            std::fs::write(dir.path().join("sub/marker.json"), b"OLD").unwrap();
            let err = write_atomic_replace_fd(&root, rel, b"NEW", &mut |s| {
                (s == stage).then(|| Error::store(format!("injected {stage:?} fault")))
            })
            .unwrap_err();
            assert!(matches!(err, Error::Store(_)), "{stage:?}: got {err:?}");
            assert_eq!(
                read_fd(&root, rel).unwrap(),
                b"OLD".to_vec(),
                "{stage:?}: the OLD content must stay visible"
            );
            assert_eq!(
                dir_names_fd(&root, Path::new("sub")),
                only("marker.json"),
                "{stage:?}: a failed replace must leave no stray temp"
            );
        }
    }

    /// A REAL failure of COMMIT POINT 1 (no fault hook): the destination is an
    /// existing DIRECTORY, so the rename fails. The temp is unlinked and the
    /// directory the rename could not replace is untouched.
    #[test]
    fn real_rename_failure_onto_a_directory_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marker.json");
        std::fs::create_dir(&path).unwrap();
        let err = write_atomic_replace(&path, b"NEW", &mut |_| None).unwrap_err();
        assert!(matches!(err, Error::Store(_)), "got: {err:?}");
        assert!(
            err.to_string().contains("rename"),
            "the failure must be the rename, got: {err}"
        );
        assert_eq!(
            entry_names(dir.path()),
            only("marker.json"),
            "a real rename failure must leave no stray temp"
        );
        assert!(path.is_dir(), "the un-replaced directory must be untouched");
    }

    /// A REAL failure of the descriptor-relative COMMIT POINT 1: `renameat`
    /// onto an existing directory fails and the temp is unlinked.
    #[test]
    fn real_fd_rename_failure_onto_a_directory_leaves_no_temp() {
        let (dir, root) = owned_root();
        std::fs::create_dir_all(dir.path().join("sub/marker.json")).unwrap();
        let err =
            write_atomic_replace_fd(&root, Path::new("sub/marker.json"), b"NEW", &mut |_| None)
                .unwrap_err();
        assert!(matches!(err, Error::Store(_)), "got: {err:?}");
        assert_eq!(
            dir_names_fd(&root, Path::new("sub")),
            only("marker.json"),
            "a real renameat failure must leave no stray temp"
        );
    }

    /// COMMIT POINT 2 (path-based): a post-rename parent-fsync fault leaves the
    /// NEW content in place, reports `ReplacedDurabilityUnknown`, and does NOT
    /// unlink the destination (there is no temp left to remove).
    #[test]
    fn post_rename_fsync_fault_leaves_new_content_and_no_temp_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marker.json");
        std::fs::write(&path, b"OLD").unwrap();
        let outcome = write_atomic_replace(&path, b"NEW", &mut |s| {
            (s == ReplaceStage::DirSync).then(|| Error::store("injected dir fsync fault"))
        })
        .unwrap();
        assert!(matches!(
            outcome,
            ReplaceOutcome::ReplacedDurabilityUnknown {
                error: Error::Store(_)
            }
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"NEW".to_vec());
        assert_eq!(entry_names(dir.path()), only("marker.json"));
    }

    /// COMMIT POINT 2 (descriptor-relative): same post-rename contract — the
    /// NEW content survives and nothing is unlinked.
    #[test]
    fn post_rename_fsync_fault_leaves_new_content_and_no_temp_fd() {
        let (dir, root) = owned_root();
        let rel = Path::new("marker.json");
        std::fs::write(dir.path().join("marker.json"), b"OLD").unwrap();
        let outcome = write_atomic_replace_fd(&root, rel, b"NEW", &mut |s| {
            (s == ReplaceStage::DirSync).then(|| Error::store("injected dir fsync fault"))
        })
        .unwrap();
        assert!(matches!(
            outcome,
            ReplaceOutcome::ReplacedDurabilityUnknown {
                error: Error::Store(_)
            }
        ));
        assert_eq!(read_fd(&root, rel).unwrap(), b"NEW".to_vec());
        assert_eq!(entry_names(dir.path()), only("marker.json"));
    }

    /// A SUCCESSFUL replace leaves exactly the destination (no temp) and still
    /// reports `ReplacedDurable`, for both the path-based and the
    /// descriptor-relative writers.
    #[test]
    fn successful_replace_leaves_only_the_destination_and_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marker.json");
        std::fs::write(&path, b"OLD").unwrap();
        let outcome = write_atomic_replace(&path, b"NEW", &mut |_| None).unwrap();
        assert!(matches!(outcome, ReplaceOutcome::ReplacedDurable));
        assert_eq!(std::fs::read(&path).unwrap(), b"NEW".to_vec());
        assert_eq!(entry_names(dir.path()), only("marker.json"));

        let (_dir, root) = owned_root();
        let rel = Path::new("nested/marker.json");
        let outcome = write_atomic_replace_fd(&root, rel, b"NEW", &mut |_| None).unwrap();
        assert!(matches!(outcome, ReplaceOutcome::ReplacedDurable));
        assert_eq!(read_fd(&root, rel).unwrap(), b"NEW".to_vec());
        assert_eq!(
            dir_names_fd(&root, Path::new("nested")),
            only("marker.json")
        );
    }

    /// The cleanup is best-effort but NOT silent: when the temp cannot be
    /// unlinked, the returned error carries BOTH the original failure and the
    /// cleanup failure. The fault hook swaps the just-written temp for a
    /// DIRECTORY, so the writer's `remove_file` cleanup must fail.
    #[test]
    fn failed_path_replace_reports_a_failed_cleanup_with_both_failures() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marker.json");
        std::fs::write(&path, b"OLD").unwrap();
        let mut swapped: Option<PathBuf> = None;
        let err = write_atomic_replace(&path, b"NEW", &mut |stage| {
            if stage != ReplaceStage::Rename {
                return None;
            }
            let temp = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|e| e.unwrap().path())
                .find(|p| {
                    p.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .starts_with(".marker.json.tmp.")
                })
                .expect("the temp exists at the rename stage");
            std::fs::remove_file(&temp).unwrap();
            std::fs::create_dir(&temp).unwrap();
            swapped = Some(temp);
            Some(Error::store("injected rename fault"))
        })
        .unwrap_err();
        assert!(matches!(err, Error::Store(_)), "got: {err:?}");
        let text = err.to_string();
        assert!(
            text.contains("injected rename fault"),
            "the ORIGINAL failure must be reported, got: {text}"
        );
        assert!(
            text.contains("failed to unlink"),
            "the CLEANUP failure must be reported, got: {text}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"OLD".to_vec(),
            "the destination must still hold the OLD content"
        );
        // Remove the deliberate stray directory so the tempdir tears down.
        std::fs::remove_dir(swapped.expect("the hook recorded the temp")).unwrap();
    }

    /// The descriptor-relative REPLACE and the CAS both leave no temp on a
    /// committed success — the temp name is consumed (replace) or unlinked
    /// (CAS) once the entry is installed.
    #[test]
    fn committed_replace_and_cas_leave_no_temp() {
        let (dir, root) = owned_root();
        let rel = Path::new("marker.json");
        write_atomic_replace_fd(&root, rel, b"NEW", &mut |_| None).unwrap();
        assert_eq!(entry_names(dir.path()), only("marker.json"));
        assert_eq!(read_fd(&root, rel).unwrap(), b"NEW".to_vec());

        let (dir, root) = owned_root();
        let rel = Path::new("cas.json");
        write_atomic_cas_fd(&root, rel, b"FIRST").unwrap();
        assert_eq!(entry_names(dir.path()), only("cas.json"));
        write_atomic_cas_fd(&root, rel, b"FIRST").unwrap();
        assert_eq!(entry_names(dir.path()), only("cas.json"));
        assert_eq!(read_fd(&root, rel).unwrap(), b"FIRST".to_vec());
    }

    /// A CAS that refuses different content returns an `Err` and leaves only
    /// the existing destination (no temp is created on the refusal path).
    #[test]
    fn refusing_cas_leaves_only_the_destination() {
        let (dir, root) = owned_root();
        let rel = Path::new("cas.json");
        std::fs::write(dir.path().join("cas.json"), b"OLD").unwrap();
        let err = write_atomic_cas_fd(&root, rel, b"NEW").unwrap_err();
        assert!(matches!(err, Error::Store(_)), "got: {err:?}");
        assert_eq!(entry_names(dir.path()), only("cas.json"));
        assert_eq!(read_fd(&root, rel).unwrap(), b"OLD".to_vec());
    }
}
