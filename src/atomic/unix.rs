//! The Unix implementation of the store atomic I/O: the descriptor-relative
//! owned-root confinement (`openat`/`renameat`/`linkat`/`unlinkat`/`mkdirat`
//! with `O_NOFOLLOW` — a symlink injected into any path component is refused,
//! never followed) plus the POSIX durability protocol (temp fsync, atomic
//! rename, parent-directory fsync). Selected by the single `#[cfg(unix)]`
//! `mod` declaration in [`super`].

use super::*;
use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;

pub fn set_private(path: &Path) -> Result<()> {
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)
        .map_err(|e| Error::store(format!("chmod {}: {e}", path.display())))
}
/// Unique temp-file name for an atomic replace of `path`: same directory,
/// hidden dot-prefixed name carrying the process id and a process-scoped
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
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| Error::store(format!("create {}: {e}", tmp.display())))?;
        f.write_all(bytes)
            .map_err(|e| Error::store(format!("write {}: {e}", tmp.display())))?;
    }
    // Stage 2: the temp fsync. A failure (or an injected
    // [`ReplaceStage::Sync`] fault) is a PRE-RENAME `Err`: only an
    // invisible dot-prefixed temp exists.
    if let Some(e) = fault(ReplaceStage::Sync) {
        return Err(e);
    }
    {
        let f = std::fs::File::open(&tmp)
            .map_err(|e| Error::store(format!("open {}: {e}", tmp.display())))?;
        f.sync_all()
            .map_err(|e| Error::store(format!("fsync {}: {e}", tmp.display())))?;
    }
    // Private BEFORE visible: the temp carries 0o600 before the rename, so
    // no reader ever observes the marker with default permissions.
    set_private(&tmp)?;
    // Stage 3: the atomic rename — COMMIT POINT 1. A failure (or an
    // injected [`ReplaceStage::Rename`] fault) is a PRE-RENAME `Err`: the
    // visible target is wholly OLD.
    if let Some(e) = fault(ReplaceStage::Rename) {
        return Err(e);
    }
    std::fs::rename(&tmp, path)
        .map_err(|e| Error::store(format!("rename {}: {e}", path.display())))?;
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
// O_NOFOLLOW` (a symlink at ANY component → ELOOP → refused), and the
// final component is opened with `O_NOFOLLOW`. A symlink injected into a
// path component can never redirect a mutation outside the owned root —
// the descriptor pins the root, and no component is ever followed. The
// path-based free functions above stay for the retention machinery (which
// operates on paths under a store base it does not hold a descriptor
// for); the store's OWN mutations route through the `_fd` variants below.
// =====================================================================
// DESCRIPTOR-RELATIVE I/O (the owned-root confinement)
// ---------------------------------------------------------------------
// The store's mutations resolve paths relative to the owned root's open
// directory descriptor, COMPONENT-WISE with `openat(O_NOFOLLOW)`: every
// intermediate component is opened as a directory with `O_DIRECTORY |
// O_NOFOLLOW` (a symlink at ANY component → ELOOP → refused), and the
// final component is opened with `O_NOFOLLOW`. A symlink injected into a
// path component can never redirect a mutation outside the owned root —
// the descriptor pins the root, and no component is ever followed.
// =====================================================================

/// Open `rel` relative to `dir_fd` COMPONENT-WISE with `O_NOFOLLOW`: every
/// intermediate component is opened as a directory (`O_RDONLY | O_DIRECTORY
/// | O_NOFOLLOW | O_CLOEXEC`), and the final component is opened with
/// `flags` plus `O_NOFOLLOW | O_CLOEXEC`. A symlink injected at ANY
/// component is refused (ELOOP) — a mutation can never be redirected
/// outside the root the descriptor pins. `mode` is used only when `flags`
/// includes `O_CREAT`. The raw `_io` variant returns the underlying io
/// error (so a caller can distinguish a genuine NotFound from a symlink
/// refusal); [`openat_no_follow`] wraps it with the path context.
/// intermediate component is opened as a directory (`O_RDONLY | O_DIRECTORY
/// | O_NOFOLLOW | O_CLOEXEC`), and the final component is opened with
/// `flags` plus `O_NOFOLLOW | O_CLOEXEC`. A symlink injected at ANY
/// component is refused (ELOOP) — a mutation can never be redirected
/// outside the root the descriptor pins. `mode` is used only when `flags`
/// includes `O_CREAT`. The raw `_io` variant returns the underlying io
/// error (so a caller can distinguish a genuine NotFound from a symlink
/// refusal); [`openat_no_follow`] wraps it with the path context.
pub fn openat_no_follow_io(
    dir_fd: &OwnedFd,
    rel: &Path,
    flags: i32,
    mode: u32,
) -> std::io::Result<OwnedFd> {
    let mut cur: OwnedFd = dir_fd.try_clone()?;
    let comps: Vec<&[u8]> = rel.components().map(|c| c.as_os_str().as_bytes()).collect();
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
/// with O_NOFOLLOW), returning the parent fd and the final file name.
fn parent_fd_of<'a>(root: &OwnedFd, rel: &'a Path) -> Result<(OwnedFd, &'a OsStr)> {
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

/// The descriptor-relative atomic replace: the same four-stage protocol as
/// [`write_atomic_replace`], but every path resolves COMPONENT-WISE
/// relative to `root` with `openat(O_NOFOLLOW)` — a symlink injected into
/// any path component is refused (ELOOP), never followed. The parent
/// directory must already exist (the store creates it via
/// [`ensure_private_dir_fd`] before the write).
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
    {
        let tmp_fd = openat_no_follow(
            &parent_fd,
            Path::new(&tmp_name),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        let mut f = std::fs::File::from(tmp_fd);
        f.write_all(bytes)
            .map_err(|e| Error::store(format!("write {}: {e}", rel.display())))?;
    }
    // Stage 2: the temp fsync. A failure (or an injected
    // [`ReplaceStage::Sync`] fault) is a PRE-RENAME `Err`: only an
    // invisible dot-prefixed temp exists.
    if let Some(e) = fault(ReplaceStage::Sync) {
        return Err(e);
    }
    {
        let f = std::fs::File::from(openat_no_follow(
            &parent_fd,
            Path::new(&tmp_name),
            libc::O_RDONLY,
            0,
        )?);
        f.sync_all()
            .map_err(|e| Error::store(format!("fsync {}: {e}", rel.display())))?;
    }
    // Private BEFORE visible: the temp carries 0o600 before the rename, so
    // no reader ever observes the marker with default permissions.
    {
        let f = std::fs::File::from(openat_no_follow(
            &parent_fd,
            Path::new(&tmp_name),
            libc::O_RDONLY,
            0,
        )?);
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))?;
    }
    // Stage 3: the atomic rename — COMMIT POINT 1. A failure (or an
    // injected [`ReplaceStage::Rename`] fault) is a PRE-RENAME `Err`: the
    // visible target is wholly OLD.
    if let Some(e) = fault(ReplaceStage::Rename) {
        return Err(e);
    }
    renameat_fd(&parent_fd, &tmp_name, &parent_fd, file_name)?;
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
    {
        let tmp_fd = openat_no_follow(
            &parent_fd,
            Path::new(&tmp_name),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        let mut f = std::fs::File::from(tmp_fd);
        f.write_all(bytes)
            .map_err(|e| Error::store(format!("write {}: {e}", rel.display())))?;
        f.sync_all()
            .map_err(|e| Error::store(format!("fsync {}: {e}", rel.display())))?;
    }
    let installed = match linkat_fd(&parent_fd, &tmp_name, &parent_fd, file_name) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(e) => {
            let _ = unlinkat_fd(&parent_fd, &tmp_name);
            return Err(Error::store(format!("install {}: {e}", rel.display())));
        }
    };
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
    let mut cur: OwnedFd = root
        .as_fd()
        .try_clone()
        .map_err(|e| Error::store(format!("dup root dir: {e}")))?;
    let comps: Vec<&[u8]> = rel.components().map(|c| c.as_os_str().as_bytes()).collect();
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
    let comps: Vec<&[u8]> = rel.components().map(|c| c.as_os_str().as_bytes()).collect();
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
    let mut cur: OwnedFd = root
        .try_clone()
        .map_err(|e| Error::store(format!("dup root dir: {e}")))?;
    let comps: Vec<&[u8]> = rel.components().map(|c| c.as_os_str().as_bytes()).collect();
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
// directory descriptor, COMPONENT-WISE with `openat(O_NOFOLLOW)` — the
// SAME refusal the mutations enforce: a symlink injected into ANY path
// component is refused (ELOOP), never followed, so a read can never be
// redirected outside the owned root. The path-based free functions above
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
