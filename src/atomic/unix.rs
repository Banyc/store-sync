//! The Unix implementation of the store atomic I/O: the descriptor-relative
//! owned-root confinement (`openat`/`renameat`/`linkat`/`unlinkat`/`mkdirat`
//! with `O_NOFOLLOW`) plus the POSIX durability protocol (temp fsync, atomic
//! rename, parent-directory fsync). Selected by the single `#[cfg(unix)]`
//! `mod` declaration in [`super`].
//!
//! # Which path SPELLINGS are refused
//!
//! Every path the DESCRIPTOR-RELATIVE (`_fd`) surface resolves is validated
//! as ROOT-RELATIVE first ([`validate_rel`]): only normal components are
//! admitted, so an ABSOLUTE path (whose `RootDir`/`Prefix` component makes
//! `openat` ignore the root descriptor) and a `..` component (which walks
//! ABOVE the root) are refused as path errors, as are `.` and the empty path
//! (they name the root, not an entry under it). Trailing and repeated
//! separators are NOT refused — [`Path::components`] erases them, so `a/b/`
//! and `a//b` name the same entry as `a/b` and resolve identically. The owned
//! root itself is normalized the same way before it is opened
//! ([`super::normalize_root`]), so `dir/` and `dir` are one root.
//!
//! # Which path components are refused
//!
//! On the DESCRIPTOR-RELATIVE (`_fd`) surface — the one that resolves a
//! root-relative path component-wise against an [`OwnedFd`] for the owned
//! root — every PARENT component is resolved with component-wise
//! `openat(O_NOFOLLOW)` and a symlink there is REFUSED (ELOOP), reads
//! included.
//!
//! NOT COVERED by that component confinement: the module's PATH-BASED free
//! functions take an ordinary [`Path`] and resolve it with
//! `std::fs`/`std::fs::Permissions`, so an INTERMEDIATE symlink in that path
//! IS followed. They are [`set_private`], [`write_atomic_replace`],
//! [`sync_parent_dir`], [`ensure_private_dir`],
//! [`ensure_private_dir_durable`], [`copy_dir_recursive`], and
//! [`remove_dir_all_path`] (the manifest walk's root access is path-based by
//! design). The component confinement claimed below belongs to the `_fd`
//! surface only, never to these.
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

/// TEST-ONLY ORDERING PROBE for the atomic replace (A1). It records, on the
/// calling thread only, the sequence of directory-entry commits the durable
/// directory helper performs and the rename the replace performs, so a test can
/// assert that every directory the replace CREATED had its entry fsynced into
/// its own parent BEFORE the rename (the ordering the durability claim rests
/// on). It is a no-op in a production build (the whole module is
/// `#[cfg(test)]`).
#[cfg(test)]
pub(crate) mod replace_order_probe {
    use std::cell::RefCell;
    thread_local! {
        static EVENTS: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
    }
    pub(crate) fn begin() {
        EVENTS.with(|events| *events.borrow_mut() = Some(Vec::new()));
    }
    pub(crate) fn record(event: String) {
        EVENTS.with(|events| {
            if let Some(list) = events.borrow_mut().as_mut() {
                list.push(event);
            }
        });
    }
    pub(crate) fn take() -> Vec<String> {
        EVENTS.with(|events| events.borrow_mut().take().unwrap_or_default())
    }
}

/// Record a created-directory ENTRY-FSYNC for the ordering probe. A no-op
/// outside test builds.
#[cfg(test)]
fn probe_commit_entry(prefix: &str) {
    replace_order_probe::record(format!("commit-dir-entry {prefix}"));
}
#[cfg(not(test))]
fn probe_commit_entry(_prefix: &str) {}

/// Record the atomic replace's `renameat` for the ordering probe.
#[cfg(test)]
fn probe_rename() {
    replace_order_probe::record("rename".to_string());
}
#[cfg(not(test))]
fn probe_rename() {}

/// Record the atomic replace's post-rename parent-directory fsync.
#[cfg(test)]
fn probe_fsync_replace_parent() {
    replace_order_probe::record("fsync-replace-parent".to_string());
}
#[cfg(not(test))]
fn probe_fsync_replace_parent() {}

pub fn set_private(path: &Path) -> Result<()> {
    refuse_lock_record_mutation(path)?;
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
    // The PATH-BASED replace DESTROYS the target entry's inode (the temp is
    // renamed OVER it), so it belongs on the guarded list exactly like the
    // `_fd` replace (F-A1): replacing the lock record would swap its inode
    // and let a later acquisition flock a fresh inode while a live holder
    // still holds the old one. The guard consults the ONE authority and the
    // FULL path (see [`refuse_lock_record_mutation`]).
    refuse_lock_record_mutation(path)?;
    if let Some(parent) = path.parent() {
        // DURABLE creation of the parent chain: every directory created here
        // has its own entry fsynced into its parent BEFORE the temp write and
        // the rename, so the replace's durability claim covers the WHOLE chain
        // (A1). `create_dir_all` left the created directories' entries unsynced.
        ensure_private_dir_durable(parent)?;
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
    probe_rename();
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
    // Creation only: a residue spelling is permitted (mkdir cannot destroy),
    // and the lock authority still runs.
    refuse_reserved_mutation(path, Sanction::Residue)?;
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
    refuse_reserved_mutation(path, Sanction::Residue)?;
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
        probe_commit_entry(&component.to_string_lossy());
        sync_parent_dir(component)?;
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        sync_parent_dir(parent)?;
    }
    Ok(true)
}

/// TEST-ONLY path-based recursive tree copy: a path-based walk that must not
/// recurse one Rust frame per level (a deep test-only store clone would
/// otherwise exhaust the C stack and abort the test process). It copies a
/// whole tree to a fresh path and holds no root descriptor; the store's own
/// fd-confined copy is the generic [`crate::transport::Remote::copy_tree`]
/// walk (`copy_tree_walk`).
///
/// The traversal descends into a subdirectory the moment it is encountered,
/// so its visit order is EXACTLY the pre-rewrite recursion's depth-first
/// pre-order (files and subdirectories interleaved in `readdir` order) —
/// not "every file at a level, then every subdirectory" — which keeps the
/// partial-failure state and the error ordering identical to the
/// recursion's. The `copy_dir_recursive_visits_in_recursive_preorder` test
/// pins this order.
#[cfg(test)]
pub fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    struct Frame {
        dst: PathBuf,
        entries: std::vec::IntoIter<std::fs::DirEntry>,
    }

    fn open_frame(src: &Path, dst: &Path) -> Result<Frame> {
        std::fs::create_dir_all(dst)
            .map_err(|e| Error::store(format!("mkdir {}: {e}", dst.display())))?;
        let entries = std::fs::read_dir(src)
            .map_err(|e| Error::store(format!("read_dir {}: {e}", src.display())))?
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|e| Error::store(format!("entry: {e}")))?;
        Ok(Frame {
            dst: dst.to_path_buf(),
            entries: entries.into_iter(),
        })
    }

    let mut stack: Vec<Frame> = vec![open_frame(src, dst)?];
    while let Some(top) = stack.last_mut() {
        let next = top.entries.next();
        let Some(entry) = next else {
            stack.pop();
            continue;
        };
        let descend: Option<Frame> = {
            let top = stack.last().expect("the frame just examined");
            let path = entry.path();
            let ft = entry
                .file_type()
                .map_err(|e| Error::store(format!("file_type: {e}")))?;
            let target = top.dst.join(entry.file_name());
            if ft.is_dir() {
                Some(open_frame(&path, &target)?)
            } else if ft.is_symlink() {
                let link = std::fs::read_link(&path)
                    .map_err(|e| Error::store(format!("readlink {}: {e}", path.display())))?;
                let _ = std::fs::remove_file(&target);
                std::os::unix::fs::symlink(&link, &target)
                    .map_err(|e| Error::store(format!("symlink {}: {e}", target.display())))?;
                None
            } else {
                std::fs::copy(&path, &target)
                    .map_err(|e| Error::store(format!("copy {}: {e}", path.display())))?;
                None
            }
        };
        if let Some(frame) = descend {
            stack.push(frame);
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
    // R3, closed at the PRIMITIVE: an open that can create, replace, or
    // truncate a directory entry is a name mutation, so the lock-record guard
    // runs HERE, on the full relative path, for EVERY caller — a new
    // primitive that reaches for this wrapper with `O_WRONLY|O_CREAT|O_TRUNC`
    // is guarded without its author remembering to be. A read-only open
    // (`O_RDONLY` is 0) is untouched.
    if open_flags_mutate(flags) {
        refuse_lock_record_mutation(rel).map_err(|e| std::io::Error::other(e.to_string()))?;
    }
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

/// Whether an `openat` flag set can CREATE, REPLACE, or TRUNCATE a directory
/// entry. `O_RDONLY` is 0, so a pure read is `false`; every write/append/
/// create/truncate flag is `true`. This is the predicate the chokepoint in
/// [`openat_no_follow_io`] uses, and it is deliberately conservative.
fn open_flags_mutate(flags: i32) -> bool {
    const MUTATING: i32 =
        libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND;
    flags & MUTATING != 0
}

/// [`openat_no_follow_io`] with the path context folded into the store
/// error.
pub fn openat_no_follow(dir_fd: &OwnedFd, rel: &Path, flags: i32, mode: u32) -> Result<OwnedFd> {
    openat_no_follow_io(dir_fd, rel, flags, mode)
        .map_err(|e| Error::store(format!("openat {}: {e}", rel.display())))
}

/// Open the final component `rel` relative to `dir_fd` without following a
/// symlink and WITHOUT BLOCKING, then require the OPENED inode to be a regular
/// file or a directory.
///
/// `open(2)` of a FIFO read-only BLOCKS until a writer appears, so a read-side
/// primitive that opens user data with a bare `O_RDONLY` hangs forever on one
/// FIFO in the store — an unbounded hang on user data. `O_NONBLOCK` is a no-op
/// for a regular file and a directory, so adding it makes the open return
/// immediately, and classifying the OPENED inode with `fstat` refuses a
/// FIFO/socket/device with a clear error instead of reading it. This is the
/// local shape of the far-side fsync helper (`sysopen(..., O_RDONLY|O_NONBLOCK)`
/// then `stat` and `die` on a non-regular entry): classify the
/// opened inode, never assume its kind from the path. `O_NOFOLLOW` is applied
/// by [`openat_no_follow_io`], so a final-component symlink is refused (ELOOP)
/// before the classification.
fn openat_readable_regular(dir_fd: &OwnedFd, rel: &Path, flags: i32) -> std::io::Result<OwnedFd> {
    let opened = openat_no_follow_io(dir_fd, rel, flags | libc::O_NONBLOCK, 0)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(opened.as_raw_fd(), &mut st) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    match kind_from_mode(st.st_mode) {
        PathKind::File | PathKind::Dir => Ok(opened),
        PathKind::Symlink => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the entry is a symlink",
        )),
        PathKind::Other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the entry is not a regular file or a directory (a FIFO, socket, or device); \
             refusing instead of opening or reading it",
        )),
    }
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

/// Guard a SINGLE-component mutation name at the syscall chokepoint: a
/// name-based syscall (`unlinkat`/`renameat`/`linkat`/`symlinkat`/`mkdirat`)
/// can only touch the entry NAMED by its final component, so checking that
/// one component is COMPLETE for the syscall's own effect. The rel-path
/// primitives ([`openat_no_follow_io`]) check every component instead,
/// because they resolve a multi-component spelling.
fn refuse_mutation_name(name: &OsStr, sanction: Sanction<'_>) -> Result<()> {
    refuse_reserved_mutation(Path::new(name), sanction)
}

/// renameat between two names in (possibly different) directory fds.
///
/// R2, closed at the PRIMITIVE: the guard used to sit only in
/// [`renameat_paths`], so calling this raw primitive (which was `pub`)
/// renamed the lock record straight through it. The name checks live HERE
/// now, and the function is PRIVATE: there is no public rename primitive
/// left to bypass.
fn renameat_fd(
    dir_fd: &OwnedFd,
    from: &OsStr,
    to_dir: &OwnedFd,
    to: &OsStr,
    sanction: Sanction<'_>,
) -> Result<()> {
    refuse_mutation_name(from, sanction)?;
    refuse_mutation_name(to, sanction)?;
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
    refuse_mutation_name(from, Sanction::None).map_err(|e| std::io::Error::other(e.to_string()))?;
    refuse_mutation_name(to, Sanction::None).map_err(|e| std::io::Error::other(e.to_string()))?;
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
/// removed, never its target). The lock-record guard runs at the chokepoint,
/// so no caller can unlink the record through this wrapper.
fn unlinkat_fd_io(dir_fd: &OwnedFd, name: &OsStr, sanction: Sanction<'_>) -> std::io::Result<()> {
    refuse_mutation_name(name, sanction).map_err(|e| std::io::Error::other(e.to_string()))?;
    let c = CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "unlink name with NUL")
    })?;
    let r = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c.as_ptr(), 0) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// [`unlinkat_fd_io`] with the store error context.
fn unlinkat_fd(dir_fd: &OwnedFd, name: &OsStr, sanction: Sanction<'_>) -> Result<()> {
    unlinkat_fd_io(dir_fd, name, sanction).map_err(|e| Error::store(format!("unlinkat: {e}")))
}

/// `unlinkat` WITHOUT the lock-record chokepoint. PRIVATE to this module, and
/// reachable only from [`remove_owned_lock_record_fd`], whose first act is to
/// present the unforgeable [`OwnedLockRecord`] capability through
/// [`GuardedRel::new_for_owned_lock_record`]. This is the ONE syscall the lock
/// guard is deliberately bypassed for — the sanctioned RETIREMENT of a record
/// the caller's own authority owns — and it exists so the bypass is a single
/// reviewed primitive rather than a raw `std::fs` call at a call site.
fn unlinkat_fd_owned(dir_fd: &OwnedFd, name: &OsStr) -> Result<()> {
    let c = CString::new(name.as_bytes()).map_err(|_| Error::store("unlink name with NUL"))?;
    let r = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c.as_ptr(), 0) };
    if r < 0 {
        return Err(Error::store(format!(
            "unlinkat the owned lock record: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// RETIRE the ONE lock record `owned` authorizes, by IDENTITY
/// ([`OwnedLockRecord::owns`]). This is the sanctioned break of the lock-record
/// guard: the caller's own protocol has decided the record is obsolete (see
/// [`crate::sync::retire_destination_lock`]). A candidate that is not the owned
/// record — including an ordinary path, and any lock-record spelling that
/// resolves to a DIFFERENT on-disk entry — is refused by
/// [`GuardedRel::new_for_owned_lock_record`] before any syscall.
///
/// The record must not be HELD when this runs; proving that is the caller's
/// job (`FileLock` acquisition), because only the caller knows the record's
/// protocol. The primitive itself does not take the flock.
pub(crate) fn remove_owned_lock_record_fd(
    root: &RootDir,
    rel: &Path,
    owned: &OwnedLockRecord,
) -> Result<()> {
    let guarded = GuardedRel::new_for_owned_lock_record(rel, owned)?;
    if !guarded.is_owned_lock_record() {
        return Err(Error::conflict(format!(
            "refusing to retire {}: it is not the lock record the presented ownership authority \
             owns (the record is recognized by resolved identity, never by a spelling fold)",
            rel.display()
        )));
    }
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    unlinkat_fd_owned(&parent_fd, name)
}

/// `unlinkat(AT_REMOVEDIR)` — `rmdir` semantics, guarded at the chokepoint.
fn rmdirat_fd_io(dir_fd: &OwnedFd, name: &OsStr, sanction: Sanction<'_>) -> std::io::Result<()> {
    refuse_mutation_name(name, sanction).map_err(|e| std::io::Error::other(e.to_string()))?;
    let c = CString::new(name.as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "rmdir name with NUL")
    })?;
    let r = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c.as_ptr(), libc::AT_REMOVEDIR) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// `mkdirat` — the directory at `name` is created; the name is guarded at
/// the chokepoint.
fn mkdirat_fd(dir_fd: &OwnedFd, name: &OsStr) -> Result<()> {
    refuse_mutation_name(name, Sanction::None)?;
    let c = CString::new(name.as_bytes()).map_err(|_| Error::store("mkdir name with NUL"))?;
    let r = unsafe { libc::mkdirat(dir_fd.as_raw_fd(), c.as_ptr(), 0o777) };
    if r < 0 {
        return Err(Error::store(format!(
            "mkdirat: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// `symlinkat` — the link at `name` is created (and any existing entry is
/// removed by the caller through [`unlinkat_fd_io`]); the name is guarded at
/// the chokepoint.
fn symlinkat_fd(dir_fd: &OwnedFd, target: &Path, name: &OsStr) -> Result<()> {
    refuse_mutation_name(name, Sanction::None)?;
    let name_c =
        CString::new(name.as_bytes()).map_err(|_| Error::store("symlink name with NUL"))?;
    let target_c = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| Error::store("symlink target with NUL"))?;
    let r = unsafe { libc::symlinkat(target_c.as_ptr(), dir_fd.as_raw_fd(), name_c.as_ptr()) };
    if r < 0 {
        return Err(Error::store(format!(
            "symlinkat: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Open-or-create a directory component relative to `cur` (O_DIRECTORY |
/// O_NOFOLLOW; created with 0o700 when missing, tolerating a racing
/// creation). A symlink at the component is refused (ELOOP); a
/// non-directory is refused (ENOTDIR). The component is guarded: creating a
/// directory whose name is a lock-record spelling would occupy the record's
/// path.
fn open_or_create_dir(cur: &OwnedFd, comp: &[u8]) -> Result<OwnedFd> {
    // OPEN-OR-CREATE only: a residue spelling is permitted (the openat cannot
    // destroy; a fresh create is not a destruction), and the lock authority
    // still runs.
    refuse_mutation_name(OsStr::from_bytes(comp), Sanction::Residue)?;
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

/// Read every entry name of the directory `dir_fd` (excluding `.`/`..`) into
/// an owned `Vec`, in `readdir` order. The tree walks below used to descend
/// from inside [`for_each_dir_entry`]'s callback, holding a live `DIR*`
/// across a recursive call; collecting the names first preserves the order
/// but lets the walk own its iteration explicitly, on the heap.
fn dir_entry_names(dir_fd: &OwnedFd) -> Result<Vec<Vec<u8>>> {
    let mut names = Vec::new();
    for_each_dir_entry(dir_fd, |name| {
        names.push(name.to_vec());
        Ok(())
    })?;
    Ok(names)
}

/// `fstatat(AT_SYMLINK_NOFOLLOW)` on `name` relative to `dir_fd`, returning
/// the raw `st_mode` (file-type bits included): the entry itself is
/// classified, never a symlink target. The raw `io::Result` lets each walk
/// attach its own path context to the error.
fn fstatat_mode_io(dir_fd: &OwnedFd, name: &[u8]) -> std::io::Result<libc::mode_t> {
    let c = CString::new(name).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path component with NUL")
    })?;
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
        return Err(std::io::Error::last_os_error());
    }
    Ok(st.st_mode)
}

/// Best-effort unlink of a FAILED descriptor-relative atomic replace's temp
/// (the [`discard_temp`] contract, expressed with `unlinkat` against the
/// parent fd): on success the original error is returned unchanged; when the
/// unlink itself fails the returned error carries BOTH failures, never a
/// swallowed cleanup failure. NEVER called after a successful rename (the
/// temp name no longer exists).
fn discard_temp_fd(original: Error, parent_fd: &OwnedFd, tmp_name: &OsStr) -> Error {
    match unlinkat_fd(parent_fd, tmp_name, Sanction::None) {
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
/// directory is created via [`ensure_private_dir_durable_fd`] if missing (so
/// every created directory's own entry is fsynced into its parent before the
/// rename). A failure
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
    match replace_core(root, rel, None, true, bytes, fault)? {
        CoreReplace::Replaced(outcome) => Ok(outcome),
        CoreReplace::Mismatch => unreachable!("no expected content was supplied"),
    }
}

/// [`write_atomic_replace_fd`] for a caller that has ALREADY ensured the
/// parent directory exists at its intended mode (`LocalTransport`'s confined
/// write does this through `ensure_dir_confined`, which preserves an existing
/// directory's mode). The parent chain is neither created nor chmodded here:
/// creating it is the caller's step, and chmodding an existing parent to the
/// store-private `0o700` would OVERRIDE a caller's mode — including a refused
/// destination directory the applier must leave untouched. The replace is
/// otherwise identical (temp, fsync, rename, parent fsync).
pub fn write_atomic_replace_fd_under_existing_parent(
    root: &RootDir,
    rel: &Path,
    bytes: &[u8],
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<ReplaceOutcome> {
    match replace_core(root, rel, None, false, bytes, fault)? {
        CoreReplace::Replaced(outcome) => Ok(outcome),
        CoreReplace::Mismatch => unreachable!("no expected content was supplied"),
    }
}

/// The verdict of [`write_atomic_if_match_fd`].
#[derive(Debug)]
pub enum CompareReplace {
    /// The live entry still held the expected bytes (or was absent when the
    /// caller expected absence) and `bytes` were installed by the atomic
    /// replace; the wrapped [`ReplaceOutcome`] carries the replace's own
    /// two-commit-point durability verdict.
    Replaced(ReplaceOutcome),
    /// The live entry did NOT hold the expected bytes at the moment of the
    /// check (it was changed by another writer, or is absent, or a symlink
    /// that was refused). NOTHING was written: the visible entry is exactly
    /// what the other writer left. The caller must re-read and re-decide.
    Mismatch,
}

/// Should the caller treat the live entry at `file_name` (relative to
/// `parent_fd`) as equal to `expected`? `Ok(false)` covers a genuine
/// [`std::io::ErrorKind::NotFound`] AND any entry that is not a readable
/// regular file the `O_NOFOLLOW` open can hand back: a symlink is refused
/// (`ELOOP`, propagated as an `Err` — never followed, never compared against
/// its target), a directory fails the read, and every other failure is a real
/// error. Fail closed: only a byte-identical regular file compares equal.
fn live_matches(parent_fd: &OwnedFd, file_name: &OsStr, expected: &[u8]) -> Result<bool> {
    match openat_readable_regular(parent_fd, Path::new(file_name), libc::O_RDONLY) {
        Ok(f) => Ok(read_fd_to_end(&f)? == expected),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::store(format!(
            "open {}: {e}",
            Path::new(file_name).display()
        ))),
    }
}

/// The internal verdict of [`replace_core`].
#[derive(Debug)]
enum CoreReplace {
    Replaced(ReplaceOutcome),
    Mismatch,
}

/// The shared core of [`write_atomic_replace_fd`] and
/// [`write_atomic_if_match_fd`]: the same atomic-replace protocol, plus an
/// optional `expected` content the LIVE entry must still equal before anything
/// is installed.
///
/// When `expected` is supplied the core is a compare-and-swap, not a blind
/// replace: it checks the live content to bytes at TWO points — once before
/// the temp is created (so an obviously-changed destination costs no write)
/// and once immediately before the `renameat` (so a writer that changed the
/// entry while the temp was being written and fsynced is still refused). The
/// window between the SECOND check and the `renameat` is irreducible without a
/// lock the far side does not provide: a writer that lands inside it is LOST,
/// and NOTHING runtime-signals the caller — after the second `live_matches`
/// there is no further observation of the entry before the `renameat`, so the
/// caller cannot be told. This residual is stated for callers on
/// [`crate::sync::EntryPolicy::AppendTail`]; the compare-and-swap itself makes
/// no claim that a write in that window is detected. A mismatch returns
/// [`CoreReplace::Mismatch`] with the entry UNTOUCHED and the temp unlinked.
fn replace_core(
    root: &RootDir,
    rel: &Path,
    expected: Option<&[u8]>,
    ensure_parent: bool,
    bytes: &[u8],
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<CoreReplace> {
    // A replace whose TARGET is a lock-record spelling would rename a fresh
    // inode over the record and so admit a second holder (F2); the guard is
    // the SAME authority the removal primitives consult.
    refuse_lock_record_mutation(rel)?;
    // The parent directory is created if missing — the same
    // `create_dir_all(parent)` the path-based protocol runs first —
    // component-wise with O_NOFOLLOW (a symlink injected into any parent
    // component is refused). A caller that has already ensured the parent
    // (`ensure_parent == false`) skips this, so no existing parent is
    // chmodded.
    let parent_rel = rel.parent().unwrap_or(Path::new(""));
    if ensure_parent && !parent_rel.as_os_str().is_empty() {
        // DURABLE creation of the parent chain: every directory this call
        // creates has its OWN entry fsynced into its parent BEFORE the temp
        // write and the rename, so the [
        // `ReplaceOutcome::ReplacedDurable`] claim ("visible under its final
        // name AND durable across power loss") is true for the WHOLE chain,
        // not only for the final entry's parent. The non-durable helper used
        // to leave the created directories' entries unsynced (A1).
        ensure_private_dir_durable_fd(root, parent_rel)?;
    }
    let (parent_fd, file_name) = parent_fd_of(root.as_fd(), rel)?;
    // The FIRST compare: fail before writing a temp if the destination already
    // moved under us.
    if let Some(expected) = expected
        && !live_matches(&parent_fd, file_name, expected)?
    {
        return Ok(CoreReplace::Mismatch);
    }
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
    // The SECOND compare, immediately before the rename: shrink the
    // compare-and-swap window to the `renameat` itself. A writer that changed
    // the live entry while the temp was being written is REFUSED here, with
    // the temp unlinked and the live entry untouched.
    if let Some(expected) = expected
        && !live_matches(&parent_fd, file_name, expected)?
    {
        let _ = unlinkat_fd(&parent_fd, &tmp_name, Sanction::None);
        return Ok(CoreReplace::Mismatch);
    }
    // Stage 3: the atomic rename — COMMIT POINT 1. A failure (or an
    // injected [`ReplaceStage::Rename`] fault) is a PRE-RENAME `Err`: the
    // visible target is wholly OLD and the temp is unlinked.
    if let Some(e) = fault(ReplaceStage::Rename) {
        return Err(discard_temp_fd(e, &parent_fd, &tmp_name));
    }
    probe_rename();
    if let Err(e) = renameat_fd(&parent_fd, &tmp_name, &parent_fd, file_name, Sanction::None) {
        return Err(discard_temp_fd(e, &parent_fd, &tmp_name));
    }
    // Stage 4: the parent-directory open + fsync — COMMIT POINT 2, AFTER
    // the rename. FAIL-CLOSED but EXPLICIT (see [`write_atomic_replace`]).
    if let Some(e) = fault(ReplaceStage::DirSync) {
        return Ok(CoreReplace::Replaced(
            ReplaceOutcome::ReplacedDurabilityUnknown { error: e },
        ));
    }
    probe_fsync_replace_parent();
    if let Err(e) = fsync_dir_fd(&parent_fd) {
        return Ok(CoreReplace::Replaced(
            ReplaceOutcome::ReplacedDurabilityUnknown { error: e },
        ));
    }
    Ok(CoreReplace::Replaced(ReplaceOutcome::ReplacedDurable))
}

/// The atomic COMPARE-AND-REPLACE: install `bytes` at `rel` only if the live
/// entry still holds `expected`, atomically and durably, and report which
/// happened as a [`CompareReplace`]. This is the primitive an append uses so
/// that a concurrent writer's bytes are not silently overwritten: the caller
/// reads the destination, decides the new content, and hands BOTH the bytes it
/// read and the bytes to install to this call. A mismatch writes nothing.
///
/// The comparison is byte-exact and descriptor-bound: the live entry is
/// opened `O_NOFOLLOW` (a symlink is REFUSED, never followed or compared
/// against its target) and read through the SAME descriptor the compare and
/// the install use. See [`replace_core`] for the two check points and for the
/// residual window between the second check and the `renameat`.
pub fn write_atomic_if_match_fd(
    root: &RootDir,
    rel: &Path,
    expected: &[u8],
    bytes: &[u8],
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<CompareReplace> {
    match replace_core(root, rel, Some(expected), true, bytes, fault)? {
        CoreReplace::Replaced(outcome) => Ok(CompareReplace::Replaced(outcome)),
        CoreReplace::Mismatch => Ok(CompareReplace::Mismatch),
    }
}

/// The descriptor-relative create-or-compare CAS: the same protocol as
/// [`write_atomic_cas`], but every path resolves COMPONENT-WISE relative to
/// `root` with `openat(O_NOFOLLOW)`. A symlink injected at the final
/// component is REFUSED (ELOOP) — never followed, never compared against
/// its target.
pub fn write_atomic_cas_fd(root: &RootDir, rel: &Path, bytes: &[u8]) -> Result<()> {
    // A CAS that would CREATE the record (or rewrite it) is a mutation of the
    // same spelling the id rule refuses; consult the ONE guard authority.
    refuse_lock_record_mutation(rel)?;
    let (parent_fd, file_name) = parent_fd_of(root.as_fd(), rel)?;
    // If the file exists, its content must be byte-identical (an identical
    // rewrite is an idempotent success; a symlink at the final component is
    // refused by the O_NOFOLLOW open — never followed).
    match openat_readable_regular(&parent_fd, Path::new(file_name), libc::O_RDONLY) {
        Ok(f) => {
            let existing = read_fd_to_end(&f)?;
            if existing == bytes {
                return Ok(());
            }
            return Err(Error::conflict(format!(
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
    let _ = unlinkat_fd(&parent_fd, &tmp_name, Sanction::None);
    if !installed {
        // Lost the race: the winner's content must match ours or refuse.
        let f = openat_readable_regular(&parent_fd, Path::new(file_name), libc::O_RDONLY)?;
        let existing = read_fd_to_end(&f)?;
        if existing != bytes {
            return Err(Error::conflict(format!(
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
        let f = std::fs::File::from(openat_readable_regular(
            &parent_fd,
            Path::new(file_name),
            libc::O_RDONLY,
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
            // The component is guarded: see [`open_or_create_dir`]. A residue
            // spelling is permitted here because the component did not exist
            // (the openat above returned NotFound), so this is a fresh create,
            // never a destruction.
            refuse_mutation_name(OsStr::from_bytes(comp), Sanction::Residue)?;
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
        let prefix = comps[..=i]
            .iter()
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("/");
        probe_commit_entry(&prefix);
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

/// The descriptor-relative private chmod (0o600) of a REGULAR FILE under the
/// root.
///
/// A DIRECTORY is REFUSED. `O_RDONLY` admits a directory, so the shared
/// regular-or-dir opener ([`openat_readable_regular`]) would hand back a
/// directory descriptor and the chmod would strip the directory's execute bit
/// (0o600), leaving it unenterable. The opened inode is therefore classified
/// and only [`PathKind::File`] is accepted.
pub fn set_private_fd(root: &RootDir, rel: &Path) -> Result<()> {
    // G4: the PATH-BASED `set_private` already consults the guard; this
    // descriptor-relative twin must too, so the two cannot disagree about the
    // record's spelling. A chmod preserves the inode (no holder split), but
    // consistency at the ONE authority is the point.
    refuse_lock_record_mutation(rel)?;
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    let f = std::fs::File::from(openat_readable_regular(
        &parent_fd,
        Path::new(name),
        libc::O_RDONLY,
    )?);
    let is_file = f
        .metadata()
        .map_err(|e| Error::store(format!("fstat {}: {e}", rel.display())))?
        .is_file();
    if !is_file {
        return Err(Error::store(format!(
            "refusing to chmod {} to 0o600: it is not a regular file (a directory chmod would strip \
             its execute bit)",
            rel.display()
        )));
    }
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))
}

/// Refuse a mutation that would MOVE OR DESTROY a subtree containing a
/// lock-record entry: walk the subtree rooted at `root`/`rel` — descriptor-
/// relative, classifying each entry with `fstatat(AT_SYMLINK_NOFOLLOW)` so a
/// symlink is never followed — and refuse if ANY entry's name is a lock-record
/// spelling (F-A2).
///
/// `refuse_lock_record_mutation` guards the path the caller NAMES; it cannot
/// see a record UNDER a directory the caller moves or removes. A `renameat` of
/// an ancestor moves the record's inode with the directory, freeing the old
/// path so a successor acquisition creates a SECOND inode — two simultaneous
/// holders. The removal walks ([`remove_dir_contents_fd`]) already consult the
/// guard at every unlink; this is the same check made BEFORE a rename, so the
/// guarantee lives at the ONE authority rather than at each call site.
///
/// This is a DESCRIPTOR-RELATIVE read-only walk (the same component-wise
/// `O_NOFOLLOW` resolution as the removal walk). It is not O(1): the check is
/// bounded by the number of entries the rename already moves. A non-directory
/// or absent `rel` needs no walk (there is no subtree to move into or out of
/// it), and a symlink is never descended.
fn refuse_lock_record_in_moved_subtree(root: &RootDir, rel: &Path) -> Result<()> {
    match path_kind_fd(root, rel)? {
        Some(PathKind::Dir) => {}
        _ => return Ok(()),
    }
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    let dir_fd = openat_no_follow(
        &parent_fd,
        Path::new(name),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    let mut stack: Vec<(OwnedFd, PathBuf)> = vec![(dir_fd, rel.to_path_buf())];
    while let Some((dir_fd, dir_rel)) = stack.pop() {
        for entry in dir_entry_names(&dir_fd)? {
            let child_name = std::ffi::OsStr::from_bytes(&entry);
            let child_rel = dir_rel.join(child_name);
            // LOCK authority only: a residue that MOVES with the subtree is not
            // destroyed, so it is permitted here.
            refuse_reserved_mutation(&child_rel, Sanction::Residue)?;
            let mode = fstatat_mode_io(&dir_fd, &entry)
                .map_err(|e| Error::store(format!("fstatat {}: {e}", child_rel.display())))?;
            if (mode & libc::S_IFMT) == libc::S_IFDIR {
                let sub = openat_no_follow(
                    &dir_fd,
                    Path::new(child_name),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?;
                stack.push((sub, child_rel));
            }
        }
    }
    Ok(())
}

/// The descriptor-relative remove of a single file (or symlink — the
/// symlink itself is removed, never its target).
pub fn remove_file_fd(root: &RootDir, rel: &Path) -> Result<()> {
    refuse_reserved_mutation(rel, Sanction::None)?;
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    unlinkat_fd(&parent_fd, name, Sanction::None)
}

/// The descriptor-relative rename of a path under the root to another path
/// under the root (both parents resolved component-wise with O_NOFOLLOW).
///
/// This is the ONLY public rename authority, and the rename WORKER below
/// demands a [`GuardedRel`] for each end — unforgeable tokens that only
/// [`GuardedRel::new`] can mint — so no new primitive can name a rename
/// without running the guard (R2, lens-g).
pub fn renameat_paths(root: &RootDir, from: &Path, to: &Path) -> Result<()> {
    // BOTH ends: renaming the record AWAY destroys the inode under the path a
    // successor acquires, and renaming ONTO it replaces the record's entry.
    // The public rename ALSO applies the residue authority at both ends, so a
    // caller cannot replace (or move) a strand through it.
    let from = GuardedRel::new(from)?;
    let to = GuardedRel::new(to)?;
    renameat_paths_guarded(root, from, to, Sanction::None)
}

/// The SANCTIONED residue-movement rename (crate-internal): the engine's own
/// claim-aside rename and `sync::Residue::recover_to` present it. Both ends may
/// carry a residue spelling (that is the point — the claim-aside IS the
/// destination, the stranded aside IS the source), and the lock authority still
/// runs on both.
pub(crate) fn rename_residue_paths(root: &RootDir, from: &Path, to: &Path) -> Result<()> {
    // A residue `to` that ALREADY EXISTS is a stranded ORIGINAL the rename
    // would REPLACE: refuse it, exactly as the public rename does. An ABSENT
    // residue `to` is a fresh claim-aside (the engine's own), and a residue
    // `from` is a MOVE (the strand survives), so both remain permitted. This
    // keeps the SANCTIONED route from becoming the old hole for a caller that
    // names an existing strand as the destination.
    if to
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(crate::reserved::is_residue_name)
        && path_kind_fd(root, to)?.is_some()
    {
        return Err(super::residue_refusal(to));
    }
    let from = GuardedRel::new_for_residue(from)?;
    let to = GuardedRel::new_for_residue(to)?;
    renameat_paths_guarded(root, from, to, Sanction::Residue)
}

/// [`renameat_paths`]'s worker: it accepts only capability tokens, so the
/// guard is structurally unavoidable here too.
fn renameat_paths_guarded(
    root: &RootDir,
    from: GuardedRel<'_>,
    to: GuardedRel<'_>,
    sanction: Sanction<'_>,
) -> Result<()> {
    let from = from.as_path();
    let to = to.as_path();
    // F-A2: the endpoints' names are not enough. A rename MOVES the source
    // entry, so if `from` is a directory CONTAINING the record (directly or at
    // any depth) the record's inode moves with it and the old path is freed.
    // Walk the source subtree (the moved tree) and refuse. `to` needs no walk:
    // a rename can only REPLACE `to` (the path guard catches a record AT `to`),
    // and a rename onto an existing directory requires it to be empty, so a
    // record inside `to` makes the rename fail on its own.
    refuse_lock_record_in_moved_subtree(root, from)?;
    let (from_fd, from_name) = parent_fd_of(root.as_fd(), from)?;
    let (to_fd, to_name) = parent_fd_of(root.as_fd(), to)?;
    renameat_fd(&from_fd, from_name, &to_fd, to_name, sanction)
}

/// The descriptor-relative recursive removal of a directory tree: every
/// entry is classified with `fstatat(AT_SYMLINK_NOFOLLOW)` (a symlink is
/// removed as the entry itself, never followed), subdirectories are
/// recursed into, and the tree root is removed last. A symlink injected at
/// any component is refused (ELOOP) — never followed.
pub fn remove_dir_all_fd(root: &RootDir, rel: &Path) -> Result<()> {
    // ONE gate: this refuses a lock-record spelling AND a residue spelling, on
    // the walk ROOT (the walk itself refuses every nested spelling).
    refuse_reserved_mutation(rel, Sanction::None)?;
    remove_dir_all_fd_inner(root, rel, Sanction::None)
}

/// The recursive-removal worker shared by the implicit and the explicit
/// (discard) entry points. It carries the ENTRY-ROOT sanction only: the walk
/// itself refuses every nested residue.
fn remove_dir_all_fd_inner(root: &RootDir, rel: &Path, sanction: Sanction<'_>) -> Result<()> {
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    let dir_fd = openat_no_follow(
        &parent_fd,
        Path::new(name),
        libc::O_RDONLY | libc::O_DIRECTORY,
        0,
    )?;
    remove_dir_contents_fd(&dir_fd, rel)?;
    rmdirat_fd_io(&parent_fd, name, sanction)
        .map_err(|e| Error::store(format!("rmdir {}: {e}", rel.display())))?;
    Ok(())
}

/// EXPLICIT DISCARD of a stranded residue (`sync::Residue::discard`): the
/// recursive removal of the ONE residue at `rel`, deliberately permitted.
///
/// The root's own residue spelling is allowed — the caller has decided the
/// strand is disposable — but the LOCK authority still runs on the whole path,
/// the walk still refuses any NESTED residue (a residue inside the strand is a
/// SEPARATE stranded original the caller must discard first), and every entry's
/// lock-record spelling is still refused. This is the only sanctioned break of
/// the implicit-removal residue guard, and it is reachable only through the
/// caller's explicit discard.
pub(crate) fn remove_residue_dir_all_fd(root: &RootDir, rel: &Path) -> Result<()> {
    // The FINAL-residue sanction lets the walk root through; the gate still
    // refuses a lock-record spelling (including a residue-shaped one) and a
    // residue in any NON-final component.
    refuse_reserved_mutation(rel, Sanction::FinalResidue)?;
    require_final_residue(rel)?;
    remove_dir_all_fd_inner(root, rel, Sanction::FinalResidue)
}

/// EXPLICIT DISCARD of a stranded residue that is a FILE or SYMLINK: the single
/// non-recursive unlink of the ONE residue at `rel`, deliberately permitted.
///
/// This is the FILE analogue of [`remove_residue_dir_all_fd`] and exists for
/// `sync::Residue::discard`. The FINAL-residue sanction lets the strand
/// through; the gate still refuses a lock-record spelling and a residue in any
/// non-final component.
pub(crate) fn remove_residue_file_fd(root: &RootDir, rel: &Path) -> Result<()> {
    refuse_reserved_mutation(rel, Sanction::FinalResidue)?;
    require_final_residue(rel)?;
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    unlinkat_fd(&parent_fd, name, Sanction::FinalResidue)
}

/// Remove ONE entry of the sync engine's own CLAIM-ASIDE walk. The path
/// necessarily includes the residue root the sync renamed aside, so residues
/// are permitted ANYWHERE on it (the engine's walk has already stopped on a
/// nested strand); the LOCK authority still runs.
pub(crate) fn remove_claim_file_fd(root: &RootDir, rel: &Path) -> Result<()> {
    refuse_reserved_mutation(rel, Sanction::Residue)?;
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    unlinkat_fd(&parent_fd, name, Sanction::Residue)
}

/// The non-recursive `rmdir` of one (already-emptied) directory of the sync
/// engine's own claim-aside walk; residues are permitted anywhere on the path
/// (see [`remove_claim_file_fd`]), the LOCK authority still runs.
pub(crate) fn remove_claim_dir_fd(root: &RootDir, rel: &Path) -> Result<()> {
    remove_dir_fd_inner(root, rel, Sanction::Residue)
}

/// The descriptor-relative single-directory creation (no parent creation,
/// no chmod — `create_dir` semantics). The name is guarded at the chokepoint.
pub fn create_dir_fd(root: &RootDir, rel: &Path) -> Result<()> {
    // CREATE only: a residue spelling is permitted (mkdir fails `EEXIST` if the
    // strand is already there, and never destroys it); the lock authority runs.
    refuse_reserved_mutation(rel, Sanction::Residue)?;
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    mkdirat_fd(&parent_fd, name)
}

/// The descriptor-relative NON-RECURSIVE directory removal. `rmdir`
/// semantics: a non-empty directory is refused (`ENOTEMPTY`) rather than
/// destroyed unnamed. A confirmed absence (a missing entry OR a missing
/// parent component) is success, matching the transport's removal walk.
///
/// This is the ONE rmdir authority: it guards the full path AND the syscall
/// chokepoint guards the final name, so no caller can rmdir the record.
pub fn remove_dir_fd(root: &RootDir, rel: &Path) -> Result<()> {
    remove_dir_fd_inner(root, rel, Sanction::None)
}

fn remove_dir_fd_inner(root: &RootDir, rel: &Path, sanction: Sanction<'_>) -> Result<()> {
    refuse_reserved_mutation(rel, sanction)?;
    let parent_rel = rel.parent().unwrap_or(Path::new(""));
    let parent_fd = if parent_rel.as_os_str().is_empty() {
        root.as_fd()
            .try_clone()
            .map_err(|e| Error::store(format!("dup root dir: {e}")))?
    } else {
        match openat_no_follow_io(
            root.as_fd(),
            parent_rel,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        ) {
            Ok(fd) => fd,
            // A missing parent component is a confirmed absence.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                return Err(Error::store(format!("rmdir {}: {e}", rel.display())));
            }
        }
    };
    let name = rel
        .file_name()
        .ok_or_else(|| Error::store(format!("rmdir {}: no file name", rel.display())))?;
    match rmdirat_fd_io(&parent_fd, name, sanction) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::store(format!("rmdir {}: {e}", rel.display()))),
    }
}

/// Create (or replace) the SYMLINK at `rel` pointing at `target`. The parent
/// chain is created descriptor-relative with `O_NOFOLLOW`; any existing
/// entry at `rel` is unlinked first (never followed); the link is created
/// with `symlinkat`; the parent directory is fsynced.
///
/// This is the ONE symlink authority. The lock-record guard runs on the full
/// path AND the `unlinkat`/`symlinkat` chokepoints guard the final name, so a
/// call that names the record cannot destroy it and install a link (R1).
pub fn symlink_fd(root: &RootDir, target: &Path, rel: &Path) -> Result<()> {
    refuse_lock_record_mutation(rel)?;
    let parent_rel = rel.parent().unwrap_or(Path::new(""));
    if !parent_rel.as_os_str().is_empty() {
        ensure_private_dir_durable_fd(root, parent_rel)?;
    }
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    match unlinkat_fd_io(&parent_fd, name, Sanction::None) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(Error::store(format!(
                "unlink {} before symlink: {e}",
                rel.display()
            )));
        }
    }
    symlinkat_fd(&parent_fd, target, name)?;
    fsync_dir_fd(&parent_fd)
}

/// The descriptor-relative ITERATIVE recursive tree copy: copy the tree at
/// the (arbitrary, possibly OUT-OF-ROOT) read path `src` to the ROOT-RELATIVE
/// destination `dst_rel`, creating `dst_rel` and every missing ancestor.
///
/// This is the public equivalent of the source tool's
/// `deploy::store::atomic::copy_dir_recursive_fd` (see the README's "Design
/// conflicts surfaced by the consumer audit"): `Remote::copy_tree` cannot
/// stand in for it, because that trait method requires BOTH endpoints to be
/// [`RootedRelativePath`]s under ONE transport root, while this primitive
/// reads its source from an arbitrary path (the source tool's staging copy
/// legitimately reads a tree outside the destination root) and confines only
/// the DESTINATION.
///
/// CONFINEMENT: the destination resolves component-wise from the owned root
/// descriptor with `O_NOFOLLOW`, so a symlink injected into any destination
/// component is REFUSED (ELOOP), never followed — the copy can never be
/// redirected outside the root. The SOURCE is a read and is path-based
/// (`std::fs::read_dir`/`read_link`/`File::open`), so an intermediate symlink
/// in the SOURCE path IS followed; that is a read, never a mutation, and it
/// is confined to the caller's own `src`.
///
/// ITERATIVE, NEVER RECURSIVE. The walk keeps an explicit heap `Vec` of open
/// frames instead of one Rust frame per directory level (the source tool's
/// original recursed); a deep tree therefore cannot exhaust the C stack and
/// ABORT the host process. The only remaining bound is the process descriptor
/// limit (one descriptor per level on the source side, none held on the
/// destination side beyond the per-frame open), which surfaces as a clean
/// `Err`, never an abort. This is why the re-added form is the iterative one.
///
/// MODE FIDELITY: directory and file modes are copied EXACTLY from the source
/// (including the setuid/setgid/sticky bits — a mode-shifted copy would fail
/// the staged-object digest verification). The walk is TWO-PHASE: every
/// destination directory is created owner-writable and widened during the
/// walk, and every final mode is applied DEEPEST-FIRST at the end, so a
/// READ-ONLY source tree copies cleanly. (The source tool's original created
/// each directory at its final mode before copying into it, so a read-only
/// source directory failed with `EACCES`; keeping the exact final modes while
/// fixing that is a deliberate, documented difference.)
///
/// RESERVED NAMES: every destination mutation runs the ONE guarded gate (the
/// directory/file creates and the mutating `openat` all refuse a lock-record
/// spelling; a residue spelling is created only when ABSENT, exactly as the
/// other creation primitives permit). A source tree that itself contains a
/// lock-record name (e.g. `operation.lock`) is therefore REFUSED on the
/// destination side; the source tool's original had no such authority.
///
/// SYMLINKS are recreated as symlinks (the link's own target is copied,
/// never followed), replacing any existing destination entry at that name,
/// exactly as the source tool's original did. A pre-existing destination FILE
/// at a copied file's name is refused (`O_EXCL`), matching the original; the
/// caller is expected to pass a fresh destination (the source tool removes a
/// stale staging directory first).
///
/// `dst_rel` must not name the destination ROOT itself (an empty path is
/// refused): use [`copy_dir_recursive_fd`] on a non-empty relative path.
/// Ancestors created for `dst_rel` use the store-private `0o700` mode (the
/// shared directory-creation authority); only the FINAL directory gets the
/// source's mode, and an intermediate staging directory's mode is outside the
/// copied tree, so it is not part of a staged-object digest.
pub fn copy_dir_recursive_fd(root: &RootDir, src: &Path, dst_rel: &Path) -> Result<()> {
    struct Frame {
        dst_rel: PathBuf,
        entries: std::fs::ReadDir,
    }

    fn read_dir_entries(src: &Path) -> Result<std::fs::ReadDir> {
        std::fs::read_dir(src).map_err(|e| Error::store(format!("read_dir {}: {e}", src.display())))
    }

    let src_meta = std::fs::symlink_metadata(src)
        .map_err(|e| Error::store(format!("stat {}: {e}", src.display())))?;
    if !src_meta.is_dir() {
        return Err(Error::store(format!(
            "copy_dir_recursive_fd: source {} is not a directory (refusing to follow a \
             symlink source)",
            src.display()
        )));
    }
    let root_mode = src_meta.permissions().mode() & 0o7777;

    // Create the destination chain (guarded, component-wise O_NOFOLLOW) and
    // widen the FINAL directory during the walk; the exact mode is restored
    // deepest-first below.
    ensure_private_dir_fd(root, dst_rel)?;
    set_dir_mode_fd(root, dst_rel, (root_mode | 0o200) & 0o7777)?;

    // `(dst_rel, final_mode)` for the deepest-first finalize.
    let mut dirs: Vec<(PathBuf, u32)> = Vec::new();
    let mut stack: Vec<Frame> = vec![Frame {
        dst_rel: dst_rel.to_path_buf(),
        entries: read_dir_entries(src)?,
    }];

    while let Some(top) = stack.last_mut() {
        let Some(entry) = top.entries.next() else {
            stack.pop();
            continue;
        };
        let entry = entry.map_err(|e| Error::store(format!("entry: {e}")))?;
        let descend: Option<Frame> = {
            let top = stack.last().expect("the frame just examined");
            let child_src = entry.path();
            let child_rel = top.dst_rel.join(entry.file_name());
            let ft = entry
                .file_type()
                .map_err(|e| Error::store(format!("file_type: {e}")))?;
            if ft.is_dir() {
                let mode = std::fs::symlink_metadata(&child_src)
                    .map_err(|e| Error::store(format!("stat {}: {e}", child_src.display())))?
                    .permissions()
                    .mode()
                    & 0o7777;
                // Guarded create (mkdir semantics: refuses a lock-record
                // spelling, never destroys a residue), then widen during the
                // walk so a read-only source directory can receive children.
                create_dir_fd(root, &child_rel)?;
                set_dir_mode_fd(root, &child_rel, (mode | 0o200) & 0o7777)?;
                dirs.push((child_rel.clone(), mode));
                Some(Frame {
                    dst_rel: child_rel,
                    entries: read_dir_entries(&entry.path())?,
                })
            } else if ft.is_symlink() {
                let link = std::fs::read_link(&child_src)
                    .map_err(|e| Error::store(format!("readlink {}: {e}", child_src.display())))?;
                // The ONE symlink authority: guards the whole path and the
                // final name, replaces an existing entry, fsyncs the parent.
                symlink_fd(root, &link, &child_rel)?;
                None
            } else {
                let mut src_f = std::fs::File::open(&child_src)
                    .map_err(|e| Error::store(format!("open {}: {e}", child_src.display())))?;
                let mode = src_f
                    .metadata()
                    .map_err(|e| Error::store(format!("fstat {}: {e}", child_src.display())))?
                    .permissions()
                    .mode()
                    & 0o7777;
                // Create-new-only through the mutating `openat` chokepoint
                // (which runs the lock-record guard); a pre-existing entry is
                // refused (O_EXCL), matching the source tool.
                let dst_fd = openat_no_follow(
                    root.as_fd(),
                    &child_rel,
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                    0o600,
                )?;
                let mut dst_f = std::fs::File::from(dst_fd);
                copy_file_streaming(&mut src_f, &mut dst_f, &child_src)?;
                dst_f
                    .set_permissions(std::fs::Permissions::from_mode(mode))
                    .map_err(|e| Error::store(format!("chmod {}: {e}", child_rel.display())))?;
                None
            }
        };
        if let Some(frame) = descend {
            stack.push(frame);
        }
    }

    // Restore every directory's exact mode, deepest-first, then the root of
    // the copy last (it is the shallowest).
    dirs.sort_by_key(|(rel, _)| std::cmp::Reverse(rel.components().count()));
    for (rel, mode) in dirs {
        set_dir_mode_fd(root, &rel, mode)?;
    }
    set_dir_mode_fd(root, dst_rel, root_mode)?;
    Ok(())
}

/// Stream `src` into `dst` through a SMALL HEAP buffer.
///
/// `std::io::copy` would place its default buffer ON THE STACK, which matters
/// here: the iterative walk is exercised on a deliberately SMALL thread stack
/// by the deep-tree regression, and a stack buffer large enough to copy a file
/// eats the budget the walk itself needs. A heap buffer keeps this frame (and
/// therefore the walk's constant stack cost) small. The function is
/// deliberately a separate, `inline(never)` frame so the copy's locals do not
/// inflate the walk's own frame.
#[inline(never)]
fn copy_file_streaming(
    src: &mut std::fs::File,
    dst: &mut std::fs::File,
    shown: &Path,
) -> Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = std::io::Read::read(src, &mut buf)
            .map_err(|e| Error::store(format!("read {}: {e}", shown.display())))?;
        if n == 0 {
            return Ok(());
        }
        dst.write_all(&buf[..n])
            .map_err(|e| Error::store(format!("write {}: {e}", shown.display())))?;
    }
}

/// Set the permission mode of the DIRECTORY at root-relative `rel` through an
/// `O_NOFOLLOW`-confined descriptor (`fchmod` on the opened inode, never a
/// path-based `chmod`). Reaches the same ONE gate as the other rel-path
/// primitives for consistency: a chmod preserves the inode (it cannot split a
/// lock holder), but the lock-record spelling is still refused so a copy
/// cannot even retune the record's mode.
fn set_dir_mode_fd(root: &RootDir, rel: &Path, mode: u32) -> Result<()> {
    refuse_lock_record_mutation(rel)?;
    let fd = openat_no_follow(root.as_fd(), rel, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    std::fs::File::from(fd)
        .set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|e| Error::store(format!("chmod {}: {e}", rel.display())))
}

/// The descriptor-relative ITERATIVE recursive tree fsync: make every regular
/// file and every directory under root-relative `rel` durable, DEEPEST-FIRST
/// (a directory is fsynced only after everything it contains), so a crash
/// after this returns loses at most content that was never claimed durable.
///
/// This is the public equivalent of the source tool's
/// `deploy::store::atomic::fsync_tree_recursive_fd`: unlike
/// [`crate::transport::Remote::fsync_tree`] (a path-based `WalkDir` over the
/// transport's base), this resolves EVERY component with
/// `openat(O_NOFOLLOW)`, so a symlink injected into any component is REFUSED
/// (ELOOP), never followed, and the fd is the one that is fsynced.
///
/// SYMLINKS ARE SKIPPED: a symlink's durability is its parent directory
/// entry, which the parent's own fsync covers. A directory that cannot be
/// opened with `O_DIRECTORY`, or a file whose `fsync` fails, is a propagated
/// `Err` (never swallowed). The walk is an explicit heap `Vec` stack, so a
/// deep tree surfaces a clean `Err` (at the descriptor limit) rather than
/// aborting the host on a stack overflow.
pub fn fsync_tree_recursive_fd(root: &RootDir, rel: &Path) -> Result<()> {
    let mut dirs: Vec<PathBuf> = vec![rel.to_path_buf()];
    let mut stack: Vec<PathBuf> = vec![rel.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in read_dir_fd(root, &dir)? {
            let child = dir.join(&entry.name);
            if entry.is_dir {
                dirs.push(child.clone());
                stack.push(child);
            } else {
                // Symlinks and other entry kinds are SKIPPED (their
                // durability is their directory entry, covered by the
                // parent's fsync below); only a regular file is fsynced.
                if let Some(PathKind::File) = path_kind_fd(root, &child)? {
                    let fd = openat_no_follow(root.as_fd(), &child, libc::O_RDONLY, 0)?;
                    std::fs::File::from(fd)
                        .sync_all()
                        .map_err(|e| Error::store(format!("fsync {}: {e}", child.display())))?;
                }
            }
        }
    }
    // Deepest-first: a child directory is durable before its parent's entry
    // that names it is fsynced.
    dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
    for dir in dirs {
        let fd = openat_no_follow(root.as_fd(), &dir, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        fsync_dir_fd(&fd)?;
    }
    Ok(())
}

/// Remove the CONTENTS of the directory `dir_fd`, leaving the directory
/// itself in place.
///
/// The walk is a POST-ORDER over an explicit heap `Vec` of open directory
/// frames instead of one recursive call per level. The recursive form used
/// one C stack frame per directory level, so a tree deeper than the stack
/// overflowed it and Rust's stack-overflow handler ABORTED the whole host
/// process — never an acceptable outcome for a library call. Each frame
/// holds the directory's descriptor and the entry names read from it (in
/// `readdir` order); a subdirectory's frame is pushed when its entry is
/// reached and popped — its entry removed from its parent — only after the
/// subdirectory's own contents are gone, which is exactly the recursion's
/// deepest-first order.
fn remove_dir_contents_fd(dir_fd: &OwnedFd, rel: &Path) -> Result<()> {
    struct Frame {
        fd: OwnedFd,
        rel: PathBuf,
        names: std::vec::IntoIter<Vec<u8>>,
    }

    let root_frame = Frame {
        fd: dir_fd
            .try_clone()
            .map_err(|e| Error::store(format!("dup dir: {e}")))?,
        rel: rel.to_path_buf(),
        names: dir_entry_names(dir_fd)?.into_iter(),
    };
    let mut stack: Vec<Frame> = vec![root_frame];

    while let Some(top) = stack.last_mut() {
        let next = top.names.next();
        let Some(name) = next else {
            // This directory's contents are gone: pop it and, unless it is
            // the walk root (whose caller removes it), remove its entry from
            // the parent, now the top frame.
            let done = stack.pop().expect("the frame just examined");
            let Some(parent) = stack.last() else {
                break;
            };
            let file_name = match done.rel.file_name() {
                Some(n) => n.to_os_string(),
                None => {
                    return Err(Error::store(format!(
                        "{} has no file name",
                        done.rel.display()
                    )));
                }
            };
            // The SAME authority the entry point consults, applied here too:
            // a subdirectory whose name is a lock-record spelling must not be
            // rmdir'd by the walk even though the walk root was not one. The
            // residue authority is NOT applied to the full `done.rel` here —
            // that path includes the walk ROOT, which an explicit discard
            // deliberately permits; the child's own name was already checked
            // for residue when the walk entered it.
            refuse_reserved_mutation(&done.rel, Sanction::Residue)?;
            rmdirat_fd_io(&parent.fd, &file_name, Sanction::None)
                .map_err(|e| Error::store(format!("rmdir {}: {e}", done.rel.display())))?;
            continue;
        };

        let child_name = std::ffi::OsStr::from_bytes(&name);
        // Both authorities at the same chokepoint, LOCK first so a lock-record
        // spelling keeps its more specific refusal. A recursive removal must
        // never walk over a stranded original (RESIDUE) nor over the record
        // (LOCK). The check is on THIS entry's own name (not the whole
        // `child_rel`), because the walk root is deliberately permitted for
        // an explicit discard (`remove_residue_*`); only a NESTED residue
        // stops a discard, and the entry points refuse a residue root.
        refuse_reserved_mutation(Path::new(child_name), Sanction::None)?;
        let descend: Option<Frame> = {
            let top = stack.last().expect("the frame just examined");
            let child_rel = top.rel.join(Path::new(child_name));
            let mode = fstatat_mode_io(&top.fd, &name)
                .map_err(|e| Error::store(format!("fstatat {}: {e}", child_rel.display())))?;
            if (mode & libc::S_IFMT) == libc::S_IFDIR {
                let sub = openat_no_follow(
                    &top.fd,
                    Path::new(child_name),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )?;
                let names = dir_entry_names(&sub)?;
                Some(Frame {
                    fd: sub,
                    rel: child_rel,
                    names: names.into_iter(),
                })
            } else {
                // A file or symlink: unlinkat removes the entry itself (a
                // symlink is removed, never its target). The guard runs on
                // EVERY entry the walk unlinks, so removing an ANCESTOR can
                // never take the record with it (F3).
                // record, not on the full `child_rel` (which includes a
                // deliberately permitted discard root).
                refuse_reserved_mutation(&child_rel, Sanction::Residue)?;
                unlinkat_fd(&top.fd, child_name, Sanction::None)?;
                None
            }
        };
        if let Some(frame) = descend {
            stack.push(frame);
        }
    }
    Ok(())
}

/// The iterative, descriptor-relative removal of a directory NAME (a PATH,
/// not a root-relative spelling). On Unix the local transport routes here;
/// on Windows it delegates to `std::fs::remove_dir_all`, whose WINDOWS
/// implementation is itself iterative on the installed toolchain
/// (`library/std/src/sys/fs/windows.rs:1382` opens the directory and calls
/// `remove_dir_all_iterative`,
/// `library/std/src/sys/fs/windows/remove_dir_all.rs:173`), so the
/// deep-tree-abort guarantee holds on BOTH platforms — this walk is the
/// Unix realization of it, not the only one. This walk reuses
/// [`remove_dir_contents_fd`]'s explicit heap frame stack and is bounded by
/// the descriptor limit — a clean `Err` (or success), never an abort.
/// Semantics follow the Unix `std::fs::remove_dir_all` the transport relied
/// on: a MISSING `path` is a successful no-op (idempotent removal), and a
/// symlink at `path` is unlinked as the entry itself, never followed.
pub fn remove_dir_all_path(path: &Path) -> Result<()> {
    // The ONE gate covers both authorities: the lock-record spelling AND the
    // residue spelling (this path-based primitive walked straight over a
    // stranded aside before).
    refuse_reserved_mutation(path, Sanction::None)?;
    let md = match std::fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::store(format!("lstat {}: {e}", path.display()))),
    };
    if md.file_type().is_symlink() {
        return std::fs::remove_file(path)
            .map_err(|e| Error::store(format!("remove {}: {e}", path.display())));
    }
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::store("remove_dir_all path with NUL"))?;
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(Error::store(format!(
            "open dir {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    let dir_fd = unsafe { OwnedFd::from_raw_fd(fd) };
    remove_dir_contents_fd(&dir_fd, path)?;
    let r = unsafe { libc::rmdir(c.as_ptr()) };
    if r < 0 {
        return Err(Error::store(format!(
            "rmdir {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// The descriptor-relative PLAIN file write (create-or-truncate, 0o600):
/// opens the final entry `O_WRONLY|O_CREAT|O_TRUNC` (refusing a symlink there)
/// and writes the bytes in ONE call.
///
/// THIS IS NOT THE SYNC WRITE PATH, and it is NOT durable: it does NOT fsync
/// the file and it has no temp, so a failure mid-write leaves the destination
/// TRUNCATED and TORN. A sync never calls it — a PULL and a PUSH both publish
/// through the durable atomic replace
/// ([`write_atomic_replace_fd`] / [`write_atomic_replace_fd_under_existing_parent`]),
/// whose failure leaves the PREVIOUS content in place. The durable and atomic
/// write discipline, by direction and destination kind, is stated in
/// [`crate::manifest`]'s "Durability and atomicity of a written entry".
///
/// No in-crate production caller uses this primitive; it remains for the
/// confinement tests (which exercise the create-or-truncate open's refusal of
/// a symlink and a traversal spelling).
pub fn write_file_fd(root: &RootDir, rel: &Path, bytes: &[u8]) -> Result<()> {
    // Create-or-truncate would rewrite the record's content in place.
    refuse_lock_record_mutation(rel)?;
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
/// `O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC`. A symlink injected at ANY
/// component is refused (ELOOP) — a read can never be redirected outside
/// the root the descriptor pins. `O_NONBLOCK` (a no-op for a regular file)
/// plus the `fstat` classification of the OPENED inode refuse a FIFO/socket/
/// device promptly instead of hanging forever on a FIFO (A2).
pub fn read_fd(root: &RootDir, rel: &Path) -> Result<Vec<u8>> {
    let f = openat_readable_regular(root.as_fd(), rel, libc::O_RDONLY)
        .map_err(|e| Error::store(format!("openat {}: {e}", rel.display())))?;
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
/// The final open is `O_NONBLOCK` and the OPENED inode is classified, so a
/// FIFO is refused promptly (A2) instead of blocking the open forever.
pub fn path_state_fd(root: &RootDir, rel: &Path) -> Result<bool> {
    match openat_readable_regular(root.as_fd(), rel, libc::O_RDONLY) {
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
/// reported as a non-directory, never followed). `rel` must name at least one
/// normal component: [`validate_rel`] refuses the empty and `.` spellings, so
/// the OWNED ROOT itself is enumerated with [`read_root_dir_fd`] instead.
pub fn read_dir_fd(root: &RootDir, rel: &Path) -> Result<Vec<DirEntry>> {
    let dir_fd = openat_no_follow(root.as_fd(), rel, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    read_dir_of_opened_fd(&dir_fd, rel)
}

/// Read the entries of the OWNED ROOT itself.
///
/// `read_dir_fd(root, "")` and `read_dir_fd(root, ".")` are refused by
/// [`validate_rel`] — those spellings name the root, not an entry UNDER it —
/// so before this function a consumer had NO public way to enumerate the root
/// and could not reach residue sitting directly at the store root (a crashed
/// temp, a stray file). The root descriptor is already pinned by the
/// [`RootDir`], so no path spelling is involved; each entry is classified
/// exactly as [`read_dir_fd`] classifies a child (B1).
pub fn read_root_dir_fd(root: &RootDir) -> Result<Vec<DirEntry>> {
    let dir_fd = root
        .as_fd()
        .try_clone()
        .map_err(|e| Error::store(format!("dup root dir: {e}")))?;
    read_dir_of_opened_fd(&dir_fd, Path::new(""))
}

/// Classify the entries of an already-open directory descriptor; `shown` is
/// used only to name a failing entry in an error (the empty path for the
/// owned root).
fn read_dir_of_opened_fd(dir_fd: &OwnedFd, shown: &Path) -> Result<Vec<DirEntry>> {
    let mut out = Vec::new();
    for_each_dir_entry(dir_fd, |name| {
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
                shown
                    .join(Path::new(std::ffi::OsStr::from_bytes(name)))
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
        Error, PathKind, ReplaceOutcome, ReplaceStage, RootDir, Sanction, copy_dir_recursive_fd,
        fsync_tree_recursive_fd, openat_no_follow, parent_fd_of, path_kind_fd, read_dir_fd,
        read_fd, read_link_fd, read_root_dir_fd, remove_dir_all_fd, remove_dir_all_path,
        remove_dir_fd, remove_file_fd, remove_owned_lock_record_fd, remove_residue_dir_all_fd,
        remove_residue_file_fd, rename_residue_paths, renameat_fd, renameat_paths,
        replace_order_probe, set_private_fd, symlink_fd, write_atomic_cas_fd, write_atomic_replace,
        write_atomic_replace_fd, write_file_fd,
    };
    use crate::error::ReservedKind;
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

    /// A CAS that refuses different content returns an `Err` of the CONFLICT
    /// class (the closed refusal a caller reacts to — not a mechanical store
    /// failure), and leaves only the existing destination (no temp is created
    /// on the refusal path).
    #[test]
    fn refusing_cas_leaves_only_the_destination() {
        let (dir, root) = owned_root();
        let rel = Path::new("cas.json");
        std::fs::write(dir.path().join("cas.json"), b"OLD").unwrap();
        let err = write_atomic_cas_fd(&root, rel, b"NEW").unwrap_err();
        assert!(
            matches!(err, Error::Conflict(_)),
            "a content divergence is the CONFLICT class: {err:?}"
        );
        assert_eq!(entry_names(dir.path()), only("cas.json"));
        assert_eq!(read_fd(&root, rel).unwrap(), b"OLD".to_vec());
    }

    /// The iterative path-based copy must visit entries in the SAME order as
    /// the recursion it replaced: depth-first pre-order, descending into a
    /// subdirectory the moment it is encountered — NOT "every file first,
    /// then every subdirectory". The final tree is identical either way, so
    /// this pins the observable consequence: on a mid-copy failure the
    /// partial state follows the recursive order. The subdirectory/file names
    /// are CHOSEN from a probe of this filesystem's own enumeration order, and
    /// BOTH creation orders are tried, so the subdirectory precedes the
    /// failing file on a name-hash filesystem (APFS), a creation-order
    /// filesystem, and a reverse-creation-order filesystem (tmpfs); the
    /// `any_non_vacuous` guard then fails the test loudly if no iteration
    /// could observe the order at all.
    #[test]
    fn copy_dir_recursive_visits_in_recursive_preorder() {
        let (sub_name, file_name) = probe_sub_before_file_names();
        let mut any_non_vacuous = false;
        for sub_created_first in [true, false] {
            let tmp = tempfile::tempdir().expect("tempdir");
            let src = tmp.path().join("src");
            let dst = tmp.path().join("dst");
            std::fs::create_dir_all(&src).unwrap();
            if sub_created_first {
                std::fs::create_dir(src.join(&sub_name)).unwrap();
                std::fs::write(src.join(&sub_name).join("inner"), b"inner").unwrap();
                std::fs::write(src.join(&file_name), b"boom").unwrap();
            } else {
                std::fs::write(src.join(&file_name), b"boom").unwrap();
                std::fs::create_dir(src.join(&sub_name)).unwrap();
                std::fs::write(src.join(&sub_name).join("inner"), b"inner").unwrap();
            }

            let order: Vec<String> = std::fs::read_dir(&src)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            let sub_before_file = order
                .iter()
                .position(|n| n == &sub_name)
                .zip(order.iter().position(|n| n == &file_name))
                .is_some_and(|(s, f)| s < f);
            any_non_vacuous |= sub_before_file;

            // Make the file's copy fail: a regular file cannot overwrite a
            // directory, so `std::fs::copy` fails once the walk reaches it.
            std::fs::create_dir_all(dst.join(&file_name)).unwrap();

            let res = super::copy_dir_recursive(&src, &dst);
            assert!(res.is_err(), "a mid-copy failure must surface as an Err");

            // Recursive order copies the subdirectory whenever it precedes
            // the failing file; the buggy "files first" order never descends
            // a subdirectory before the failing file, so this would be false
            // under it.
            assert_eq!(
                dst.join(&sub_name).join("inner").is_file(),
                sub_before_file,
                "the partial-failure state must follow the recursion's depth-first \
                 pre-order (sub_created_first={sub_created_first}, readdir order {order:?})"
            );
        }
        assert!(
            any_non_vacuous,
            "this filesystem's enumeration order never placed the subdirectory before the \
             failing file, so the test could not observe the visit order"
        );
    }

    /// Choose a directory name and a file name such that the directory is
    /// enumerated FIRST on THIS filesystem. A name-hash filesystem (APFS) has
    /// a fixed per-name order, so probing in a scratch directory and reusing
    /// the two names reproduces that order; on a creation-order or
    /// reverse-creation-order filesystem the caller also tries both creation
    /// orders.
    fn probe_sub_before_file_names() -> (String, String) {
        let tmp = tempfile::tempdir().expect("probe tempdir");
        let names: Vec<String> = (0..16).map(|i| format!("c{i:02}")).collect();
        for name in &names {
            std::fs::write(tmp.path().join(name), b"").unwrap();
        }
        let order: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(order.len(), names.len(), "the probe must list every name");
        (order[0].clone(), order[order.len() - 1].clone())
    }

    // -----------------------------------------------------------------
    // A1: the durable ordering the replace claims
    // -----------------------------------------------------------------

    /// The ORDERING PROOF for A1: replacing a path whose parent chain is
    /// MISSING commits every CREATED directory's own entry into its parent
    /// BEFORE the rename, so `ReplacedDurable` is true for the whole chain.
    /// The pre-fix code created the chain with the non-durable helper and
    /// fsynced only the file's parent, so this test failed with "the created
    /// directory entry ... was never fsynced into its parent".
    #[test]
    fn a_missing_parent_chain_is_committed_durably_before_the_rename() {
        let (_dir, root) = owned_root();
        replace_order_probe::begin();
        let outcome =
            write_atomic_replace_fd(&root, Path::new("newdir/sub/file.txt"), b"x", &mut |_| None)
                .unwrap();
        let events = replace_order_probe::take();
        assert!(
            matches!(outcome, ReplaceOutcome::ReplacedDurable),
            "a replace of a fresh chain is durable: {outcome:?}"
        );
        let rename_at = events
            .iter()
            .position(|event| event == "rename")
            .unwrap_or_else(|| panic!("the rename must be recorded: {events:?}"));
        for expected in ["commit-dir-entry newdir", "commit-dir-entry newdir/sub"] {
            let at = events.iter().position(|event| event == expected).unwrap_or_else(|| {
                panic!(
                    "the created directory entry {expected:?} was never fsynced into its parent, \
                     so a power loss could lose it while the replace reports ReplacedDurable: {events:?}"
                )
            });
            assert!(
                at < rename_at,
                "{expected:?} must be committed BEFORE the rename: {events:?}"
            );
        }
    }

    /// The same ordering for the PATH-BASED replace (the Windows local path,
    /// also reachable on Unix): `create_dir_all` used to leave the new
    /// directories' entries unsynced.
    #[test]
    fn the_path_based_replace_commits_new_parent_entries_before_the_rename() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pnew/sub/file.txt");
        replace_order_probe::begin();
        let outcome = write_atomic_replace(&path, b"x", &mut |_| None).unwrap();
        let events = replace_order_probe::take();
        assert!(
            matches!(outcome, ReplaceOutcome::ReplacedDurable),
            "a replace of a fresh chain is durable: {outcome:?}"
        );
        let rename_at = events
            .iter()
            .position(|event| event == "rename")
            .unwrap_or_else(|| panic!("the rename must be recorded: {events:?}"));
        let commits: Vec<usize> = events
            .iter()
            .enumerate()
            .filter(|(_, event)| event.starts_with("commit-dir-entry "))
            .map(|(at, _)| at)
            .collect();
        assert!(
            commits.len() >= 2,
            "both created directories must have their entry fsynced before the rename: {events:?}"
        );
        for at in commits {
            assert!(
                at < rename_at,
                "every created directory entry must be committed BEFORE the rename: {events:?}"
            );
        }
    }

    // -----------------------------------------------------------------
    // B1: the owned root is enumerable
    // -----------------------------------------------------------------

    /// Residue sitting DIRECTLY at the store root used to be unreachable: the
    /// empty and `.` spellings are refused by `validate_rel`. The dedicated
    /// root enumerator reaches it, while those child spellings stay refused.
    #[test]
    fn the_owned_root_is_enumerable_and_root_child_spellings_stay_refused() {
        let (dir, root) = owned_root();
        std::fs::write(dir.path().join("root-residue"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        assert!(
            read_dir_fd(&root, Path::new("")).is_err(),
            "the empty spelling names the root, not an entry under it"
        );
        assert!(
            read_dir_fd(&root, Path::new(".")).is_err(),
            "the `.` spelling names the root, not an entry under it"
        );
        let mut names: Vec<String> = read_root_dir_fd(&root)
            .unwrap()
            .into_iter()
            .map(|entry| entry.name.to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, vec!["root-residue".to_string(), "sub".to_string()]);
    }

    // -----------------------------------------------------------------
    // B2: the crate's OWN crash-temp recognizer is public
    // -----------------------------------------------------------------

    /// A crashed atomic replace (SIGKILL mid-protocol) leaves its temp behind;
    /// the now-public recognizer is the recovery hook, and it must NOT confuse
    /// a genuine claim-ASIDE (which HOLDS a stranded original) for a temp.
    #[test]
    fn the_crate_temp_recognizer_is_public_and_distinguishes_a_held_aside() {
        let temp = crate::atomic::temp_name_for(Path::new("record.json"));
        let temp_name = temp.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            crate::atomic::is_crate_temp_name(&temp_name),
            "the crate's own temp must be recognized: {temp_name}"
        );
        assert!(
            !crate::atomic::is_crate_temp_name(".sync-aside.123.0"),
            "a genuine claim-aside holds the stranded original and is NOT a temp"
        );
        // The recognizer reaches residue ENUMERATED AT THE ROOT.
        let (dir, root) = owned_root();
        std::fs::write(dir.path().join(&temp_name), b"partial").unwrap();
        let listed = read_root_dir_fd(&root).unwrap();
        let listed_names: Vec<String> = listed
            .iter()
            .map(|entry| entry.name.to_string_lossy().into_owned())
            .collect();
        assert!(
            listed
                .iter()
                .any(|entry| crate::atomic::is_crate_temp_name(&entry.name.to_string_lossy())),
            "root enumeration must surface the crashed temp: {listed_names:?}"
        );
    }

    // -----------------------------------------------------------------
    // A5: the stable-inode guarantee is structural
    // -----------------------------------------------------------------

    /// The two-holder reproduction: while A holds the record, B used to UNLINK
    /// it through the substrate and C then created a fresh inode and acquired
    /// it — two simultaneous holders. The removal primitive now refuses a
    /// lock-record spelling, so the record keeps A's inode and C is refused.
    #[test]
    fn removing_the_lock_record_is_refused_so_no_second_holder_can_appear() {
        use std::os::unix::fs::MetadataExt;
        let (dir, root) = owned_root();
        let path = dir.path().join("operation.lock");
        let holder = crate::lock::FileLock::acquire(&path, "op-A").expect("A acquires");
        let inode_a = std::fs::metadata(&path).unwrap().ino();
        let err = remove_file_fd(&root, Path::new("operation.lock"))
            .expect_err("removing the crate's lock record through the substrate must be refused");
        assert!(
            matches!(err, Error::Conflict(_)),
            "the removal refusal is a conflict: {err:?}"
        );
        // The record still names A's inode, so C cannot acquire: ONE holder.
        let err2 = match crate::lock::FileLock::acquire(&path, "op-C") {
            Ok(_) => panic!("C must not acquire while A holds the record"),
            Err(e) => e,
        };
        assert!(
            matches!(err2, Error::LockContended(_)),
            "C must be refused with the typed contention signal: {err2:?}"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().ino(),
            inode_a,
            "the record must keep its stable inode"
        );
        drop(holder);
        // The case ALIAS of the record is protected too (A3/A5).
        let alias_err = remove_file_fd(&root, Path::new(".Destroot.Operation.Lock"))
            .expect_err("a case alias of the lock record must be refused");
        assert!(matches!(alias_err, Error::Conflict(_)), "{alias_err:?}");
    }

    /// F2: the atomic REPLACE must consult the same guard as removal. Pre-fix
    /// `replace_core` renamed a fresh inode over the record: A held
    /// `operation.lock`, a replace swapped the inode, and C then acquired the
    /// NEW inode while A still held the old one — two simultaneous holders.
    /// The replace is now refused, the inode is A's, and C is contended.
    #[test]
    fn replacing_the_lock_record_is_refused_so_no_second_holder_can_appear() {
        use std::os::unix::fs::MetadataExt;
        let (dir, root) = owned_root();
        let path = dir.path().join("operation.lock");
        let holder = crate::lock::FileLock::acquire(&path, "op-A").expect("A acquires");
        let inode_a = std::fs::metadata(&path).unwrap().ino();
        let err =
            write_atomic_replace_fd(&root, Path::new("operation.lock"), b"evil", &mut |_| None)
                .expect_err(
                    "replacing the crate's lock record through the substrate must be refused",
                );
        assert!(
            matches!(err, Error::Conflict(_)),
            "the replace refusal is a conflict: {err:?}"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().ino(),
            inode_a,
            "the record must keep its stable inode"
        );
        let err2 = match crate::lock::FileLock::acquire(&path, "op-C") {
            Ok(_) => panic!("C must not acquire while A holds the record"),
            Err(e) => e,
        };
        assert!(
            matches!(err2, Error::LockContended(_)),
            "C must be refused with the typed contention signal: {err2:?}"
        );
        // Every mutating primitive that could reach the record consults the
        // SAME authority: the CAS and the plain write refuse too.
        let cas = write_atomic_cas_fd(&root, Path::new(".Destroot.Operation.Lock"), b"evil")
            .expect_err("a CAS of a case alias of the record must be refused");
        assert!(matches!(cas, Error::Conflict(_)), "{cas:?}");
        let plain = write_file_fd(&root, Path::new("OPERATION.LOCK"), b"evil")
            .expect_err("a plain write of an alias of the record must be refused");
        assert!(matches!(plain, Error::Conflict(_)), "{plain:?}");
        drop(holder);
    }

    /// F3: removing an ANCESTOR of the record must not unlink it. Pre-fix the
    /// guard checked only the ENTRY path's final component, so
    /// `remove_dir_all_fd(root, "state")` walked into `state` and unlinked
    /// `state/operation.lock`; a second acquisition then succeeded. The walk
    /// now consults the guard at every unlink, so the ancestor removal is
    /// refused and the record keeps its inode.
    #[test]
    fn removing_an_ancestor_of_the_lock_record_is_refused() {
        use std::os::unix::fs::MetadataExt;
        let (dir, root) = owned_root();
        std::fs::create_dir_all(dir.path().join("state")).unwrap();
        let path = dir.path().join("state/operation.lock");
        let holder = crate::lock::FileLock::acquire(&path, "op-A").expect("A acquires");
        let inode_a = std::fs::metadata(&path).unwrap().ino();
        let err = remove_dir_all_fd(&root, Path::new("state"))
            .expect_err("removing an ancestor of the lock record must be refused");
        assert!(
            matches!(err, Error::Conflict(_)),
            "the ancestor refusal is a conflict: {err:?}"
        );
        assert!(
            path.exists(),
            "the record must survive the refused ancestor removal"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().ino(),
            inode_a,
            "the record must keep its stable inode"
        );
        let err2 = match crate::lock::FileLock::acquire(&path, "op-C") {
            Ok(_) => panic!("C must not acquire while A holds the record"),
            Err(e) => e,
        };
        assert!(
            matches!(err2, Error::LockContended(_)),
            "C must be refused with the typed contention signal: {err2:?}"
        );
        drop(holder);
    }

    /// F-A1: the PATH-BASED `write_atomic_replace` had NO lock-record guard.
    /// Pre-fix it renamed a fresh inode over the record: A held
    /// `operation.lock`, a path-based replace swapped the inode, and C then
    /// acquired the NEW inode while A still held the old one — two simultaneous
    /// holders. The replace is now refused, the inode is A's, and C is
    /// contended.
    #[test]
    fn path_based_replace_of_the_lock_record_is_refused() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operation.lock");
        let holder = crate::lock::FileLock::acquire(&path, "op-A").expect("A acquires");
        let inode_a = std::fs::metadata(&path).unwrap().ino();
        let err = write_atomic_replace(&path, b"evil", &mut |_| None)
            .expect_err("a path-based replace of the lock record must be refused");
        assert!(
            matches!(err, Error::Conflict(_)),
            "the refusal is a conflict: {err:?}"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().ino(),
            inode_a,
            "the record must keep its stable inode"
        );
        let err2 = match crate::lock::FileLock::acquire(&path, "op-C") {
            Ok(_) => panic!("C must not acquire while A holds the record"),
            Err(e) => e,
        };
        assert!(
            matches!(err2, Error::LockContended(_)),
            "C must be refused with the typed contention signal: {err2:?}"
        );
        drop(holder);
    }

    /// F-A2: renaming an ANCESTOR of the lock record MOVES the record with its
    /// directory (the inode follows), freeing the old path. Pre-fix the guard
    /// checked only the endpoints' final components, so
    /// `renameat_paths(root, "state", "state2")` succeeded and a second
    /// acquisition at `state/operation.lock` created a NEW inode — two
    /// simultaneous holders. The source SUBTREE is now walked and the rename is
    /// refused; the record keeps its inode and C is contended.
    #[test]
    fn renaming_an_ancestor_of_the_lock_record_is_refused() {
        use std::os::unix::fs::MetadataExt;
        let (dir, root) = owned_root();
        std::fs::create_dir_all(dir.path().join("state/inner")).unwrap();
        // The record sits TWO levels down, so a DIRECT-child check would miss
        // it: the walk must be transitive.
        let path = dir.path().join("state/inner/operation.lock");
        let holder = crate::lock::FileLock::acquire(&path, "op-A").expect("A acquires");
        let inode_a = std::fs::metadata(&path).unwrap().ino();
        let err = renameat_paths(&root, Path::new("state"), Path::new("state2"))
            .expect_err("renaming an ancestor of the lock record must be refused");
        assert!(
            matches!(err, Error::Conflict(_)),
            "the ancestor refusal is a conflict: {err:?}"
        );
        assert!(
            path.exists(),
            "the record must survive the refused ancestor rename"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().ino(),
            inode_a,
            "the record must keep its stable inode"
        );
        let err2 = match crate::lock::FileLock::acquire(&path, "op-C") {
            Ok(_) => panic!("C must not acquire while A holds the record"),
            Err(e) => e,
        };
        assert!(
            matches!(err2, Error::LockContended(_)),
            "C must be refused with the typed contention signal: {err2:?}"
        );
        drop(holder);
    }

    /// F-A2 control: renaming a directory that holds NO lock record (and whose
    /// siblings are ordinary) is still allowed, so the subtree guard does not
    /// refuse every directory rename.
    #[test]
    fn renaming_a_record_free_directory_still_works() {
        let (dir, root) = owned_root();
        std::fs::create_dir_all(dir.path().join("state/inner")).unwrap();
        std::fs::write(dir.path().join("state/inner/data"), b"x").unwrap();
        renameat_paths(&root, Path::new("state"), Path::new("state2"))
            .expect("a record-free directory rename must still succeed");
        assert!(dir.path().join("state2/inner/data").exists());
        assert!(!dir.path().join("state").exists());
    }

    /// F7: `set_private_fd` used to admit a DIRECTORY (`O_RDONLY` on a
    /// directory succeeds) and chmod it to 0o600, stripping its execute bit.
    /// The opened inode is classified now, so a directory is refused and its
    /// mode is untouched, while a regular file is still chmodded.
    #[test]
    fn set_private_refuses_a_directory_and_chmods_a_file() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, root) = owned_root();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::set_permissions(
            dir.path().join("sub"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let err = set_private_fd(&root, Path::new("sub"))
            .expect_err("chmodding a directory to 0o600 must be refused");
        assert!(matches!(err, Error::Store(_)), "got: {err:?}");
        let mode = std::fs::metadata(dir.path().join("sub"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            mode, 0o755,
            "the refused chmod must leave the directory's execute bit intact"
        );
        std::fs::write(dir.path().join("f"), b"x").unwrap();
        std::fs::set_permissions(dir.path().join("f"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        set_private_fd(&root, Path::new("f")).expect("a regular file is chmodded");
        let file_mode = std::fs::metadata(dir.path().join("f"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(file_mode, 0o600, "a regular file is narrowed to 0o600");
    }

    /// G4: the descriptor-relative `set_private_fd` consults the SAME guard as
    /// the path-based `set_private`. A chmod preserves the inode, so this is
    /// not a holder split, but the two spellings of the primitive must not
    /// disagree about the record. Pre-fix `set_private_fd` chmodded the record
    /// and returned `Ok(())`.
    #[test]
    fn set_private_fd_refuses_the_lock_record() {
        let (dir, root) = owned_root();
        std::fs::write(dir.path().join("operation.lock"), b"HELD").unwrap();
        let err = set_private_fd(&root, Path::new("operation.lock"))
            .expect_err("the descriptor-relative chmod must refuse the lock record");
        assert!(
            format!("{err}").contains("lock record"),
            "the refusal must name the lock record, got: {err}"
        );
        assert_eq!(
            std::fs::read(dir.path().join("operation.lock")).unwrap(),
            b"HELD".to_vec(),
            "the record must be untouched"
        );
    }

    /// R2 — the RAW rename primitive is guarded at the PRIMITIVE, not at the
    /// higher-level `renameat_paths`. Pre-fix `renameat_fd` was `pub` and
    /// unguarded: calling it directly renamed the record and freed the path a
    /// successor lock acquires (two holders, different inodes). PRE-FIX
    /// MESSAGE: the call returned `Ok(())` and `operation.lock` was gone.
    #[test]
    fn the_raw_rename_primitive_refuses_the_lock_record() {
        let (dir, root) = owned_root();
        std::fs::write(dir.path().join("operation.lock"), b"HELD").unwrap();
        let (parent_fd, name) = parent_fd_of(root.as_fd(), Path::new("operation.lock")).unwrap();
        let err = renameat_fd(
            &parent_fd,
            name,
            &parent_fd,
            std::ffi::OsStr::new("moved"),
            Sanction::None,
        )
        .expect_err("the raw rename primitive must refuse the record as source");
        assert!(
            format!("{err}").contains("lock record"),
            "the refusal must name the lock record, got: {err}"
        );
        assert_eq!(
            std::fs::read(dir.path().join("operation.lock")).unwrap(),
            b"HELD".to_vec(),
            "the record must be untouched"
        );
        assert!(
            !dir.path().join("moved").exists(),
            "nothing may be renamed through the raw primitive"
        );
        // And as the DESTINATION.
        std::fs::write(dir.path().join("benign"), b"x").unwrap();
        let err = renameat_fd(
            &parent_fd,
            std::ffi::OsStr::new("benign"),
            &parent_fd,
            std::ffi::OsStr::new("operation.lock"),
            Sanction::None,
        )
        .expect_err("the raw rename primitive must refuse the record as destination");
        assert!(format!("{err}").contains("lock record"), "got: {err}");
    }

    /// R3 — a raw open with a MUTATING flag set is refused at the primitive.
    /// Pre-fix `openat_no_follow` was `pub` and unguarded, so
    /// `O_WRONLY|O_TRUNC` truncated the record (the inode survived, but the
    /// holder-identity bytes the contention diagnostic reads were destroyed).
    /// PRE-FIX MESSAGE: the open returned a writable fd and the content
    /// became empty.
    #[test]
    fn the_raw_truncating_open_refuses_the_lock_record() {
        let (dir, root) = owned_root();
        std::fs::write(dir.path().join("operation.lock"), b"HELD-BY-A").unwrap();
        let err = openat_no_follow(
            root.as_fd(),
            Path::new("operation.lock"),
            libc::O_WRONLY | libc::O_TRUNC,
            0,
        )
        .expect_err("a truncating open of the lock record must be refused");
        assert!(
            format!("{err}").contains("lock record"),
            "the refusal must name the lock record, got: {err}"
        );
        assert_eq!(
            std::fs::read(dir.path().join("operation.lock")).unwrap(),
            b"HELD-BY-A".to_vec(),
            "the record's content must be intact"
        );
        // A READ-ONLY open is unaffected (the guard is keyed on the flags).
        let fd = openat_no_follow(root.as_fd(), Path::new("operation.lock"), libc::O_RDONLY, 0)
            .expect("a read-only open of the record is not a mutation");
        drop(fd);
    }

    /// R1 (DATA LOSS): the recursive-removal walk consulted only the
    /// lock-record authority, so `remove_dir_all_path`/`remove_dir_all_fd`
    /// walked straight over a stranded `.sync-aside.` and destroyed the
    /// caller's only copy of the original. The walk and the entry points now
    /// consult the RESIDUE authority at the same chokepoint, and the refusal
    /// names the sync's own `ResidueBelow` vocabulary.
    ///
    /// PRE-FIX MESSAGE: `remove_dir_all_path(victim)` returned `Ok`, and
    /// `victim/.sync-aside.1234.0` no longer existed.
    #[test]
    fn recursive_removal_never_destroys_a_stranded_aside() {
        let (dir, root) = owned_root();
        let stranded = dir.path().join("victim/.sync-aside.1234.0/stranded");
        std::fs::create_dir_all(stranded.parent().unwrap()).unwrap();
        std::fs::write(&stranded, b"precious").unwrap();

        // (a) Removing the ANCESTOR walks over the aside without the guard.
        let err = remove_dir_all_fd(&root, Path::new("victim"))
            .expect_err("removing an ancestor of a stranded aside must be refused");
        assert!(
            matches!(
                err,
                Error::Reserved {
                    reason: ReservedKind::ResidueBelow,
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(
            format!("{err}").contains(crate::reserved::RESIDUE_BELOW),
            "the refusal reuses the sync's ResidueBelow vocabulary: {err}"
        );
        assert_eq!(std::fs::read(&stranded).unwrap(), b"precious".to_vec());

        // (b) The PATH-BASED primitive the recovery recipe named is refused
        // for the aside itself. PRE-FIX: returned `Ok` and removed it.
        let aside_abs = dir.path().join("victim/.sync-aside.1234.0");
        let err = remove_dir_all_path(&aside_abs)
            .expect_err("removing the stranded aside itself must be refused");
        assert!(
            matches!(
                err,
                Error::Reserved {
                    reason: ReservedKind::ResidueBelow,
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(aside_abs.exists(), "the aside survives the refused removal");

        // (c) The descriptor-relative primitive, for the same root spelling.
        let err = remove_dir_all_fd(&root, Path::new("victim/.sync-aside.1234.0"))
            .expect_err("removing the stranded aside itself must be refused");
        assert!(
            matches!(
                err,
                Error::Reserved {
                    reason: ReservedKind::ResidueBelow,
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(aside_abs.exists());

        // (d) A LOCK record in a residue-free tree is still refused by the LOCK
        // authority (the residue guard must not have replaced it).
        std::fs::create_dir_all(dir.path().join("other")).unwrap();
        std::fs::write(dir.path().join("other/.dest.operation.lock"), b"held").unwrap();
        let err = remove_dir_all_fd(&root, Path::new("other"))
            .expect_err("a lock record in the removed tree is still refused");
        assert!(format!("{err}").contains("lock record"), "{err}");
    }

    /// The reviewer's EXACT primitive: `remove_dir_all_path` over the aside
    /// path itself. PRE-FIX: returned `Ok(())` and destroyed it.
    #[test]
    fn path_based_removal_never_destroys_a_stranded_aside() {
        let (dir, _root) = owned_root();
        let aside = dir.path().join("victim/.sync-aside.4242.0");
        std::fs::create_dir_all(&aside).unwrap();
        std::fs::write(aside.join("stranded"), b"precious").unwrap();
        let err = remove_dir_all_path(&aside)
            .expect_err("removing the stranded aside itself must be refused");
        assert!(
            matches!(
                err,
                Error::Reserved {
                    reason: ReservedKind::ResidueBelow,
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(
            std::fs::read(aside.join("stranded")).unwrap(),
            b"precious".to_vec()
        );
    }

    /// R6 at the authority: the capability-gated retirement removes ONLY the
    /// record the presented [`OwnedLockRecord`] owns. A DIFFERENT record — even
    /// one of the same spelling family — and ordinary content are refused, so
    /// the sanctioned break cannot be reached for anything but the owned
    /// record.
    #[test]
    fn the_owned_record_retirement_removes_only_the_owned_record() {
        let (dir, root) = owned_root();
        std::fs::write(dir.path().join(".gone.operation.lock"), b"gone").unwrap();
        std::fs::write(dir.path().join(".keep.operation.lock"), b"keep").unwrap();
        let layout = crate::transport::Layout {
            lock: crate::transport::RootedRelativePath::parse(Path::new(".gone.operation.lock"))
                .unwrap(),
            ..crate::transport::Layout::empty()
        };
        let owned = crate::atomic::OwnedLockRecord::local(dir.path(), &layout);

        remove_owned_lock_record_fd(&root, Path::new(".gone.operation.lock"), &owned)
            .expect("the owned record is retired");
        assert!(!dir.path().join(".gone.operation.lock").exists());

        let err = remove_owned_lock_record_fd(&root, Path::new(".keep.operation.lock"), &owned)
            .expect_err("a record the authority does not own must be refused");
        assert!(matches!(err, Error::Conflict(_)), "{err:?}");
        assert!(dir.path().join(".keep.operation.lock").exists());

        std::fs::write(dir.path().join("ordinary"), b"data").unwrap();
        assert!(
            remove_owned_lock_record_fd(&root, Path::new("ordinary"), &owned).is_err(),
            "ordinary content is not reachable through the retirement primitive"
        );
        assert!(dir.path().join("ordinary").exists());
    }

    /// R2: the EXPLICIT discard is the only sanctioned break of the implicit
    /// residue guard. It removes the ONE strand, still refuses the lock
    /// authority, and still refuses a NESTED residue (a second stranded
    /// original inside the strand).
    #[test]
    fn explicit_discard_removes_one_strand_but_not_a_nested_one() {
        let (dir, root) = owned_root();
        std::fs::create_dir_all(dir.path().join(".sync-aside.7.0/nested/deep")).unwrap();
        std::fs::write(dir.path().join(".sync-aside.7.0/nested/deep/f"), b"x").unwrap();

        // The IMPLICIT removal still refuses it.
        assert!(remove_dir_all_fd(&root, Path::new(".sync-aside.7.0")).is_err());

        // A NESTED strand stops the discard.
        std::fs::create_dir_all(dir.path().join(".sync-aside.7.0/nested/.sync-aside.9.9")).unwrap();
        std::fs::write(
            dir.path()
                .join(".sync-aside.7.0/nested/.sync-aside.9.9/held"),
            b"y",
        )
        .unwrap();
        let err = remove_residue_dir_all_fd(&root, Path::new(".sync-aside.7.0"))
            .expect_err("a nested strand stops a discard");
        assert!(
            format!("{err}").contains(crate::reserved::RESIDUE_BELOW),
            "{err}"
        );
        assert!(
            dir.path()
                .join(".sync-aside.7.0/nested/.sync-aside.9.9/held")
                .exists()
        );

        // Once the nested strand is gone, the discard removes the outer one.
        std::fs::remove_dir_all(dir.path().join(".sync-aside.7.0/nested/.sync-aside.9.9")).unwrap();
        remove_residue_dir_all_fd(&root, Path::new(".sync-aside.7.0")).unwrap();
        assert!(std::fs::symlink_metadata(dir.path().join(".sync-aside.7.0")).is_err());

        // Ordinary content is not discardable by the same primitive.
        std::fs::write(dir.path().join("ordinary"), b"data").unwrap();
        let err = remove_residue_dir_all_fd(&root, Path::new("ordinary"))
            .expect_err("a discard only ever removes a residue");
        assert!(
            format!("{err}").contains(crate::reserved::RESIDUE_BELOW),
            "{err}"
        );
        assert!(dir.path().join("ordinary").exists());
    }

    /// A1: EVERY name-mutating primitive that could touch a strand FILE refuses
    /// it with the TYPED `ResidueBelow` reason, and the strand's bytes AND mode
    /// are intact. PRE-FIX: each of these returned `Ok` (or clobbered/replaced)
    /// and destroyed the caller's only copy.
    #[test]
    fn every_mutating_primitive_refuses_an_existing_strand_file() {
        use std::os::unix::fs::PermissionsExt;
        let strand = Path::new(".sync-aside.1.0");
        let seed = || {
            let (dir, root) = owned_root();
            std::fs::write(dir.path().join(strand), b"precious original").unwrap();
            std::fs::set_permissions(
                dir.path().join(strand),
                std::fs::Permissions::from_mode(0o640),
            )
            .unwrap();
            (dir, root)
        };
        let intact = |dir: &tempfile::TempDir| {
            assert_eq!(
                std::fs::read(dir.path().join(strand)).unwrap(),
                b"precious original"
            );
            assert_eq!(
                std::fs::metadata(dir.path().join(strand))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o640,
                "the strand's mode is untouched"
            );
        };
        let assert_residue = |err: Error| {
            assert!(
                matches!(
                    err,
                    Error::Reserved {
                        reason: ReservedKind::ResidueBelow,
                        ..
                    }
                ),
                "{err:?}"
            );
        };

        // 1. remove_file_fd — unlink.
        let (dir, root) = seed();
        assert_residue(remove_file_fd(&root, strand).unwrap_err());
        intact(&dir);

        // 2. write_file_fd — create-or-truncate.
        let (dir, root) = seed();
        assert_residue(write_file_fd(&root, strand, b"CLOBBERED").unwrap_err());
        intact(&dir);

        // 3. write_atomic_replace_fd — atomic replace.
        let (dir, root) = seed();
        assert_residue(
            write_atomic_replace_fd(&root, strand, b"CLOBBERED", &mut |_| None).unwrap_err(),
        );
        intact(&dir);

        // 4. write_atomic_replace (PATH-BASED).
        let (dir, _root) = seed();
        assert_residue(
            write_atomic_replace(&dir.path().join(strand), b"CLOBBERED", &mut |_| None)
                .unwrap_err(),
        );
        intact(&dir);

        // 5. renameat_paths — ordinary content renamed ONTO the strand.
        let (dir, root) = seed();
        std::fs::write(dir.path().join("ordinary"), b"ordinary").unwrap();
        assert_residue(renameat_paths(&root, Path::new("ordinary"), strand).unwrap_err());
        intact(&dir);
        assert!(dir.path().join("ordinary").exists(), "the source survives");

        // 6. symlink_fd — unlink-then-link.
        let (dir, root) = seed();
        assert_residue(symlink_fd(&root, Path::new("target"), strand).unwrap_err());
        intact(&dir);

        // 7. remove_dir_fd — an EMPTY strand DIRECTORY.
        let (dir, root) = owned_root();
        std::fs::create_dir(dir.path().join(".sync-aside.2.0")).unwrap();
        assert_residue(remove_dir_fd(&root, Path::new(".sync-aside.2.0")).unwrap_err());
        assert!(dir.path().join(".sync-aside.2.0").is_dir());

        // The ONE sanctioned break still works: the explicit file discard.
        let (dir, root) = seed();
        remove_residue_file_fd(&root, strand).unwrap();
        assert!(!dir.path().join(strand).exists());

        // The SANCTIONED residue-movement rename still REFUSES to replace an
        // EXISTING strand (it must not become the old hole), while a FRESH
        // (absent) aside destination is permitted — that is the engine's own
        // claim-aside rename.
        let (dir, root) = seed();
        std::fs::write(dir.path().join("ordinary2"), b"ordinary2").unwrap();
        assert_residue(rename_residue_paths(&root, Path::new("ordinary2"), strand).unwrap_err());
        intact(&dir);
        rename_residue_paths(&root, Path::new("ordinary2"), Path::new(".sync-aside.5.0")).unwrap();
        assert!(!dir.path().join("ordinary2").exists());
        assert_eq!(
            std::fs::read(dir.path().join(".sync-aside.5.0")).unwrap(),
            b"ordinary2"
        );
    }

    /// A source tree OUTSIDE the owned root (with an out-of-root source, the
    /// shape `deploy`'s `copy_dir_recursive_fd` is called with) plus a root
    /// that is a SIBLING of it.
    fn out_of_root_fixture() -> (tempfile::TempDir, RootDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(base.path().join("root")).unwrap();
        let root = RootDir::open(&base.path().join("root")).expect("open the owned root");
        let src = base.path().join("src");
        std::fs::create_dir_all(src.join("ro")).unwrap();
        std::fs::write(src.join("file.txt"), b"hello").unwrap();
        std::fs::write(src.join("ro").join("inner"), b"deep").unwrap();
        std::fs::write(src.join("bin"), b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(src.join("bin"), std::fs::Permissions::from_mode(0o4755)).unwrap();
        // A READ-ONLY source directory: the two-phase walk must widen it,
        // copy the child, then restore 0o555 (the source tool's one-phase
        // original failed here with EACCES).
        std::fs::set_permissions(src.join("ro"), std::fs::Permissions::from_mode(0o555)).unwrap();
        std::os::unix::fs::symlink("file.txt", src.join("link")).unwrap();
        (base, root, src)
    }

    /// The re-added public tree copy carries content, symlink targets, and
    /// EXACT modes (including a read-only directory and the setuid bit) into
    /// the root-confined destination, and the re-added tree fsync accepts the
    /// result. PRE-FIX: these two public primitives did not exist, so this
    /// test did not COMPILE (the failure was a missing primitive); there is no
    /// runtime assertion that could have failed first.
    #[test]
    fn copy_dir_recursive_fd_carries_content_modes_and_symlinks() {
        use std::os::unix::fs::PermissionsExt;
        let (base, root, src) = out_of_root_fixture();
        copy_dir_recursive_fd(&root, &src, Path::new("dst")).unwrap();

        assert_eq!(
            std::fs::read(base.path().join("root/dst/file.txt")).unwrap(),
            b"hello"
        );
        assert_eq!(
            std::fs::read(base.path().join("root/dst/ro/inner")).unwrap(),
            b"deep"
        );
        assert_eq!(
            std::fs::read_link(base.path().join("root/dst/link")).unwrap(),
            Path::new("file.txt")
        );
        let mode_of = |rel: &str| {
            std::fs::symlink_metadata(base.path().join("root").join(rel))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        };
        assert_eq!(
            mode_of("dst/ro"),
            0o555,
            "a read-only directory keeps its mode"
        );
        assert_eq!(mode_of("dst/bin"), 0o4755, "setuid is carried");
        // A plain file's mode is whatever the SOURCE has (the test process's
        // umask decides it), so compare against the source rather than a
        // hardcoded 0o644 — the copy must carry the EXACT source mode.
        assert_eq!(
            mode_of("dst/file.txt"),
            std::fs::symlink_metadata(src.join("file.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            "the copied file keeps the source's mode under any umask"
        );

        // A subtree fsync must accept the copied tree (and skip the symlink).
        fsync_tree_recursive_fd(&root, Path::new("dst")).unwrap();
    }

    /// A symlink injected into a DESTINATION component of the copy is refused
    /// (the destination is descriptor-confined), and nothing is written
    /// outside the root.
    #[test]
    fn copy_dir_recursive_fd_refuses_a_symlinked_destination_component() {
        let (base, root, src) = out_of_root_fixture();
        let outside = base.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, base.path().join("root/escape")).unwrap();

        let err = copy_dir_recursive_fd(&root, &src, Path::new("escape/nested"))
            .expect_err("a symlink-injected destination component must be refused");
        assert!(
            matches!(err, Error::Store(_)),
            "the refusal must be a store error, got: {err:?}"
        );
        assert!(
            err.to_string().contains("openat"),
            "the refusal must name the component-wise open, got: {err}"
        );
        assert!(
            !outside.join("nested").exists(),
            "nothing may be written through the injected symlink"
        );
    }

    /// The copy reaches the ONE reserved-spelling gate: a source entry that a
    /// destination mutation would name as a lock record is refused, rather
    /// than copied into the destination namespace.
    #[test]
    fn copy_dir_recursive_fd_refuses_a_lock_record_name() {
        let (base, root, src) = out_of_root_fixture();
        std::fs::write(src.join("operation.lock"), b"content").unwrap();
        let err = copy_dir_recursive_fd(&root, &src, Path::new("dst"))
            .expect_err("a lock-record spelling must be refused on the destination side");
        assert!(
            matches!(err, Error::Store(_)),
            "the refusal must be a store error from the guarded openat, got: {err:?}"
        );
        assert!(
            err.to_string().contains("lock record"),
            "the refusal must name the lock record, got: {err}"
        );
        assert!(
            !base.path().join("root/dst/operation.lock").exists(),
            "the lock record was never created"
        );
    }

    /// The re-added tree fsync is fd-confined: a symlink injected into a
    /// component of the tree path is refused rather than followed out of the
    /// root (the path-based `Remote::fsync_tree` would follow it).
    #[test]
    fn fsync_tree_recursive_fd_refuses_a_symlinked_component() {
        let (base, root, _src) = out_of_root_fixture();
        std::fs::create_dir(base.path().join("root/real")).unwrap();
        std::fs::write(base.path().join("root/real/f"), b"x").unwrap();
        std::os::unix::fs::symlink("real", base.path().join("root/alias")).unwrap();
        let err = fsync_tree_recursive_fd(&root, Path::new("alias/f"))
            .expect_err("a symlink component must be refused");
        assert!(
            err.to_string().contains("openat"),
            "the refusal must name the component-wise open, got: {err}"
        );
    }
}
