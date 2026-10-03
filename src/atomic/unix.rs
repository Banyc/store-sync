//! The Unix implementation of the store atomic I/O: the descriptor-relative
//! owned-root confinement (`openat`/`renameat`/`linkat`/`unlinkat`/`mkdirat`
//! with `O_NOFOLLOW`) plus the POSIX durability protocol (temp fsync, atomic
//! rename, parent-directory fsync). Selected by the single `#[cfg(unix)]`
//! `mod` declaration in [`super`].
//!
//! # Which path SPELLINGS are refused
//!
//! Every path the DESCRIPTOR-RELATIVE (`_fd`) surface resolves arrives as a
//! [`RootedRelativePath`], validated at the boundary: only normal components are
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
//! [`sync_parent_dir`], [`ensure_private_dir_durable`], and
//! [`copy_dir_recursive`]. The component confinement claimed below belongs to
//! the `_fd` surface only, never to these.
//!
//! The `_fd` tree copy [`copy_dir_recursive_fd`] is a PARTIAL exception and
//! is called out here so the list above is not read as exhaustive: it takes an
//! arbitrary, possibly OUT-OF-ROOT source path by design, so its SOURCE side
//! is path-based — the caller's `src` spelling (including any intermediate
//! symlink in it) is followed ONCE when the source directory descriptor is
//! opened, and only the caller's own tree is read. Every entry below it is
//! then reached RELATIVE to that descriptor. Its DESTINATION side is fully
//! component-confined (`O_NOFOLLOW`, `ELOOP` on a symlink in any component).
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

pub(crate) fn set_private(path: &Path) -> Result<()> {
    refuse_reserved_mutation(path, Sanction::None)?;
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
    // FULL path (see [`refuse_reserved_mutation`]).
    refuse_reserved_mutation(path, Sanction::None)?;
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
pub(crate) fn sync_parent_dir(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::store(format!("sync parent of {}: no parent", path.display())))?;
    let dir = std::fs::File::open(parent)
        .map_err(|e| Error::store(format!("open parent dir {}: {e}", parent.display())))?;
    dir.sync_all()
        .map_err(|e| Error::store(format!("fsync parent dir {}: {e}", parent.display())))
}

/// DURABLE private directory creation: create `path` (and every missing
/// ancestor) at the private 0o700 chmod, then make
/// EVERY newly created directory entry durable BEFORE the call returns — fsync
/// the parent directory of each component this call created (deepest first), and
/// then the parent of the new path's own parent (the entry that names the
/// directory HOLDING the new path). The store case this exists for is the FIRST
/// ledger append on a NEW target: the walk creates `targets/<target>/` while
/// `targets/` itself was already created (UNSYNCED) by the store open, so
/// the append must fsync BOTH the `targets/<target>/`
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
pub(crate) fn ensure_private_dir_durable(path: &Path) -> Result<bool> {
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
    // private 0o700 chmod, exactly as `create_dir_all` would — one component
    // at a time so the caller knows what was created. A
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

/// Split a ROOT-RELATIVE path into its components as raw bytes for the
/// `openat`/`mkdirat` loops.
///
/// The path is ALREADY VALIDATED: every caller reaches this through a
/// [`RootedRelativePath`] (the public boundary) or a component derived from
/// one (a parent, a final name, or a generated temp name), so the spelling
/// rule is enforced once, at the boundary, and is not re-derived here.
/// [`Path::components`] has already erased trailing and repeated separators,
/// so `a/b/` and `a//b` yield the same `a`, `b` as `a/b` and keep resolving
/// identically.
fn rel_components(rel: &Path) -> Vec<&[u8]> {
    rel.components().map(|c| c.as_os_str().as_bytes()).collect()
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
    rel: &RootedRelativePath,
    flags: i32,
    mode: u32,
) -> std::io::Result<OwnedFd> {
    openat_no_follow_io_path(dir_fd, rel.as_path(), flags, mode)
}

/// [`openat_no_follow_io`] for an INTERNAL, already-validated `&Path`: a
/// component derived from a [`RootedRelativePath`] (a parent, a final name, or
/// a generated temp name). It is PRIVATE because the public boundary is the
/// validated type — an arbitrary caller-supplied spelling cannot reach it.
fn openat_no_follow_io_path(
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
        refuse_reserved_mutation(rel, Sanction::None)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
    }
    let mut cur: OwnedFd = dir_fd.try_clone()?;
    let comps = rel_components(rel);
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
pub fn openat_no_follow(
    dir_fd: &OwnedFd,
    rel: &RootedRelativePath,
    flags: i32,
    mode: u32,
) -> Result<OwnedFd> {
    openat_no_follow_path(dir_fd, rel.as_path(), flags, mode)
}

/// [`openat_no_follow`] for an INTERNAL, already-validated `&Path` (see
/// [`openat_no_follow_io_path`]).
fn openat_no_follow_path(dir_fd: &OwnedFd, rel: &Path, flags: i32, mode: u32) -> Result<OwnedFd> {
    openat_no_follow_io_path(dir_fd, rel, flags, mode)
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
    let opened = openat_no_follow_io_path(dir_fd, rel, flags | libc::O_NONBLOCK, 0)?;
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
/// with O_NOFOLLOW), returning the parent fd and the final file name.
///
/// `rel` is ALREADY VALIDATED, so `rel.parent()` cannot point outside the
/// root: the boundary refused `/b` (whose parent is `/`) and `a/../b` (whose
/// parent is `a/..`) before this is reached.
fn parent_fd_of<'a>(root: &OwnedFd, rel: &'a Path) -> Result<(OwnedFd, &'a OsStr)> {
    let parent_rel = rel.parent().unwrap_or(Path::new(""));
    let parent_fd = if parent_rel.as_os_str().is_empty() {
        root.try_clone()
            .map_err(|e| Error::store(format!("dup root dir: {e}")))?
    } else {
        openat_no_follow_path(root, parent_rel, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
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
    rel: &RootedRelativePath,
    owned: &OwnedLockRecord,
) -> Result<()> {
    let rel = rel.as_path();
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
/// creation), reporting whether THIS call created the component. A symlink at
/// the component is refused (ELOOP); a non-directory is refused (ENOTDIR). The
/// component is guarded: creating a directory whose name is a lock-record
/// spelling would occupy the record's path.
fn open_or_create_dir(cur: &OwnedFd, comp: &[u8]) -> Result<(OwnedFd, bool)> {
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
        return Ok((unsafe { OwnedFd::from_raw_fd(fd) }, false));
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
    Ok((unsafe { OwnedFd::from_raw_fd(fd2) }, true))
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
///
/// COST: O(entries) heap for the WIDEST directory of the walk (measured ~50 B
/// per name, so 200 000 entries is ~13.7 MB and ~7.9 s to collect in one
/// process), freed when the frame drops. This is a stated cost, not a leak:
/// the alternative (a live `DIR*` per level) holds a descriptor AND a `DIR`
/// buffer per level and cannot be resumed after an error part-way through one
/// directory's iteration. No cap is imposed; a caller with a directory of
/// millions of entries should stream it through its own walk rather than the
/// tree copy.
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
    rel: &RootedRelativePath,
    bytes: &[u8],
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<ReplaceOutcome> {
    let rel = rel.as_path();
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
    rel: &RootedRelativePath,
    bytes: &[u8],
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<ReplaceOutcome> {
    let rel = rel.as_path();
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
    refuse_reserved_mutation(rel, Sanction::None)?;
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
        ensure_private_dir_durable_fd_path(root, parent_rel)?;
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
    let tmp_fd = openat_no_follow_path(
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
    let f = match openat_no_follow_path(&parent_fd, Path::new(&tmp_name), libc::O_RDONLY, 0) {
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
    let f = match openat_no_follow_path(&parent_fd, Path::new(&tmp_name), libc::O_RDONLY, 0) {
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
    rel: &RootedRelativePath,
    expected: &[u8],
    bytes: &[u8],
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<CompareReplace> {
    let rel = rel.as_path();
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
pub fn write_atomic_cas_fd(root: &RootDir, rel: &RootedRelativePath, bytes: &[u8]) -> Result<()> {
    let rel = rel.as_path();
    // A CAS that would CREATE the record (or rewrite it) is a mutation of the
    // same spelling the id rule refuses; consult the ONE guard authority.
    refuse_reserved_mutation(rel, Sanction::None)?;
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
    let tmp_fd = openat_no_follow_path(
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
/// (the private-directory contract: create the missing chain at 0o700 and
/// chmod the FINAL directory to 0o700). A symlink at any component is refused
/// (ELOOP) — never followed.
pub fn ensure_private_dir_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<()> {
    let rel = rel.as_path();
    let comps = rel_components(rel);
    let mut cur: OwnedFd = root
        .as_fd()
        .try_clone()
        .map_err(|e| Error::store(format!("dup root dir: {e}")))?;
    for (i, comp) in comps.iter().enumerate() {
        let is_last = i == comps.len() - 1;
        let (dir, _created) = open_or_create_dir(&cur, comp)?;
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
pub fn ensure_private_dir_durable_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<bool> {
    ensure_private_dir_durable_fd_path(root, rel.as_path())
}

/// [`ensure_private_dir_durable_fd`] for an INTERNAL, already-validated
/// `&Path` (a parent derived from a [`RootedRelativePath`]).
fn ensure_private_dir_durable_fd_path(root: &RootDir, rel: &Path) -> Result<bool> {
    let comps = rel_components(rel);
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
pub fn sync_parent_dir_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<()> {
    let rel = rel.as_path();
    let parent_rel = rel.parent().unwrap_or(Path::new(""));
    let parent_fd = if parent_rel.as_os_str().is_empty() {
        root.as_fd()
            .try_clone()
            .map_err(|e| Error::store(format!("dup root dir: {e}")))?
    } else {
        openat_no_follow_path(
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
pub fn set_private_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<()> {
    let rel = rel.as_path();
    // G4: the PATH-BASED `set_private` already consults the guard; this
    // descriptor-relative twin must too, so the two cannot disagree about the
    // record's spelling. A chmod preserves the inode (no holder split), but
    // consistency at the ONE authority is the point.
    refuse_reserved_mutation(rel, Sanction::None)?;
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
/// [`refuse_reserved_mutation`] guards the path the caller NAMES; it cannot
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
    match path_kind_fd_path(root, rel)? {
        Some(PathKind::Dir) => {}
        _ => return Ok(()),
    }
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    let dir_fd = openat_no_follow_path(
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
                let sub = openat_no_follow_path(
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
pub fn remove_file_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<()> {
    let rel = rel.as_path();
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
pub fn renameat_paths(
    root: &RootDir,
    from: &RootedRelativePath,
    to: &RootedRelativePath,
) -> Result<()> {
    let from = from.as_path();
    let to = to.as_path();
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
pub(crate) fn rename_residue_paths(
    root: &RootDir,
    from: &RootedRelativePath,
    to: &RootedRelativePath,
) -> Result<()> {
    let from = from.as_path();
    let to = to.as_path();
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
        && path_kind_fd_path(root, to)?.is_some()
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
pub fn remove_dir_all_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<()> {
    let rel = rel.as_path();
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
    let dir_fd = openat_no_follow_path(
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
pub(crate) fn remove_residue_dir_all_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<()> {
    let rel = rel.as_path();
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
pub(crate) fn remove_residue_file_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<()> {
    let rel = rel.as_path();
    refuse_reserved_mutation(rel, Sanction::FinalResidue)?;
    require_final_residue(rel)?;
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    unlinkat_fd(&parent_fd, name, Sanction::FinalResidue)
}

/// Remove ONE entry of the sync engine's own CLAIM-ASIDE walk. The path
/// necessarily includes the residue root the sync renamed aside, so residues
/// are permitted ANYWHERE on it (the engine's walk has already stopped on a
/// nested strand); the LOCK authority still runs.
pub(crate) fn remove_claim_file_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<()> {
    let rel = rel.as_path();
    refuse_reserved_mutation(rel, Sanction::Residue)?;
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    unlinkat_fd(&parent_fd, name, Sanction::Residue)
}

/// The non-recursive `rmdir` of one (already-emptied) directory of the sync
/// engine's own claim-aside walk; residues are permitted anywhere on the path
/// (see [`remove_claim_file_fd`]), the LOCK authority still runs.
pub(crate) fn remove_claim_dir_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<()> {
    let rel = rel.as_path();
    remove_dir_fd_inner(root, rel, Sanction::Residue)
}

/// The descriptor-relative single-directory creation (no parent creation,
/// no chmod — `create_dir` semantics). The name is guarded at the chokepoint.
///
/// A residue spelling is REFUSED BEFORE the mkdir, at THIS gate — not merely
/// by the [`mkdirat_fd`] chokepoint, which also presents [`Sanction::None`].
/// The copy primitive refuses every destination residue for the same reason,
/// so the two creation paths agree on ONE sanction: a residue spelling is
/// never created, because a copy must not occupy a strand that may hold a
/// stranded original. The previous `Sanction::Residue` here was dead (the
/// chokepoint refused) and its comment claimed a create the copy must never
/// make.
pub fn create_dir_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<()> {
    create_dir_fd_path(root, rel.as_path())
}

/// [`create_dir_fd`] for an INTERNAL, already-validated `&Path` (a child
/// derived from a [`RootedRelativePath`]).
fn create_dir_fd_path(root: &RootDir, rel: &Path) -> Result<()> {
    refuse_reserved_mutation(rel, Sanction::None)?;
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
pub fn remove_dir_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<()> {
    let rel = rel.as_path();
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
        match openat_no_follow_io_path(
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
pub fn symlink_fd(root: &RootDir, target: &Path, rel: &RootedRelativePath) -> Result<()> {
    let rel = rel.as_path();
    refuse_reserved_mutation(rel, Sanction::None)?;
    let parent_rel = rel.parent().unwrap_or(Path::new(""));
    if !parent_rel.as_os_str().is_empty() {
        ensure_private_dir_durable_fd_path(root, parent_rel)?;
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

/// Land a freshly-COPIED symlink WITHOUT replacing anything: the destination
/// name must be free, so the copy is all-or-nothing exactly as its file
/// (`O_CREAT|O_EXCL`) and directory (`mkdirat` `EEXIST`) rules are. The PUBLIC
/// [`symlink_fd`] unlinks first because its callers WANT replace semantics;
/// the copy must not, so it uses this instead. `symlinkat` itself refuses an
/// existing name with `EEXIST`, so the refusal is ATOMIC (not a check-then-
/// create race); the `fstatat` probe in front of it exists only to name the
/// clash in the error.
fn symlink_new_fd(root: &RootDir, target: &Path, rel: &Path) -> Result<()> {
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    match fstatat_stat_io(&parent_fd, name.as_bytes()) {
        Ok(_) => {
            return Err(Error::store(format!(
                "copy_dir_recursive_fd: refusing to replace the existing destination entry {} with \
                 a copied symlink — a copy is all-or-nothing (a copied file is refused with \
                 `O_EXCL`, a copied directory with `mkdirat` `EEXIST`), so a copied symlink refuses \
                 a pre-existing entry too",
                rel.display()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::store(format!("fstatat {}: {e}", rel.display()))),
    }
    symlinkat_fd(&parent_fd, target, name)?;
    fsync_dir_fd(&parent_fd)
}

/// The canonical filesystem path pinned by an owned-root DESCRIPTOR.
///
/// The Unix [`RootDir`] stores only a descriptor, so the copy's overlap check
/// needs the descriptor's own resolved path. Linux exposes it as
/// `/proc/self/fd/N`; macOS via `fcntl(F_GETPATH)`. Either answer is already
/// canonical (the kernel tracks the resolved path), which is exactly what the
/// overlap comparison needs.
fn owned_root_self_path(root: &RootDir) -> Result<PathBuf> {
    let fd = root.as_fd().as_raw_fd();
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/self/fd/{fd}"))
            .map_err(|e| Error::store(format!("resolve the owned root descriptor: {e}")))
    }
    #[cfg(target_os = "macos")]
    {
        let mut buf = [0 as libc::c_char; libc::PATH_MAX as usize];
        let r = unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) };
        if r < 0 {
            return Err(Error::store(format!(
                "fcntl(F_GETPATH) on the owned root descriptor: {}",
                std::io::Error::last_os_error()
            )));
        }
        let bytes = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes().to_vec();
        Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = fd;
        Err(Error::store(
            "resolving the owned root descriptor's path is not implemented on this platform",
        ))
    }
}

/// Refuse a copy whose SOURCE and DESTINATION overlap, deciding OVERLAP BY
/// IDENTITY rather than by spelling.
///
/// The old check compared `canonicalize(src)` against a lexical join of the
/// owned root's resolved self-path and `dst_rel`. Two spellings of ONE
/// directory that `realpath(3)` does not unify evade that comparison — a Linux
/// `mount --bind` alias of the root, or a macOS firmlink spelling — and the
/// destination is then created INSIDE the source, whose `read_dir` re-yields it
/// and the walk recurses without bound (reproduced: 57 `sub/.../sub` levels to
/// `EMFILE` on Linux, `ENAMETOOLONG` on macOS). A case-fold-equal `dst_rel` on
/// a case-insensitive filesystem (macOS APFS) evades it too, and the copy then
/// MUTATES ITS OWN SOURCE.
///
/// THE RULE: open the source directory and the DESTINATION ANCHOR — the deepest
/// existing directory on `dst_rel`, resolved component-wise from the owned root
/// descriptor — and compare their `(st_dev, st_ino)` identities (the crate's
/// ONE identity pair, resolved by [`fd_entry_identity`]). Refuse when
///
/// * the anchor IS the source (they are the same directory — this is the
///   bind-mount, firmlink, and case-fold case), or
/// * the anchor is at or INSIDE the source (creating `dst_rel` would put it in
///   the source subtree, which is what runs the walk away), or
/// * the whole `dst_rel` already exists AND is at or above the source (the
///   source is inside the destination).
///
/// The second and third arms walk the directory's own `..` chain, comparing
/// identities at each step, so they too are spelling-blind. A component that
/// exists but cannot be opened as a directory (a symlink, a non-directory) is a
/// fail-CLOSED refusal, and any identity probe failure refuses rather than
/// guessing: an overlap that cannot be ruled out is not allowed through.
///
/// WHAT IT STILL CANNOT CATCH: two distinct paths onto the SAME tree that
/// report DIFFERENT `(st_dev, st_ino)` pairs. On Linux a bind mount of a
/// directory reports the SAME device and inode as the original (bind mounts do
/// not change `st_dev`), and on macOS a firmlink likewise resolves to the same
/// inode, so both are caught. It would NOT catch an alias that presents a
/// different device number for the same underlying directory (some overlay or
/// network filesystems report a per-mount device); such an alias would have to
/// be reproduced on that filesystem to be seen, and this primitive documents
/// the limit rather than pretending to close it. A `btrfs` subvolume or a
/// `mount --bind` across a bind of a bind still report one inode.
fn refuse_overlapping_copy(
    root: &RootDir,
    src: &Path,
    src_fd: &OwnedFd,
    dst_rel: &Path,
) -> Result<()> {
    let src_id = fd_entry_identity(src_fd)
        .map_err(|e| Error::store(format!("identity of the source {}: {e}", src.display())))?;
    let (anchor_fd, dst_exists) = open_destination_anchor(root, dst_rel)?;
    let anchor_id = fd_entry_identity(&anchor_fd).map_err(|e| {
        Error::store(format!(
            "identity of the destination {}: {e}",
            dst_rel.display()
        ))
    })?;
    let anchor_inside_source = dir_chain_contains(&anchor_fd, src_id)?;
    // Only an EXISTING destination can contain the source: a destination that
    // does not exist cannot be an ancestor of an existing source directory.
    let source_inside_destination = if dst_exists {
        dir_chain_contains(src_fd, anchor_id)?
    } else {
        false
    };
    if anchor_id == src_id || anchor_inside_source || source_inside_destination {
        let dst_shown = owned_root_self_path(root)
            .map(|root_path| root_path.join(dst_rel).display().to_string())
            .unwrap_or_else(|_| dst_rel.display().to_string());
        return Err(Error::store(format!(
            "copy_dir_recursive_fd: refusing to copy {} to {} — the source and the destination \
             overlap (the destination is inside the source, the source is inside the destination, \
             or they are the same directory), so the walk would copy the tree into itself without \
             bound; the decision is made by directory IDENTITY (device, inode), not by spelling, so \
             a bind-mount, firmlink, or case-fold alias of one spelling cannot evade it",
            src.display(),
            dst_shown
        )));
    }
    Ok(())
}

/// Open the DEEPEST EXISTING directory on the destination path `dst_rel`,
/// component-wise from the owned root descriptor with `O_NOFOLLOW`, and report
/// whether the WHOLE path resolved to an existing directory. A component that
/// exists but is not a directory (a symlink or a regular file) is REFUSED (fail
/// closed): it is never a directory the copy could write into, and the guarded
/// create would refuse it too.
fn open_destination_anchor(root: &RootDir, dst_rel: &Path) -> Result<(OwnedFd, bool)> {
    let comps = rel_components(dst_rel);
    let mut cur: OwnedFd = root
        .as_fd()
        .try_clone()
        .map_err(|e| Error::store(format!("dup root dir: {e}")))?;
    let mut complete = true;
    for comp in comps {
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
            cur = unsafe { OwnedFd::from_raw_fd(fd) };
        } else {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::NotFound {
                complete = false;
                break;
            }
            return Err(Error::store(format!(
                "copy_dir_recursive_fd: openat {}: {e}",
                dst_rel.display()
            )));
        }
    }
    Ok((cur, complete))
}

/// Whether the directory `from` IS `target` or is INSIDE it, by walking `from`'s
/// own `..` chain and comparing `(st_dev, st_ino)` identities. The walk stops at
/// the filesystem root (where `..` resolves to the same entry); a chain longer
/// than [`MAX_ANCESTRY`] is a fail-CLOSED error rather than an unbounded walk.
fn dir_chain_contains(from: &OwnedFd, target: (u64, u64)) -> Result<bool> {
    let mut cur: OwnedFd = from
        .try_clone()
        .map_err(|e| Error::store(format!("dup dir: {e}")))?;
    for _ in 0..MAX_ANCESTRY {
        let id = fd_entry_identity(&cur)
            .map_err(|e| Error::store(format!("identity while walking the ancestry: {e}")))?;
        if id == target {
            return Ok(true);
        }
        let c = CString::new("..").expect("no NUL in ..");
        let parent = unsafe {
            libc::openat(
                cur.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
            )
        };
        if parent < 0 {
            return Err(Error::store(format!(
                "copy_dir_recursive_fd: openat ..: {}",
                std::io::Error::last_os_error()
            )));
        }
        let parent = unsafe { OwnedFd::from_raw_fd(parent) };
        let parent_id = fd_entry_identity(&parent)
            .map_err(|e| Error::store(format!("identity of the parent directory: {e}")))?;
        if parent_id == id {
            // Reached the filesystem root: its `..` is itself.
            return Ok(false);
        }
        cur = parent;
    }
    Err(Error::store(format!(
        "copy_dir_recursive_fd: could not determine the directory ancestry within {MAX_ANCESTRY} \
         levels; refusing to guess whether the source and the destination overlap"
    )))
}

// The ancestry bound is SHARED with the Windows port: [`super::MAX_ANCESTRY`]
// (single-sourced in `atomic/mod.rs`, next to the other shared atomic
// constants).

/// The ONE name gate the copy applies to every entry name BEFORE it lands:
/// the crate's name authority ([`crate::manifest::validate_entry_path`], the
/// rule the manifest walk and the far-side wire both apply: valid UTF-8,
/// already NFC, free of NUL/LF/CR/TAB, within [`NAME_MAX`], a normal
/// component) PLUS [`crate::reserved::is_unaddressable_name`], the id rule's
/// unaddressability half (a reserved spelling, the application lock record,
/// a case/trailing-dot alias of either, or one of the crate's own TEMP
/// shapes).
///
/// The temp half is load-bearing: the crate's documented recovery
/// sweep removes every [`crate::atomic::is_crate_temp_name`] match, and
/// `reserved.rs` states the sweep is safe BY CONSTRUCTION because no
/// ADDRESSABLE content can match. A copy that landed a raw source name would
/// break that construction, so the name is refused instead of landed.
fn refuse_unlandable_name<'a>(name: &'a [u8], parent: &Path) -> Result<&'a str> {
    let shown = parent.join(std::ffi::OsStr::from_bytes(name));
    let name_str = std::str::from_utf8(name).map_err(|_| {
        Error::store(format!(
            "refusing to copy {}: the entry name is not valid UTF-8, and the crate's manifests \
             require NFC/UTF-8 names",
            shown.display()
        ))
    })?;
    crate::manifest::validate_entry_path(name_str)
        .map_err(|e| Error::store(format!("refusing to copy {}: {e}", shown.display())))?;
    if crate::reserved::is_unaddressable_name(name_str) {
        return Err(Error::store(format!(
            "refusing to copy {}: the name {name_str:?} is unaddressable in this crate (a reserved \
             spelling, the application lock record, or one of the crate's own temp shapes). The \
             documented recovery sweep removes every temp-shaped name, so a copy must never land \
             such a name",
            shown.display()
        )));
    }
    Ok(name_str)
}

/// The mode bits of an OPENED directory (`fstat`), so a caller never re-resolves
/// a path to read a mode it already holds a descriptor for.
fn mode_of_opened_dir(fd: &OwnedFd) -> Result<u32> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
        return Err(Error::store(format!(
            "fstat the opened directory: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok((st.st_mode as u32) & 0o7777)
}

/// The on-disk identity `(st_dev, st_ino)` of an OPENED directory (`fstat`),
/// through the crate's ONE identity type
/// ([`crate::atomic::guard::EntryIdentity`], the same pair [`entry_identity`]
/// resolves for a path). Resolving an fd avoids re-resolving a spelling, so the
/// copy's overlap decision cannot be raced by a spelling swap between the probe
/// and the walk. Implemented HERE (not in `guard`) because `libc` may only be
/// referenced from the Unix funnel.
fn fd_entry_identity(fd: &OwnedFd) -> std::io::Result<crate::atomic::guard::EntryIdentity> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((st.st_dev as u64, st.st_ino as u64))
}

/// Create `dst_rel` and every missing ancestor under the owned root
/// (component-wise, `O_NOFOLLOW`, through the shared directory-creation
/// authority [`open_or_create_dir`]), and report:
///
/// * the mode of the FINAL component if it ALREADY EXISTED (so the undo journal
///   can put it back), and
/// * the root-relative paths of the components THIS call created (shallowest
///   first), so the journal knows which directories are the call's own.
///
/// A pre-existing FINAL directory is reported with its ORIGINAL mode and is
/// NOT chmodded here; the caller records that mode in its undo journal before
/// widening the directory. The ancestors are created at the store-private
/// `0o700`; a created final is chmodded to `0o700` for the same reason
/// [`ensure_private_dir_fd`] does (the `mkdirat` mode is subject to the process
/// umask).
fn create_destination_chain(root: &RootDir, dst_rel: &Path) -> Result<(Option<u32>, Vec<PathBuf>)> {
    let comps = rel_components(dst_rel);
    let mut cur: OwnedFd = root
        .as_fd()
        .try_clone()
        .map_err(|e| Error::store(format!("dup root dir: {e}")))?;
    let mut created: Vec<PathBuf> = Vec::new();
    let mut prefix = PathBuf::new();
    let mut final_preexisting_mode = None;
    for (i, comp) in comps.iter().enumerate() {
        let is_last = i + 1 == comps.len();
        prefix.push(std::ffi::OsStr::from_bytes(comp));
        let (dir, was_created) = open_or_create_dir(&cur, comp)?;
        if was_created {
            created.push(prefix.clone());
            if is_last {
                std::fs::File::from(
                    dir.try_clone()
                        .map_err(|e| Error::store(format!("dup dir: {e}")))?,
                )
                .set_permissions(std::fs::Permissions::from_mode(0o700))
                .map_err(|e| Error::store(format!("chmod {}: {e}", prefix.display())))?;
            }
        } else if is_last {
            final_preexisting_mode = Some(mode_of_opened_dir(&dir)?);
        }
        cur = dir;
    }
    Ok((final_preexisting_mode, created))
}

/// The copy's UNDO JOURNAL for destination directory modes (I2/I3). Every
/// directory whose mode the call changes — or creates — is recorded with the
/// mode to restore if the call FAILS, and `Drop` restores them deepest-first.
/// This is what makes a FAILED copy leave a destination the crate can remove
/// itself ([`remove_dir_all_fd`]) instead of a `0o200` directory nothing can
/// open, and what keeps a fold-equal source's own mode byte-identical after a
/// failed copy.
///
/// `Drop` is the right shape: the copy has many `?` returns, and a guard makes
/// the restore run on EVERY one without each error path remembering to. A
/// successful copy DISARMS the journal once the exact final modes are applied,
/// so the guard never fights the finalize.
struct CopyUndo<'a> {
    root: &'a RootDir,
    /// `(rel, mode_to_restore_on_failure)`: a directory the call CREATED
    /// restores to the removable `0o700`; one that PRE-EXISTED restores to its
    /// original mode.
    modes: Vec<(PathBuf, u32)>,
    armed: bool,
}

impl<'a> CopyUndo<'a> {
    fn new(root: &'a RootDir) -> Self {
        Self {
            root,
            modes: Vec::new(),
            armed: true,
        }
    }

    /// Record the mode to restore for `rel` if the call fails. The FIRST record
    /// for a path wins, so a later re-plan cannot overwrite the true original.
    fn plan(&mut self, rel: &Path, restore_mode: u32) {
        if !self.modes.iter().any(|(planned, _)| planned == rel) {
            self.modes.push((rel.to_path_buf(), restore_mode));
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CopyUndo<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut modes = std::mem::take(&mut self.modes);
        // Deepest-first, so a parent widened for its children is restored after
        // them. Best-effort: the call is already returning an error, and a
        // concurrent removal may make a restore fail — the original error is
        // what the caller must see.
        modes.sort_by_key(|(rel, _)| std::cmp::Reverse(rel.components().count()));
        for (rel, mode) in modes {
            let _ = set_dir_mode_fd(self.root, &rel, mode);
        }
    }
}

/// `fstatat(AT_SYMLINK_NOFOLLOW)` on `name` relative to `dir_fd`, returning the
/// whole `stat` (so the copy can read both the kind/mode and the link count).
fn fstatat_stat_io(dir_fd: &OwnedFd, name: &[u8]) -> std::io::Result<libc::stat> {
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
    Ok(st)
}

/// Read the target of the symlink `name` relative to `dir_fd`, WITHOUT
/// following it and without materializing a long path (so a deep source tree is
/// never limited by `PATH_MAX`).
fn readlinkat_name(dir_fd: &OwnedFd, name: &[u8], shown: &Path) -> Result<PathBuf> {
    let c = CString::new(name).map_err(|_| Error::store("symlink name with NUL"))?;
    let mut buf: Vec<u8> = vec![0; 256];
    loop {
        let n = unsafe {
            libc::readlinkat(
                dir_fd.as_raw_fd(),
                c.as_ptr(),
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
            )
        };
        if n < 0 {
            return Err(Error::store(format!(
                "readlinkat {}: {}",
                shown.display(),
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
/// redirected outside the root. The SOURCE spelling is NORMALIZED first
/// (`normalize_root`, the crate's own normalizer: trailing/repeated separators
/// and `.` noise are erased) and its FINAL component must not be a symlink — a
/// trailing separator would otherwise make POSIX resolve the final component as
/// an intermediate one, and `lstat("link/")` would FOLLOW the link the refusal
/// exists to stop. The source is then opened ONCE as a descriptor (the caller's
/// own `src`, deliberately an arbitrary possibly-out-of-root path) and the walk
/// reads it with `fstatat`/`readlinkat`/`openat` RELATIVE to that descriptor,
/// so an INTERMEDIATE symlink in the caller's `src` SPELLING is followed
/// exactly once (a read, never a mutation, confined to the caller's own
/// source). Opening the source entries through the descriptor also means no
/// entry is reached by a path longer than one component, so a deep source tree
/// is not bounded by `PATH_MAX`. The crate's guarded, classified open
/// ([`openat_readable_regular`]) is what reads a regular file: `O_NONBLOCK`
/// plus an `fstat` of the OPENED inode, so a FIFO, socket, or device is
/// REFUSED rather than opened.
///
/// ITERATIVE, NEVER RECURSIVE. The walk keeps an explicit heap `Vec` of open
/// frames instead of one Rust frame per directory level (the source tool's
/// original recursed); a deep tree therefore cannot exhaust the C stack and
/// ABORT the host process. The descriptor bound is ~ONE PER LEVEL of source
/// depth, plus O(1) transient descriptors per destination mutation:
/// `parent_fd_of`/`openat_no_follow` re-resolve the whole ancestor chain, but
/// they do it ONE COMPONENT AT A TIME and drop each intermediate descriptor
/// before the next `openat`, so a mutation holds ONE destination descriptor at
/// the instant of the syscall, never `depth` of them. MEASURED (Linux, depth
/// 256): the copy succeeds at `RLIMIT_NOFILE=262` and fails at 260, i.e. peak
/// ~= depth + 6 — NOT the ~`2 * depth` a first reading of the re-opening might
/// suggest. The bound surfaces as a clean `Err`, never an abort. The COST that
/// does grow with depth is TIME: each destination entry re-resolves its parent
/// chain from the root, so it costs O(depth) `openat` calls (a directory also
/// pays one O(depth) pass in the deepest-first finalize); the source side stays
/// O(1) per entry. This is a deliberate, stated cost, not a hidden one. This is
/// why the re-added form is the iterative one.
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
/// A FAILED COPY RESTORES EVERY MODE IT CHANGED ([`CopyUndo`], an RAII
/// journal): the widened walk modes are for the walk only, so an error return
/// puts a PRE-EXISTING destination directory back to its original mode and a
/// directory the call CREATED back to the removable `0o700`. A destination
/// that is (or aliases) the source can therefore never be left mutated by a
/// failed copy, and a destination the call CREATED is always removable with
/// the crate's own [`remove_dir_all_fd`] — no `chmod` first. A PRE-EXISTING
/// destination keeps ITS OWN mode (the caller's choice, which the call does not
/// second-guess); a caller merging into a read-only directory owns its
/// removability. On SUCCESS the exact modes are applied and the journal is
/// disarmed.
///
/// FIDELITY IS TO THE MANIFEST MODEL, NOT TO EVERY INODE ATTRIBUTE. The copy
/// carries content, modes (including the special bits), and symlink targets —
/// exactly what [`crate::manifest::canonicalize_tree`] records and the digest
/// covers — so a copied tree is BYTE-FAITHFUL to the manifest model. It does
/// NOT carry mtime, atime, xattrs, ACLs, ownership, or file flags; a caller
/// that needs those (e.g. to preserve a build cache's timestamps) must restore
/// them itself. The cron/manifest of this crate never compares them, so the
/// copy cannot fail a digest check for their absence.
///
/// NAMES: every entry name is validated BEFORE any destination mutation by
/// [`refuse_unlandable_name`], which applies the crate's ONE name authority
/// ([`crate::manifest::validate_entry_path`] — valid UTF-8, already NFC, free
/// of NUL/LF/CR/TAB, within [`NAME_MAX`]) AND the id rule's unaddressability
/// half ([`crate::reserved::is_unaddressable_name`] — reserved spellings, the
/// application lock record, their case/trailing-dot aliases, and the crate's
/// own TEMP shapes). A name the crate would refuse as an id, or strip from a
/// manifest, or that the documented recovery sweep
/// ([`crate::atomic::is_crate_temp_name`]) would REMOVE, is therefore refused
/// instead of landed. The `dst_rel` path itself runs
/// [`refuse_reserved_creation`] before anything is created, so a
/// residue-spelled destination component is refused with NO partial state and
/// with CREATE/COPY wording (never the removal `recover_to` vocabulary).
/// Every destination mutation still runs the ONE guarded gate as well (the
/// directory/file creates and the mutating `openat`), so a lock-record
/// spelling cannot be created by any route.
///
/// THE DESTINATION PATH IS EXEMPT FROM THE RECOVERY SWEEP; A TEMP-SHAPED ENTRY
/// NAME IS NOT. `dst_rel` may itself contain a TEMP-shaped component (the
/// staging shape `deploy` needs, e.g. `.staged.tmp.1.2/root`):
/// [`refuse_reserved_creation`] refuses only RESIDUE spellings (an
/// unaddressable name that is not a crate temp), and the guarded create
/// tolerates a temp spelling because it merely CREATES a fresh entry. The
/// caller must therefore RENAME the finished tree into its real name: a copy
/// left sitting at a temp-shaped destination is matched by the documented
/// recovery sweep ([`crate::atomic::is_crate_temp_name`]) and the WHOLE tree
/// under it is swept. A copied ENTRY name is the opposite: a temp-shaped entry
/// name would be a live file the sweep destroys, so [`refuse_unlandable_name`]
/// REFUSES it. Memory: [`dir_entry_names`] buffers EVERY entry name of a
/// directory into a `Vec` before iterating (measured ~50 B/entry: 200 000
/// entries took 7.86 s in one process and ~13.7 MB), so the walk's peak heap is
/// O(entries) in the widest directory, not O(depth). No cap is imposed: a cap
/// would be an arbitrary refusal of a legal tree, and the cost is linear and
/// freed as each frame drops.
///
/// HARD LINKS are REFUSED (a regular file with `st_nlink > 1`): the crate's
/// own `canonicalize_tree` refuses hard links by rule, so silently
/// duplicating one into an independent regular file would materialize a tree
/// the crate cannot canonicalize. A caller that must copy such a tree
/// pre-checks and dereferences them itself.
///
/// OVERLAP is refused BEFORE anything is created, and the decision is made by
/// directory IDENTITY, not by path spelling ([`refuse_overlapping_copy`]): the
/// source directory and the DESTINATION ANCHOR (the deepest existing directory
/// on `dst_rel`, resolved component-wise from the owned root descriptor) are
/// compared by `(st_dev, st_ino)`, and the call refuses when they are the same
/// directory, when the anchor is inside the source, or when an EXISTING
/// destination is above the source. A spelling-based comparison is bypassable
/// by any two spellings `realpath` does not unify — a Linux `mount --bind`
/// alias, a macOS firmlink, a case-fold-equal `dst_rel` on a folding
/// filesystem — and each of those made the destination be created INSIDE the
/// source, whose `read_dir` re-yielded it and ran the walk without bound
/// (reproduced: 57 `sub/.../sub` levels to `EMFILE` at `RLIMIT_NOFILE=64` on
/// Linux, `ENAMETOOLONG` on macOS). Identity also closes the fold-equal case
/// that MUTATED THE SOURCE's mode. What identity still cannot catch: two
/// spellings that report DIFFERENT `(st_dev, st_ino)` pairs for one underlying
/// directory (some overlay/network filesystems); a bind mount and a firmlink
/// both report the SAME pair, so they are caught. A component that cannot be
/// opened as a directory, or any identity-probe failure, refuses (fail
/// closed).
///
/// NOT ATOMIC, NOT DURABLE, PARTIAL ON FAILURE: there is no temp directory and
/// no final rename, so entries appear at their destination in `read_dir`
/// order, a crash or error mid-walk leaves a PARTIAL destination tree, and the
/// primitive does not fsync. A caller that needs either guarantee must copy
/// into a fresh staging path it owns and rename it into place itself, and must
/// treat ANY `Err` as "the destination may hold a partial subtree at
/// `dst_rel`". A destination the call CREATED is removable with the crate's own
/// [`remove_dir_all_fd`]: the undo journal restores every mode the call changed
/// before the error return. A PRE-EXISTING destination keeps its own mode, so a
/// caller merging into a read-only directory owns its removability. A partial
/// tree is also never mistakable for a complete one — it is missing entries, so
/// `canonicalize_tree` on it either errors or yields a different digest. Use
/// [`fsync_tree_recursive_fd`] to make a completed copy durable.
///
/// ANCESTORS CREATED FOR `dst_rel` ARE KEPT, and they are the call's own
/// artifacts: they are created at the store-private `0o700` and remain after
/// a failure so the documented cleanup spelling keeps working
/// ([`remove_dir_all_fd`] requires the parent chain to exist). A caller that
/// wants a pristine prefix removes them itself with [`remove_dir_fd`]
/// (non-recursive, so it can never delete a concurrent user's content).
///
/// SYMLINKS are recreated as symlinks (the link's own target is copied, never
/// followed). The copy is ALL-OR-NOTHING for EVERY kind pair, matching the
/// file (`O_CREAT|O_EXCL`) and directory (`mkdirat`) rules: an entry the copy
/// would land on a PRE-EXISTING destination name is REFUSED and the old entry
/// is left byte-identical. Concretely: file over file / dir / symlink, and
/// dir over file / dir / symlink, are all refused by `O_EXCL`/`mkdirat`; a
/// SYMLINK over file, dir, or symlink is refused by [`symlink_new_fd`]
/// (`symlinkat` `EEXIST`), never by unlinking the old entry. The public
/// [`symlink_fd`] keeps its replace semantics for callers that want them; the
/// copy does not, and there is deliberately NO overwrite FLAG — a copy into a
/// fresh staging path is the documented contract, so an enum choice would only
/// invite a caller to destroy a live entry. The caller is expected to pass a
/// fresh destination (the source tool removes a stale staging directory
/// first).
///
/// SYMLINK CONTAINMENT uses the SAME ONE AUTHORITY as the two manifest views:
/// the copy builds a [`crate::manifest::SymlinkContainmentIndex`] from a
/// filesystem ENUMERATION — the source subtree relocated under `dst_rel`, plus
/// the destination entries the run leaves in place — and runs the indexed rule
/// ([`crate::manifest::check_relative_symlink_target_indexed`]). One rule, one
/// fold, all three views. The destination's existing entries are part of the
/// post-copy view: a destination-only symlink at a component a copied link
/// walks through is REFUSED (the run may not install a link whose kernel
/// resolution leaves the root, even when the escaping component is a
/// destination entry the run did not create). This primitive TOLERATES an
/// existing `dst_rel` DIRECTORY (it reuses and finalizes it, leaving a
/// pre-existing entry's content untouched) but refuses every colliding
/// destination entry (see the SYMLINKS landing rule) and never tolerates a
/// surviving destination symlink on a copied link's path. For the CONTAINMENT
/// verdict a source entry SHADOWS a destination entry at the same path (the
/// source's kind is what the post-copy tree will hold there); the LANDING
/// rules above are separate and refuse a pre-existing destination entry
/// outright. When the source holds no
/// symlink the rule is never consulted and the destination is not enumerated.
/// If a tree cannot be enumerated (a walk or `stat` error), the copy fails
/// CLOSED rather than guessing.
///
/// SOURCE QUIESCENCE: a containment verdict is made from the source's SHAPE
/// enumerated before the walk, and the copy holds no source lock. When the
/// source holds a symlink the copy re-enumerates the source at the end and
/// fails if its shape changed, so a source that moved during the copy is a
/// LOUD error rather than a silent divergence. This is the copy's analogue of
/// `sync`'s end-of-run source re-read. It DETECTS a persistent change; it does
/// NOT close the window between the final check and the `symlinkat` syscalls,
/// so a caller that cannot guarantee a quiescent source must serialize it
/// itself (a lock, or copying from a snapshot) — the crate does not lock an
/// arbitrary source path.
///
/// ERROR CLASSES (H3): the old live `symlink_metadata` probe collapsed EVERY
/// error — ENOENT, ENOTDIR, ELOOP, EACCES, ENAMETOOLONG — into `Absent` ("no
/// symlink here", i.e. ACCEPT), a fail-OPEN arm. The containment index has no
/// error arm: it answers `Absent`/`NotSymlink`/`Symlink` from enumerated
/// entries, so none of those classes can arise INSIDE the rule. They surface
/// in the ENUMERATION and fail CLOSED — the copy refuses rather than guessing
/// a component is absent:
///
/// * `ENOENT`: an entry that vanished between enumeration and the copy is a
///   tree that moved; refused (and the end-of-run source re-check reports a
///   source that changed shape).
/// * `ENOTDIR` / `ELOOP`: a component that is not a directory (or is a symlink
///   loop) cannot be enumerated; refused.
/// * `EACCES`: an unreadable directory cannot be enumerated; refused.
/// * `ENAMETOOLONG`: a spelling too long to enumerate is refused (the fd-based
///   copy walk itself still handles a deep tree; the enumeration is the
///   bound).
///
/// `dst_rel` must not name the destination ROOT itself (an empty path is
/// refused): use [`copy_dir_recursive_fd`] on a non-empty relative path.
/// Ancestors created for `dst_rel` use the store-private `0o700` mode (the
/// shared directory-creation authority); only the FINAL directory gets the
/// source's mode, and an intermediate staging directory's mode is outside the
/// copied tree, so it is not part of a staged-object digest.
pub fn copy_dir_recursive_fd(
    root: &RootDir,
    src: &Path,
    dst_rel: &RootedRelativePath,
) -> Result<()> {
    let dst_rel = dst_rel.as_path();
    struct Frame {
        dst_rel: PathBuf,
        src_dir: OwnedFd,
        /// The source directory's path, for error display ONLY (never a
        /// syscall argument, so a deep tree is not bounded by `PATH_MAX`).
        src_shown: PathBuf,
        names: std::vec::IntoIter<Vec<u8>>,
    }

    // NORMALIZE the source SPELLING first. A trailing separator (or a repeated
    // one) makes POSIX resolve the final component as an INTERMEDIATE one, so
    // `lstat("link/")` FOLLOWS the link and reports a directory — the very
    // symlink the refusal below exists to stop. `normalize_root` is the crate's
    // own spelling normalizer (the same one `RootDir` opening applies to the
    // destination side), so `link/` and `link` take one path.
    let src = normalize_root(src);
    let src_meta = std::fs::symlink_metadata(&src)
        .map_err(|e| Error::store(format!("stat {}: {e}", src.display())))?;
    if src_meta.file_type().is_symlink() {
        return Err(Error::store(format!(
            "copy_dir_recursive_fd: source {} is a symlink (refusing to follow a symlink \
             source)",
            src.display()
        )));
    }
    if !src_meta.is_dir() {
        return Err(Error::store(format!(
            "copy_dir_recursive_fd: source {} is not a directory",
            src.display()
        )));
    }
    let root_mode = src_meta.permissions().mode() & 0o7777;

    // Open the source ONCE, as a descriptor: the identity that decides overlap
    // is then the SAME directory the walk reads, so a concurrent spelling swap
    // cannot make the two disagree. An INTERMEDIATE symlink in the caller's
    // spelling is followed here (a read of the caller's own source, never a
    // mutation); the FINAL component was just proven not to be one.
    let src_root_fd: OwnedFd = std::fs::File::open(&src)
        .map_err(|e| Error::store(format!("open dir {}: {e}", src.display())))?
        .into();

    // Run the ONE gate on the WHOLE destination path BEFORE creating
    // anything, so a residue-spelled component is refused with no partial
    // state and in the operation's own (CREATE/COPY) vocabulary. The child
    // names are gated per-entry by [`refuse_unlandable_name`].
    refuse_reserved_creation(dst_rel)?;

    // Refuse an overlapping source/destination BEFORE creating anything.
    refuse_overlapping_copy(root, &src, &src_root_fd, dst_rel)?;
    // The resolved destination root, used to judge a symlink target whose
    // spelled walk leaves the copied SUBTREE (`../foo`): inside the subtree the
    // SOURCE tree answers whether a component is a symlink (it mirrors the
    // copy), but outside it only the destination root can, which is exactly
    // what `canonicalize_tree` will see.
    let dst_root_abs = owned_root_self_path(root)?;

    // THE ONE CONTAINMENT AUTHORITY. The two manifest views build a
    // [`crate::manifest::SymlinkContainmentIndex`] from their entry list and
    // run the indexed rule over it; this copy builds the SAME index from a
    // filesystem ENUMERATION of the source subtree (at `dst_rel`) and the
    // destination entries the run leaves in place, so all three views apply
    // exactly one rule over one fold and cannot disagree. Before this the copy
    // passed a LIVE `symlink_metadata` probe closure, which erred in BOTH
    // directions: its exact-string probe missed a fold-equal symlink the index
    // refuses (an accepted escape on a case-sensitive source copied to a
    // folding destination), it had NO destination result-view (a destination-
    // only symlink under `dst_rel` was invisible because the probe answered
    // from the source), and it collapsed EVERY `symlink_metadata` error to
    // `Absent` (fail-open).
    //
    // The source is enumerated with `WalkDir` (no follow) and the destination
    // root likewise; a source-relative path is relocated under `dst_rel`. A
    // destination entry at a path the source also provides is SHADOWED by the
    // source FOR THE CONTAINMENT VERDICT (the source's kind is what the
    // post-copy tree will hold there); the LANDING rules are separate and
    // refuse a pre-existing destination entry outright. A destination-only
    // entry survives (`Extraneous::Keep` is not a parameter of this primitive)
    // and does constrain the link. The destination
    // walk is skipped when the source holds NO symlink, because the rule is
    // consulted only for symlinks. An enumeration failure is an `Err` (fail
    // closed): an entry the walk could not describe could be a symlink the rule
    // must see.
    let source_entries = crate::manifest::live_entry_kinds(&src)?;
    let has_source_symlink = source_entries.iter().any(|(_, is_link)| *is_link);
    let dst_entries: Vec<(String, bool)> = if has_source_symlink {
        crate::manifest::live_entry_kinds(&dst_root_abs)?
    } else {
        Vec::new()
    };
    let dst_spelling = crate::manifest::canonical_rel_string(dst_rel).ok_or_else(|| {
        Error::store(format!(
            "copy_dir_recursive_fd: destination {} is not a canonical relative path",
            dst_rel.display()
        ))
    })?;
    // A source entry is spelled at `dst_rel/<sub>` in the index's root-relative
    // coordinates; the SOURCE view is the relocation of its own spelling.
    let source_paths: std::collections::BTreeSet<String> = source_entries
        .iter()
        .map(|(sub, _)| crate::manifest::relocate_under(&dst_spelling, sub))
        .collect();
    let mut combined: Vec<(String, bool)> =
        Vec::with_capacity(dst_entries.len() + source_entries.len());
    for (path, is_link) in &dst_entries {
        if source_paths.contains(path) {
            continue;
        }
        combined.push((path.clone(), *is_link));
    }
    for (sub, is_link) in &source_entries {
        combined.push((
            crate::manifest::relocate_under(&dst_spelling, sub),
            *is_link,
        ));
    }
    let containment_index = crate::manifest::SymlinkContainmentIndex::from_pairs(
        combined
            .iter()
            .map(|(path, is_link)| (path.as_str(), *is_link)),
    );

    // Create the destination chain (guarded, component-wise O_NOFOLLOW) and
    // record an UNDO JOURNAL of every directory mode this call changes, so a
    // failure restores them (I2/I3). A PRE-EXISTING final directory is added
    // to the journal with its ORIGINAL mode before it is widened, so a failed
    // copy puts it back exactly; a directory this call CREATED is added with
    // the removable 0o700.
    let (final_preexisting_mode, _created_ancestors) = create_destination_chain(root, dst_rel)?;
    let mut undo = CopyUndo::new(root);
    undo.plan(dst_rel, final_preexisting_mode.unwrap_or(0o700));
    // Widen the FINAL directory during the walk so a read-only SOURCE root can
    // receive children; the journal restores the original mode on failure and
    // the finalize applies the source's exact mode on success.
    set_dir_mode_fd(root, dst_rel, (root_mode | 0o200) & 0o7777)?;

    // `(dst_rel, final_mode)` for the deepest-first finalize.
    let mut dirs: Vec<(PathBuf, u32)> = Vec::new();
    let names = dir_entry_names(&src_root_fd)?;
    let mut stack: Vec<Frame> = vec![Frame {
        dst_rel: dst_rel.to_path_buf(),
        src_dir: src_root_fd,
        src_shown: src.to_path_buf(),
        names: names.into_iter(),
    }];

    while let Some(top) = stack.last_mut() {
        let Some(name) = top.names.next() else {
            stack.pop();
            continue;
        };
        // Validate the NAME through the crate's ONE name authority
        // BEFORE any destination mutation.
        let name_str = refuse_unlandable_name(&name, &top.src_shown)?;
        let child_rel = top.dst_rel.join(name_str);
        let child_src = top.src_shown.join(name_str);
        let st = fstatat_stat_io(&top.src_dir, &name)
            .map_err(|e| Error::store(format!("fstatat {}: {e}", child_src.display())))?;
        // `st_mode` is `u16` on macOS and `u32` on Linux: cast, not
        // `u32::from`, so the SAME expression is clippy-clean on both.
        let mode = (st.st_mode as u32) & 0o7777;
        let descend: Option<Frame> = match kind_from_mode(st.st_mode) {
            PathKind::Dir => {
                // Guarded create (mkdir semantics, refusing a residue/lock
                // spelling), then widen during the walk so a read-only source
                // directory can receive children. The created directory is
                // the call's own, so the undo journal restores it to 0o700 on a
                // failure (making the partial tree removable) and the finalize
                // gives it the source's exact mode on success.
                create_dir_fd_path(root, &child_rel)?;
                undo.plan(&child_rel, 0o700);
                set_dir_mode_fd(root, &child_rel, (mode | 0o200) & 0o7777)?;
                dirs.push((child_rel.clone(), mode));
                let child_fd = openat_no_follow_io_path(
                    &top.src_dir,
                    Path::new(name_str),
                    libc::O_RDONLY | libc::O_DIRECTORY,
                    0,
                )
                .map_err(|e| Error::store(format!("open dir {}: {e}", child_src.display())))?;
                let names = dir_entry_names(&child_fd)?;
                Some(Frame {
                    dst_rel: child_rel,
                    src_dir: child_fd,
                    src_shown: child_src,
                    names: names.into_iter(),
                })
            }
            PathKind::Symlink => {
                let link = readlinkat_name(&top.src_dir, &name, &child_src)?;
                // The crate's OWN symlink rules, REUSED rather than
                // restated — the target must be valid UTF-8 and free of
                // NUL/LF/CR/TAB ([`crate::manifest::validate_symlink_target`]),
                // and its spelled walk from the link's directory must not
                // escape the root or pass THROUGH a symlink component
                // ([`crate::manifest::check_relative_symlink_target`]). A link
                // is copied AS a link, never followed.
                let link_str = std::str::from_utf8(link.as_os_str().as_bytes()).map_err(|_| {
                    Error::store(format!(
                        "refusing to copy symlink {}: its target is not valid UTF-8",
                        child_src.display()
                    ))
                })?;
                crate::manifest::validate_symlink_target(&child_rel.to_string_lossy(), link_str)
                    .map_err(|e| {
                        Error::store(format!(
                            "refusing to copy symlink {}: {e}",
                            child_src.display()
                        ))
                    })?;
                if let Err(refusal) = crate::manifest::check_relative_symlink_target_indexed(
                    &child_rel,
                    &link,
                    &containment_index,
                ) {
                    return Err(Error::store(format!(
                        "refusing to copy symlink {}: {}",
                        child_src.display(),
                        crate::manifest::symlink_target_refusal_message(
                            refusal,
                            &child_src.display().to_string(),
                            &link.to_string_lossy(),
                        )
                    )));
                }
                // ALL-OR-NOTHING symlink landing: the ONE symlink authority
                // without its replace half, so a copied symlink refuses a
                // pre-existing destination entry exactly as the file and
                // directory rules do (a source symlink must not silently
                // UNLINK and replace a live destination file).
                symlink_new_fd(root, &link, &child_rel)?;
                None
            }
            kind @ (PathKind::File | PathKind::Other) => {
                // The crate refuses HARD LINKS by rule
                // (`canonicalize_tree` refuses a file with nlink > 1), so a
                // copy must not silently duplicate one into an independent
                // regular file.
                if kind == PathKind::File && st.st_nlink > 1 {
                    return Err(Error::store(format!(
                        "refusing to copy {}: it is a hard link (link count {}); the crate refuses \
                         hard links by rule, so a copy must not silently duplicate one into an \
                         independent regular file",
                        child_src.display(),
                        st.st_nlink
                    )));
                }
                // The source read goes through the crate's OWN guarded,
                // classified open ([`openat_readable_regular`]), which adds
                // `O_NONBLOCK` (a no-op for a regular file) and classifies the
                // OPENED inode — so a FIFO/socket/device is REFUSED instead of
                // blocking forever in `open(2)`.
                let src_fd =
                    openat_readable_regular(&top.src_dir, Path::new(name_str), libc::O_RDONLY)
                        .map_err(|e| {
                            Error::store(format!(
                                "refusing to copy {}: {e} (the crate refuses special files by \
                                 rule)",
                                child_src.display()
                            ))
                        })?;
                let mut src_f = std::fs::File::from(src_fd);
                // Create-new-only through the mutating `openat` chokepoint
                // (which runs the lock-record guard); a pre-existing entry is
                // refused (O_EXCL), matching the source tool.
                let dst_fd = openat_no_follow_path(
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
    // the copy last (it is the shallowest). The pre-existing final directory's
    // original mode was saved in the journal, so on SUCCESS it takes the
    // source's mode exactly as before.
    dirs.sort_by_key(|(rel, _)| std::cmp::Reverse(rel.components().count()));
    for (rel, mode) in dirs {
        set_dir_mode_fd(root, &rel, mode)?;
    }
    set_dir_mode_fd(root, dst_rel, root_mode)?;
    // The exact modes are in place; an error from here on leaves them intended,
    // so the undo journal must not fight the finalize.
    undo.disarm();

    // SOURCE-QUIESCENCE DETECTION (the copy's analogue of `sync`'s end-of-run
    // source re-read). The containment verdict for every copied link was made
    // from the source SHAPE enumerated before the walk; a source that changed
    // its shape (a component turned into or out of a symlink, an entry added or
    // removed) after that enumeration could be copied into a tree the verdict
    // did not describe. The copy holds no source lock, so rather than trust the
    // caller's quiescent-source obligation it re-enumerates the source and
    // compares the shape the verdict used, turning a silent divergence into a
    // LOUD `Err`. This runs only when the source held a symlink (otherwise no
    // containment verdict was made). The window between this check and the
    // `symlinkat` syscalls is NOT closed — see the primitive doc.
    if has_source_symlink {
        let after = crate::manifest::live_entry_kinds(&src)?;
        if after != source_entries {
            return Err(Error::store(format!(
                "copy_dir_recursive_fd: the source {} changed shape while it was being copied \
                 (its entries no longer match the view the symlink-containment verdict was made \
                 against), so the copied tree cannot be trusted; the destination may hold a \
                 partial tree",
                src.display()
            )));
        }
    }
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
    refuse_reserved_mutation(rel, Sanction::None)?;
    let fd = openat_no_follow_path(root.as_fd(), rel, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
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
///
/// COST — O(depth^2) `openat` CALLS (documented, deliberately NOT changed
/// here): the walk reopens the whole root-relative path COMPONENT-WISE for
/// every directory it enumerates, every file it fsyncs, and every directory it
/// finally fsyncs, because it keeps only the path in its heap stack, never a
/// directory descriptor. Measured `openat` counts (Linux, one `open` per
/// component): 1202 at depth 32, 17042 at depth 128, 264722 at depth 512 —
/// i.e. ~depth^2. The fix (hold one directory descriptor per level and reach
/// each child relative to its parent) is understood but not taken here: it
/// trades the open count for one descriptor per level, so its failure mode at
/// the descriptor limit changes shape, and the current form is already
/// fail-closed, error-propagating, deepest-first, and ITERATIVE (a deep tree
/// surfaces a clean `Err`, never an abort). A caller fsyncing trees deeper than
/// a few hundred levels should prefer a streaming walk.
pub fn fsync_tree_recursive_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<()> {
    let rel = rel.as_path();
    let mut dirs: Vec<PathBuf> = vec![rel.to_path_buf()];
    let mut stack: Vec<PathBuf> = vec![rel.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in read_dir_fd_path(root, &dir)? {
            let child = dir.join(&entry.name);
            if entry.is_dir {
                dirs.push(child.clone());
                stack.push(child);
            } else {
                // Symlinks and other entry kinds are SKIPPED (their
                // durability is their directory entry, covered by the
                // parent's fsync below); only a regular file is fsynced.
                if let Some(PathKind::File) = path_kind_fd_path(root, &child)? {
                    let fd = openat_no_follow_path(root.as_fd(), &child, libc::O_RDONLY, 0)?;
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
        let fd = openat_no_follow_path(root.as_fd(), &dir, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
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
                let sub = openat_no_follow_path(
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
#[cfg(test)]
pub(crate) fn remove_dir_all_path(path: &Path) -> Result<()> {
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
pub fn write_file_fd(root: &RootDir, rel: &RootedRelativePath, bytes: &[u8]) -> Result<()> {
    let rel = rel.as_path();
    // Create-or-truncate would rewrite the record's content in place.
    refuse_reserved_mutation(rel, Sanction::None)?;
    let (parent_fd, name) = parent_fd_of(root.as_fd(), rel)?;
    let f = openat_no_follow_path(
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
pub fn read_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<Vec<u8>> {
    let rel = rel.as_path();
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
pub fn read_link_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<PathBuf> {
    let rel = rel.as_path();
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
pub fn read_json_fd<T: serde::de::DeserializeOwned>(
    root: &RootDir,
    rel: &RootedRelativePath,
) -> Result<T> {
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
pub fn path_state_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<bool> {
    let rel = rel.as_path();
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
pub fn path_kind_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<Option<PathKind>> {
    path_kind_fd_path(root, rel.as_path())
}

/// [`path_kind_fd`] for an INTERNAL, already-validated `&Path` (a child
/// derived from a [`RootedRelativePath`]).
fn path_kind_fd_path(root: &RootDir, rel: &Path) -> Result<Option<PathKind>> {
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
/// normal component: the validated boundary refuses the empty and `.`
/// spellings, so the OWNED ROOT itself is enumerated with [`read_root_dir_fd`]
/// instead.
pub fn read_dir_fd(root: &RootDir, rel: &RootedRelativePath) -> Result<Vec<DirEntry>> {
    read_dir_fd_path(root, rel.as_path())
}

/// [`read_dir_fd`] for an INTERNAL, already-validated `&Path` (a directory
/// derived from a [`RootedRelativePath`]).
fn read_dir_fd_path(root: &RootDir, rel: &Path) -> Result<Vec<DirEntry>> {
    let dir_fd = openat_no_follow_path(root.as_fd(), rel, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    read_dir_of_opened_fd(&dir_fd, rel)
}

/// Read the entries of the OWNED ROOT itself.
///
/// `read_dir_fd(root, "")` and `read_dir_fd(root, ".")` are refused by the
/// validated [`RootedRelativePath`] boundary — those spellings name the root,
/// not an entry UNDER it —
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
        Error, PathKind, ReplaceOutcome, ReplaceStage, RootDir, RootedRelativePath, Sanction,
        copy_dir_recursive_fd, fsync_tree_recursive_fd, openat_no_follow, parent_fd_of,
        path_kind_fd, read_dir_fd, read_fd, read_link_fd, read_root_dir_fd, remove_dir_all_fd,
        remove_dir_all_path, remove_dir_fd, remove_file_fd, remove_owned_lock_record_fd,
        remove_residue_dir_all_fd, remove_residue_file_fd, rename_residue_paths, renameat_fd,
        renameat_paths, replace_order_probe, set_private_fd, symlink_fd, write_atomic_cas_fd,
        write_atomic_replace, write_atomic_replace_fd, write_file_fd,
    };
    use crate::error::ReservedKind;
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    /// A validated root-relative path for the tests: the primitives take the
    /// validated type, so a test spelling is parsed at the boundary too.
    fn rp(s: &str) -> RootedRelativePath {
        RootedRelativePath::parse(Path::new(s)).unwrap()
    }

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
    fn dir_names_fd(root: &RootDir, rel: &RootedRelativePath) -> Vec<String> {
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
            read_link_fd(&root, &rp("link")).unwrap(),
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

        let err = read_link_fd(&root, &rp("sub/secret"))
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
        let err = read_link_fd(&root, &rp("plain.txt"))
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
        let err = read_link_fd(&root, &rp("missing")).expect_err("a missing entry must error");
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
            path_kind_fd(&root, &rp("file")).unwrap(),
            Some(PathKind::File),
            "a regular file is File"
        );
        assert_eq!(
            path_kind_fd(&root, &rp("dir")).unwrap(),
            Some(PathKind::Dir),
            "a directory is Dir"
        );
        assert_eq!(
            path_kind_fd(&root, &rp("link")).unwrap(),
            Some(PathKind::Symlink),
            "a symlink is Symlink, never its target's kind"
        );
        assert_eq!(
            path_kind_fd(&root, &rp("dirlink")).unwrap(),
            Some(PathKind::Symlink),
            "a symlink TO A DIRECTORY must still be Symlink, never Dir"
        );
        assert_eq!(
            path_kind_fd(&root, &rp("fifo")).unwrap(),
            Some(PathKind::Other),
            "a FIFO is Other"
        );
        assert_eq!(
            path_kind_fd(&root, &rp("missing")).unwrap(),
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

        let err = path_kind_fd(&root, &rp("sub/secret"))
            .expect_err("a parent-component symlink must be refused, not followed");
        assert!(matches!(err, Error::Store(_)), "got: {err:?}");
        assert!(
            err.to_string().contains("openat"),
            "the refusal must name the component-wise open, got: {err}"
        );
    }

    /// An absolute path, a `..` walk, a `.`, and the empty path are refused
    /// by the VALIDATED BOUNDARY ([`RootedRelativePath::parse`]) — the ONE
    /// place a root-relative spelling is checked now that the primitives take
    /// the type. The primitive can no longer be handed such a spelling at all,
    /// so the refusal is asserted where it happens.
    #[test]
    fn path_kind_fd_refuses_escaping_spellings() {
        let (dir, _root) = owned_root();
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
            let err = RootedRelativePath::parse(&spelling)
                .expect_err("an escaping or empty spelling must be refused");
            assert!(
                matches!(err, Error::Transport(_)),
                "{spelling:?} must be refused by the validated boundary, got: {err}"
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
    /// `..` walk, a literal `.` segment, and the empty path are refused by the
    /// VALIDATED BOUNDARY — not incidentally by a missing or symlinked outside
    /// entry — and so can never resolve to an outside entry.
    #[test]
    fn relative_path_spelling_resolves_identically_or_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let root_path = tmp.path().join("root");
        std::fs::create_dir(&root_path).unwrap();
        let root = RootDir::open(&root_path).expect("open the owned root");
        std::fs::create_dir_all(root_path.join("a")).unwrap();
        std::fs::write(root_path.join("a/b"), b"IN-ROOT").unwrap();
        for spelling in ["a/b", "a/b/", "a//b"] {
            assert_eq!(
                read_fd(&root, &rp(spelling)).unwrap(),
                b"IN-ROOT".to_vec(),
                "{spelling:?} must name the same entry as a/b"
            );
        }
        // THE DELIBERATE TIGHTENING (constraint #1): `a/./b` used to resolve
        // to `a/b` through the looser `validate_rel` guard (which inherited
        // `Path::components`' erasure of a non-leading `.`). The validated
        // boundary scans the literal spelling and REFUSES it, so it is no
        // longer an accepted spelling.
        assert!(
            RootedRelativePath::parse(Path::new("a/./b")).is_err(),
            "a literal `.` segment must be refused by the validated boundary"
        );

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
            let err = RootedRelativePath::parse(&spelling)
                .expect_err("an escaping or empty spelling must be refused");
            assert!(
                matches!(err, Error::Transport(_)),
                "{spelling:?} must be refused by the validated boundary, got: {err}"
            );
        }

        // A mutation spelling is refused the same way: nothing lands outside.
        assert!(
            RootedRelativePath::parse(Path::new("../outside-secret")).is_err(),
            "a `..` mutation spelling must be refused by the validated boundary"
        );
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
        let rel = &rp("sub/marker.json");
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
                dir_names_fd(&root, &rp("sub")),
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
        let err = write_atomic_replace_fd(&root, &rp("sub/marker.json"), b"NEW", &mut |_| None)
            .unwrap_err();
        assert!(matches!(err, Error::Store(_)), "got: {err:?}");
        assert_eq!(
            dir_names_fd(&root, &rp("sub")),
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
        let rel = &rp("marker.json");
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
        let rel = &rp("nested/marker.json");
        let outcome = write_atomic_replace_fd(&root, rel, b"NEW", &mut |_| None).unwrap();
        assert!(matches!(outcome, ReplaceOutcome::ReplacedDurable));
        assert_eq!(read_fd(&root, rel).unwrap(), b"NEW".to_vec());
        assert_eq!(dir_names_fd(&root, &rp("nested")), only("marker.json"));
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
        let rel = &rp("marker.json");
        write_atomic_replace_fd(&root, rel, b"NEW", &mut |_| None).unwrap();
        assert_eq!(entry_names(dir.path()), only("marker.json"));
        assert_eq!(read_fd(&root, rel).unwrap(), b"NEW".to_vec());

        let (dir, root) = owned_root();
        let rel = &rp("cas.json");
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
        let rel = &rp("cas.json");
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
            write_atomic_replace_fd(&root, &rp("newdir/sub/file.txt"), b"x", &mut |_| None)
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
    /// empty and `.` spellings are refused by the validated boundary. The
    /// dedicated root enumerator reaches it, while those child spellings stay
    /// refused.
    #[test]
    fn the_owned_root_is_enumerable_and_root_child_spellings_stay_refused() {
        let (dir, root) = owned_root();
        std::fs::write(dir.path().join("root-residue"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        assert!(
            RootedRelativePath::parse(Path::new("")).is_err(),
            "the empty spelling names the root, not an entry under it"
        );
        assert!(
            RootedRelativePath::parse(Path::new(".")).is_err(),
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
        let err = remove_file_fd(&root, &rp("operation.lock"))
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
        let alias_err = remove_file_fd(&root, &rp(".Destroot.Operation.Lock"))
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
        let err = write_atomic_replace_fd(&root, &rp("operation.lock"), b"evil", &mut |_| None)
            .expect_err("replacing the crate's lock record through the substrate must be refused");
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
        let cas = write_atomic_cas_fd(&root, &rp(".Destroot.Operation.Lock"), b"evil")
            .expect_err("a CAS of a case alias of the record must be refused");
        assert!(matches!(cas, Error::Conflict(_)), "{cas:?}");
        let plain = write_file_fd(&root, &rp("OPERATION.LOCK"), b"evil")
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
        let err = remove_dir_all_fd(&root, &rp("state"))
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
        let err = renameat_paths(&root, &rp("state"), &rp("state2"))
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
        renameat_paths(&root, &rp("state"), &rp("state2"))
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
        let err = set_private_fd(&root, &rp("sub"))
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
        set_private_fd(&root, &rp("f")).expect("a regular file is chmodded");
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
        let err = set_private_fd(&root, &rp("operation.lock"))
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
            &rp("operation.lock"),
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
        let fd = openat_no_follow(root.as_fd(), &rp("operation.lock"), libc::O_RDONLY, 0)
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
        let err = remove_dir_all_fd(&root, &rp("victim"))
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
        let err = remove_dir_all_fd(&root, &rp("victim/.sync-aside.1234.0"))
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
        let err = remove_dir_all_fd(&root, &rp("other"))
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

        remove_owned_lock_record_fd(&root, &rp(".gone.operation.lock"), &owned)
            .expect("the owned record is retired");
        assert!(!dir.path().join(".gone.operation.lock").exists());

        let err = remove_owned_lock_record_fd(&root, &rp(".keep.operation.lock"), &owned)
            .expect_err("a record the authority does not own must be refused");
        assert!(matches!(err, Error::Conflict(_)), "{err:?}");
        assert!(dir.path().join(".keep.operation.lock").exists());

        std::fs::write(dir.path().join("ordinary"), b"data").unwrap();
        assert!(
            remove_owned_lock_record_fd(&root, &rp("ordinary"), &owned).is_err(),
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
        assert!(remove_dir_all_fd(&root, &rp(".sync-aside.7.0")).is_err());

        // A NESTED strand stops the discard.
        std::fs::create_dir_all(dir.path().join(".sync-aside.7.0/nested/.sync-aside.9.9")).unwrap();
        std::fs::write(
            dir.path()
                .join(".sync-aside.7.0/nested/.sync-aside.9.9/held"),
            b"y",
        )
        .unwrap();
        let err = remove_residue_dir_all_fd(&root, &rp(".sync-aside.7.0"))
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
        remove_residue_dir_all_fd(&root, &rp(".sync-aside.7.0")).unwrap();
        assert!(std::fs::symlink_metadata(dir.path().join(".sync-aside.7.0")).is_err());

        // Ordinary content is not discardable by the same primitive.
        std::fs::write(dir.path().join("ordinary"), b"data").unwrap();
        let err = remove_residue_dir_all_fd(&root, &rp("ordinary"))
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
        let strand = &rp(".sync-aside.1.0");
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
        assert_residue(renameat_paths(&root, &rp("ordinary"), strand).unwrap_err());
        intact(&dir);
        assert!(dir.path().join("ordinary").exists(), "the source survives");

        // 6. symlink_fd — unlink-then-link.
        let (dir, root) = seed();
        assert_residue(symlink_fd(&root, Path::new("target"), strand).unwrap_err());
        intact(&dir);

        // 7. remove_dir_fd — an EMPTY strand DIRECTORY.
        let (dir, root) = owned_root();
        std::fs::create_dir(dir.path().join(".sync-aside.2.0")).unwrap();
        assert_residue(remove_dir_fd(&root, &rp(".sync-aside.2.0")).unwrap_err());
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
        assert_residue(rename_residue_paths(&root, &rp("ordinary2"), strand).unwrap_err());
        intact(&dir);
        rename_residue_paths(&root, &rp("ordinary2"), &rp(".sync-aside.5.0")).unwrap();
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
        copy_dir_recursive_fd(&root, &src, &rp("dst")).unwrap();

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
        fsync_tree_recursive_fd(&root, &rp("dst")).unwrap();
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

        let err = copy_dir_recursive_fd(&root, &src, &rp("escape/nested"))
            .expect_err("a symlink-injected destination component must be refused");
        assert!(
            matches!(err, Error::Store(_)),
            "the refusal must be a store error, got: {err:?}"
        );
        let msg = err.to_string();
        // Named condition, not merely "some openat failed": the component-wise
        // `O_NOFOLLOW` open raises ELOOP on the injected symlink.
        assert!(
            msg.contains("openat") && msg.contains("escape/nested"),
            "the refusal must name the component-wise open of the offending path, got: {msg}"
        );
        assert!(
            msg.contains("Too many levels of symbolic links")
                || msg.contains("ELOOP")
                || msg.contains("Not a directory"),
            "the refusal must name the SYMLINK refusal the component-wise O_NOFOLLOW open raises \
             (ELOOP on Linux; macOS classifies the O_NOFOLLOW|O_DIRECTORY refusal as ENOTDIR, \
             which is `open_or_create_dir`'s documented non-directory arm), got: {msg}"
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
        let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
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
        let err = fsync_tree_recursive_fd(&root, &rp("alias/f"))
            .expect_err("a symlink component must be refused");
        let msg = err.to_string();
        // The named condition: ELOOP from the component-wise `O_NOFOLLOW` open,
        // not merely the presence of the word "openat".
        assert!(
            msg.contains("openat") && msg.contains("alias/f"),
            "the refusal must name the component-wise open of the offending path, got: {msg}"
        );
        assert!(
            msg.contains("Too many levels of symbolic links")
                || msg.contains("ELOOP")
                || msg.contains("Not a directory"),
            "the refusal must name the SYMLINK refusal of the component-wise O_NOFOLLOW open \
             (ELOOP on Linux; ENOTDIR on macOS), got: {msg}"
        );
    }

    // ------------------------------------------------------------------
    // A FIFO (or socket/device) in the source is REFUSED promptly.
    // ------------------------------------------------------------------

    /// A FIFO in the source tree must be refused PROMPTLY, never opened
    /// blocking. `open(2)` of a FIFO read-only blocks until a writer appears,
    /// and the primitive used to `File::open` every non-dir/non-symlink entry.
    /// The call runs on a worker thread so the WAIT IS BOUNDED: the test
    /// returns (failing) after the timeout even if the fix regresses, and the
    /// suite can never hang. PRE-FIX: the worker blocks in `open` and never
    /// answers, so the timeout fires.
    #[test]
    fn copy_dir_recursive_fd_refuses_a_fifo_source_without_blocking() {
        let (base, _root, src) = out_of_root_fixture();
        std::fs::write(src.join("a-before"), b"before").unwrap();
        let fifo = src.join("pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(c.as_ptr(), 0o600) },
            0,
            "mkfifo: {}",
            std::io::Error::last_os_error()
        );

        let (tx, rx) = std::sync::mpsc::channel();
        let root_path = base.path().join("root");
        let src_path = src.clone();
        std::thread::spawn(move || {
            let owned = RootDir::open(&root_path).expect("open the owned root");
            let r = copy_dir_recursive_fd(&owned, &src_path, &rp("dst"));
            let _ = tx.send(r.map_err(|e| e.to_string()));
        });
        let outcome = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap_or_else(|_| {
                panic!(
                    "copy_dir_recursive_fd did not return within 5s: the FIFO open is BLOCKING \
                 an unbounded hang on user data"
                )
            });
        let err = outcome.expect_err("a FIFO in the source must be refused, not opened");
        assert!(
            err.contains("not a regular file") && err.contains("refusing to copy"),
            "the refusal must classify the OPENED inode and name the copy, got: {err}"
        );
        assert!(
            !base.path().join("root/dst/pipe").exists(),
            "the FIFO must not be materialized in the destination"
        );
    }

    /// Companion: a Unix SOCKET is a non-regular entry that `open(2)` does
    /// not block on (it fails `ENXIO`), so this is a COVERAGE case rather than
    /// a hang reproduction — but it proves the classified-open path refuses a
    /// non-regular entry with a store error. A DEVICE cannot be created by an
    /// unprivileged process (`mknod` needs `CAP_MKNOD`), so the device case is
    /// REASONED, not run: [`openat_readable_regular`] classifies every
    /// `S_IFMT` outside file/dir/symlink as `PathKind::Other` and refuses it,
    /// exactly as it refuses the FIFO and the socket.
    #[test]
    fn copy_dir_recursive_fd_refuses_a_socket_source() {
        let (base, root, src) = out_of_root_fixture();
        let sock = src.join("sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
            .expect_err("a socket in the source must be refused");
        let msg = err.to_string();
        assert!(
            matches!(err, Error::Store(_)) && msg.contains("refusing to copy"),
            "the refusal must be a store error naming the copy, got: {err}"
        );
        assert!(!base.path().join("root/dst/sock").exists());
    }

    // ------------------------------------------------------------------
    // The crate's ONE name authority gates every landed name.
    // ------------------------------------------------------------------

    /// A source entry whose name is a crate TEMP shape is refused instead
    /// of landed. `is_crate_temp_name` recognises the landed entry, so the
    /// documented recovery sweep would DELETE a live file. PRE-FIX: the name
    /// was written verbatim and the copy returned `Ok`.
    #[test]
    fn copy_dir_recursive_fd_refuses_a_crate_temp_name() {
        let (base, root, src) = out_of_root_fixture();
        std::fs::write(src.join(".victim.tmp.1.2"), b"live content").unwrap();
        let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
            .expect_err("a crate-temp-shaped name must be refused, not landed");
        assert!(
            err.to_string().contains("unaddressable") && err.to_string().contains("recovery sweep"),
            "the refusal must name the unaddressability and the sweep, got: {err}"
        );
        assert!(
            !base.path().join("root/dst/.victim.tmp.1.2").exists(),
            "the temp-shaped name was never landed"
        );
    }

    /// A reserved SPELLING (the claim-aside namespace) is refused for the
    /// same reason: the sync strips reserved components from both manifests,
    /// so the crate could never transfer or destroy an entry with this name.
    #[test]
    fn copy_dir_recursive_fd_refuses_a_reserved_source_name() {
        let (base, root, src) = out_of_root_fixture();
        std::fs::write(src.join(".sync-aside.1.2"), b"live content").unwrap();
        let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
            .expect_err("a reserved spelling must be refused");
        assert!(err.to_string().contains("unaddressable"), "{err}");
        assert!(!base.path().join("root/dst/.sync-aside.1.2").exists());
    }

    /// A name carrying a manifest-wire separator (LF, CR, TAB) is refused,
    /// so the destination always `canonicalize_tree`s cleanly. NUL cannot be
    /// tested because NO supported filesystem can represent it (an OS filename
    /// is a NUL-terminated C string).
    #[test]
    fn copy_dir_recursive_fd_refuses_a_wire_unrepresentable_name() {
        let (base, root, src) = out_of_root_fixture();
        for (rep, name) in [
            ("LF", "bad\nname"),
            ("CR", "bad\rname"),
            ("TAB", "bad\tname"),
        ] {
            std::fs::write(src.join(name), b"x").unwrap();
            // A FRESH destination per case: reusing one would make an earlier
            // case's landed entries collide (`O_EXCL`) before this case's name
            // is reached.
            let dst = format!("dst-{rep}");
            let err = copy_dir_recursive_fd(&root, &src, &rp(&dst))
                .expect_err("a wire-unrepresentable name must be refused");
            assert!(
                err.to_string().contains("wire-unrepresentable"),
                "the refusal must name the wire rule for {rep}, got: {err}"
            );
            assert!(
                !base.path().join("root").join(&dst).join(name).exists(),
                "the {rep} name was never landed"
            );
            std::fs::remove_file(src.join(name)).unwrap();
        }
    }

    /// A decomposed (non-NFC) name is refused rather than landed on a
    /// normalization-sensitive filesystem. This is representable on macOS APFS
    /// and Linux alike (both store the decomposed spelling), so it runs on
    /// both.
    #[test]
    fn copy_dir_recursive_fd_refuses_a_non_nfc_name() {
        let (base, root, src) = out_of_root_fixture();
        // `e` + COMBINING ACUTE ACCENT: NFD, not NFC.
        let decomposed = "e\u{301}";
        std::fs::write(src.join(decomposed), b"x").unwrap();
        let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
            .expect_err("a non-NFC name must be refused");
        assert!(
            err.to_string().contains("NFC"),
            "the refusal must name the NFC rule, got: {err}"
        );
        assert!(!base.path().join("root/dst").join(decomposed).exists());
    }

    /// A NON-UTF-8 name is refused. The spelling can only be CREATED on a
    /// filesystem that stores raw bytes (Linux ext4/tmpfs); macOS APFS refuses
    /// the write, so the case is announced as a SKIP there rather than silently
    /// passing.
    #[test]
    fn copy_dir_recursive_fd_refuses_a_non_utf8_name() {
        let (base, root, src) = out_of_root_fixture();
        let raw = std::ffi::OsStr::from_bytes(b"raw\xffname");
        if std::fs::write(src.join(raw), b"x").is_err() {
            crate::test_support::announce_skip(
                "this filesystem cannot store a non-UTF-8 name, so the refusal cannot be exercised here",
            );
            return;
        }
        let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
            .expect_err("a non-UTF-8 name must be refused");
        assert!(
            err.to_string().contains("not valid UTF-8"),
            "the refusal must name the UTF-8 rule, got: {err}"
        );
        assert!(!base.path().join("root/dst").join(raw).exists());
    }

    /// The legitimate cases still copy — ordinary names, spaces, quotes,
    /// `$`, `;`, `*`, a leading `-`, a 255-byte name, and a DIRECTORY with a
    /// space. These are exactly the classes the crate's id charset refuses but
    /// a manifest NAME accepts, so the name gate must not be the id charset.
    #[test]
    fn copy_dir_recursive_fd_still_copies_legal_awkward_names() {
        let (base, root, src) = out_of_root_fixture();
        let long = "L".repeat(crate::atomic::NAME_MAX);
        let names = [
            "ordinary",
            "with space",
            "quote's\"x",
            "dollar$d",
            "semi;colon",
            "star*star",
            "-leading-dash",
            long.as_str(),
        ];
        for name in names {
            std::fs::write(src.join(name), name.as_bytes()).unwrap();
        }
        std::fs::create_dir(src.join("dir with space")).unwrap();
        std::fs::write(src.join("dir with space/inner"), b"inner").unwrap();

        copy_dir_recursive_fd(&root, &src, &rp("dst")).unwrap();
        for name in names {
            assert_eq!(
                std::fs::read(base.path().join("root/dst").join(name)).unwrap(),
                name.as_bytes(),
                "the legal name {name:?} must copy"
            );
        }
        assert_eq!(
            std::fs::read(base.path().join("root/dst/dir with space/inner")).unwrap(),
            b"inner"
        );
        // The whole result must canonicalize cleanly (the manifest walk's oracle).
        crate::manifest::canonicalize_tree(&base.path().join("root/dst")).unwrap();
    }

    // ------------------------------------------------------------------
    // Overlapping source/destination is refused by construction.
    // ------------------------------------------------------------------

    /// The overlapping reproduction — `src = <root>/tree`, `dst_rel =
    /// "tree/sub"` — must be refused BEFORE anything is created, so no partial
    /// tree is left. PRE-FIX: `ensure_private_dir_fd` created `<root>/tree/sub`,
    /// the source `read_dir` re-yielded it, and the walk recursed to
    /// `ENAMETOOLONG` (macOS depth 236, Linux 1017).
    #[test]
    fn copy_dir_recursive_fd_refuses_a_destination_inside_the_source() {
        let (base, root, _src) = out_of_root_fixture();
        let tree = base.path().join("root/tree");
        std::fs::create_dir(&tree).unwrap();
        std::fs::write(tree.join("f"), b"f").unwrap();
        std::fs::create_dir(tree.join("d")).unwrap();
        std::fs::write(tree.join("d/inner"), b"inner").unwrap();

        let err = copy_dir_recursive_fd(&root, &tree, &rp("tree/sub"))
            .expect_err("a destination inside the source must be refused");
        assert!(
            err.to_string().contains("overlap"),
            "the refusal must name the overlap, got: {err}"
        );
        assert!(
            !base.path().join("root/tree/sub").exists(),
            "no partial destination tree may be left behind"
        );
    }

    /// The reverse overlap (source inside the destination root) and the
    /// equal case are refused too.
    #[test]
    fn copy_dir_recursive_fd_refuses_a_source_inside_the_destination() {
        let (base, root, _src) = out_of_root_fixture();
        std::fs::create_dir_all(base.path().join("root/tree/sub")).unwrap();
        std::fs::write(base.path().join("root/tree/sub/f"), b"f").unwrap();
        let inner = base.path().join("root/tree/sub");
        let err = copy_dir_recursive_fd(&root, &inner, &rp("tree"))
            .expect_err("a source inside the destination must be refused");
        assert!(err.to_string().contains("overlap"), "{err}");
    }

    /// A genuinely non-overlapping source still copies — including a source
    /// INSIDE the root that is a sibling of the destination, and an
    /// out-of-root source sharing a long path prefix with the root.
    #[test]
    fn copy_dir_recursive_fd_allows_non_overlapping_sources() {
        let (base, root, _src) = out_of_root_fixture();
        // A sibling under the root.
        let tree = base.path().join("root/tree");
        std::fs::create_dir(&tree).unwrap();
        std::fs::write(tree.join("f"), b"f").unwrap();
        copy_dir_recursive_fd(&root, &tree, &rp("copy")).unwrap();
        assert_eq!(
            std::fs::read(base.path().join("root/copy/f")).unwrap(),
            b"f"
        );

        // An out-of-root source whose spelling shares the root's prefix.
        let twin = base.path().join("root2");
        std::fs::create_dir(&twin).unwrap();
        std::fs::write(twin.join("g"), b"g").unwrap();
        copy_dir_recursive_fd(&root, &twin, &rp("copy2")).unwrap();
        assert_eq!(
            std::fs::read(base.path().join("root/copy2/g")).unwrap(),
            b"g"
        );
    }

    // ------------------------------------------------------------------
    // Symlink containment is the crate's own rule.
    // ------------------------------------------------------------------

    /// An ESCAPING relative symlink target is refused (both platforms), and
    /// once it is removed the ordinary tree plus the legitimate in-root
    /// relative link copy and the destination `canonicalize_tree`s cleanly.
    /// PRE-FIX: the escaping target was copied verbatim and the result failed
    /// `canonicalize_tree`.
    #[test]
    fn copy_dir_recursive_fd_refuses_an_escaping_symlink_and_keeps_the_tree_canonicalizable() {
        let (base, root, src) = out_of_root_fixture();
        std::os::unix::fs::symlink("../../outside", src.join("esc")).unwrap();
        let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
            .expect_err("an escaping symlink target must be refused");
        assert!(
            err.to_string().contains("escaping symlink"),
            "the refusal must reuse the crate's symlink vocabulary, got: {err}"
        );
        assert!(!base.path().join("root/dst/esc").exists());

        // With the escaping link gone, the legitimate in-root relative link
        // (`link -> file.txt`, seeded by the fixture) copies, and the whole
        // destination canonicalizes cleanly.
        std::fs::remove_file(src.join("esc")).unwrap();
        copy_dir_recursive_fd(&root, &src, &rp("dst2")).unwrap();
        assert_eq!(
            std::fs::read_link(base.path().join("root/dst2/link")).unwrap(),
            Path::new("file.txt")
        );
        crate::manifest::canonicalize_tree(&base.path().join("root/dst2")).unwrap();
    }

    /// A relative symlink target that stays INSIDE the root but leaves the
    /// COPIED subtree and resolves THROUGH a pre-existing destination symlink
    /// is refused too: the kernel follows the component, so
    /// `canonicalize_tree(root)` would refuse the result. Inside the copied
    /// subtree the SOURCE tree answers whether a component is a symlink;
    /// outside it the resolved destination root does.
    #[test]
    fn copy_dir_recursive_fd_refuses_a_target_through_an_outside_symlink() {
        let (base, root, src) = out_of_root_fixture();
        std::os::unix::fs::symlink("real", base.path().join("root/outside-link")).unwrap();
        std::fs::create_dir(base.path().join("root/real")).unwrap();
        // From `dst/esc`, `../outside-link` lands on `<root>/outside-link`.
        std::os::unix::fs::symlink("../outside-link", src.join("esc")).unwrap();
        let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
            .expect_err("a target through an outside symlink component must be refused");
        assert!(
            err.to_string().contains("escaping symlink"),
            "the refusal must reuse the crate's symlink vocabulary, got: {err}"
        );
    }

    // ------------------------------------------------------------------
    // H2: the copy uses the SAME index as the two manifest views.
    // ------------------------------------------------------------------

    /// A CASE-SENSITIVE source directory, with the platform resource that
    /// provides it kept alive until drop.
    ///
    /// A Linux tempdir (ext4) is case-sensitive. macOS's default APFS is
    /// case-INsensitive, so the helper creates and mounts a case-sensitive
    /// APFS image (no privileges needed); the image is detached and deleted on
    /// drop. Returns `None` after announcing a skip when no case-sensitive
    /// filesystem can be provided, so a run that cannot host the case is never
    /// silent.
    struct CaseSensitiveSource {
        path: PathBuf,
        _tmp: tempfile::TempDir,
        #[cfg(target_os = "macos")]
        _mount: Option<MacCaseSensitiveMount>,
    }

    impl CaseSensitiveSource {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    #[cfg(target_os = "macos")]
    struct MacCaseSensitiveMount {
        mountpoint: PathBuf,
        dmg: PathBuf,
    }

    #[cfg(target_os = "macos")]
    impl Drop for MacCaseSensitiveMount {
        fn drop(&mut self) {
            let _ = std::process::Command::new("hdiutil")
                .args(["detach", "-force"])
                .arg(&self.mountpoint)
                .output();
            let _ = std::fs::remove_file(&self.dmg);
        }
    }

    fn case_sensitive_source() -> Option<CaseSensitiveSource> {
        let tmp = tempfile::tempdir().unwrap();
        #[cfg(not(target_os = "macos"))]
        {
            let path = tmp.path().join("cs-src");
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("Case-Probe"), b"x").unwrap();
            if std::fs::symlink_metadata(path.join("cASE-pROBE")).is_ok() {
                crate::test_support::announce_skip(
                    "this host filesystem folds ASCII case, so a case-sensitive source cannot be \
                     provided here; the case-sensitive-source reproductions are untestable",
                );
                return None;
            }
            Some(CaseSensitiveSource { path, _tmp: tmp })
        }
        #[cfg(target_os = "macos")]
        {
            use std::sync::atomic::{AtomicU64, Ordering};
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dmg = tmp.path().join(format!("cs-{n}.dmg"));
            let mountpoint = tmp.path().join(format!("mnt-{n}"));
            std::fs::create_dir_all(&mountpoint).unwrap();
            let created = std::process::Command::new("hdiutil")
                .args([
                    "create",
                    "-size",
                    "32m",
                    "-fs",
                    "Case-sensitive APFS",
                    "-volname",
                ])
                .arg(format!("storesynccs{n}"))
                .args(["-ov"])
                .arg(&dmg)
                .output();
            if !matches!(&created, Ok(o) if o.status.success()) {
                crate::test_support::announce_skip(
                    "hdiutil could not create a case-sensitive APFS image, so a case-sensitive \
                     source cannot be provided here",
                );
                return None;
            }
            let attached = std::process::Command::new("hdiutil")
                .args(["attach", "-nobrowse", "-mountpoint"])
                .arg(&mountpoint)
                .arg(&dmg)
                .output();
            if !matches!(&attached, Ok(o) if o.status.success()) {
                let _ = std::fs::remove_file(&dmg);
                crate::test_support::announce_skip(
                    "hdiutil could not mount a case-sensitive APFS image, so a case-sensitive \
                     source cannot be provided here",
                );
                return None;
            }
            let mount = MacCaseSensitiveMount {
                mountpoint: mountpoint.clone(),
                dmg,
            };
            let path = mountpoint.join("cs-src");
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("Case-Probe"), b"x").unwrap();
            if std::fs::symlink_metadata(path.join("cASE-pROBE")).is_ok() {
                crate::test_support::announce_skip(
                    "the mounted APFS image unexpectedly folds ASCII case, so a case-sensitive \
                     source cannot be provided here",
                );
                return None;
            }
            Some(CaseSensitiveSource {
                path,
                _tmp: tmp,
                _mount: Some(mount),
            })
        }
    }

    /// H2a: on a CASE-SENSITIVE source the old live `symlink_metadata` probe
    /// missed a component the crate's full case fold matches, so the copy
    /// LANDED an escaping link that `canonicalize_tree(dst)` then refused. The
    /// copy now uses the manifest's index and refuses before landing it.
    /// PRE-FIX this test FAILED on a case-sensitive source: the copy returned
    /// `Ok`, `root/dst/dir/link/secret` reached the canary, and
    /// `canonicalize_tree(dst)` refused the tree the copy produced.
    #[test]
    fn copy_dir_recursive_fd_refuses_a_fold_escape_from_a_case_sensitive_source() {
        let Some(cs) = case_sensitive_source() else {
            return;
        };
        let src = cs.path().join("tree");
        std::fs::create_dir_all(src.join("dir")).unwrap();
        std::fs::create_dir_all(src.join("other")).unwrap();
        std::fs::write(src.join("other/file"), b"inside").unwrap();
        std::os::unix::fs::symlink("../other", src.join("dir/stra\u{df}e")).unwrap();
        std::os::unix::fs::symlink("STRASSE/../../outside", src.join("dir/link")).unwrap();

        let base = tempfile::tempdir().unwrap();
        std::fs::create_dir(base.path().join("root")).unwrap();
        let root = RootDir::open(&base.path().join("root")).unwrap();
        // The canary is a sibling of `dst` under the owned root: the landed
        // link's `..` after the symlink component reaches the root's parent.
        std::fs::create_dir_all(base.path().join("root/outside")).unwrap();
        std::fs::write(base.path().join("root/outside/secret"), b"SECRET").unwrap();

        let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
            .expect_err("a full-fold-equal symlink component must be refused");
        assert!(
            err.to_string().contains("escaping symlink"),
            "the refusal must reuse the crate's symlink vocabulary, got: {err}"
        );
        assert!(
            !base.path().join("root/dst/dir/link").exists(),
            "the escaping link must never be landed"
        );
        assert!(
            std::fs::read(base.path().join("root/dst/dir/link/secret")).is_err(),
            "the canary must be unreachable through the refused copy"
        );
    }

    /// H2b: a destination-only symlink INSIDE `dst_rel` is part of the
    /// post-copy view. The old probe answered from the SOURCE, so it was
    /// invisible and `src/link -> evil/secret` landed on top of a pre-existing
    /// `dst/evil -> ../../outside` and escaped. The copy now consults the
    /// destination's surviving entries, so it refuses.
    /// PRE-FIX this test FAILED: the copy returned `Ok`, `root/dst/esc` reached
    /// the canary, and `canonicalize_tree(dst)` refused the result.
    #[test]
    fn copy_dir_recursive_fd_refuses_a_destination_only_symlink_component() {
        let (base, root, src) = out_of_root_fixture();
        std::fs::create_dir_all(base.path().join("root/dst")).unwrap();
        std::os::unix::fs::symlink("../../outside", base.path().join("root/dst/evil")).unwrap();
        std::fs::create_dir_all(base.path().join("outside")).unwrap();
        std::fs::write(base.path().join("outside/secret"), b"SECRET").unwrap();
        // `dst/esc -> evil/secret` walks through the pre-existing `dst/evil`.
        std::os::unix::fs::symlink("evil/secret", src.join("esc")).unwrap();

        let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
            .expect_err("a destination-only symlink component must be refused");
        assert!(
            err.to_string().contains("escaping symlink"),
            "the refusal must reuse the crate's symlink vocabulary, got: {err}"
        );
        assert!(!base.path().join("root/dst/esc").exists());
        assert!(
            std::fs::read(base.path().join("root/dst/esc/secret")).is_err(),
            "the canary must be unreachable through the refused copy"
        );
    }

    /// H2c: with NO host folding, the copy and `canonicalize_tree` must reach
    /// the SAME verdict on a fold-equal symlink component. The old live probe
    /// (case-sensitive source) missed `Sub`, accepted the tree, and
    /// contradicted the manifest. The copy now uses the manifest's index, so
    /// both refuse. PRE-FIX this test FAILED on a case-sensitive source: the
    /// manifest refused while the copy returned `Ok`.
    #[test]
    fn copy_dir_recursive_fd_agrees_with_canonicalize_tree_on_a_fold_equal_component() {
        let Some(cs) = case_sensitive_source() else {
            return;
        };
        let src = cs.path().join("tree");
        std::fs::create_dir_all(src.join("dir")).unwrap();
        std::fs::create_dir_all(src.join("other")).unwrap();
        std::fs::write(src.join("other/file"), b"inside").unwrap();
        std::os::unix::fs::symlink("../other", src.join("dir/sub")).unwrap();
        std::os::unix::fs::symlink("Sub/../other/file", src.join("dir/link")).unwrap();

        let manifest_err = crate::manifest::canonicalize_tree(&src)
            .expect_err("the manifest must refuse the fold-equal symlink component");
        assert!(
            manifest_err.to_string().contains("escaping symlink"),
            "the manifest refusal must name the escape, got: {manifest_err}"
        );

        let base = tempfile::tempdir().unwrap();
        std::fs::create_dir(base.path().join("root")).unwrap();
        let root = RootDir::open(&base.path().join("root")).unwrap();
        let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
            .expect_err("the copy must reach the manifest's SAME verdict");
        assert!(
            err.to_string().contains("escaping symlink"),
            "the copy refusal must name the escape, got: {err}"
        );
        assert!(!base.path().join("root/dst/dir/link").exists());
    }

    /// H2d: on a host that folds `STRASSE` onto `straße`, the old copy's LIVE
    /// probe REFUSED a tree the manifest (narrow fold) ACCEPTED. After H1+H2
    /// both views refuse, so they AGREE. PRE-FIX this test FAILED: the manifest
    /// accepted the tree (the narrow fold missed the pair).
    #[test]
    fn copy_dir_recursive_fd_and_manifest_agree_on_a_host_folded_component() {
        let (base, root, src) = out_of_root_fixture();
        std::fs::create_dir_all(src.join("dir")).unwrap();
        std::fs::create_dir_all(src.join("other")).unwrap();
        std::fs::write(src.join("other/file"), b"inside").unwrap();
        std::os::unix::fs::symlink("../other", src.join("dir/stra\u{df}e")).unwrap();
        std::os::unix::fs::symlink("STRASSE/../../outside", src.join("dir/link")).unwrap();

        let manifest_err = crate::manifest::canonicalize_tree(&src)
            .expect_err("the manifest must refuse the full-fold-equal component");
        assert!(
            manifest_err.to_string().contains("escaping symlink"),
            "the manifest refusal must name the escape, got: {manifest_err}"
        );

        let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
            .expect_err("the copy must reach the manifest's SAME verdict");
        assert!(
            err.to_string().contains("escaping symlink"),
            "the copy refusal must name the escape, got: {err}"
        );
        assert!(!base.path().join("root/dst/dir/link").exists());
    }

    /// ORDER fix, the FOURTH caller (the tree copy): the pre-fix order bug was
    /// in the ONE fold authority, so the copy had the SAME under-fold as the
    /// manifest. Both must refuse the Greek escape. PRE-FIX this is the
    /// tree-copy half of the observed escape: the manifest ACCEPTED (checked by
    /// the integration `greek_*` tests) and the copy returned `Ok`.
    #[test]
    fn copy_dir_recursive_fd_and_manifest_agree_on_a_greek_order_fold() {
        for (on_disk, capital) in [
            ("\u{1fb7}", "\u{1fbc}\u{0342}"),
            ("\u{1fb7}", "\u{0391}\u{0342}\u{0345}"),
            ("\u{1fc7}", "\u{1fcc}\u{0342}"),
            ("\u{1ff7}", "\u{1ffc}\u{0342}"),
        ] {
            let (base, root, src) = out_of_root_fixture();
            std::fs::create_dir_all(src.join("dir")).unwrap();
            std::fs::create_dir_all(src.join("other")).unwrap();
            std::fs::write(src.join("other/file"), b"inside").unwrap();
            std::os::unix::fs::symlink("../other", src.join("dir").join(on_disk)).unwrap();
            std::os::unix::fs::symlink(format!("{capital}/../../outside"), src.join("dir/link"))
                .unwrap();

            let manifest_err = crate::manifest::canonicalize_tree(&src)
                .expect_err("the manifest must refuse the Greek order-fold component");
            assert!(
                manifest_err.to_string().contains("escaping symlink"),
                "the manifest refusal must name the escape, got: {manifest_err}"
            );

            let copy_err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
                .expect_err("the copy must reach the manifest's SAME verdict");
            assert!(
                copy_err.to_string().contains("escaping symlink"),
                "the copy refusal must name the escape, got: {copy_err}"
            );
            assert!(!base.path().join("root/dst/dir/link").exists());
            assert!(
                std::fs::read(base.path().join("root/dst/dir/link/secret")).is_err(),
                "the canary must be unreachable through the refused copy"
            );
        }
    }

    /// H3: the copy no longer collapses a filesystem error to "no symlink
    /// here". An unreadable destination subtree makes the enumeration fail, and
    /// the copy fails CLOSED rather than guessing the escaped component is
    /// absent. (Reproducible only where a mode-0000 directory really refuses
    /// reads; the premise is probed with a REAL `read_dir`.)
    /// PRE-FIX this test FAILED: the live probe only `symlink_metadata`d the
    /// specific target components, which did not touch the unreadable sibling,
    /// so the copy returned `Ok`.
    #[test]
    fn copy_dir_recursive_fd_fails_closed_when_the_destination_cannot_be_enumerated() {
        use std::os::unix::fs::PermissionsExt;
        let (base, root, src) = out_of_root_fixture();
        let unreadable = base.path().join("root/unreadable");
        std::fs::create_dir_all(&unreadable).unwrap();
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&unreadable).is_ok() {
            std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o755)).unwrap();
            crate::test_support::announce_skip(
                "this process can still enumerate a mode-0000 directory, so the enumeration-\
                 failure premise is untestable here",
            );
            return;
        }
        // `out_of_root_fixture`'s source holds `link`, so the destination is
        // enumerated and the unreadable subtree is reached.
        let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
            .expect_err("an unenumerable destination must fail closed");
        assert!(
            err.to_string().contains("enumerate"),
            "the refusal must name the failed enumeration, got: {err}"
        );
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // ------------------------------------------------------------------
    // A residue-spelled destination is refused with no partial state.
    // ------------------------------------------------------------------

    /// A residue-spelled DESTINATION component is refused BEFORE anything
    /// is created, with the CREATE/COPY vocabulary (not the removal
    /// `recover_to` wording), and no partial directory is left. PRE-FIX:
    /// `ensure_private_dir_fd` created `<root>/.sync-aside.probe`, then the
    /// NEXT call refused with a REMOVAL-worded message and left the directory
    /// behind.
    #[test]
    fn copy_dir_recursive_fd_refuses_a_residue_destination_with_no_partial_state() {
        let (base, root, src) = out_of_root_fixture();

        let err = copy_dir_recursive_fd(&root, &src, &rp(".sync-aside.probe/inner"))
            .expect_err("a residue-spelled destination component must be refused");
        assert_eq!(err.reserved_kind(), Some(ReservedKind::ResidueBelow));
        let msg = err.to_string();
        assert!(
            msg.contains("refusing to create") && msg.contains(crate::reserved::RESIDUE_BELOW),
            "the refusal must use the CREATE vocabulary and keep the token, got: {msg}"
        );
        assert!(
            !msg.contains("refusing to remove"),
            "a copy must not report a removal, got: {msg}"
        );
        assert!(
            !base.path().join("root/.sync-aside.probe").exists(),
            "NO partial state may be created before the refusal"
        );

        // The single-component spelling is refused the same way.
        let err = copy_dir_recursive_fd(&root, &src, &rp(".sync-aside.probe"))
            .expect_err("a residue-spelled destination root must be refused");
        assert_eq!(err.reserved_kind(), Some(ReservedKind::ResidueBelow));
        assert!(!base.path().join("root/.sync-aside.probe").exists());
    }

    /// A LOCK-RECORD destination spelling is still refused
    /// cleanly, with no partial state.
    #[test]
    fn copy_dir_recursive_fd_still_refuses_a_lock_record_destination() {
        let (base, root, src) = out_of_root_fixture();
        let err = copy_dir_recursive_fd(&root, &src, &rp(".dest.operation.lock"))
            .expect_err("a lock-record destination must be refused");
        assert!(
            err.to_string().contains("lock record"),
            "the refusal must name the lock record, got: {err}"
        );
        assert!(!base.path().join("root/.dest.operation.lock").exists());
    }

    // ------------------------------------------------------------------
    // Hard links are refused, matching `canonicalize_tree`.
    // ------------------------------------------------------------------

    /// A HARD LINK in the source is refused rather than duplicated as
    /// an independent regular file (`nlink` 1 vs 2), because the crate's own
    /// `canonicalize_tree` refuses hard links by rule.
    #[test]
    fn copy_dir_recursive_fd_refuses_a_hard_link_source() {
        let (base, root, src) = out_of_root_fixture();
        std::fs::hard_link(src.join("file.txt"), src.join("hard")).unwrap();
        let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
            .expect_err("a hard link must be refused, not duplicated");
        assert!(
            err.to_string().contains("hard link"),
            "the refusal must name the hard link, got: {err}"
        );
        assert!(!base.path().join("root/dst/hard").exists());
    }
}
