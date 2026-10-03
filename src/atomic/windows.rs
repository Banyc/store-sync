//! The Windows implementation of the store atomic I/O: PATH-BASED (no
//! directory descriptors — the owned root is a path) with documented
//! weaker guarantees than the Unix descriptor-relative confinement:
//!
//! * no symlink-refusing component-wise resolution (Windows symlinks
//!   require admin/developer mode, so the injection attack surface is
//!   smaller);
//! * every `_fd` path is validated as ROOT-RELATIVE first ([`validate_rel`]):
//!   an absolute path, a `..`, a `.`, or the empty path is refused as a
//!   path error, so the spelling of `rel` cannot redirect a `Path::join`
//!   outside the root — symlinks INSIDE the root are still not refused;
//! * no parent-directory fsync durability (a directory cannot be opened
//!   as a file on Windows) — the rename is the only commit point;
//! * a NON-atomic replace (Windows `rename` does not overwrite an
//!   existing target — the target is removed first, so a reader can
//!   observe a transient absence); a failed replace UNLINKS its temp
//!   before returning, but because the target is removed before the
//!   rename, a rename-stage failure can leave NO destination entry at all
//!   rather than the OLD content the Unix port keeps visible;
//! * no Unix mode bits (the private-permission chmods are no-ops; file
//!   ACLs are the privacy mechanism).
//!
//! Selected by the single `#[cfg(windows)]` `mod` declaration in
//! [`super`].

use super::*;
use std::io::Write;

/// Windows has no Unix mode bits: the private-permission contract is a
/// no-op (file ACLs are the privacy mechanism). Documented weaker
/// guarantee of the Windows port.
pub fn set_private(_path: &Path) -> Result<()> {
    Ok(())
}

/// Durably replace a mutable marker file: write a UNIQUE temp file in the
/// same directory, fsync it, rename over the target. On Windows the
/// replace is NOT atomic (`rename` does not overwrite — the target is
/// removed first, so a reader can observe a transient absence) and there is
/// no parent-directory fsync (the rename is the only commit point) — the
/// documented weaker guarantees of the Windows port. A failure after the
/// temp exists UNLINKS the temp before the `Err` returns (best-effort, and
/// reported together with the original failure when the unlink itself
/// fails), so a failed replace leaves no stray temp; the post-rename
/// [`ReplaceStage::DirSync`] failure is NOT a cleanup point (the temp name
/// no longer exists — it IS the destination) and still reports
/// [`ReplaceOutcome::ReplacedDurabilityUnknown`]. The per-stage fault hook
/// fires at every stage exactly as on Unix (the test surface is
/// platform-independent).
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
        // Close the temp before unlinking and remove the stray the failed
        // write left behind.
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
    // Stage 3: the rename — COMMIT POINT 1. Windows `rename` does not
    // overwrite an existing target: remove it first (the replace is NOT
    // atomic — a reader can observe a transient absence). A failure (or an
    // injected [`ReplaceStage::Rename`] fault) is a PRE-RENAME `Err`; the
    // temp is unlinked. (A post-remove failure can no longer leave the OLD
    // content visible — the documented weaker guarantee of this port.)
    if let Some(e) = fault(ReplaceStage::Rename) {
        return Err(discard_temp(e, &tmp));
    }
    let _ = std::fs::remove_file(path);
    if let Err(e) = std::fs::rename(&tmp, path) {
        return Err(discard_temp(
            Error::store(format!("rename {}: {e}", path.display())),
            &tmp,
        ));
    }
    // Stage 4: the parent-directory fsync — Windows has no directory fsync
    // (a directory cannot be opened as a file); the rename is the only
    // commit point. The injected [`ReplaceStage::DirSync`] fault still
    // fires (the test surface is platform-independent).
    if let Some(e) = fault(ReplaceStage::DirSync) {
        return Ok(ReplaceOutcome::ReplacedDurabilityUnknown { error: e });
    }
    Ok(ReplaceOutcome::ReplacedDurable)
}

/// Windows has no directory fsync (a directory cannot be opened as a
/// file): a no-op. Documented weaker durability guarantee of the Windows
/// port.
pub fn sync_parent_dir(_path: &Path) -> Result<()> {
    Ok(())
}

pub fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| Error::store(format!("mkdir {}: {e}", path.display())))?;
    // Windows has no Unix mode bits: the private chmod is a no-op.
    Ok(())
}

/// DURABLE private directory creation: create `path` (and every missing
/// ancestor). On Windows there is no parent-directory fsync (the durable
/// commit is a no-op) — the documented weaker guarantee of the Windows
/// port. Returns `true` when this call created at least one directory.
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
    // Create the chain TOP-DOWN (parents before their children). A racing
    // creation of an ancestor is tolerated.
    for component in missing.iter().rev() {
        match std::fs::create_dir(component) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                return Err(Error::store(format!("mkdir {}: {e}", component.display())));
            }
        }
    }
    Ok(true)
}

/// TEST-ONLY path-based recursive tree copy (the retention checkpoint's
/// test-only store clone). On Windows, symlinks are copied as their
/// target's content (Windows symlinks require admin/developer mode) — the
/// documented weaker guarantee of the Windows port.
///
/// The walk queues each directory on an explicit heap `Vec` instead of
/// recursing one Rust frame per level, so a deep tree fails cleanly (or
/// succeeds) rather than exhausting the C stack and aborting the host
/// process. It descends into a subdirectory the moment it is encountered, so
/// its visit order matches the pre-rewrite recursion's depth-first
/// pre-order (files and subdirectories interleaved in `readdir` order).
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
                std::fs::copy(&link, &target)
                    .map_err(|e| Error::store(format!("copy {}: {e}", target.display())))?;
                None
            } else {
                std::fs::copy(&path, &target)
                    .map_err(|e| Error::store(format!("copy {}: {e}", target.display())))?;
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
// THE `_fd` SURFACE (path-based on Windows)
// ---------------------------------------------------------------------
// The store's mutations call the same `_fd` names as on Unix; on Windows
// they resolve PATH-BASED relative to the root path with the documented
// weaker guarantees above.
// =====================================================================

/// Join `rel` under the root path, REFUSING every spelling that could
/// resolve outside the root first (see [`validate_rel`]). The guard is what
/// keeps the path-based port under the owned root too: [`Path::join`]
/// REPLACES the root when `rel` is absolute (`C:\...`, `\...`) and a `..`
/// component walks out of it, so the join is never performed on an
/// unvalidated spelling. The root itself is the normalized [`RootDir`] path.
fn rel_join(root: &RootDir, rel: &Path) -> Result<PathBuf> {
    validate_rel(rel).map_err(|e| Error::store(format!("refusing path {}: {e}", rel.display())))?;
    Ok(root.path().join(rel))
}

/// Path-based atomic replace (see [`write_atomic_replace`]). Refuses a crate
/// lock-record spelling (the stable-inode discipline's structural guard; see
/// the Unix port).
pub fn write_atomic_replace_fd(
    root: &RootDir,
    rel: &Path,
    bytes: &[u8],
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<ReplaceOutcome> {
    refuse_lock_record_mutation(rel)?;
    write_atomic_replace(&rel_join(root, rel)?, bytes, fault)
}

/// [`write_atomic_replace_fd`] for a caller that has already ensured the
/// parent (the path-based `write_atomic_replace` runs `create_dir_all`
/// itself; this port has no fd to chmod an existing parent through, so the
/// two are identical here).
pub fn write_atomic_replace_fd_under_existing_parent(
    root: &RootDir,
    rel: &Path,
    bytes: &[u8],
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<ReplaceOutcome> {
    refuse_lock_record_mutation(rel)?;
    write_atomic_replace(&rel_join(root, rel)?, bytes, fault)
}

/// The verdict of [`write_atomic_if_match_fd`] (see the Unix port for the
/// full contract; the Windows replace is the documented NON-atomic one).
#[derive(Debug)]
pub enum CompareReplace {
    /// The live entry held the expected bytes and `bytes` were installed.
    Replaced(ReplaceOutcome),
    /// The live entry did NOT hold the expected bytes: nothing was written.
    Mismatch,
}

/// PATH-BASED compare-and-replace: install `bytes` only if the entry at `rel`
/// currently reads as `expected`. The comparison is a best-effort read
/// followed by the non-atomic Windows replace, so a writer that changes the
/// entry between the read and the replace is NOT detected — the documented
/// weaker guarantee of the Windows port (no descriptor to compare through,
/// no atomic rename). Fail closed on an unreadable entry or a symlink (the
/// read follows it on this port).
///
/// An ENTRY THAT IS ABSENT is a `Mismatch`, never an error, matching the Unix
/// port's contract: the caller read the destination, so a live entry that is
/// now gone is a change it must re-read and re-decide. A read that fails for
/// any OTHER reason still propagates.
///
/// This port is TYPE-CHECKED ONLY in this repository — it is compiled by
/// `cargo check --target x86_64-pc-windows-msvc --lib` and never executed
/// here — so the absent-vs-error split above is a compile-time claim, not an
/// observed one.
pub fn write_atomic_if_match_fd(
    root: &RootDir,
    rel: &Path,
    expected: &[u8],
    bytes: &[u8],
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<CompareReplace> {
    refuse_lock_record_mutation(rel)?;
    let path = rel_join(root, rel)?;
    match std::fs::read(&path) {
        Ok(existing) if existing == expected => {} // still ours: replace below
        Ok(_) => return Ok(CompareReplace::Mismatch),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CompareReplace::Mismatch);
        }
        Err(e) => return Err(Error::store(format!("read {}: {e}", path.display()))),
    }
    let outcome = write_atomic_replace(&path, bytes, fault)?;
    Ok(CompareReplace::Replaced(outcome))
}

/// Path-based create-or-compare CAS: the create-new install is the
/// atomicity primitive (a racing loser fails on AlreadyExists and can
/// never clobber a winner); there is no parent-directory fsync durability.
pub fn write_atomic_cas_fd(root: &RootDir, rel: &Path, bytes: &[u8]) -> Result<()> {
    refuse_lock_record_mutation(rel)?;
    let path = rel_join(root, rel)?;
    // If the file exists, its content must be byte-identical.
    match std::fs::read(&path) {
        Ok(existing) => {
            if existing == bytes {
                return Ok(());
            }
            return Err(Error::conflict(format!(
                "refusing to replace existing {} with different content",
                rel.display()
            )));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::store(format!("open {}: {e}", rel.display()))),
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| Error::store(format!("create {}: {e}", path.display())))?;
    f.write_all(bytes)
        .map_err(|e| Error::store(format!("write {}: {e}", path.display())))?;
    f.sync_all()
        .map_err(|e| Error::store(format!("fsync {}: {e}", path.display())))?;
    Ok(())
}

/// Path-based private-directory creation (see [`ensure_private_dir`]).
pub fn ensure_private_dir_fd(root: &RootDir, rel: &Path) -> Result<()> {
    ensure_private_dir(&rel_join(root, rel)?)
}

/// Path-based DURABLE private-directory creation (see
/// [`ensure_private_dir_durable`] — the durable commit is a no-op on
/// Windows).
pub fn ensure_private_dir_durable_fd(root: &RootDir, rel: &Path) -> Result<bool> {
    ensure_private_dir_durable(&rel_join(root, rel)?)
}

/// Windows has no directory fsync: a no-op (documented weaker durability
/// guarantee of the Windows port).
pub fn sync_parent_dir_fd(_root: &RootDir, _rel: &Path) -> Result<()> {
    Ok(())
}

/// Path-based private chmod (see [`set_private`] — a no-op on Windows).
pub fn set_private_fd(root: &RootDir, rel: &Path) -> Result<()> {
    set_private(&rel_join(root, rel)?)
}

/// Path-based remove of a single file. Refuses a crate lock-record spelling
/// (the stable-inode discipline's structural guard; see the Unix port).
pub fn remove_file_fd(root: &RootDir, rel: &Path) -> Result<()> {
    refuse_lock_record_mutation(rel)?;
    std::fs::remove_file(rel_join(root, rel)?)
        .map_err(|e| Error::store(format!("remove {}: {e}", rel.display())))
}

/// Refuse a destructive mutation whose TARGET names one of the crate's
/// lock-record spellings (see the Unix port for the full rationale and for the
/// list of mutating primitives that consult it).
fn refuse_lock_record_mutation(rel: &Path) -> Result<()> {
    if let Some(name) = rel.file_name().and_then(|name| name.to_str())
        && crate::reserved::is_lock_record_name(name)
    {
        return Err(Error::conflict(format!(
            "refusing to mutate the crate's lock record {}: the record's stable inode is what makes \
             two simultaneous holders impossible, so removing, replacing, or renaming it would \
             admit a second holder",
            rel.display()
        )));
    }
    Ok(())
}

/// Refuse a recursive removal whose tree CONTAINS a lock-record spelling at any
/// depth.
///
/// The Windows port delegates the walk to `std::fs::remove_dir_all`, which
/// unlinks descendants without consulting this crate's guard, so the guard is
/// applied to the WHOLE tree before anything is removed (fail closed). A
/// directory entry's own `file_type` is consulted, so a symlink is classified
/// as the entry itself and is never descended into.
fn refuse_lock_record_in_tree(root: &Path) -> Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::store(format!("read_dir {}: {e}", dir.display()))),
        };
        for entry in entries {
            let entry =
                entry.map_err(|e| Error::store(format!("read_dir {}: {e}", dir.display())))?;
            let child = entry.path();
            if let Some(name) = child.file_name().and_then(|name| name.to_str())
                && crate::reserved::is_lock_record_name(name)
            {
                return Err(Error::conflict(format!(
                    "refusing to remove the tree {}: it holds the crate's lock record {} whose \
                     stable inode is what makes two simultaneous holders impossible",
                    root.display(),
                    child.display()
                )));
            }
            let is_dir = entry
                .file_type()
                .map_err(|e| Error::store(format!("file_type {}: {e}", child.display())))?
                .is_dir();
            if is_dir {
                stack.push(child);
            }
        }
    }
    Ok(())
}

/// Path-based rename of a path under the root to another path under the
/// root. Windows `rename` does not overwrite an existing target: remove it
/// first (documented weaker guarantee — not atomic).
pub fn renameat_paths(root: &RootDir, from: &Path, to: &Path) -> Result<()> {
    refuse_lock_record_mutation(from)?;
    refuse_lock_record_mutation(to)?;
    let from = rel_join(root, from)?;
    let to = rel_join(root, to)?;
    let _ = std::fs::remove_file(&to);
    std::fs::rename(&from, &to).map_err(|e| {
        Error::store(format!(
            "rename {} -> {}: {e}",
            from.display(),
            to.display()
        ))
    })
}

/// Path-based recursive removal of a directory tree. On Windows this
/// delegates to `std::fs::remove_dir_all`, which is ITERATIVE on the
/// installed toolchain: `library/std/src/sys/fs/windows.rs:1382` opens the
/// directory and calls `remove_dir_all_iterative`
/// (`library/std/src/sys/fs/windows/remove_dir_all.rs:173`), so a deep tree
/// fails cleanly rather than aborting the host — the same guarantee the Unix
/// path gets from its own walk. (Windows is type-checked only, never run
/// here.)
pub fn remove_dir_all_fd(root: &RootDir, rel: &Path) -> Result<()> {
    refuse_lock_record_mutation(rel)?;
    let joined = rel_join(root, rel)?;
    // `std::fs::remove_dir_all` unlinks descendants itself, so the whole tree
    // is checked BEFORE it runs.
    refuse_lock_record_in_tree(&joined)?;
    std::fs::remove_dir_all(joined)
        .map_err(|e| Error::store(format!("remove_dir_all {}: {e}", rel.display())))
}

/// Path-based plain file write (create-or-truncate).
pub fn write_file_fd(root: &RootDir, rel: &Path, bytes: &[u8]) -> Result<()> {
    refuse_lock_record_mutation(rel)?;
    std::fs::write(rel_join(root, rel)?, bytes)
        .map_err(|e| Error::store(format!("write {}: {e}", rel.display())))
}

/// Read the whole file at `rel` under the root path.
pub fn read_fd(root: &RootDir, rel: &Path) -> Result<Vec<u8>> {
    std::fs::read(rel_join(root, rel)?)
        .map_err(|e| Error::store(format!("read {}: {e}", rel.display())))
}

/// Path-based read of the target of the symlink at `rel` under the root.
/// Windows has no fd-relative resolution, so this does NOT refuse a symlink
/// injected into a parent component — the documented weaker guarantee of the
/// Windows port (Windows symlinks also require admin/developer mode, a
/// smaller injection surface).
pub fn read_link_fd(root: &RootDir, rel: &Path) -> Result<PathBuf> {
    std::fs::read_link(rel_join(root, rel)?)
        .map_err(|e| Error::store(format!("readlink {}: {e}", rel.display())))
}

/// [`read_fd`] + JSON deserialization.
pub fn read_json_fd<T: serde::de::DeserializeOwned>(root: &RootDir, rel: &Path) -> Result<T> {
    let bytes = read_fd(root, rel)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::store(format!("deserialize {}: {e}", rel.display())))
}

/// The TRI-STATE existence check under the root path (see [`path_state`]).
pub fn path_state_fd(root: &RootDir, rel: &Path) -> Result<bool> {
    path_state(&rel_join(root, rel)?)
}

/// The KIND of the entry at `rel` under the root path, classified WITHOUT
/// following a final-component symlink.
///
/// Path-based, with the documented weaker guarantee of the Windows port,
/// and the guarantee is split precisely:
///
/// * GUARANTEED: the FINAL component is classified with `symlink_metadata`
///   (the path-based `lstat`), so a symlink there is NOT followed and is
///   reported as [`PathKind::Symlink`] whatever its target's kind — a
///   symlink TO A DIRECTORY is never [`PathKind::Dir`]. A missing entry is
///   ABSENCE (`Ok(None)`); every other filesystem error is [`Error::store`].
///   `rel` is validated as ROOT-RELATIVE first ([`rel_join`]), so an
///   absolute path, a `..`, a `.`, and the empty path are refused.
/// * NOT GUARANTEED: a symlink injected at a PARENT component IS followed
///   (`Path::join` has no component-wise `O_NOFOLLOW`), and a non-symlink
///   reparse point is reported by its resolved kind (the classification
///   uses Rust's `FileType`, which does not surface every reparse tag).
///   Windows symlinks also require admin/developer mode, the smaller
///   injection surface the Windows port documents elsewhere.
pub fn path_kind_fd(root: &RootDir, rel: &Path) -> Result<Option<PathKind>> {
    match std::fs::symlink_metadata(rel_join(root, rel)?) {
        Ok(md) => Ok(Some(kind_from_file_type(md.file_type()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::store(format!("stat {}: {e}", rel.display()))),
    }
}

/// Classify an entry kind from a [`std::fs::FileType`] obtained WITHOUT
/// following the final component (`symlink_metadata`). A symlink is tested
/// FIRST so a link to a directory can never be reported as `Dir`.
fn kind_from_file_type(ft: std::fs::FileType) -> PathKind {
    if ft.is_symlink() {
        PathKind::Symlink
    } else if ft.is_file() {
        PathKind::File
    } else if ft.is_dir() {
        PathKind::Dir
    } else {
        PathKind::Other
    }
}

/// Read the entries of the directory at `rel` under the root path. `rel` must
/// name at least one normal component ([`validate_rel`] refuses the empty and
/// `.` spellings); the OWNED ROOT itself is enumerated with
/// [`read_root_dir_fd`].
pub fn read_dir_fd(root: &RootDir, rel: &Path) -> Result<Vec<DirEntry>> {
    let entries = std::fs::read_dir(rel_join(root, rel)?)
        .map_err(|e| Error::store(format!("read_dir {}: {e}", rel.display())))?;
    read_dir_entries(entries)
}

/// Read the entries of the OWNED ROOT itself (see the Unix port for the B1
/// rationale).
pub fn read_root_dir_fd(root: &RootDir) -> Result<Vec<DirEntry>> {
    let entries = std::fs::read_dir(root.path())
        .map_err(|e| Error::store(format!("read_dir {}: {e}", root.path().display())))?;
    read_dir_entries(entries)
}

fn read_dir_entries(entries: std::fs::ReadDir) -> Result<Vec<DirEntry>> {
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::store(format!("entry: {e}")))?;
        let ft = entry
            .file_type()
            .map_err(|e| Error::store(format!("file_type: {e}")))?;
        out.push(DirEntry {
            name: entry.file_name(),
            is_dir: ft.is_dir(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        Error, PathKind, ReplaceOutcome, ReplaceStage, RootDir, path_kind_fd, write_atomic_replace,
    };
    use std::path::{Path, PathBuf};

    /// The entry names directly under `dir`, sorted.
    fn entry_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
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

    /// The kinds Windows can always create: a regular file is `File`, a
    /// directory is `Dir`, a missing entry is `Ok(None)`.
    #[test]
    fn path_kind_fd_classifies_a_file_a_directory_and_absence() {
        let (dir, root) = owned_root();
        std::fs::write(dir.path().join("file"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("dir")).unwrap();
        assert_eq!(
            path_kind_fd(&root, Path::new("file")).unwrap(),
            Some(PathKind::File)
        );
        assert_eq!(
            path_kind_fd(&root, Path::new("dir")).unwrap(),
            Some(PathKind::Dir)
        );
        assert_eq!(path_kind_fd(&root, Path::new("missing")).unwrap(), None);
    }

    /// A symlink is `Symlink` — never its target's kind — when Windows lets
    /// the test create one. Symlink creation requires admin/developer mode,
    /// so a refusal is skipped: there is nothing to classify (the
    /// documented weaker Windows guarantee).
    #[test]
    fn path_kind_fd_reports_a_symlink_when_one_can_be_created() {
        let (dir, root) = owned_root();
        std::fs::create_dir(dir.path().join("dir")).unwrap();
        if std::os::windows::fs::symlink_dir(dir.path().join("dir"), dir.path().join("dirlink"))
            .is_err()
        {
            return;
        }
        assert_eq!(
            path_kind_fd(&root, Path::new("dirlink")).unwrap(),
            Some(PathKind::Symlink),
            "a symlink TO A DIRECTORY must still be Symlink, never Dir"
        );
    }

    /// An absolute path, a `..` walk, a `.`, and the empty path are refused
    /// by the ROOT-RELATIVE guard, exactly as the other `_fd` primitives
    /// refuse them.
    #[test]
    fn path_kind_fd_refuses_escaping_spellings() {
        let (dir, root) = owned_root();
        let absolute = dir.path().join("outside").as_os_str().to_os_string();
        for spelling in [
            PathBuf::from("C:\\outside"),
            PathBuf::from(".."),
            PathBuf::from("..\\secret"),
            PathBuf::from("a/../secret"),
            PathBuf::from("."),
            PathBuf::new(),
            PathBuf::from(&absolute),
        ] {
            let err = path_kind_fd(&root, &spelling)
                .expect_err("an escaping or empty spelling must be refused");
            assert!(
                matches!(err, Error::Store(_)) && err.to_string().contains("normal component"),
                "{spelling:?} must be refused by the root-relative guard, got: {err}"
            );
        }
    }

    /// A fault at EACH pre-rename stage leaves no stray temp behind. On this
    /// port the OLD content stays visible for the pre-rename stages too (the
    /// target is removed only AT the rename stage, after the rename fault
    /// fires).
    #[test]
    fn failed_path_replace_at_each_pre_rename_stage_leaves_no_temp() {
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

    /// A post-rename [`ReplaceStage::DirSync`] fault still reports
    /// `ReplacedDurabilityUnknown`, leaves the NEW content in place, and
    /// unlinks nothing.
    #[test]
    fn post_rename_fsync_fault_leaves_new_content_and_no_temp() {
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

    /// A successful replace leaves exactly the destination and no temp.
    #[test]
    fn successful_replace_leaves_only_the_destination() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("marker.json");
        std::fs::write(&path, b"OLD").unwrap();
        let outcome = write_atomic_replace(&path, b"NEW", &mut |_| None).unwrap();
        assert!(matches!(outcome, ReplaceOutcome::ReplacedDurable));
        assert_eq!(std::fs::read(&path).unwrap(), b"NEW".to_vec());
        assert_eq!(entry_names(dir.path()), only("marker.json"));
    }

    /// The cleanup failure is reported together with the original failure:
    /// the hook swaps the temp for a DIRECTORY so the writer's `remove_file`
    /// cleanup fails.
    #[test]
    fn failed_path_replace_reports_a_failed_cleanup() {
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
        let text = err.to_string();
        assert!(
            text.contains("injected rename fault") && text.contains("failed to unlink"),
            "both failures must be reported, got: {text}"
        );
        std::fs::remove_dir(swapped.expect("the hook recorded the temp")).unwrap();
    }
}
