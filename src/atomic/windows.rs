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
pub fn set_private(path: &Path) -> Result<()> {
    // The mode change is inode-preserving, but the guard keeps the spelling
    // contract uniform with the Unix port.
    refuse_lock_record_mutation(path)?;
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
    // F-A1: the PATH-BASED replace removes the target entry before the rename
    // (Windows `rename` does not overwrite), so it DESTROYS the target's inode
    // exactly like the Unix port; consult the ONE guard authority and the FULL
    // path (see [`refuse_lock_record_mutation`]). Type-checked only here (this
    // port is never executed in this repository).
    refuse_lock_record_mutation(path)?;
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
    // Creation only: a residue spelling is permitted (mkdir cannot destroy),
    // and the lock authority still runs.
    refuse_reserved_mutation(path, Sanction::Residue)?;
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

/// The Windows twin of the Unix name gate: the crate's ONE name authority
/// ([`crate::manifest::validate_entry_path`] plus
/// [`crate::reserved::is_unaddressable_name`]) applied to every landed entry
/// name, so a name the crate would refuse as an id, strip from a manifest, or
/// that the documented recovery sweep would REMOVE is refused instead of
/// landed. A Windows name is UTF-16, so `to_str` refuses an unpaired surrogate
/// (the platform's non-UTF-8 case).
fn refuse_unlandable_name<'a>(name: &'a std::ffi::OsStr, parent: &Path) -> Result<&'a str> {
    let shown = parent.join(name);
    let Some(name_str) = name.to_str() else {
        return Err(Error::store(format!(
            "refusing to copy {}: the entry name is not valid UTF-8, and the crate's manifests \
             require NFC/UTF-8 names",
            shown.display()
        )));
    };
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

/// The Windows twin of the Unix overlap refusal, using the platform's
/// case-INSENSITIVE comparison: a Windows filesystem folds case, so `Tree` and
/// `tree` are one directory and a case-only difference must not evade the
/// check.
fn refuse_overlapping_copy(root: &RootDir, src: &Path, dst_rel: &Path) -> Result<()> {
    fn key(p: &Path) -> Vec<String> {
        p.components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect()
    }
    let root_c = std::fs::canonicalize(root.path())
        .map_err(|e| Error::store(format!("canonicalize root {}: {e}", root.path().display())))?;
    let dst_abs = root_c.join(dst_rel);
    let src_c = std::fs::canonicalize(src)
        .map_err(|e| Error::store(format!("canonicalize source {}: {e}", src.display())))?;
    let (d, s) = (key(&dst_abs), key(&src_c));
    let prefix = |a: &[String], b: &[String]| b.len() >= a.len() && a == &b[..a.len()];
    if d == s || prefix(&s, &d) || prefix(&d, &s) {
        return Err(Error::store(format!(
            "copy_dir_recursive_fd: refusing to copy {} to {} — the source and the destination \
             overlap (the destination is inside the source, the source is inside the destination, \
             or they are the same directory), so the walk would copy the tree into itself without \
             bound",
            src.display(),
            dst_abs.display()
        )));
    }
    Ok(())
}

/// Path-based equivalent of the Unix fd-confined `copy_dir_recursive_fd`:
/// copy the
/// tree at `src` to the root-relative `dst_rel`, iteratively (an explicit
/// heap `Vec` stack, so a deep tree cannot exhaust the C stack), preserving
/// symlinks and (best-effort — a no-op on Windows) modes.
///
/// NAMES: every entry name is validated by [`refuse_unlandable_name`] before
/// it lands, and `dst_rel` runs [`refuse_reserved_creation`] before anything
/// is created, exactly as the Unix port does.
///
/// OVERLAP: a source/destination overlap is refused by
/// [`refuse_overlapping_copy`] (case-insensitively) before anything is
/// created, so the walk cannot copy a tree into itself without bound.
///
/// SYMLINKS: the crate's OWN target rules are reused
/// ([`crate::manifest::validate_symlink_target`] and
/// [`crate::manifest::check_relative_symlink_target`]), and a link is copied
/// as a link, never followed.
///
/// HARD LINKS are NOT detected on this port (Windows exposes no stable
/// `nlink` through `std::fs`), and the crate's own Windows manifest cannot
/// refuse them either (its check is `#[cfg(unix)]`), so this port duplicates
/// them; a caller that must not duplicate them pre-checks on the source.
///
/// MEMORY BOUND: every regular file is read WHOLE into memory
/// (`std::fs::read`) and then written, so the peak allocation is the size of
/// the LARGEST file in the source tree, plus the destination write buffer. A
/// tree with a multi-gigabyte file must not be copied through this port; use
/// a streaming copy instead. (The Unix port streams through a 64 KiB heap
/// buffer.)
///
/// NOT ATOMIC, NOT DURABLE, PARTIAL ON FAILURE: as on Unix, there is no temp
/// directory and no final rename, so entries appear in place, an error
/// mid-walk leaves a PARTIAL destination tree, and this port cannot fsync a
/// directory entry. A caller that needs atomicity copies into a staging path
/// it owns and renames it into place, and must treat ANY `Err` as "the
/// destination may hold a partial subtree at `dst_rel`".
///
/// DOCUMENTED WEAKER GUARANTEE: there is no directory descriptor and no
/// `O_NOFOLLOW`, so a symlink injected into a destination component IS
/// followed (`rel_join` only refuses absolute/`..`/`.` spellings). This is
/// the same weakness every other `_fd` primitive of the Windows port carries.
/// A pre-existing destination file at a copied file's name is overwritten
/// (`std::fs::copy`), where the Unix port refuses it with `O_EXCL`; the
/// caller is expected to pass a fresh destination.
pub fn copy_dir_recursive_fd(root: &RootDir, src: &Path, dst_rel: &Path) -> Result<()> {
    // Every destination mutation routes through the SAME guarded rel-path
    // primitives the rest of the port uses (`create_dir_fd`, `write_file_fd`,
    // `symlink_fd`), so the ONE reserved-spelling gate runs here too rather
    // than a raw `std::fs` call bypassing it.
    fn open_frame(src: &Path) -> Result<std::vec::IntoIter<std::fs::DirEntry>> {
        let entries = std::fs::read_dir(src)
            .map_err(|e| Error::store(format!("read_dir {}: {e}", src.display())))?
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|e| Error::store(format!("entry: {e}")))?;
        Ok(entries.into_iter())
    }

    let src_meta = std::fs::symlink_metadata(src)
        .map_err(|e| Error::store(format!("stat {}: {e}", src.display())))?;
    if !src_meta.is_dir() {
        return Err(Error::store(format!(
            "copy_dir_recursive_fd: source {} is not a directory",
            src.display()
        )));
    }
    let root_mode = crate::platform::metadata_mode(&src_meta);
    refuse_reserved_creation(dst_rel)?;
    refuse_overlapping_copy(root, src, dst_rel)?;
    // See the Unix port: a symlink target that walks OUT of the copied subtree
    // is judged against the destination root, exactly as `canonicalize_tree`
    // will judge the result.
    let dst_root_abs = root.path().to_path_buf();
    ensure_private_dir_fd(root, dst_rel)?;
    crate::platform::chmod(&rel_join(root, dst_rel)?, (root_mode | 0o200) & 0o7777)
        .map_err(|e| Error::store(format!("chmod {}: {e}", dst_rel.display())))?;

    struct Frame {
        dst_rel: PathBuf,
        src_shown: PathBuf,
        entries: std::vec::IntoIter<std::fs::DirEntry>,
    }
    let mut dirs: Vec<(PathBuf, u32)> = Vec::new();
    let mut stack: Vec<Frame> = vec![Frame {
        dst_rel: dst_rel.to_path_buf(),
        src_shown: src.to_path_buf(),
        entries: open_frame(src)?,
    }];
    while let Some(top) = stack.last_mut() {
        let Some(entry) = top.entries.next() else {
            stack.pop();
            continue;
        };
        let name = entry.file_name();
        let name_str = refuse_unlandable_name(&name, &top.src_shown)?;
        let child_rel = top.dst_rel.join(name_str);
        let child_src = entry.path();
        let ft = entry
            .file_type()
            .map_err(|e| Error::store(format!("file_type: {e}")))?;
        if ft.is_dir() {
            let mode = crate::platform::metadata_mode(
                &std::fs::symlink_metadata(&child_src)
                    .map_err(|e| Error::store(format!("stat {}: {e}", child_src.display())))?,
            );
            create_dir_fd(root, &child_rel)?;
            crate::platform::chmod(&rel_join(root, &child_rel)?, (mode | 0o200) & 0o7777)
                .map_err(|e| Error::store(format!("chmod {}: {e}", child_rel.display())))?;
            dirs.push((child_rel.clone(), mode));
            let entries = open_frame(&entry.path())?;
            stack.push(Frame {
                dst_rel: child_rel,
                src_shown: child_src,
                entries,
            });
        } else if ft.is_symlink() {
            let link = std::fs::read_link(&child_src)
                .map_err(|e| Error::store(format!("readlink {}: {e}", child_src.display())))?;
            let link_str = link.to_str().ok_or_else(|| {
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
            let mut resolve = |rel: &Path| -> crate::manifest::ComponentResolution {
                let probe = match rel.strip_prefix(dst_rel) {
                    Ok(sub) => src.join(sub),
                    Err(_) => dst_root_abs.join(rel),
                };
                match std::fs::symlink_metadata(probe) {
                    Ok(m) if m.is_symlink() => crate::manifest::ComponentResolution::Symlink,
                    Ok(_) => crate::manifest::ComponentResolution::NotSymlink,
                    Err(_) => crate::manifest::ComponentResolution::Absent,
                }
            };
            if let Err(refusal) =
                crate::manifest::check_relative_symlink_target(&child_rel, &link, &mut resolve)
            {
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
            symlink_fd(root, &link, &child_rel)?;
        } else if ft.is_file() {
            // MEMORY BOUND (see the primitive's doc): read whole.
            let bytes = std::fs::read(&child_src)
                .map_err(|e| Error::store(format!("read {}: {e}", child_src.display())))?;
            let mode = crate::platform::metadata_mode(
                &std::fs::metadata(&child_src)
                    .map_err(|e| Error::store(format!("stat {}: {e}", child_src.display())))?,
            );
            write_file_fd(root, &child_rel, &bytes)?;
            crate::platform::chmod(&rel_join(root, &child_rel)?, mode)
                .map_err(|e| Error::store(format!("chmod {}: {e}", child_rel.display())))?;
        } else {
            return Err(Error::store(format!(
                "refusing to copy {}: it is not a regular file, directory, or symlink",
                child_src.display()
            )));
        }
    }
    dirs.sort_by_key(|(rel, _)| std::cmp::Reverse(rel.components().count()));
    for (dir, mode) in dirs {
        crate::platform::chmod(&rel_join(root, &dir)?, mode)
            .map_err(|e| Error::store(format!("chmod {}: {e}", dir.display())))?;
    }
    crate::platform::chmod(&rel_join(root, dst_rel)?, root_mode)
        .map_err(|e| Error::store(format!("chmod {}: {e}", dst_rel.display())))?;
    Ok(())
}

/// Path-based equivalent of the Unix `fsync_tree_recursive_fd`.
///
/// DOCUMENTED WEAKER GUARANTEE: the Windows port has no directory-entry fsync
/// (`sync_parent_dir` is a no-op), so only regular FILES are fsynced here and
/// directory entries rely on the filesystem's own ordering. Symlinks are
/// skipped. A file in a deep tree is reached by accumulating PATH components,
/// so the platform path limit applies.
pub fn fsync_tree_recursive_fd(root: &RootDir, rel: &Path) -> Result<()> {
    let start = rel_join(root, rel)?;
    let mut stack: Vec<PathBuf> = vec![start];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .map_err(|e| Error::store(format!("read_dir {}: {e}", dir.display())))?
        {
            let entry = entry.map_err(|e| Error::store(format!("entry: {e}")))?;
            let path = entry.path();
            let ft = entry
                .file_type()
                .map_err(|e| Error::store(format!("file_type: {e}")))?;
            if ft.is_dir() {
                stack.push(path);
            } else if ft.is_file() {
                std::fs::File::open(&path)
                    .map_err(|e| Error::store(format!("open {}: {e}", path.display())))?
                    .sync_all()
                    .map_err(|e| Error::store(format!("fsync {}: {e}", path.display())))?;
            }
        }
    }
    Ok(())
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

/// RETIRE the ONE lock record `owned` authorizes, by IDENTITY — the Windows
/// twin of the Unix `remove_owned_lock_record_fd`. The candidate is recognized
/// only by [`GuardedRel::new_for_owned_lock_record`] (ordinary content, and any
/// record spelling resolving to a DIFFERENT entry, is refused); the removal is
/// a raw `std::fs::remove_file` because the whole point is to break the record
/// the guard protects, and the capability is the authorization. A held record
/// is never removed: proving no live holder is the caller's job
/// ([`crate::sync::retire_destination_lock`] acquires the flock first).
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
    std::fs::remove_file(rel_join(root, rel)?)
        .map_err(|e| Error::store(format!("retire {}: {e}", rel.display())))
}

/// Path-based single-directory creation (`create_dir` semantics), guarded like
/// the Unix port's `create_dir_fd`: a residue spelling is REFUSED before the
/// mkdir, exactly as the copy's own destination components are.
pub fn create_dir_fd(root: &RootDir, rel: &Path) -> Result<()> {
    refuse_reserved_mutation(rel, Sanction::None)?;
    std::fs::create_dir(rel_join(root, rel)?)
        .map_err(|e| Error::store(format!("mkdir {}: {e}", rel.display())))
}

/// Path-based NON-RECURSIVE directory removal (`rmdir` semantics), guarded
/// like the Unix port's `remove_dir_fd`. A confirmed absence is success.
pub fn remove_dir_fd(root: &RootDir, rel: &Path) -> Result<()> {
    refuse_reserved_mutation(rel, Sanction::None)?;
    match std::fs::remove_dir(rel_join(root, rel)?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::store(format!("rmdir {}: {e}", rel.display()))),
    }
}

/// Path-based symlink creation (unlink any existing entry first, then link),
/// guarded like the Unix port's `symlink_fd` (R1). The platform helper
/// requires admin/developer mode; a failure propagates.
pub fn symlink_fd(root: &RootDir, target: &Path, rel: &Path) -> Result<()> {
    refuse_lock_record_mutation(rel)?;
    let link = rel_join(root, rel)?;
    if let Some(parent) = link.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::store(format!("mkdir {}: {e}", parent.display())))?;
    }
    match std::fs::remove_file(&link) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::store(format!("remove {}: {e}", rel.display()))),
    }
    crate::platform::symlink(target, &link)
        .map_err(|e| Error::store(format!("symlink {}: {e}", rel.display())))
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

/// Refuse a recursive removal whose tree CONTAINS destination residue at any
/// depth BELOW `root` (`root` itself is the caller's entry-point decision: an
/// implicit removal refuses it through the ONE gate, an explicit discard
/// permits it). The Windows port delegates the walk to
/// `std::fs::remove_dir_all`, which unlinks descendants without consulting any
/// authority, so the residue authority is applied to the WHOLE tree before
/// anything is removed (fail closed), exactly as
/// [`refuse_lock_record_in_tree`] applies the lock authority. A directory
/// entry's own `file_type` is consulted, so a symlink is classified as the
/// entry itself and is never descended into.
fn refuse_residue_in_tree(root: &Path) -> Result<()> {
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
                && crate::reserved::is_residue_name(name)
            {
                return Err(residue_refusal(&child));
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
    let from = GuardedRel::new(from)?;
    let to = GuardedRel::new(to)?;
    renameat_paths_guarded(root, from, to)
}

/// The SANCTIONED residue-movement rename (crate-internal), the Windows twin of
/// `unix::rename_residue_paths`: both ends may carry a residue spelling (the
/// engine's own claim-aside rename and `sync::Residue::recover_to`), and the
/// lock authority still runs on both.
pub(crate) fn rename_residue_paths(root: &RootDir, from: &Path, to: &Path) -> Result<()> {
    // A residue `to` that ALREADY EXISTS is a stranded ORIGINAL the rename
    // would REPLACE: refuse it, exactly as the public rename does. An ABSENT
    // residue `to` is a fresh claim-aside (the engine's own), and a residue
    // `from` is a MOVE (the strand survives), so both remain permitted.
    if to
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(crate::reserved::is_residue_name)
        && path_kind_fd(root, to)?.is_some()
    {
        return Err(residue_refusal(to));
    }
    let from = GuardedRel::new_for_residue(from)?;
    let to = GuardedRel::new_for_residue(to)?;
    renameat_paths_guarded(root, from, to)
}

/// [`renameat_paths`]'s worker: it accepts only capability tokens, so the
/// rel-path rename cannot be named without the guard on this port either.
fn renameat_paths_guarded(root: &RootDir, from: GuardedRel<'_>, to: GuardedRel<'_>) -> Result<()> {
    let from = rel_join(root, from.as_path())?;
    let to = rel_join(root, to.as_path())?;
    // F-A2: renaming a directory that CONTAINS the record moves the record's
    // inode and frees the old path. Windows delegates the walk to the same
    // tree guard the recursive removal uses (type-checked only here).
    refuse_lock_record_in_tree(&from)?;
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
    // The ONE gate at the entry point refuses a lock-record spelling AND a
    // residue spelling. Without the residue half, `std::fs::remove_dir_all`
    // walked straight over a stranded aside.
    refuse_reserved_mutation(rel, Sanction::None)?;
    let joined = rel_join(root, rel)?;
    // `std::fs::remove_dir_all` unlinks descendants itself, so the whole tree
    // is checked BEFORE it runs — for BOTH authorities.
    refuse_lock_record_in_tree(&joined)?;
    refuse_residue_in_tree(&joined)?;
    std::fs::remove_dir_all(joined)
        .map_err(|e| Error::store(format!("remove_dir_all {}: {e}", rel.display())))
}

/// EXPLICIT DISCARD of a stranded residue (`sync::Residue::discard`), the
/// Windows twin of `unix::remove_residue_dir_all_fd`: the root's own residue
/// spelling is permitted, the lock authority still runs, and a NESTED residue
/// is still refused.
pub(crate) fn remove_residue_dir_all_fd(root: &RootDir, rel: &Path) -> Result<()> {
    // The FINAL-residue sanction lets the walk root through; the gate still
    // refuses a lock-record spelling (including a residue-shaped one) and a
    // residue in any NON-final component.
    refuse_reserved_mutation(rel, Sanction::FinalResidue)?;
    require_final_residue(rel)?;
    let joined = rel_join(root, rel)?;
    refuse_lock_record_in_tree(&joined)?;
    refuse_residue_in_tree(&joined)?;
    std::fs::remove_dir_all(joined)
        .map_err(|e| Error::store(format!("remove_dir_all {}: {e}", rel.display())))
}

/// EXPLICIT DISCARD of a stranded residue that is a FILE or SYMLINK, the
/// Windows twin of `unix::remove_residue_file_fd`: the FINAL-residue sanction
/// lets the strand through, the lock authority still runs, and a residue in any
/// non-final component is still refused.
pub(crate) fn remove_residue_file_fd(root: &RootDir, rel: &Path) -> Result<()> {
    refuse_reserved_mutation(rel, Sanction::FinalResidue)?;
    require_final_residue(rel)?;
    std::fs::remove_file(rel_join(root, rel)?)
        .map_err(|e| Error::store(format!("remove {}: {e}", rel.display())))
}

/// Remove ONE entry of the sync engine's own CLAIM-ASIDE walk. Residues are
/// permitted anywhere on the path; the LOCK authority still runs.
pub(crate) fn remove_claim_file_fd(root: &RootDir, rel: &Path) -> Result<()> {
    refuse_reserved_mutation(rel, Sanction::Residue)?;
    std::fs::remove_file(rel_join(root, rel)?)
        .map_err(|e| Error::store(format!("remove {}: {e}", rel.display())))
}

/// The non-recursive `rmdir` of one (already-emptied) directory of the sync
/// engine's own claim-aside walk; residues are permitted anywhere on the path
/// (see [`remove_claim_file_fd`]).
pub(crate) fn remove_claim_dir_fd(root: &RootDir, rel: &Path) -> Result<()> {
    refuse_reserved_mutation(rel, Sanction::Residue)?;
    match std::fs::remove_dir(rel_join(root, rel)?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::store(format!("rmdir {}: {e}", rel.display()))),
    }
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
