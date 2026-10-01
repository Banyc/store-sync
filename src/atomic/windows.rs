//! The Windows implementation of the store atomic I/O: PATH-BASED (no
//! directory descriptors — the owned root is a path) with documented
//! weaker guarantees than the Unix descriptor-relative confinement:
//!
//! * no symlink-refusing component-wise resolution (Windows symlinks
//!   require admin/developer mode, so the injection attack surface is
//!   smaller);
//! * no parent-directory fsync durability (a directory cannot be opened
//!   as a file on Windows) — the rename is the only commit point;
//! * a NON-atomic replace (Windows `rename` does not overwrite an
//!   existing target — the target is removed first, so a reader can
//!   observe a transient absence);
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
/// documented weaker guarantees of the Windows port. The per-stage fault
/// hook fires at every stage exactly as on Unix (the test surface is
/// platform-independent); the post-rename [`ReplaceStage::DirSync`] fault
/// still reports [`ReplaceOutcome::ReplacedDurabilityUnknown`].
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
    // Stage 3: the rename — COMMIT POINT 1. Windows `rename` does not
    // overwrite an existing target: remove it first (the replace is NOT
    // atomic — a reader can observe a transient absence). A failure (or an
    // injected [`ReplaceStage::Rename`] fault) is a PRE-RENAME `Err`.
    if let Some(e) = fault(ReplaceStage::Rename) {
        return Err(e);
    }
    let _ = std::fs::remove_file(path);
    std::fs::rename(&tmp, path)
        .map_err(|e| Error::store(format!("rename {}: {e}", path.display())))?;
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
            std::fs::copy(&link, &target)
                .map_err(|e| Error::store(format!("copy {}: {e}", target.display())))?;
        } else {
            std::fs::copy(&path, &target)
                .map_err(|e| Error::store(format!("copy {}: {e}", target.display())))?;
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

/// Path-based atomic replace (see [`write_atomic_replace`]).
pub fn write_atomic_replace_fd(
    root: &RootDir,
    rel: &Path,
    bytes: &[u8],
    fault: &mut dyn FnMut(ReplaceStage) -> Option<Error>,
) -> Result<ReplaceOutcome> {
    write_atomic_replace(&root.path().join(rel), bytes, fault)
}

/// Path-based create-or-compare CAS: the create-new install is the
/// atomicity primitive (a racing loser fails on AlreadyExists and can
/// never clobber a winner); there is no parent-directory fsync durability.
pub fn write_atomic_cas_fd(root: &RootDir, rel: &Path, bytes: &[u8]) -> Result<()> {
    let path = root.path().join(rel);
    // If the file exists, its content must be byte-identical.
    match std::fs::read(&path) {
        Ok(existing) => {
            if existing == bytes {
                return Ok(());
            }
            return Err(Error::store(format!(
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
    ensure_private_dir(&root.path().join(rel))
}

/// Path-based DURABLE private-directory creation (see
/// [`ensure_private_dir_durable`] — the durable commit is a no-op on
/// Windows).
pub fn ensure_private_dir_durable_fd(root: &RootDir, rel: &Path) -> Result<bool> {
    ensure_private_dir_durable(&root.path().join(rel))
}

/// Windows has no directory fsync: a no-op (documented weaker durability
/// guarantee of the Windows port).
pub fn sync_parent_dir_fd(_root: &RootDir, _rel: &Path) -> Result<()> {
    Ok(())
}

/// Path-based private chmod (see [`set_private`] — a no-op on Windows).
pub fn set_private_fd(root: &RootDir, rel: &Path) -> Result<()> {
    set_private(&root.path().join(rel))
}

/// Path-based remove of a single file.
pub fn remove_file_fd(root: &RootDir, rel: &Path) -> Result<()> {
    std::fs::remove_file(root.path().join(rel))
        .map_err(|e| Error::store(format!("remove {}: {e}", rel.display())))
}

/// Path-based rename of a path under the root to another path under the
/// root. Windows `rename` does not overwrite an existing target: remove it
/// first (documented weaker guarantee — not atomic).
pub fn renameat_paths(root: &RootDir, from: &Path, to: &Path) -> Result<()> {
    let from = root.path().join(from);
    let to = root.path().join(to);
    let _ = std::fs::remove_file(&to);
    std::fs::rename(&from, &to).map_err(|e| {
        Error::store(format!(
            "rename {} -> {}: {e}",
            from.display(),
            to.display()
        ))
    })
}

/// Path-based recursive removal of a directory tree.
pub fn remove_dir_all_fd(root: &RootDir, rel: &Path) -> Result<()> {
    std::fs::remove_dir_all(root.path().join(rel))
        .map_err(|e| Error::store(format!("remove_dir_all {}: {e}", rel.display())))
}

/// Path-based recursive tree copy: the destination resolves under the root
/// path; symlinks are copied as their target's content (Windows symlinks
/// require admin/developer mode) — the documented weaker guarantee of the
/// Windows port.
pub fn copy_dir_recursive_fd(root: &RootDir, src: &Path, dst_rel: &Path) -> Result<()> {
    let dst = root.path().join(dst_rel);
    std::fs::create_dir_all(&dst)
        .map_err(|e| Error::store(format!("mkdir {}: {e}", dst.display())))?;
    for entry in std::fs::read_dir(src)
        .map_err(|e| Error::store(format!("read_dir {}: {e}", src.display())))?
    {
        let entry = entry.map_err(|e| Error::store(format!("entry: {e}")))?;
        let ft = entry
            .file_type()
            .map_err(|e| Error::store(format!("file_type: {e}")))?;
        let target = dst.join(entry.file_name());
        if ft.is_dir() {
            copy_dir_recursive_fd(root, &entry.path(), &dst_rel.join(entry.file_name()))?;
        } else if ft.is_symlink() {
            let link = std::fs::read_link(entry.path())
                .map_err(|e| Error::store(format!("readlink {}: {e}", entry.path().display())))?;
            let _ = std::fs::remove_file(&target);
            std::fs::copy(&link, &target)
                .map_err(|e| Error::store(format!("copy {}: {e}", target.display())))?;
        } else {
            std::fs::copy(entry.path(), &target)
                .map_err(|e| Error::store(format!("copy {}: {e}", target.display())))?;
        }
    }
    Ok(())
}

/// Windows has no directory fsync: a no-op (documented weaker durability
/// guarantee of the Windows port).
pub fn fsync_tree_recursive_fd(_root: &RootDir, _rel: &Path) -> Result<()> {
    Ok(())
}

/// Path-based plain file write (create-or-truncate).
pub fn write_file_fd(root: &RootDir, rel: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(root.path().join(rel), bytes)
        .map_err(|e| Error::store(format!("write {}: {e}", rel.display())))
}

/// Read the whole file at `rel` under the root path.
pub fn read_fd(root: &RootDir, rel: &Path) -> Result<Vec<u8>> {
    std::fs::read(root.path().join(rel))
        .map_err(|e| Error::store(format!("read {}: {e}", rel.display())))
}

/// [`read_fd`] + JSON deserialization.
pub fn read_json_fd<T: serde::de::DeserializeOwned>(root: &RootDir, rel: &Path) -> Result<T> {
    let bytes = read_fd(root, rel)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::store(format!("deserialize {}: {e}", rel.display())))
}

/// The TRI-STATE existence check under the root path (see [`path_state`]).
pub fn path_state_fd(root: &RootDir, rel: &Path) -> Result<bool> {
    path_state(&root.path().join(rel))
}

/// Read the entries of the directory at `rel` under the root path.
pub fn read_dir_fd(root: &RootDir, rel: &Path) -> Result<Vec<DirEntry>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(root.path().join(rel))
        .map_err(|e| Error::store(format!("read_dir {}: {e}", rel.display())))?
    {
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
