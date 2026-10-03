//! Recovery and explicit discard for a STRANDED claim-aside.
//!
//! A sync that replaces an entry whose KIND changed first RENAMES the original
//! aside to a hidden sibling (`.sync-aside.<pid>.<n>`), installs the new entry
//! at the real name, and only then deletes the aside. A process KILLED between
//! the rename and the delete leaves the aside behind holding the ORIGINAL — the
//! pre-replace state. [`SyncReport::residue`](crate::sync::SyncReport::residue)
//! detects the strand and reports it; the sync itself never removes it (its
//! removal of a destination-only directory holding residue is refused as
//! [`ConflictReason::ResidueBelow`](crate::sync::ConflictReason::ResidueBelow)).
//!
//! What was MISSING was a way to put the original back. The old documentation
//! told the caller to remove each reported path — which DESTROYS the caller's
//! only copy. This module is the pair of deliberate operations the recovery
//! recipe actually needs:
//!
//! * [`Residue::recover_to`] RENAMES the stranded aside back to the path it
//!   belongs at;
//! * [`Residue::discard`] REMOVES it, explicitly, for the case where the caller
//!   has decided the strand is disposable.
//!
//! # Why a handle, and why `recover_to` takes a target
//!
//! The pair shares ONE precondition (the path really is a stranded residue) and
//! ONE subject (the aside), and the two operations are exactly the two
//! decisions a caller can make about it; exposing them as methods on a
//! [`Residue`] makes "I have identified a strand" a state the caller cannot
//! forget to re-establish before acting. The construction is fallible
//! ([`Residue::detect`]), so a caller cannot recover or discard a path that is
//! not a residue.
//!
//! `recover_to` takes the TARGET path rather than deriving it, because the
//! aside spelling deliberately carries only the process id and a counter
//! (`.sync-aside.<pid>.<n>`) — it never encodes the name it was claimed from.
//! That is not an oversight: embedding the original name would push the aside
//! over `NAME_MAX` for an original at the manifest's legal maximum. The caller
//! knows the original name from [`SyncError::restore_failures`](crate::sync::SyncError)
//! (whose message names both spellings) or from the source tree it was
//! restoring.
//!
//! # Fail closed
//!
//! [`Residue::recover_to`] REFUSES when the target path is already occupied.
//! That is the ambiguous case: the entry at the target may itself hold data
//! (the install may have landed before the crash, or a foreign writer may have
//! created something there), so overwriting it silently could lose THAT data.
//! The refusal leaves the aside and the target BOTH intact and names them; the
//! caller must then decide which of the two is the state it wants — inspect
//! them, keep the target and [`Residue::discard`] the aside, or move the target
//! out of the way itself and retry. The crate never makes that decision for the
//! caller.
//!
//! The check-then-rename window is closed against a COOPERATING writer because
//! [`Residue::recover_to`] takes the destination's operation lock
//! ([`crate::sync::destination_lock_path`], through the SAME
//! [`crate::lock::FileLock`] authority a sync run holds for its whole duration)
//! for the duration of the recovery; a live holder is the typed contention
//! refusal. A NON-cooperating writer is outside the crate's exclusion, exactly
//! as it is for every other sync mutation (see [`crate::sync`]'s lock
//! discipline). The rename is made DURABLE by fsyncing the parent directory
//! after it lands.

use crate::atomic::{self, PathKind, RootDir};
use crate::error::{Error, ReservedKind, Result};
use std::path::{Path, PathBuf};

/// One stranded claim-aside at a LOCAL destination root, identified by its own
/// root-relative path.
///
/// A `Residue` is a PROOF that the path was a residue spelling at detection
/// time; recovery and discard re-validate against the live filesystem, so a
/// path that changed under the caller is refused rather than acted on blindly.
#[derive(Clone, Debug)]
pub struct Residue {
    root: PathBuf,
    aside: PathBuf,
}

impl Residue {
    /// Identify the residue at `aside`, a path RELATIVE to `root`.
    ///
    /// Refuses when `aside` is not a residue spelling
    /// ([`crate::reserved::is_residue_name`] on the final component — a genuine
    /// claim-aside, never a crate temp, which is `extraneous` and removable by
    /// the crate's own sweep), when it does not exist, or when `root` itself is
    /// not an openable directory. `aside` is validated as root-relative by the
    /// underlying primitives (no absolute path, no `..`).
    pub fn detect(root: impl AsRef<Path>, aside: impl AsRef<Path>) -> Result<Residue> {
        let root = root.as_ref().to_path_buf();
        let aside = aside.as_ref().to_path_buf();
        let final_is_residue = aside
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(crate::reserved::is_residue_name);
        if !final_is_residue {
            return Err(Error::reserved(
                ReservedKind::NotResidue,
                format!(
                    "{}: {} is not destination residue — its final component is not a claim-aside \
                     spelling (`.sync-aside.<pid>.<n>`) or another unaddressable spelling; a crate \
                     temp holds no original and is removed by the ordinary extraneous sweep",
                    crate::reserved::RESIDUE_BELOW,
                    aside.display()
                ),
            ));
        }
        let dir = RootDir::open(&root)?;
        match atomic::path_kind_fd(&dir, &aside)? {
            None => Err(Error::not_found(format!(
                "no residue at {} under {}",
                aside.display(),
                root.display()
            ))),
            Some(PathKind::Other) => Err(Error::store(format!(
                "the residue at {} is not a regular file, a directory, or a symlink, so it cannot \
                 be recovered or discarded by name",
                aside.display()
            ))),
            Some(_) => Ok(Residue { root, aside }),
        }
    }

    /// The stranded aside's root-relative spelling.
    pub fn aside(&self) -> &Path {
        &self.aside
    }

    /// RECOVER: move the stranded aside back to `target` (also root-relative),
    /// the path the aside was claimed from.
    ///
    /// FAILS CLOSED when `target` is occupied: the aside and the target are
    /// both left exactly as they were, and the error names both. See the module
    /// docs for what the caller must do then. On success the aside no longer
    /// exists and `target` holds the stranded bytes; the parent directory is
    /// synced (the rename's durability), and the result is verified against the
    /// live filesystem before `Ok` is returned.
    pub fn recover_to(&self, target: impl AsRef<Path>) -> Result<()> {
        let target = target.as_ref();
        // SERIALIZE against a cooperating writer. A sync run holds the
        // destination's operation lock for its whole duration, so recovering a
        // strand takes the SAME lock through the SAME authority
        // ([`crate::lock::FileLock`]) for this recovery's duration. A live
        // holder is the typed contention refusal — the check-then-rename window
        // is therefore closed against a cooperating writer, as the module docs
        // claim.
        let lock_path = crate::sync::destination_lock_path(&self.root).ok_or_else(|| {
            Error::preflight(format!(
                "cannot recover the residue at {}: the destination root {} has no derivable \
                 operation-lock path, so the recovery cannot be serialized against a sync run",
                self.aside.display(),
                self.root.display()
            ))
        })?;
        let _operation_lock = crate::lock::FileLock::acquire(
            &lock_path,
            &format!(
                "store-sync residue recover at {} (pid {})",
                self.root.display(),
                std::process::id()
            ),
        )?;
        let dir = RootDir::open(&self.root)?;
        // The aside must STILL be there. A `detect`-then-`recover` gap in which
        // something removed it is a refusal, not a silent success naming no
        // original.
        if atomic::path_kind_fd(&dir, &self.aside)?.is_none() {
            return Err(Error::not_found(format!(
                "the residue {} no longer exists, so there is nothing to recover",
                self.aside.display()
            )));
        }
        // A target that EXISTS as anything — a regular file, a directory, or a
        // SYMLINK — is OCCUPIED. Using the live KIND (not the tri-state presence
        // probe, which REFUSES a symlink with a raw `ELOOP` store error) makes
        // the symlink-occupant case a TYPED conflict, exactly like a regular
        // occupant, instead of a `Store("openat ... ELOOP")` a consumer cannot
        // classify.
        if atomic::path_kind_fd(&dir, target)?.is_some() {
            return Err(Error::reserved(
                ReservedKind::RecoverTargetOccupied,
                format!(
                    "{}: refusing to recover the residue {} to {} — the target path is OCCUPIED, so \
                     overwriting it could destroy the entry that is there. Both are left intact: \
                     inspect them, then either keep the target and discard the residue, or move the \
                     target aside yourself and retry",
                    crate::reserved::RESIDUE_BELOW,
                    self.aside.display(),
                    target.display()
                ),
            ));
        }
        // The guarded, descriptor-relative rename (both endpoints validated and
        // refused for a lock-record spelling) through the SANCTIONED
        // residue-movement primitive: recovering a strand is the whole point of
        // this operation, so the aside's own residue spelling is permitted (the
        // public `renameat_paths` refuses it).
        atomic::rename_residue_paths(&dir, &self.aside, target)?;
        // The rename's DURABILITY: fsync the parent directory (the aside and the
        // target are siblings in ONE directory, so this covers both the removal
        // of the aside and the appearance of the target). A recovery a crash can
        // undo would be a poor recovery.
        atomic::sync_parent_dir_fd(&dir, target)?;
        // Read back: a rename that reported success but did not land would
        // otherwise be an `Ok` naming a recovered original that is not there.
        if atomic::path_kind_fd(&dir, &self.aside)?.is_some() {
            return Err(Error::store(format!(
                "recovering the residue {} reported success, but a read-back confirms the aside \
                 is STILL present: the recovery did not land",
                self.aside.display()
            )));
        }
        if atomic::path_kind_fd(&dir, target)?.is_none() {
            return Err(Error::store(format!(
                "recovering the residue {} reported success, but a read-back confirms the target \
                 {} is ABSENT: no original was restored",
                self.aside.display(),
                target.display()
            )));
        }
        Ok(())
    }

    /// DISCARD: deliberately remove the stranded aside.
    ///
    /// This is IRREVERSIBLE and is the caller's explicit decision that the
    /// strand is disposable. It is the only sanctioned break of the crate's
    /// implicit-removal residue guard: the aside's own spelling is permitted,
    /// but the LOCK authority still runs and a NESTED residue is still refused
    /// (a residue inside the strand is a SEPARATE stranded original the caller
    /// must discard first). A missing aside is an idempotent success.
    pub fn discard(&self) -> Result<()> {
        let dir = RootDir::open(&self.root)?;
        // Re-establish the ONE precondition against the spelling, so the pair
        // shares it: a handle can only ever discard a residue, never ordinary
        // content.
        if !self
            .aside
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(crate::reserved::is_residue_name)
        {
            return Err(Error::reserved(
                ReservedKind::NotResidue,
                format!(
                    "{}: refusing to discard {} — its final component is not a residue \
                     (`.sync-aside.<pid>.<n>` or another unaddressable spelling); a discard only ever \
                     removes a stranded original, never ordinary content",
                    crate::reserved::RESIDUE_BELOW,
                    self.aside.display()
                ),
            ));
        }
        match atomic::path_kind_fd(&dir, &self.aside)? {
            None => Ok(()),
            Some(PathKind::Dir) => atomic::remove_residue_dir_all_fd(&dir, &self.aside),
            // A file or symlink aside: one non-recursive unlink through the
            // sanctioned FILE primitive — the implicit `remove_file_fd` now
            // refuses a residue, and this strand is the ONE the caller has
            // explicitly decided to discard. The aside is already proven to be
            // a residue spelling by `detect`.
            Some(_) => atomic::remove_residue_file_fd(&dir, &self.aside),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
    }

    fn tmpdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// The detection boundary: a genuine claim-aside is accepted; a crate temp
    /// (which holds no original), ordinary content, and an absent path are all
    /// refused. This is what makes `recover_to`/`discard` unable to act on
    /// anything that is not a strand.
    #[test]
    fn detect_accepts_only_a_genuine_stranded_aside() {
        let dir = tmpdir();
        let root = dir.path();

        let temp = crate::atomic::temp_name_for(Path::new("ordinary"))
            .file_name()
            .unwrap()
            .to_owned();
        write(&root.join(&temp), b"temp");
        let err = Residue::detect(root, Path::new(&temp)).unwrap_err();
        assert!(
            matches!(
                err,
                Error::Reserved {
                    reason: ReservedKind::NotResidue,
                    ..
                }
            ),
            "{err:?}"
        );

        write(&root.join("ordinary"), b"data");
        assert!(Residue::detect(root, Path::new("ordinary")).is_err());
        assert!(Residue::detect(root, Path::new(".sync-aside.999.0")).is_err());

        write(&root.join(".sync-aside.999.0"), b"stranded");
        let residue = Residue::detect(root, Path::new(".sync-aside.999.0")).unwrap();
        assert_eq!(residue.aside(), Path::new(".sync-aside.999.0"));
    }

    /// Recover restores the original byte-identically and removes the aside; a
    /// second recover is a refusal naming the now-absent aside rather than a
    /// silent success.
    #[test]
    fn recover_restores_the_original_and_is_not_a_silent_no_op() {
        let dir = tmpdir();
        let root = dir.path();
        write(&root.join(".sync-aside.999.0"), b"original bytes");
        let residue = Residue::detect(root, Path::new(".sync-aside.999.0")).unwrap();
        residue.recover_to(Path::new("restored")).unwrap();
        assert_eq!(fs::read(root.join("restored")).unwrap(), b"original bytes");
        assert!(fs::symlink_metadata(root.join(".sync-aside.999.0")).is_err());
        let err = residue.recover_to(Path::new("restored")).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "{err:?}");
    }

    /// Recover into an OCCUPIED path fails closed: BOTH the target's bytes and
    /// the aside's bytes survive untouched.
    #[test]
    fn recover_into_an_occupied_path_fails_closed() {
        let dir = tmpdir();
        let root = dir.path();
        write(&root.join(".sync-aside.999.0"), b"stranded original");
        write(&root.join("occupied"), b"occupant");
        let residue = Residue::detect(root, Path::new(".sync-aside.999.0")).unwrap();
        let err = residue.recover_to(Path::new("occupied")).unwrap_err();
        assert!(
            matches!(
                err,
                Error::Reserved {
                    reason: ReservedKind::RecoverTargetOccupied,
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(
            err.to_string().contains(crate::reserved::RESIDUE_BELOW),
            "{err}"
        );
        assert_eq!(fs::read(root.join("occupied")).unwrap(), b"occupant");
        assert_eq!(
            fs::read(root.join(".sync-aside.999.0")).unwrap(),
            b"stranded original"
        );
    }

    /// Discard removes a directory strand RECURSIVELY and a file strand with a
    /// single unlink, and is an idempotent success when the strand is already
    /// gone.
    #[test]
    fn discard_removes_directory_and_file_strands() {
        let dir = tmpdir();
        let root = dir.path();
        write(&root.join(".sync-aside.1.0/nested/deep"), b"a");
        write(&root.join(".sync-aside.1.0/top"), b"b");
        let residue = Residue::detect(root, Path::new(".sync-aside.1.0")).unwrap();
        residue.discard().unwrap();
        assert!(fs::symlink_metadata(root.join(".sync-aside.1.0")).is_err());
        // Idempotent.
        residue.discard().unwrap();

        write(&root.join(".sync-aside.2.0"), b"file strand");
        let residue = Residue::detect(root, Path::new(".sync-aside.2.0")).unwrap();
        residue.discard().unwrap();
        assert!(fs::symlink_metadata(root.join(".sync-aside.2.0")).is_err());
    }

    /// A discard REFUSES a NESTED residue: the strand holds a second stranded
    /// original, and the caller must discard that one first. This is the strict
    /// half of the explicit-discard design — one decision discards one strand.
    #[test]
    fn discard_refuses_a_nested_residue() {
        let dir = tmpdir();
        let root = dir.path();
        write(
            &root.join(".sync-aside.1.0/inner/.sync-aside.9.9/held"),
            b"x",
        );
        let residue = Residue::detect(root, Path::new(".sync-aside.1.0")).unwrap();
        let err = residue.discard().unwrap_err();
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
            fs::symlink_metadata(root.join(".sync-aside.1.0/inner/.sync-aside.9.9/held")).is_ok(),
            "the nested strand survives a refused discard"
        );
    }

    /// Discard refuses ordinary content and a lock record even when handed a
    /// handle that never went through `detect`.
    #[test]
    fn discard_never_acts_on_ordinary_content_or_a_lock_record() {
        let dir = tmpdir();
        let root = dir.path();
        write(&root.join("ordinary"), b"data");
        write(&root.join(".dest.operation.lock"), b"lock");
        let forged = Residue {
            root: root.to_path_buf(),
            aside: PathBuf::from("ordinary"),
        };
        let err = forged.discard().unwrap_err();
        assert!(
            matches!(
                err,
                Error::Reserved {
                    reason: ReservedKind::NotResidue,
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(root.join("ordinary").is_file());
        let forged = Residue {
            root: root.to_path_buf(),
            aside: PathBuf::from(".dest.operation.lock"),
        };
        assert!(forged.discard().is_err());
        assert!(root.join(".dest.operation.lock").is_file());
    }

    /// A4: `recover_to` HOLDS the destination operation lock (the SAME
    /// `FileLock` authority a sync run holds) for its duration. PRE-FIX it took
    /// no lock at all, so a cooperating writer could install the target inside
    /// the check-then-rename window and be silently replaced by the rename.
    #[test]
    fn recover_to_is_serialized_by_the_destination_operation_lock() {
        use crate::lock::FileLock;
        let dir = tmpdir();
        let root = dir.path();
        write(&root.join(".sync-aside.999.0"), b"stranded original");
        let residue = Residue::detect(root, Path::new(".sync-aside.999.0")).unwrap();
        let lock_path = crate::sync::destination_lock_path(root)
            .expect("the root names a derivable lock record");
        let held = FileLock::acquire(&lock_path, "held").expect("hold the operation lock");
        let err = residue.recover_to(Path::new("restored")).unwrap_err();
        assert!(matches!(err, Error::LockContended(_)), "{err:?}");
        assert!(
            root.join(".sync-aside.999.0").exists(),
            "the strand survives"
        );
        assert!(!root.join("restored").exists(), "nothing was renamed");
        // Once the lock is released the recovery lands (and fsyncs the parent).
        drop(held);
        residue.recover_to(Path::new("restored")).unwrap();
        assert_eq!(
            fs::read(root.join("restored")).unwrap(),
            b"stranded original"
        );
    }

    /// A6: a consumer can tell DESTROYING A STRAND (`ResidueBelow`) from an
    /// OCCUPIED recovery target (`RecoverTargetOccupied`) via the TYPED reason,
    /// without string-matching; and a SYMLINK occupant is that same typed
    /// conflict, not a raw `Store("openat ... ELOOP")`.
    #[test]
    #[cfg(unix)]
    fn the_reserved_kind_distinguishes_strand_from_occupied_target() {
        let dir = tmpdir();
        let root = dir.path();
        write(&root.join(".sync-aside.999.0"), b"strand");
        write(&root.join("occupied"), b"occupant");
        std::os::unix::fs::symlink("somewhere", root.join("occupied_link")).unwrap();
        let residue = Residue::detect(root, Path::new(".sync-aside.999.0")).unwrap();

        let occupied = residue.recover_to(Path::new("occupied")).unwrap_err();
        assert_eq!(
            occupied.reserved_kind(),
            Some(ReservedKind::RecoverTargetOccupied)
        );
        let linked = residue.recover_to(Path::new("occupied_link")).unwrap_err();
        assert_eq!(
            linked.reserved_kind(),
            Some(ReservedKind::RecoverTargetOccupied),
            "a symlink occupant is a typed conflict, not a raw Store error: {linked:?}"
        );

        let strand = Residue::detect(root, Path::new("ordinary"));
        assert!(strand.is_err());
    }

    /// A1/A6: the substrate refusal itself carries the typed reason, and the
    /// message keeps the historical `ResidueBelow` token.
    #[test]
    fn the_substrate_refusal_carries_a_typed_residue_reason() {
        let dir = tmpdir();
        let root = dir.path();
        write(&root.join(".sync-aside.7.0"), b"precious");
        let owned = RootDir::open(root).unwrap();
        let err = atomic::remove_file_fd(&owned, Path::new(".sync-aside.7.0")).unwrap_err();
        assert_eq!(err.reserved_kind(), Some(ReservedKind::ResidueBelow));
        assert!(
            err.to_string().contains(crate::reserved::RESIDUE_BELOW),
            "the historical token survives: {err}"
        );
        assert_eq!(fs::read(root.join(".sync-aside.7.0")).unwrap(), b"precious");
    }
}
