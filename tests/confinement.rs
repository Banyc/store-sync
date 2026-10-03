//! THE OWNED-ROOT CONFINEMENT PROPERTY, re-established against this crate's
//! own primitives.
//!
//! The store's `_fd` family resolves every path COMPONENT-WISE relative to
//! the owned root's open directory descriptor with `openat(O_NOFOLLOW)`. A
//! symlink injected into a path component must therefore never redirect a
//! mutation or a read outside the owned root: the operation is refused by the
//! component-wise open (the error names `openat`/`open`, never a byte from the
//! outside target), and the outside target is left byte-for-byte untouched.
//!
//! This is the crate-level re-establishment of the two tests the source crate
//! carried in `src/store/local/owned_root.rs`
//! (`symlink_injected_path_component_cannot_redirect_a_mutation` /
//! `..._a_read`), which drove the property through application types
//! (`LocalStore`/`TargetName`/`retention_debt`) that do not exist here.

#![cfg(unix)]

use std::path::{Path, PathBuf};

use storekit::Error;
use storekit::RootedRelativePath;
use storekit::atomic::{
    RootDir, path_state_fd, read_fd, renameat_paths, write_atomic_cas_fd, write_atomic_replace,
    write_atomic_replace_fd, write_file_fd,
};
use storekit::lock::FileLock;
use storekit::root::{EndpointKey, OwnedRoot};

/// A validated root-relative path: the mutating primitives take the validated
/// type, so a test spelling is parsed at the boundary too.
fn rp(s: &str) -> RootedRelativePath {
    RootedRelativePath::parse(Path::new(s)).unwrap()
}

/// Known content of the outside file an injected symlink points at; a leak of
/// these bytes through a refused read, or a mutation of them through a
/// replace, is the failure this suite forbids.
const OUTSIDE_BYTES: &[u8] = b"OUTSIDE-KNOWN-CONTENT";

/// A real owned root plus the descriptor that pins it. The [`OwnedRoot`] must
/// outlive the test (it holds the process-global ownership registration).
fn open_root(base: &Path, endpoint_tag: &str) -> (OwnedRoot, RootDir) {
    let root_path = base.join("root");
    std::fs::create_dir_all(&root_path).unwrap();
    let endpoint = EndpointKey::parse(endpoint_tag).unwrap();
    let owned = OwnedRoot::parse(&endpoint, &root_path).unwrap();
    let root = RootDir::open(owned.canonical()).unwrap();
    (owned, root)
}

/// An outside directory the injected symlink would point at. Nothing inside
/// it may ever be created, read through, or mutated.
fn outside_dir(base: &Path) -> PathBuf {
    let outside = base.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    outside
}

/// The refusal must be the confinement failure — a [`Error::Store`] raised by
/// the component-wise `openat`/`open` — not an unrelated error. `needle` is
/// the open prefix the caller observed this crate actually produces for the
/// case at hand.
fn assert_open_refusal(err: &Error, needle: &str) {
    assert!(
        matches!(err, Error::Store { .. }),
        "the refusal must be a store error, got: {err:?}"
    );
    let text = err.to_string();
    assert!(
        text.contains(needle),
        "the refusal must name the component-wise open ({needle:?}), got: {text}"
    );
}

/// A symlink at a MIDDLE component (`<root>/targets` -> outside) cannot
/// redirect a mutation: `write_atomic_replace_fd` is refused by the
/// component-wise open, and the outside directory stays empty.
#[test]
fn middle_component_symlink_refuses_a_mutation_and_leaves_outside_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let (owned, root) = open_root(tmp.path(), "confinement-mid-mutation");
    let outside = outside_dir(tmp.path());
    std::os::unix::fs::symlink(&outside, owned.canonical().join("targets")).unwrap();

    let err = write_atomic_replace_fd(&root, &rp("targets/t1/file.json"), b"payload", &mut |_| {
        None
    })
    .expect_err("a mutation through a symlink-injected component must be refused");
    assert_open_refusal(&err, "openat");
    assert_eq!(
        std::fs::read_dir(&outside).unwrap().count(),
        0,
        "the outside directory must be untouched"
    );
}

/// A symlink at a MIDDLE component cannot redirect a READ (or make the path
/// look absent): `read_fd` and `path_state_fd` are both refused by the
/// component-wise open, and the outside file's bytes are never returned.
#[test]
fn middle_component_symlink_refuses_a_read_and_never_returns_outside_content() {
    let tmp = tempfile::tempdir().unwrap();
    let (owned, root) = open_root(tmp.path(), "confinement-mid-read");
    let outside = outside_dir(tmp.path());
    // The outside layout the symlink WOULD resolve to if ever followed.
    std::fs::create_dir_all(outside.join("t1")).unwrap();
    std::fs::write(outside.join("t1/file.json"), OUTSIDE_BYTES).unwrap();
    std::os::unix::fs::symlink(&outside, owned.canonical().join("targets")).unwrap();

    let err = read_fd(&root, &rp("targets/t1/file.json"))
        .expect_err("a read through a symlink-injected component must be refused");
    assert_open_refusal(&err, "openat");

    let err = path_state_fd(&root, &rp("targets/t1/file.json"))
        .expect_err("a symlink-injected component must be refused, never treated as absence");
    assert_open_refusal(&err, "openat");

    assert_eq!(
        std::fs::read(outside.join("t1/file.json"))
            .unwrap()
            .as_slice(),
        OUTSIDE_BYTES,
        "the outside file must be untouched and its bytes never returned"
    );
}

/// A symlink at the FINAL component (`<root>/entry` -> an outside file) cannot
/// redirect a read: `read_fd` is refused (ELOOP from the final `O_NOFOLLOW`
/// open) and never returns the outside file's content.
#[test]
fn final_component_symlink_refuses_a_read_and_never_returns_outside_content() {
    let tmp = tempfile::tempdir().unwrap();
    let (owned, root) = open_root(tmp.path(), "confinement-final-read");
    let outside_file = tmp.path().join("outside-file");
    std::fs::write(&outside_file, OUTSIDE_BYTES).unwrap();
    std::os::unix::fs::symlink(&outside_file, owned.canonical().join("entry")).unwrap();

    let err = read_fd(&root, &rp("entry"))
        .expect_err("a read of a symlink final component must be refused");
    assert_open_refusal(&err, "openat entry");
    assert_eq!(
        std::fs::read(&outside_file).unwrap().as_slice(),
        OUTSIDE_BYTES,
        "the outside file must be untouched and its bytes never returned"
    );
}

/// A symlink at the FINAL component cannot redirect a create-new write: both
/// `write_file_fd` (O_CREAT|O_TRUNC) and `write_atomic_cas_fd` refuse the
/// final `O_NOFOLLOW` open, the link is not replaced, and the outside file is
/// byte-for-byte untouched.
#[test]
fn final_component_symlink_refuses_create_new_writes_and_never_touches_outside() {
    let tmp = tempfile::tempdir().unwrap();
    let (owned, root) = open_root(tmp.path(), "confinement-final-write");
    let outside_file = tmp.path().join("outside-file");
    std::fs::write(&outside_file, OUTSIDE_BYTES).unwrap();
    let entry = owned.canonical().join("entry");
    std::os::unix::fs::symlink(&outside_file, &entry).unwrap();

    let err = write_file_fd(&root, &rp("entry"), b"IN-ROOT-NEW")
        .expect_err("a create-or-truncate write to a symlink final component must be refused");
    assert_open_refusal(&err, "openat entry");

    // The CAS refusal text names `open` (the CAS opens the final component
    // directly and formats its own error), not `openat` — asserted as it
    // really is, not as the source's mutation path phrases it.
    let err = write_atomic_cas_fd(&root, &rp("entry"), b"IN-ROOT-NEW")
        .expect_err("a creating CAS write to a symlink final component must be refused");
    assert_open_refusal(&err, "open entry");

    assert!(
        std::fs::symlink_metadata(&entry)
            .unwrap()
            .file_type()
            .is_symlink(),
        "a refused write must not replace the symlink entry"
    );
    assert_eq!(
        std::fs::read(&outside_file).unwrap().as_slice(),
        OUTSIDE_BYTES,
        "the outside file must be untouched"
    );
}

/// The FINAL-COMPONENT REPLACE path never escapes the root.
///
/// DESIGNED SEMANTIC: `write_atomic_replace_fd` does NOT refuse a
/// final-component symlink. It installs the new file with `renameat`, which
/// replaces the final directory entry itself and never opens it, so there is
/// no final `O_NOFOLLOW` open to refuse — the write lands at the link's own
/// in-root path. That is the deliberate "replace, never follow" rule: the
/// link is never followed and the outside target is never opened or modified,
/// so the replace cannot escape the root, race-free (the rename cannot follow
/// the link). A caller that must instead REFUSE a foreign final entry uses a
/// primitive that opens it with `O_NOFOLLOW` — `openat_no_follow`,
/// `write_file_fd`, `write_atomic_cas_fd`, `read_fd`, or `path_state_fd`.
/// This test pins the safety-critical half (no escape) plus the designed
/// non-refusal.
#[test]
fn final_component_symlink_replace_does_not_escape_the_root() {
    let tmp = tempfile::tempdir().unwrap();
    let (owned, root) = open_root(tmp.path(), "confinement-final-replace");
    let outside_file = tmp.path().join("outside-file");
    std::fs::write(&outside_file, OUTSIDE_BYTES).unwrap();
    let entry = owned.canonical().join("entry");
    std::os::unix::fs::symlink(&outside_file, &entry).unwrap();

    let outcome = write_atomic_replace_fd(&root, &rp("entry"), b"IN-ROOT-NEW", &mut |_| None);

    // THE ESCAPE THIS FORBIDS: a replace that followed the link would leave
    // the new bytes in the outside file. It must be byte-identical.
    assert_eq!(
        std::fs::read(&outside_file).unwrap().as_slice(),
        OUTSIDE_BYTES,
        "an atomic replace must never write through a final-component symlink"
    );
    // DESIGNED: not refused — `renameat` replaces the link entry and never
    // opens (so never follows) it.
    assert!(
        outcome.is_ok(),
        "observed non-refusal: replacing a final-component symlink replaces the link entry"
    );
    assert!(
        !std::fs::symlink_metadata(&entry)
            .unwrap()
            .file_type()
            .is_symlink(),
        "a successful replace must leave a regular file at the link's own path"
    );
    assert_eq!(
        std::fs::read(&entry).unwrap().as_slice(),
        b"IN-ROOT-NEW",
        "the bytes must land inside the owned root, never in the outside file"
    );
}

/// [`RootDir::open`] opens with `O_DIRECTORY | O_NOFOLLOW`, so the root itself
/// may not be a symlink-to-a-directory: opening the symlink is refused, while
/// opening the real directory succeeds.
#[test]
fn root_dir_open_refuses_a_symlink_root_but_opens_the_real_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let (owned, root) = open_root(tmp.path(), "confinement-root-open");
    assert!(
        RootDir::open(owned.canonical()).is_ok(),
        "opening the real owned directory must succeed"
    );
    drop(root);

    let link = tmp.path().join("link-dir");
    std::os::unix::fs::symlink(owned.canonical(), &link).unwrap();
    let err = match RootDir::open(&link) {
        Ok(_) => panic!("RootDir::open must refuse a symlink-to-directory root"),
        Err(e) => e,
    };
    assert_open_refusal(&err, "open root");
}

/// F-A1 (production-lib reproduction): the PATH-BASED
/// `atomic::write_atomic_replace` had NO lock-record guard. Pre-fix a holder
/// held `operation.lock`, the path-based replace renamed a fresh inode OVER
/// the record, and a second acquisition then flocked the NEW inode while the
/// first holder still held the old one — TWO simultaneous holders. The replace
/// is now refused, the inode is unchanged, and the second acquisition
/// contends.
#[test]
fn path_based_write_atomic_replace_cannot_swap_the_lock_record_inode() {
    use std::os::unix::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    let record = tmp.path().join("operation.lock");
    let holder = FileLock::acquire(&record, "A").expect("A acquires the record");
    let ino_a = std::fs::metadata(&record).unwrap().ino();
    let err = write_atomic_replace(&record, b"evil", &mut |_| None)
        .expect_err("a path-based replace of the lock record must be refused");
    assert!(
        matches!(err, Error::Conflict(_)),
        "the refusal must be a conflict, got: {err:?}"
    );
    assert_eq!(
        std::fs::metadata(&record).unwrap().ino(),
        ino_a,
        "the record must keep its stable inode"
    );
    let err2 = match FileLock::acquire(&record, "C") {
        Ok(_) => panic!("C must not acquire while A holds the record"),
        Err(e) => e,
    };
    assert!(
        matches!(err2, Error::LockContended(_)),
        "C must be refused with the typed contention signal: {err2:?}"
    );
    drop(holder);
}

/// F-A2 (production-lib reproduction): `renameat_paths` guarded only the
/// endpoints' FINAL components, so renaming a directory CONTAINING the record
/// moved the record with its inode and freed the old path; a second
/// acquisition at the old path then created a DIFFERENT inode — TWO holders.
/// The source SUBTREE is now walked and the rename is refused, so the record's
/// path cannot move.
#[test]
fn renameat_paths_cannot_move_an_ancestor_of_the_lock_record() {
    use std::os::unix::fs::MetadataExt;
    let tmp = tempfile::tempdir().unwrap();
    let (owned, root) = open_root(tmp.path(), "confinement-f-a2");
    std::fs::create_dir_all(owned.canonical().join("state")).unwrap();
    let record = owned.canonical().join("state/operation.lock");
    let holder = FileLock::acquire(&record, "A").expect("A acquires the record");
    let ino_a = std::fs::metadata(&record).unwrap().ino();
    let err = renameat_paths(&root, &rp("state"), &rp("state2"))
        .expect_err("renaming an ancestor of the lock record must be refused");
    assert!(
        matches!(err, Error::Conflict(_)),
        "the ancestor refusal must be a conflict, got: {err:?}"
    );
    assert!(
        record.exists(),
        "the record must survive the refused ancestor rename"
    );
    assert_eq!(
        std::fs::metadata(&record).unwrap().ino(),
        ino_a,
        "the record must keep its stable inode"
    );
    let err2 = match FileLock::acquire(&record, "C") {
        Ok(_) => panic!("C must not acquire while A holds the record"),
        Err(e) => e,
    };
    assert!(
        matches!(err2, Error::LockContended(_)),
        "C must be refused with the typed contention signal: {err2:?}"
    );
    drop(holder);
}
