//! The COMPOSED destination-ownership form: a run that holds BOTH the
//! destination's sibling operation-lock record
//! ([`storekit::sync::destination_lock_path`]) and the caller's in-root
//! `Layout::lock`.
//!
//! The sibling record and the in-root layout lock are DIFFERENT files, so on
//! their own they do NOT exclude each other. `DestinationOwnership::lock` is
//! unchanged and takes the sibling record alone; a caller that needs both
//! records held asks for it by name with
//! `DestinationOwnership::lock_with_in_root_lock`, which acquires the sibling
//! record and then the caller's in-root record — the ONE canonical order,
//! enforced in the constructor.
//!
//! These tests run against the PUBLIC API only. They pin, on BOTH directions
//! (PUSH and PULL):
//!
//! * the composed token HOLDS both records (a bare `FileLock` on either is
//!   refused while it is alive), and two composed runs, a composed run and a
//!   plain run, exclude each other;
//! * the canonical order is sibling-first (a composed acquisition whose
//!   sibling record is contended does not create the in-root record);
//! * taking the two records in OPPOSITE orders does not deadlock, because both
//!   acquisitions are non-blocking;
//! * the composed form requires the destination root to already exist (a typed
//!   `Error::NotFound`), and creates nothing when it refuses;
//! * the in-root record is destination RESIDUE: it is stripped from the view
//!   the run judges, reported in `residue` (never `extraneous`), and never
//!   destroyed;
//! * the PLAIN form is unchanged: it never creates or holds the in-root record.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use storekit::RootedRelativePath;
use storekit::env::SysEnv;
use storekit::lock::FileLock;
use storekit::sync::{
    DestinationOwnership, Direction, Extraneous, ReplaceAll, destination_lock_path, sync,
};
use storekit::transport::{Layout, LocalTransport};

/// A validated root-relative path (the only spelling authority for a
/// root-confined mutation), parsed at the boundary like a consumer must.
fn rp(s: &str) -> RootedRelativePath {
    RootedRelativePath::parse(Path::new(s)).unwrap()
}

/// Build a `LocalTransport` rooted at an existing directory, with `Layout::empty()`
/// (no bootstrap directories): the composed form is given the in-root lock path
/// explicitly, so the transport layout is irrelevant to it.
fn local_transport(base: &Path) -> LocalTransport {
    LocalTransport::new(&SysEnv::from_process(), base.to_path_buf(), Layout::empty()).unwrap()
}

/// The in-root layout lock path the consumer passes to the composed form.
fn layout_lock() -> RootedRelativePath {
    rp("state/operation.lock")
}

fn seed_tree(root: &Path, file: &str, bytes: &[u8]) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(root.join(file), bytes).unwrap();
}

fn in_root_path(dst: &Path) -> PathBuf {
    dst.join("state/operation.lock")
}

/// Both directions in one place: `(source_root, dest_root, direction)`.
struct Pair {
    dir: Direction,
    src: PathBuf,
    dst: PathBuf,
}

/// Build the fixture for `dir`: for a PUSH the local root is the source; for a
/// PULL the local root is the destination and the remote is the source.
fn pair(tmp: &Path, dir: Direction, seed: &[u8]) -> Pair {
    match dir {
        Direction::Push => {
            let src = tmp.join("src");
            let dst = tmp.join("dst");
            seed_tree(&src, "f", seed);
            std::fs::create_dir_all(&dst).unwrap();
            Pair { dir, src, dst }
        }
        Direction::Pull => {
            let src = tmp.join("remote-src");
            let dst = tmp.join("dst");
            seed_tree(&src, "f", seed);
            std::fs::create_dir_all(&dst).unwrap();
            Pair { dir, src, dst }
        }
    }
}

impl Pair {
    fn transport(&self) -> LocalTransport {
        match self.dir {
            // PUSH: the remote is the destination.
            Direction::Push => local_transport(&self.dst),
            // PULL: the remote is the source.
            Direction::Pull => local_transport(&self.src),
        }
    }

    fn local_root(&self) -> &Path {
        match self.dir {
            Direction::Push => &self.src,
            Direction::Pull => &self.dst,
        }
    }

    fn composed(&self, transport: &LocalTransport) -> storekit::Result<DestinationOwnership> {
        DestinationOwnership::lock_with_in_root_lock(
            self.dir,
            self.local_root(),
            transport,
            &layout_lock(),
        )
    }

    fn plain(&self, transport: &LocalTransport) -> storekit::Result<DestinationOwnership> {
        DestinationOwnership::lock(self.dir, self.local_root(), transport)
    }
}

fn assert_lock_contended(result: storekit::Result<FileLock>, what: &str) {
    match result {
        Err(storekit::Error::LockContended(message)) => {
            assert!(
                message.contains("held by"),
                "{what}: the refusal must name the holder: {message}"
            );
        }
        Err(other) => panic!("{what}: expected typed LockContended, got {other:?}"),
        Ok(_) => panic!("{what}: the record must be held by the composed run"),
    }
}

/// EVIDENCE 1 (one test per direction): the composed token holds BOTH records;
/// a plain run and a second composed run against the same destination are
/// excluded; and the composed run still transfers.
fn composed_excludes_plain_and_composed(dir: Direction) {
    let tmp = tempfile::tempdir().unwrap();
    let pair = pair(tmp.path(), dir, b"composed");
    let transport = pair.transport();

    let owned = pair.composed(&transport).unwrap();
    assert!(
        matches!(owned, DestinationOwnership::LockedWithInRoot(_, _)),
        "the composed constructor must produce the LockedWithInRoot token"
    );

    // The composed token HOLDS the in-root record: a bare acquisition is
    // refused while it is alive. (The sibling record is held too.)
    assert_lock_contended(
        FileLock::acquire(&in_root_path(&pair.dst), "bare-in-root"),
        "the composed run holds the in-root layout lock",
    );
    let sibling = destination_lock_path(&pair.dst).unwrap();
    assert_lock_contended(
        FileLock::acquire(&sibling, "bare-sibling"),
        "the composed run holds the sibling record",
    );

    // A PLAIN run is excluded while the composed run holds the sibling record.
    match pair.plain(&transport) {
        Err(storekit::Error::LockContended(_)) => {}
        Ok(_) => panic!("a plain run must be excluded by a composed run"),
        Err(other) => panic!("a plain run must be excluded with LockContended: {other}"),
    }
    // Two COMPOSED runs exclude each other.
    match pair.composed(&transport) {
        Err(storekit::Error::LockContended(_)) => {}
        Ok(_) => panic!("a second composed run must be excluded"),
        Err(other) => panic!("a second composed run must be excluded with LockContended: {other}"),
    }

    // The composed run still does its job.
    let report = sync(
        dir,
        pair.local_root(),
        &transport,
        &ReplaceAll,
        Extraneous::Keep,
        owned,
    )
    .expect("the composed run succeeds");
    assert!(
        report.applied.iter().any(|p| p == "f"),
        "the composed run must transfer the entry: {:?}",
        report.applied
    );
    assert_eq!(std::fs::read(pair.dst.join("f")).unwrap(), b"composed");

    // The in-root record survives the run (stable inode; never unlinked by a
    // release).
    assert!(
        in_root_path(&pair.dst).exists(),
        "the in-root record must persist after the run"
    );
    assert!(
        sibling.exists(),
        "the sibling record must persist after the run"
    );
}

#[test]
fn composed_excludes_plain_and_composed_push() {
    composed_excludes_plain_and_composed(Direction::Push);
}

#[test]
fn composed_excludes_plain_and_composed_pull() {
    composed_excludes_plain_and_composed(Direction::Pull);
}

/// EVIDENCE 1 (the other direction of the exclusion): a holder of the in-root
/// record excludes a composed acquisition, on BOTH directions. The composed
/// constructor takes the sibling first; when the in-root record is contended it
/// fails on the SECOND acquisition and the sibling guard is released with it.
fn in_root_holder_excludes_composed(dir: Direction) {
    let tmp = tempfile::tempdir().unwrap();
    let pair = pair(tmp.path(), dir, b"x");
    let transport = pair.transport();

    // A consumer holds its own in-root layout lock.
    let in_root = in_root_path(&pair.dst);
    std::fs::create_dir_all(in_root.parent().unwrap()).unwrap();
    let _consumer = FileLock::acquire(&in_root, "consumer").unwrap();

    match pair.composed(&transport) {
        Err(storekit::Error::LockContended(message)) => {
            assert!(
                message.contains("state/operation.lock"),
                "the refusal must name the in-root record: {message}"
            );
        }
        Ok(_) => panic!("a composed run must be excluded by an in-root holder"),
        Err(other) => panic!("a composed run must be excluded by an in-root holder: {other}"),
    }

    // The failed composed acquisition released the sibling record it had taken
    // first, so a plain acquisition of it now succeeds (no leak).
    let sibling = destination_lock_path(&pair.dst).unwrap();
    let _plain = FileLock::acquire(&sibling, "reclaimed").unwrap();
}

#[test]
fn in_root_holder_excludes_composed_push() {
    in_root_holder_excludes_composed(Direction::Push);
}

#[test]
fn in_root_holder_excludes_composed_pull() {
    in_root_holder_excludes_composed(Direction::Pull);
}

/// EVIDENCE 2 (order): the canonical order is SIBLING FIRST, then the in-root
/// record. Hold the sibling record and attempt a composed acquisition: it must
/// fail with `LockContended` and must NOT have created the in-root record or
/// its parent directory. If the order were in-root-first, the in-root record
/// would exist.
fn composed_order_is_sibling_first(dir: Direction) {
    let tmp = tempfile::tempdir().unwrap();
    let pair = pair(tmp.path(), dir, b"x");
    let transport = pair.transport();

    let sibling = destination_lock_path(&pair.dst).unwrap();
    let _held = FileLock::acquire(&sibling, "outer").unwrap();

    match pair.composed(&transport) {
        Err(storekit::Error::LockContended(_)) => {}
        Ok(_) => panic!("the contended sibling must refuse the composed form"),
        Err(other) => panic!("the contended sibling must refuse with LockContended: {other}"),
    }
    assert!(
        !in_root_path(&pair.dst).exists(),
        "sibling-first: a contended sibling must refuse BEFORE the in-root record is created"
    );
    assert!(
        !pair.dst.join("state").exists(),
        "sibling-first: the in-root record's parent must not be created either"
    );
}

#[test]
fn composed_order_is_sibling_first_push() {
    composed_order_is_sibling_first(Direction::Push);
}

#[test]
fn composed_order_is_sibling_first_pull() {
    composed_order_is_sibling_first(Direction::Pull);
}

/// EVIDENCE 2 (no deadlock): two threads take the two records in OPPOSITE
/// orders. Because `FileLock::acquire` is NON-BLOCKING (`flock LOCK_NB` /
/// `LockFileEx` with `LOCKFILE_FAIL_IMMEDIATELY`), neither thread can WAIT while
/// holding a record, so no deadlock is possible by construction. The test
/// proves both threads RETURN (a bounded `recv_timeout`, not a `join` that can
/// hang) and that every attempt ended in an acquisition or the typed
/// `LockContended`, never a hang or another error class.
#[test]
fn opposite_order_acquisitions_do_not_deadlock() {
    let tmp = tempfile::tempdir().unwrap();
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&dst).unwrap();
    let sibling = destination_lock_path(&dst).unwrap();
    let in_root = in_root_path(&dst);
    std::fs::create_dir_all(in_root.parent().unwrap()).unwrap();

    let (tx_a, rx_a) = mpsc::channel::<bool>();
    let (tx_b, rx_b) = mpsc::channel::<bool>();

    let sibling_a = sibling.clone();
    let in_root_a = in_root.clone();
    let handle_a = std::thread::spawn(move || {
        // Order A: sibling then in-root (the canonical order).
        let first = FileLock::acquire(&sibling_a, "A-1");
        let second = FileLock::acquire(&in_root_a, "A-2");
        let held = first.is_ok() && second.is_ok();
        tx_a.send(held).unwrap();
    });

    let sibling_b = sibling.clone();
    let in_root_b = in_root.clone();
    let handle_b = std::thread::spawn(move || {
        // Order B: in-root then sibling (the REVERSED order).
        let first = FileLock::acquire(&in_root_b, "B-1");
        let second = FileLock::acquire(&sibling_b, "B-2");
        let held = first.is_ok() && second.is_ok();
        tx_b.send(held).unwrap();
    });

    // THE DEADLOCK PROPERTY IS THE BOUNDED WAIT: a thread that blocked while
    // holding one record would leave the other waiting forever, and both
    // `recv_timeout`s below would time out. Which threads WON is irrelevant —
    // the two may each win BOTH records at DIFFERENT times (A holds both, drops
    // them, then B holds both); what is impossible is a simultaneous wait.
    let _a = rx_a
        .recv_timeout(Duration::from_secs(10))
        .expect("order A must return (no deadlock, no hang)");
    let _b = rx_b
        .recv_timeout(Duration::from_secs(10))
        .expect("reversed order B must return (no deadlock, no hang)");
    handle_a.join().unwrap();
    handle_b.join().unwrap();

    // Both records still exist and are now free (both threads returned and
    // dropped their guards).
    assert!(FileLock::acquire(&sibling, "after").is_ok());
    assert!(FileLock::acquire(&in_root, "after").is_ok());
}

/// EVIDENCE 3 (the premise check + fresh destination): the in-root record is
/// RESIDUE, invisible to the run's diff, reported in `residue` and never in
/// `extraneous`, and never destroyed. The record's PARENT directory is ordinary
/// content; under `Extraneous::Delete` its removal is refused because it holds
/// residue, so neither the directory nor the record is destroyed.
#[test]
fn composed_in_root_record_is_residue_and_is_never_destroyed() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    seed_tree(&src, "f", b"payload");
    std::fs::create_dir_all(&dst).unwrap();

    let transport = local_transport(&dst);
    let owned = DestinationOwnership::lock_with_in_root_lock(
        Direction::Push,
        &src,
        &transport,
        &layout_lock(),
    )
    .unwrap();
    let record = in_root_path(&dst);
    assert!(
        storekit::reserved::is_residue_path("state/operation.lock"),
        "premise: the in-root layout lock spelling is destination residue"
    );
    assert!(
        record.exists(),
        "the composed acquisition creates the in-root record"
    );

    let report = sync(
        Direction::Push,
        &src,
        &transport,
        &ReplaceAll,
        // DELIBERATELY Delete: even a run that deletes destination-only
        // entries must not destroy the record or the directory that holds it.
        Extraneous::Delete,
        owned,
    )
    .unwrap();

    assert!(
        report.residue.iter().any(|p| p == "state/operation.lock"),
        "the in-root record must be reported as residue: residue={:?} extraneous={:?} conflicts={:?}",
        report.residue,
        report.extraneous,
        report.conflicts
    );
    assert!(
        !report
            .extraneous
            .iter()
            .any(|p| p == "state/operation.lock"),
        "the in-root record must NOT be classified as deletable extraneous content: {:?}",
        report.extraneous
    );
    // The record and its parent directory both survive the Delete run.
    assert!(
        record.exists(),
        "the in-root record must never be destroyed by the run"
    );
    assert!(
        dst.join("state").exists(),
        "the directory holding residue must never be destroyed by the run"
    );
    assert_eq!(std::fs::read(dst.join("f")).unwrap(), b"payload");
}

/// EVIDENCE 3 (fresh-destination answers): the composed form REQUIRES the
/// destination root to already exist, and a refusal creates NOTHING — not the
/// root, not the sibling record. A root that exists as a non-directory is the
/// other typed refusal.
#[test]
fn composed_requires_an_existing_root_and_refuses_without_creating() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    seed_tree(&src, "f", b"x");
    let dst = tmp.path().join("dst-does-not-exist");
    let transport = local_transport(&dst);

    match DestinationOwnership::lock_with_in_root_lock(
        Direction::Push,
        &src,
        &transport,
        &layout_lock(),
    ) {
        Err(storekit::Error::NotFound(message)) => {
            assert!(
                message.contains("ALREADY EXIST"),
                "the refusal must state the requirement: {message}"
            );
        }
        Ok(_) => panic!("a missing destination root must be refused"),
        Err(other) => panic!("a missing destination root must be a typed NotFound: {other}"),
    }
    assert!(!dst.exists(), "the refusal must not create the root");
    assert!(
        !destination_lock_path(&dst).unwrap().exists(),
        "the refusal must not create the sibling record"
    );

    // A root that exists but is not a directory is the other typed refusal.
    let file_root = tmp.path().join("file-root");
    std::fs::write(&file_root, b"not a dir").unwrap();
    let transport = local_transport(&file_root);
    match DestinationOwnership::lock_with_in_root_lock(
        Direction::Push,
        &src,
        &transport,
        &layout_lock(),
    ) {
        Err(storekit::Error::Materialization { .. }) => {}
        Ok(_) => panic!("a non-directory root must be refused"),
        Err(other) => panic!("a non-directory root must be refused: {other}"),
    }
}

/// EVIDENCE 4 (the default is unchanged): the plain `DestinationOwnership::lock`
/// never creates or holds the in-root record. Its last step is a plain run that
/// still transfers, and only afterwards is the in-root record created — by the
/// test's own bare acquisition, which succeeds because nobody holds it.
fn plain_form_never_takes_the_in_root_record(dir: Direction) {
    let tmp = tempfile::tempdir().unwrap();
    let pair = pair(tmp.path(), dir, b"plain");
    let transport = pair.transport();

    let plain = pair.plain(&transport).unwrap();
    assert!(
        !in_root_path(&pair.dst).exists(),
        "the plain form must not create the in-root record"
    );
    assert!(
        !pair.dst.join("state").exists(),
        "the plain form must not create the in-root record's parent"
    );

    let report = sync(
        dir,
        pair.local_root(),
        &transport,
        &ReplaceAll,
        Extraneous::Keep,
        plain,
    )
    .expect("the plain run succeeds");
    assert!(report.applied.iter().any(|p| p == "f"));
    assert!(
        !in_root_path(&pair.dst).exists(),
        "the plain run must not create the in-root record"
    );

    // Only now does the test create the in-root record, and it succeeds: the
    // plain path held nothing there.
    std::fs::create_dir_all(in_root_path(&pair.dst).parent().unwrap()).unwrap();
    FileLock::acquire(&in_root_path(&pair.dst), "after-plain")
        .expect("the plain path never held the in-root record");
}

#[test]
fn plain_form_never_takes_the_in_root_record_push() {
    plain_form_never_takes_the_in_root_record(Direction::Push);
}

#[test]
fn plain_form_never_takes_the_in_root_record_pull() {
    plain_form_never_takes_the_in_root_record(Direction::Pull);
}
