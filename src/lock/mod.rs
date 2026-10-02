//! Advisory locking for push transactions.
//!
//! `FileLock` is an advisory lock held by an open file descriptor — `flock`
//! on Unix, `LockFileEx` on Windows (the platform split lives in the
//! [`unix`] / [`windows`] submodules behind ONE cfg switch at the module
//! boundary).
//! While the guard is alive the kernel prevents any other process from
//! acquiring the same lock, and the lock is released automatically if the
//! owning process dies — so a stale lock from a crashed controller can never
//! be double-owned, and two live contenders can never both win the
//! acquisition. Locks are taken in a fixed local-then-target order — the
//! application-store `operation.lock` first, then the target lock — so every
//! caller pipeline that touches both, a push or a checkpoint pass alike, runs
//! under the same lock discipline.
//!
//! [`crate::sync`] is deliberately OUTSIDE that discipline: it locks the
//! SIBLING record `<parent>/.<name>.operation.lock`
//! ([`crate::sync::destination_lock_path`]), not this in-root `operation.lock`,
//! so a `sync` and a push/checkpoint pass do NOT exclude each other in either
//! direction.
//!
//! # The STABLE-INODE discipline (why the lock file is never deleted)
//!
//! POSIX `flock` locks are attached to an INODE, not a path. The lock file is
//! created ONCE (on the first acquisition) and is NEVER removed, so every
//! acquisition in the store/session lifetime flocks the SAME inode. Releasing
//! closes the descriptor only (`flock LOCK_UN` + close) — the file itself
//! persists. This is deliberate: an unlock-then-unlink release would open an
//! inode-SPLIT window in which a second process flocks the OLD inode between
//! the unlock and the unlink while a third process creates a NEW inode and
//! flocks that — two processes simultaneously holding "the lock". With a
//! single never-removed inode no such window can exist: a fresh open of the
//! path always finds the same inode, so at most one holder can ever win the
//! flock.

use crate::error::{Error, Result};
use std::path::Path;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

pub(crate) use platform::{contended_errno, try_lock, unlock};

/// The outcome of a platform lock attempt: acquired, contended (another
/// holder — the caller reports the "held by" message), or a real failure.
pub(crate) enum LockAttempt {
    Acquired,
    Contended,
    Failed(std::io::Error),
}

/// An advisory (flock) lock held by an open file descriptor. While the guard
/// is alive the kernel prevents any other process from acquiring the same lock,
/// and the lock is released automatically if the owning process dies. This
/// makes the stale-lock double-ownership race impossible: a dead controller's
/// lock is released by the kernel rather than lingering, and two live
/// contenders can never both win the acquisition.
///
/// The lock file is created once on the first acquisition and is NEVER
/// removed by a release or drop (the STABLE-INODE discipline above): every
/// acquisition flocks the same inode, so the old delete-on-release design's
/// unlock→unlink inode-split window cannot exist.
///
/// Public so a caller's checkpoint pass runs under the SAME lock discipline as
/// its pushes: the application-store lock then the target lock, in the one
/// fixed order.
pub struct FileLock {
    file: std::fs::File,
}

impl FileLock {
    /// Acquire the advisory lock at `path`: open (creating the file on the
    /// FIRST acquisition only — after that the persistent inode is reused),
    /// then `flock LOCK_EX|LOCK_NB`. The parent directory is durably created
    /// by [`crate::atomic::ensure_private_dir_durable`] before the lock
    /// is taken (see the durable-first-append machinery the lock path must
    /// never bypass).
    ///
    /// The file is created with `create(true).truncate(false)`: when it
    /// already exists (always, after the first acquisition of this path) the
    /// SAME inode is opened, never a fresh one — the lock never swaps inodes.
    /// The persistent file does not disturb the durable-first-append
    /// machinery: directory creation is detected by the directory-entry
    /// fsyncs in [`crate::atomic::ensure_private_dir_durable`] (which
    /// reports what it CREATED), never by files inside the directory, so a
    /// surviving `operation.lock` changes nothing for a first append.
    pub fn acquire(path: &Path, op_id: &str) -> Result<Self> {
        // DURABLE parent creation: the lock file's parent directory is
        // created with EVERY newly created directory entry fsynced (see
        // [`crate::atomic::ensure_private_dir_durable`]) BEFORE the
        // lock is taken. A lock acquisition that creates a directory must
        // never do so with a plain unsynced mkdir — the first write into a
        // freshly created directory used to let the lock path create the
        // directory that way, bypassing the durable first-append helper (the
        // directory already existed when the append's creation detection ran,
        // so no parent sync happened) and a reported-successful first write
        // could recover with the directory missing after power loss. A caller
        // that needs a durable directory ahead of locking pre-creates it
        // itself; this helper makes the lock path itself durable for every
        // caller.
        if let Some(parent) = path.parent() {
            crate::atomic::ensure_private_dir_durable(parent)
                .map_err(|e| Error::preflight(format!("mkdir {}: {e}", parent.display())))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| Error::preflight(format!("open lock {}: {e}", path.display())))?;
        // Exclusive, non-blocking advisory lock (flock on Unix, LockFileEx
        // on Windows — the platform split lives in the [`platform`]
        // submodule). Only one holder at a time.
        match platform::try_lock(&file) {
            platform::LockAttempt::Acquired => {}
            platform::LockAttempt::Contended => {
                let held = std::fs::read_to_string(path).unwrap_or_default();
                return Err(Error::preflight(format!(
                    "local lock {} held by '{}'",
                    path.display(),
                    held.trim()
                )));
            }
            platform::LockAttempt::Failed(err) => {
                return Err(Error::preflight(format!("lock {}: {err}", path.display())));
            }
        }
        // We hold the lock: record our operation id for diagnostics.
        use std::io::Write;
        file.set_len(0)
            .and_then(|_| file.write_all(op_id.as_bytes()))
            .map_err(|e| Error::preflight(format!("write lock {}: {e}", path.display())))?;
        Ok(FileLock { file })
    }
}

impl std::ops::Drop for FileLock {
    fn drop(&mut self) {
        // Release the advisory lock; then the descriptor's drop closes it.
        // THE LOCK FILE IS NEVER REMOVED (the STABLE-INODE discipline): a
        // release is unlock + close ONLY, so the next acquisition re-opens
        // the SAME inode and the unlock→unlink inode-split window (a second
        // process flocking the old inode while a third creates and flocks a
        // new one — two simultaneous holders) is structurally impossible.
        // Best-effort by design, like the other Drop fallbacks: this runs on
        // every return path (including panic/unwind), so a failure must not
        // surface, and the flock itself is released by the kernel when the
        // fd drops even if the explicit unlock below never ran. The file is
        // left in place as a stable diagnostic record (the last holder's
        // operation id); exclusion comes from the flock on the single inode.
        platform::unlock(&self.file);
    }
}

/// A typed ADMINISTRATIVE capability: owns the local application-store lock
/// (`FileLock` on the store's `operation.lock`) for the duration of an
/// explicit remote-lock recovery (the administrative entry point that has
/// confirmed the remote holder is dead).
///
/// Recovery is an administrative operation that is legal ONLY while the local
/// application lock is held: every live controller holds that lock while it
/// operates, so a recovery performed under it cannot race a live controller
/// on the same store. The TYPE enforces the precondition — the recovery
/// routine accepts only `&AdministrativeRecoveryGuard` — and the guard can be
/// constructed only by actually acquiring the local `FileLock`
/// ([`Self::acquire`]); there is no free constructor, so a library caller
/// cannot recover a remote lock without first holding the local lock.
///
/// The local lock is held for exactly the guard's lifetime. Its release is
/// the `FileLock` release above: unlock + close, never unlink (the stable
/// inode survives, exactly as for every other lock file).
pub struct AdministrativeRecoveryGuard {
    _local_lock: FileLock,
}

impl AdministrativeRecoveryGuard {
    /// Construct the recovery capability by ACQUIRING the local
    /// application-store lock at `lock_path` (the store's `operation.lock`).
    /// The caller must be an administrative path that has confirmed the
    /// remote holder is dead; holding this guard for the whole recovery is
    /// what serializes a recovery against any LIVE controller on the same
    /// store.
    pub fn acquire(lock_path: &Path, op_id: &str) -> Result<Self> {
        Ok(Self {
            _local_lock: FileLock::acquire(lock_path, op_id)?,
        })
    }
}

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::os::unix::io::AsRawFd;
    use std::sync::{Arc, Barrier};
    use std::thread;

    /// The (device, inode) identity of the file `path` — the inode the
    /// advisory flock is attached to. Two opens of the same path yield the
    /// same pair iff no unlink+recreate happened between them; with the
    /// stable-inode discipline the pair NEVER changes for the lifetime of
    /// the lock path.
    fn inode_id(path: &std::path::Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let m = std::fs::metadata(path).expect("the lock file must exist");
        (m.dev(), m.ino())
    }

    /// The delete-window shape is gone: a release NEVER removes the lock
    /// file (unlock → unlink is the old inode-split window), a re-acquire
    /// reuses the SAME inode (never a recreated one), and the durable
    /// directory machinery is untouched (the persistent file changes nothing
    /// for a first append's directory-creation detection).
    #[test]
    fn release_never_removes_the_lock_file() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let path = dir.path().join("operation.lock");
        let first_inode = {
            let _guard = FileLock::acquire(&path, "op-1").expect("acquire 1");
            inode_id(&path)
        };
        // The file PERSISTS after the release.
        assert!(
            path.exists(),
            "the lock file must never be removed on release (stable inode)"
        );
        // A re-acquire reuses the SAME inode — a contender can never race a
        // new inode into existence between an unlock and an unlink.
        let guard2 = FileLock::acquire(&path, "op-2").expect("re-acquire");
        assert_eq!(
            first_inode,
            inode_id(&path),
            "re-acquisition must flock the SAME inode — never a recreated one"
        );
        drop(guard2);
        assert!(
            path.exists(),
            "the lock file still persists after the second release"
        );
    }

    /// EAGAIN handling is preserved: while a guard is alive a second acquire
    /// of the same path fails with the explicit "held by" message (the flock
    /// is exclusive on the single inode, so any contender is refused).
    #[test]
    fn contention_is_refused_with_holder_message() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let path = dir.path().join("operation.lock");
        let _a = FileLock::acquire(&path, "op-A").expect("A acquires");
        let err = match FileLock::acquire(&path, "op-B") {
            Err(e) => e,
            Ok(_) => panic!("B must be refused while A holds the lock"),
        };
        assert!(
            err.to_string().contains("held by 'op-A'"),
            "the refusal must name the holder: {err}"
        );
    }

    // ---------------------------------------------------------------------
    // THE THREE-CONTENDER INTERLEAVING PROPERTY (the review's acceptance):
    // contender A unlocks/drops, contender B tries to acquire, contender C
    // tries to acquire — at NO point may two contenders both hold the flock.
    // With the stable-inode release this is structural (there is no unlink,
    // so no old-inode/new-inode split is reachable), but the property pins
    // the invariant across the interleaving SHAPES of the old delete-window
    // design:
    //
    //   * unlock→unlink               — covered structurally by
    //                                   [release_never_removes_the_lock_file]:
    //                                   a release has NO unlink; the file and
    //                                   its inode persist after every drop.
    //   * unlock→reacquire-on-old-inode — A drops; B and C race to re-lock
    //                                   the SAME persistent inode (schedules
    //                                   1 and 2 order their go-signals); the
    //                                   flock is exclusive, so exactly one
    //                                   wins and the other is refused.
    //   * re-create-new-inode         — a fresh open of the path after the
    //                                   race still yields the ORIGINAL inode
    //                                   (the file was never unlinked); no
    //                                   second inode can be spun up to split
    //                                   the lock.
    //
    // The property drives REAL flock operations. Threads of one process that
    // open the same path separately DO contend — flock locks are attached to
    // open file descriptions, not to processes — so B and C's race is real.
    // Each proptest case draws a schedule (the barrier order that re-enacts
    // one interleaving shape) and asserts:
    //   * exactly ONE contender holds the flock after A's drop (XOR);
    //   * the loser failed with EAGAIN;
    //   * the persistent inode is unchanged, so no split is possible;
    //   * while the winner holds, a fresh acquisition is refused.
    // ---------------------------------------------------------------------

    /// One proptest case of the three-contender schedule model: a REAL
    /// release of A while B and C race the flock, under the barrier schedule
    /// `schedule` (0 = simultaneous race; 1 = B signaled first, then C;
    /// 2 = C signaled first, then B).
    fn run_three_contender_case(schedule: u8) -> proptest::test_runner::TestCaseResult {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env())
            .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
        let path = dir.path().join("operation.lock");

        // A acquires first: the persistent inode is created exactly once.
        let guard_a = FileLock::acquire(&path, "op-A")
            .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
        let inode_a = inode_id(&path);

        // B and C open their fds BEFORE A drops: both land on the SAME
        // persistent inode (a fresh open can never produce a second inode —
        // the file is never unlinked). They flock when the schedule signals.
        let fd_b = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
        let fd_c = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;

        // Every thread parks on `start` first so A's drop and the contenders
        // are all registered; the per-contender `go` barriers then admit the
        // flock attempts in the schedule's order. A thread that wins returns
        // its open File so the flock STAYS held until the case drops it; a
        // loser returns Err(EAGAIN).
        let start = Arc::new(Barrier::new(3));
        let go_b = Arc::new(Barrier::new(2));
        let go_c = Arc::new(Barrier::new(2));

        let b_start = Arc::clone(&start);
        let b_go = Arc::clone(&go_b);
        let b_handle = thread::spawn(move || {
            b_start.wait();
            b_go.wait();
            let ret = unsafe { libc::flock(fd_b.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if ret == 0 {
                Ok(fd_b)
            } else {
                Err(std::io::Error::last_os_error())
            }
        });

        let c_start = Arc::clone(&start);
        let c_go = Arc::clone(&go_c);
        let c_handle = thread::spawn(move || {
            c_start.wait();
            c_go.wait();
            let ret = unsafe { libc::flock(fd_c.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if ret == 0 {
                Ok(fd_c)
            } else {
                Err(std::io::Error::last_os_error())
            }
        });

        // All three are registered; execute the schedule's interleaving. In
        // every schedule A's release (unlock + close) completes BEFORE any
        // contender attempts the flock, so the flock is free when B and C
        // race it — exactly one must win.
        start.wait();
        match schedule {
            // Schedule 0: A drops; both contenders are released together
            // (the genuine race over the persistent inode).
            0 => {
                drop(guard_a);
                go_b.wait();
                go_c.wait();
            }
            // Schedule 1: A drops; B is released first, C follows after a
            // short bias (unlock->reacquire-on-old-inode with B first).
            1 => {
                drop(guard_a);
                go_b.wait();
                std::thread::sleep(std::time::Duration::from_millis(2));
                go_c.wait();
            }
            // Schedule 2: the mirror of schedule 1 (C first).
            2 => {
                drop(guard_a);
                go_c.wait();
                std::thread::sleep(std::time::Duration::from_millis(2));
                go_b.wait();
            }
            _ => unreachable!("three-contender schedule tags are 0..=2"),
        }

        let b_res = b_handle
            .join()
            .map_err(|_| proptest::test_runner::TestCaseError::fail("B thread panicked"))?;
        let c_res = c_handle
            .join()
            .map_err(|_| proptest::test_runner::TestCaseError::fail("C thread panicked"))?;
        let b_won = b_res.is_ok();
        let c_won = c_res.is_ok();

        // THE INVARIANT: flock is exclusive per inode, and BOTH contenders
        // flocked the SAME persistent inode — at most one can hold it. Since
        // A released before they raced and the flock is exclusive, exactly
        // one wins (XOR); the loser must have been refused with EAGAIN.
        prop_assert!(
            b_won != c_won,
            "two contenders must never BOTH hold the flock (inode split), and one must win after the release (b_won={b_won}, c_won={c_won})"
        );
        for (name, res) in [("B", &b_res), ("C", &c_res)] {
            if let Err(e) = res {
                prop_assert!(
                    matches!(
                        e.raw_os_error(),
                        Some(c) if c == libc::EWOULDBLOCK || c == libc::EAGAIN
                    ),
                    "the losing contender {name} must fail with EAGAIN, got: {e:?}"
                );
            }
        }
        // Keep the winner's fd alive (holding the flock) while probing below.
        let _b_hold = b_res.ok();
        let _c_hold = c_res.ok();

        // The re-create-new-inode shape is structurally impossible: a fresh
        // open of the path still yields the ORIGINAL inode, so a third
        // process can never spin up a second inode to split the lock.
        prop_assert_eq!(
            inode_a,
            inode_id(&path),
            "the lock file must keep its single stable inode across the whole race (no unlink, no recreate)"
        );
        prop_assert!(path.exists(), "the lock file persists after the race");

        // While the winner holds the flock, a fresh acquisition on the SAME
        // inode is refused (flock exclusion), and after the winner's fd
        // closes the lock returns to the free state on the SAME inode.
        {
            let probe = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(|e| proptest::test_runner::TestCaseError::fail(e.to_string()))?;
            let ret = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            prop_assert!(
                ret != 0,
                "a fresh acquisition while a contender holds must be refused (flock is exclusive on the single inode)"
            );
        }
        drop(_b_hold);
        drop(_c_hold);
        // The flock may be TRANSIENTLY held by a forked child of a parallel
        // test: a child spawned (fork+exec) while the winner's fd was open
        // inherits the fd during its fork→exec window, and the flock
        // persists until the child's exec closes it (O_CLOEXEC). The
        // discipline under test — the lock returns to the free state on the
        // SAME inode once the winner's fd closes — is unaffected; only the
        // instant at which it is observable is. Wait (bounded) for the free
        // state instead of asserting it is immediate.
        let last = (0..50)
            .find_map(|_| match FileLock::acquire(&path, "op-last") {
                Ok(lock) => Some(lock),
                Err(_) => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    None
                }
            })
            .ok_or_else(|| {
                proptest::test_runner::TestCaseError::fail(
                    "the lock must return to the free state after the winner's fd closes",
                )
            })?;
        prop_assert_eq!(
            inode_a,
            inode_id(&path),
            "the stable inode survives the full acquire/release cycle"
        );
        drop(last);

        Ok(())
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: crate::test_support::proptest_cases(64),
            max_shrink_iters: 10000,
            rng_seed: proptest::test_runner::RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..proptest::test_runner::Config::default()
        })]
        /// The three-contender no-split property: for every schedule of the
        /// old delete-window shapes around a real release, at no observable
        /// point do two contenders both hold the flock, and the stable inode
        /// is never recreated.
        #[test]
        fn no_two_contenders_hold_the_flock(schedule in 0u8..3u8) {
            run_three_contender_case(schedule)?;
        }
    }
}
