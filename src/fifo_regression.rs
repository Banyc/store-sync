//! Regression: a FIFO in a store must not hang the read-side primitives.
//!
//! `path_state_fd`, `read_fd`/`read_json_fd`, `write_atomic_cas_fd`, and
//! `write_atomic_if_match_fd` all used to open the final entry `O_RDONLY`
//! without `O_NONBLOCK`. `open(2)` of a FIFO read-only BLOCKS until a writer
//! appears, so ONE FIFO in a store — from another tool, or an attacker — hung
//! a consumer's verify/recovery and a sync's `AppendTail` compare FOREVER: an
//! unbounded hang on user data. The primitives now open with `O_NONBLOCK` (a
//! no-op for a regular file) and classify the OPENED inode, refusing a
//! FIFO/socket/device with a clear error.
//!
//! The pre-fix failure is a HANG, so an in-process assertion cannot observe it
//! (the test process would block). These tests therefore RE-EXEC this test
//! binary as a child (behind [`MODE_ENV`]) that performs the four probes, and
//! the parent enforces a HARD WALL-CLOCK TIMEOUT: a child that does not finish
//! is KILLED and reported, so the suite itself can never hang.
#![cfg(unix)]

use std::ffi::CString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::atomic::RootDir;
use crate::env::SysEnv;

/// The child re-exec reads its work mode from this.
const MODE_ENV: &str = "STOREKIT_FIFO_MODE";
/// The child creates its FIFO under this directory (set by the parent).
const ROOT_ENV: &str = "STOREKIT_FIFO_ROOT";
/// The exact libtest name of [`fifo_child`] (for the child's `--exact`).
const CHILD_TEST: &str = "fifo_regression::fifo_child";
/// The child's work mode.
const CHILD_MODE: &str = "probe";
/// Printed by the child only after ALL FOUR probes returned; the parent
/// requires it so a child that ran no test can never pass this suite.
const DONE_MARKER: &str = "STOREKIT_FIFO_CHILD_DONE";
/// The per-probe wall-clock bound the CHILD asserts. Well above any scheduling
/// jitter, far below a hang.
const PROBE_LIMIT: Duration = Duration::from_secs(5);
/// The parent's HARD wall-clock cap on the whole child: the child's four probes
/// at [`PROBE_LIMIT`] plus process startup fit comfortably; a pre-fix child
/// (which blocks on the first probe) is killed here and the test fails.
const CHILD_LIMIT: Duration = Duration::from_secs(20);

/// A FIFO in a store is refused promptly by every read-side primitive, never
/// opened blocking.
#[test]
fn fifo_entries_do_not_hang_the_read_side_primitives() {
    let tmp = crate::test_support::fixture_tmpdir(&SysEnv::from_process())
        .expect("tempdir for the FIFO probe");
    let root = tmp.path().to_path_buf();
    match run_child(&root, CHILD_LIMIT) {
        ChildOutcome::TimedOut(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            panic!(
                "the FIFO child did not finish within {CHILD_LIMIT:?} and was killed: a \
                 read-side primitive opened the FIFO blocking (the pre-fix hang). A hang is an \
                 unbounded failure on user data and is never acceptable.\n\
                 --- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}"
            );
        }
        ChildOutcome::Exited(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                out.status.success(),
                "the FIFO child failed: status={:?}\n--- child stdout ---\n{stdout}\n\
                 --- child stderr ---\n{stderr}",
                out.status
            );
            assert!(
                stdout.contains(DONE_MARKER),
                "the child exited 0 but never reached the end of the four probes, so it ran no \
                 test and this assertion would pass vacuously:\n--- child stdout ---\n{stdout}\n\
                 --- child stderr ---\n{stderr}"
            );
            let probes = stdout
                .lines()
                .filter(|line| line.contains("FIFO_PROBE"))
                .count();
            assert_eq!(
                probes, 4,
                "all four read-side primitives must have been probed:\n{stdout}"
            );
            // Say WHICH platform ran the probe (A2's report requirement).
            println!(
                "FIFO regression probes ran on platform={} (4 primitives refused a FIFO promptly)",
                std::env::consts::OS
            );
        }
    }
}

/// The child worker: no-op unless the parent set [`MODE_ENV`], so an ordinary
/// `cargo test` only lists it as ignored. The parent re-execs the binary with
/// `--ignored --exact` and the env switch.
#[test]
#[ignore = "spawned by the FIFO regression test via MODE_ENV"]
fn fifo_child() {
    let Ok(mode) = std::env::var(MODE_ENV) else {
        return;
    };
    assert_eq!(mode, CHILD_MODE, "unexpected FIFO child mode {mode:?}");
    let root = PathBuf::from(std::env::var_os(ROOT_ENV).expect("ROOT_ENV is set by the parent"));
    std::fs::create_dir_all(&root).expect("create the FIFO root");
    let fifo = root.join("fifo");
    let c = CString::new(fifo.as_os_str().as_bytes()).expect("no NUL in the FIFO path");
    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
        panic!(
            "mkfifo {}: {}",
            fifo.display(),
            std::io::Error::last_os_error()
        );
    }
    let owned = RootDir::open(&root).expect("open the owned root");
    let rel = &crate::relpath::RootedRelativePath::parse(Path::new("fifo")).unwrap();

    // The four probes, in the order the review measured them.
    probe("state", || crate::atomic::path_state_fd(&owned, rel));
    probe("read", || crate::atomic::read_fd(&owned, rel));
    probe("cas", || {
        crate::atomic::write_atomic_cas_fd(&owned, rel, b"x")
    });
    probe("ifmatch", || {
        crate::atomic::write_atomic_if_match_fd(&owned, rel, b"x", b"y", &mut |_| None)
    });

    println!("{DONE_MARKER} platform={}", std::env::consts::OS);
}

/// Run one probe, require it to return PROMPTLY and to REFUSE the FIFO, and
/// print its result (flushed, so a later hang is visible to the parent).
fn probe<T: std::fmt::Debug>(label: &str, f: impl FnOnce() -> crate::Result<T>) {
    let start = Instant::now();
    let outcome = f();
    let elapsed = start.elapsed();
    assert!(
        elapsed < PROBE_LIMIT,
        "the {label} probe took {elapsed:?}, over the {PROBE_LIMIT:?} bound: the FIFO open was \
         not non-blocking"
    );
    match outcome {
        Err(e) => println!("FIFO_PROBE {label} elapsed={elapsed:?} refused={e}"),
        Ok(value) => panic!(
            "the {label} probe must REFUSE the FIFO, not open and report it, got Ok({value:?})"
        ),
    }
    std::io::stdout()
        .flush()
        .expect("flush the probe result to the parent");
}

/// The parent's verdict on a child run.
enum ChildOutcome {
    Exited(std::process::Output),
    TimedOut(std::process::Output),
}

/// Spawn the parent's own test binary as a child and wait for it with a HARD
/// wall-clock cap: past the cap the child is killed and its (partial) output
/// returned, so a pre-fix hang fails the test instead of hanging the suite.
fn run_child(root: &Path, limit: Duration) -> ChildOutcome {
    let exe = std::env::current_exe().expect("the running test binary path");
    let mut child = std::process::Command::new(exe)
        .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
        .env(MODE_ENV, CHILD_MODE)
        .env(ROOT_ENV, root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the FIFO child test binary");
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return ChildOutcome::Exited(child.wait_with_output().expect("output")),
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                return ChildOutcome::TimedOut(child.wait_with_output().expect("output"));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("waiting on the FIFO child: {e}"),
        }
    }
}
