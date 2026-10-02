//! Regression: a directory tree deeper than the C stack must never abort the
//! host process.
//!
//! The tree walks used to recurse one Rust frame per directory level
//! (`atomic::unix::remove_dir_contents_fd`, the default `Remote::copy_tree`
//! walk, and the path-based `remove_dir_all` the UNIX transport delegates
//! to). A tree deeper than the caller's stack exhausted it, and Rust's
//! stack-overflow handler ABORTS the whole process (SIGABRT) — a library
//! call killing its host is never acceptable. The walks are now explicit
//! heap `Vec` stacks; the only remaining bound is the descriptor limit,
//! which surfaces as a clean `Err`, never an abort. (The Windows transport
//! delegates removal to `std::fs::remove_dir_all`, which is itself iterative
//! on the installed toolchain — see `atomic::unix::remove_dir_all_path`.)
//!
//! The pre-fix failure is a PROCESS abort, so an in-process assertion cannot
//! observe it (the test process would die with the child). These tests
//! therefore RE-EXEC this test binary as a child (behind [`MODE_ENV`]) that
//! builds a deep tree with RELATIVE descriptors (`mkdirat`/`openat`, so
//! `PATH_MAX` never limits the construction), runs the walk on a
//! deliberately SMALL thread stack, and exits; the parent asserts the child
//! exited successfully and cleans the tree up before asserting.
#![cfg(unix)]

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::env::SysEnv;
use crate::transport::{Layout, LocalTransport, Remote, RootedRelativePath};

/// The child re-exec reads its work mode (`remove` / `copy`) from this.
const MODE_ENV: &str = "STORE_SYNC_DEEP_TREE_MODE";
/// The child builds its tree under this directory.
const ROOT_ENV: &str = "STORE_SYNC_DEEP_TREE_ROOT";
/// The child nests this many directory levels.
const DEPTH_ENV: &str = "STORE_SYNC_DEEP_TREE_DEPTH";
/// The exact libtest name of [`deep_tree_child`] (for the child's `--exact`).
const CHILD_TEST: &str = "deep_tree_regression::deep_tree_child";
/// Printed by the child only once its small-stack walk COMPLETES; the parent
/// requires it so a child that ran no test can never pass this suite.
const DONE_MARKER: &str = "STORE_SYNC_DEEP_TREE_CHILD_DONE";
/// The child's descriptor-exhaustion mode: lower `RLIMIT_NOFILE` before the
/// removal walk so its one-descriptor-per-level frontier hits `EMFILE`.
const EMFILE_MODE: &str = "remove_emfile";
/// The soft `RLIMIT_NOFILE` the child lowers to. The observed threshold is
/// `limit - 8`, so this is reached long before `DEPTH` levels.
const EMFILE_NOFILE: u64 = 64;
/// Printed by the child once the descriptor-exhaustion case has run and its
/// in-child assertions held; the parent requires it (non-vacuity).
const EMFILE_MARKER: &str = "STORE_SYNC_DEEP_TREE_EMFILE";

/// Directory levels the child nests. Calibrated against the PRE-fix
/// one-frame-per-level walk: at [`CHILD_STACK`] it overflows between depth 96
/// and 128, so 256 leaves a >2x margin while every intermediate spelling
/// stays far below `PATH_MAX`.
const DEPTH: usize = 256;
/// The stack the child runs the walk on. 16 KiB is the smallest thread stack
/// macOS allows; it is far below the 2 MiB libtest uses, so per-level stack
/// growth is the only thing under test.
const CHILD_STACK: usize = 16 * 1024;
/// The tree root under the transport base; also the walk's `src`.
const TOP: &str = "deep";
/// The `copy_tree` destination, a sibling of [`TOP`].
const COPY: &str = "copy";

/// A deep tree is removed without overflowing the stack (subprocess).
#[test]
fn deep_tree_removal_does_not_abort_the_process() {
    assert_child_succeeds("remove");
}

/// A deep tree is copied by the default `Remote::copy_tree` without
/// overflowing the stack (subprocess).
#[test]
fn deep_tree_copy_does_not_abort_the_process() {
    assert_child_succeeds("copy");
}

/// A deep removal with `RLIMIT_NOFILE` lowered surfaces a CLEAN
/// descriptor-exhaustion `Err` (never an abort, never a panic, never a
/// silent partial success), leaks no descriptor, and leaves the tree in a
/// defined, retryable state. The pre-rewrite recursive form held the same
/// one-descriptor-per-level frontier and failed the same way, so this is a
/// COVERAGE-ONLY pin of the documented "bounded by the descriptor limit, a
/// clean `Err`" contract rather than a regression the rewrite fixed.
#[test]
fn deep_tree_removal_surfaces_a_clean_descriptor_exhaustion() {
    assert_emfile_child();
}

/// The child worker. It does nothing unless the parent set [`MODE_ENV`], so
/// the ordinary `cargo test` run only lists it as ignored; the parent
/// re-execs the binary with `--ignored --exact` and the env switch.
#[test]
#[ignore = "spawned by the deep-tree regression tests via MODE_ENV"]
fn deep_tree_child() {
    let Ok(mode) = std::env::var(MODE_ENV) else {
        return;
    };
    let root = PathBuf::from(std::env::var_os(ROOT_ENV).expect("ROOT_ENV is set by the parent"));
    let depth: usize = std::env::var(DEPTH_ENV)
        .expect("DEPTH_ENV is set by the parent")
        .parse()
        .expect("DEPTH_ENV is a number");
    if mode == EMFILE_MODE {
        run_emfile_case(&root, depth);
        println!("{DONE_MARKER} mode={mode} depth={depth}");
        return;
    }
    std::thread::Builder::new()
        .stack_size(CHILD_STACK)
        .spawn(move || {
            build_deep_tree(&root, depth).unwrap_or_else(|e| panic!("build: {e}"));
            run_walk(&root, &mode).unwrap_or_else(|e| panic!("walk: {e}"));
            // Printed only after the walk COMPLETES on the small stack, so
            // the parent can tell "the walk ran to the end" from "the child
            // filter matched no test and exited 0" (which would make this
            // regression test pass vacuously).
            println!("{DONE_MARKER} mode={mode} depth={depth}");
        })
        .expect("spawn the small-stack worker thread")
        .join()
        .expect("the small-stack worker thread must finish without panicking");
}

/// Run the requested transport walk as the child's payload.
fn run_walk(root: &Path, mode: &str) -> Result<(), String> {
    let env = SysEnv::from_process();
    let transport = LocalTransport::new(&env, root.to_path_buf(), Layout::empty())
        .map_err(|e| format!("local transport: {e}"))?;
    let src = RootedRelativePath::parse(Path::new(TOP)).map_err(|e| format!("src: {e}"))?;
    match mode {
        "remove" => transport
            .remove_dir_all(&src)
            .map_err(|e| format!("remove_dir_all: {e}")),
        "copy" => {
            let dest =
                RootedRelativePath::parse(Path::new(COPY)).map_err(|e| format!("dest: {e}"))?;
            transport
                .copy_tree(&src, &dest)
                .map_err(|e| format!("copy_tree: {e}"))
        }
        other => Err(format!("unknown mode {other:?}")),
    }
}

/// Build `<base>/<TOP>/d/d/.../d/leaf` with `OPENAT`/`MKDIRAT` relative to the
/// descriptor of the level above, so no long path is ever materialized and
/// `PATH_MAX` does not bound the construction. The `leaf` file gives the copy
/// walk bytes to carry out of the deepest level.
fn build_deep_tree(base: &Path, depth: usize) -> Result<(), String> {
    let mut cur = open_dir_at(libc::AT_FDCWD, base.as_os_str().as_bytes(), base)?;
    mkdir_at(&cur, TOP.as_bytes())?;
    cur = open_dir_at(cur.as_raw_fd(), TOP.as_bytes(), Path::new(TOP))?;
    for _ in 0..depth {
        mkdir_at(&cur, b"d")?;
        cur = open_dir_at(cur.as_raw_fd(), b"d", Path::new("d"))?;
    }
    let leaf = openat_create(&cur, b"leaf")?;
    let mut leaf = std::fs::File::from(leaf);
    std::io::Write::write_all(&mut leaf, b"deep\n").map_err(|e| format!("write leaf: {e}"))
}

/// `openat(dirfd, name, O_DIRECTORY | O_NOFOLLOW)` as an owned descriptor.
fn open_dir_at(dirfd: i32, name: &[u8], shown: &Path) -> Result<OwnedFd, String> {
    let c = cstr(name)?;
    let fd = unsafe {
        libc::openat(
            dirfd,
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "openat dir {}: {}",
            shown.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `mkdirat(dir, name, 0o755)`.
fn mkdir_at(dir: &OwnedFd, name: &[u8]) -> Result<(), String> {
    let c = cstr(name)?;
    if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o755) } < 0 {
        return Err(format!(
            "mkdirat {:?}: {}",
            String::from_utf8_lossy(name),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// `openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW)`.
fn openat_create(dir: &OwnedFd, name: &[u8]) -> Result<OwnedFd, String> {
    let c = cstr(name)?;
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd < 0 {
        return Err(format!(
            "openat create {:?}: {}",
            String::from_utf8_lossy(name),
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn cstr(name: &[u8]) -> Result<CString, String> {
    CString::new(name).map_err(|_| "name contains NUL".to_string())
}

/// Spawn the parent's own test binary as a child, wait for it, clean the deep
/// tree up, and only THEN assert the child succeeded.
fn assert_child_succeeds(mode: &str) {
    let env = SysEnv::from_process();
    let tmp = crate::test_support::fixture_tmpdir(&env).expect("tempdir for the deep tree");
    let root = tmp.path().to_path_buf();
    let exe = std::env::current_exe().expect("the running test binary path");
    let done_marker = format!("{DONE_MARKER} mode={mode} depth={DEPTH}");
    let out = std::process::Command::new(exe)
        .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
        .env(MODE_ENV, mode)
        .env(ROOT_ENV, &root)
        .env(DEPTH_ENV, DEPTH.to_string())
        .output()
        .expect("spawn the child test binary");

    // Clean up BEFORE asserting, even when the child aborted: a pre-fix abort
    // leaves a partially removed deep tree behind, and the host must not keep
    // it. `DEPTH` is far below the parent thread's stack budget.
    let _ = std::fs::remove_dir_all(root.join(TOP));
    let _ = std::fs::remove_dir_all(root.join(COPY));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the {mode} child did not exit successfully on a {DEPTH}-level tree: \
         status={:?}\n--- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}",
        out.status,
    );
    assert!(
        stdout.contains(&done_marker),
        "the {mode} child exited 0 but never reached the end of the walk, so it ran no \
         test and this regression assertion would pass vacuously:\n\
         --- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}"
    );
}

/// Run the descriptor-exhaustion case in the child: build the deep tree, lower
/// `RLIMIT_NOFILE`, remove it, and assert the contract. Panics (so the child
/// exits nonzero) on any violation; the parent then sees a failed child.
fn run_emfile_case(root: &Path, depth: usize) {
    build_deep_tree(root, depth).unwrap_or_else(|e| panic!("build: {e}"));
    let env = SysEnv::from_process();
    let transport = LocalTransport::new(&env, root.to_path_buf(), Layout::empty())
        .unwrap_or_else(|e| panic!("local transport: {e}"));
    let src = RootedRelativePath::parse(Path::new(TOP)).expect("src path");
    let before = open_fd_count().unwrap_or_else(|e| panic!("fd count before: {e}"));
    let saved = set_nofile_soft(EMFILE_NOFILE).unwrap_or_else(|e| panic!("lower nofile: {e}"));
    let first = transport.remove_dir_all(&src);
    let after = open_fd_count().unwrap_or_else(|e| panic!("fd count after: {e}"));
    restore_nofile(saved).unwrap_or_else(|e| panic!("restore nofile: {e}"));

    let err = first.expect_err("the walk must surface a clean Err, never a silent success");
    let msg = format!("{err}");
    assert!(
        msg.contains("Too many open files") || msg.contains("EMFILE"),
        "the error must name the descriptor exhaustion, got: {msg}"
    );
    assert_eq!(
        before, after,
        "the failed walk must not leak a descriptor (before={before}, after={after})"
    );
    assert!(
        root.join(TOP).exists(),
        "post-order removal deletes a directory only after its contents, so the \
         partially removed tree root must still exist"
    );
    transport
        .remove_dir_all(&src)
        .expect("a retry with the limit restored must finish the removal");
    assert!(
        !root.join(TOP).exists(),
        "the retry must remove the tree root, proving the partial state was defined"
    );
    println!("{EMFILE_MARKER} fds_before={before} fds_after={after} err={msg}");
}

/// Count this process's open descriptors via `/proc/self/fd` (Linux) or
/// `/dev/fd` (macOS). Both include the directory handle this read opens, so
/// the two calls are comparable.
fn open_fd_count() -> Result<usize, String> {
    for dir in ["/proc/self/fd", "/dev/fd"] {
        if let Ok(rd) = std::fs::read_dir(dir) {
            return Ok(rd.count());
        }
    }
    Err("no descriptor directory (/proc/self/fd or /dev/fd)".to_string())
}

/// Save the current `RLIMIT_NOFILE` and lower its SOFT limit. The hard limit
/// is left untouched so [`restore_nofile`] can put the soft limit back.
fn set_nofile_soft(soft: u64) -> Result<libc::rlimit, String> {
    let mut cur: libc::rlimit = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut cur) } != 0 {
        return Err(format!("getrlimit: {}", std::io::Error::last_os_error()));
    }
    let mut lowered = cur;
    lowered.rlim_cur = soft.min(cur.rlim_max);
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) } != 0 {
        return Err(format!("setrlimit: {}", std::io::Error::last_os_error()));
    }
    Ok(cur)
}

/// Restore the soft `RLIMIT_NOFILE` saved by [`set_nofile_soft`].
fn restore_nofile(saved: libc::rlimit) -> Result<(), String> {
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &saved) } != 0 {
        return Err(format!(
            "restore setrlimit: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Spawn the child in [`EMFILE_MODE`], clean up, and require that it exited
/// successfully AND printed [`EMFILE_MARKER`] (so a child that ran no test
/// cannot pass vacuously).
fn assert_emfile_child() {
    let env = SysEnv::from_process();
    let tmp = crate::test_support::fixture_tmpdir(&env).expect("tempdir for the emfile tree");
    let root = tmp.path().to_path_buf();
    let exe = std::env::current_exe().expect("the running test binary path");
    let out = std::process::Command::new(exe)
        .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
        .env(MODE_ENV, EMFILE_MODE)
        .env(ROOT_ENV, &root)
        .env(DEPTH_ENV, DEPTH.to_string())
        .output()
        .expect("spawn the emfile child test binary");

    let _ = std::fs::remove_dir_all(root.join(TOP));
    let _ = std::fs::remove_dir_all(root.join(COPY));

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the descriptor-exhaustion child did not exit successfully: status={:?}\n\
         --- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}",
        out.status,
    );
    assert!(
        stdout.contains(EMFILE_MARKER),
        "the child exited 0 but never reached the descriptor-exhaustion case, so this \
         assertion would pass vacuously:\n\
         --- child stdout ---\n{stdout}\n--- child stderr ---\n{stderr}"
    );
}
