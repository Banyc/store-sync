//! A PUSH into a LOCAL destination must be atomic and durable, exactly like a
//! PULL. Before the fix the push direction wrote through `Remote::write`
//! (`LocalTransport::write_confined`), which opened the destination
//! `O_WRONLY|O_CREAT|O_TRUNC` and did ONE `write` with no temp, no rename and
//! no fsync anywhere under the destination. A write that failed part-way — the
//! reviewer's ENOSPC on a small tmpfs — therefore DESTROYED the previous
//! content and left the entry TORN: truncated to zero, then partially
//! rewritten. The identical operation expressed as a PULL (which already used
//! the crate's durable fd-confined primitives) left the old file intact.
//!
//! This suite reproduces the failure deterministically without a tmpfs, using
//! `RLIMIT_FSIZE` (an ENOSPC-like, mid-write `EFBIG` on the 8 MiB source with
//! the per-file limit set to 4 MiB). The reproducing body must run in its OWN
//! process because `RLIMIT_FSIZE` and the ignored `SIGXFSZ` are process-wide:
//! the test binary re-executes itself with an exact filter and a marker
//! variable, and the child reports through its exit status.

#![cfg(unix)]

use store_sync::env::SysEnv;
use store_sync::sync::{ReplaceAll, push};
use store_sync::transport::{Layout, LocalTransport};

/// The marker variable the child process sets; the parent test returns early
/// when it is set, and the child body returns early when it is not.
const CHILD_ENV: &str = "STORE_SYNC_PUSH_ATOMICITY_CHILD";
/// The exact libtest name of the child body.
const CHILD_TEST: &str = "push_mid_write_failure_leaves_previous_content_intact_child";

/// The per-file size cap the child installs (bytes): large enough for the
/// 2 MiB destination file and every metadata write, too small for the 8 MiB
/// source. The failed write therefore stops mid-stream, exactly like ENOSPC.
const FILE_SIZE_LIMIT: u64 = 4 * 1024 * 1024;

/// The parent: re-execute this test binary so the size limit is confined to a
/// child process.
#[test]
fn push_mid_write_failure_leaves_previous_content_intact() {
    if std::env::var_os(CHILD_ENV).is_some() {
        // The child selected this test too (no exact filter); its own body is
        // the one under test.
        return;
    }
    let exe = std::env::current_exe().expect("the test binary path");
    let out = std::process::Command::new(exe)
        .args(["--exact", CHILD_TEST, "--nocapture"])
        .env(CHILD_ENV, "1")
        .output()
        .expect("spawn the size-limited child");
    assert!(
        out.status.success(),
        "the size-limited child FAILED — a push whose write fails mid-stream \
         did not leave the previous content intact.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// The reproducing body, run only in the re-executed child.
#[test]
fn push_mid_write_failure_leaves_previous_content_intact_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }

    let tmp = tempfile::Builder::new()
        .prefix("storesync-push-atomic-")
        .tempdir()
        .expect("create the tempdir");
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir_all(&src).expect("create the source root");
    std::fs::create_dir_all(&dst).expect("create the destination root");

    // The PREVIOUS snapshot (2 MiB) and the NEW content (8 MiB), both written
    // BEFORE the cap is installed.
    let previous = vec![b'A'; 2 * 1024 * 1024];
    let incoming = vec![b'B'; 8 * 1024 * 1024];
    std::fs::write(src.join("f"), &incoming).expect("write the 8 MiB source");
    std::fs::write(dst.join("f"), &previous).expect("write the 2 MiB destination");

    // Ignore SIGXFSZ so an over-limit write returns EFBIG (an error the
    // transport propagates) instead of killing the child, then cap any single
    // file at 4 MiB so the 8 MiB source cannot be written in full.
    unsafe {
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
    }
    let limit = libc::rlimit {
        rlim_cur: FILE_SIZE_LIMIT,
        rlim_max: FILE_SIZE_LIMIT,
    };
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limit) },
        0,
        "install RLIMIT_FSIZE"
    );

    let transport =
        LocalTransport::new(&SysEnv::from_process(), dst.clone(), Layout::empty()).expect("build");
    let result = push(&src, &transport, &ReplaceAll);
    assert!(
        result.is_err(),
        "the push MUST fail when the destination write cannot complete: {result:?}"
    );

    // THE CONTRACT: the previous content is intact, neither truncated nor
    // partially overwritten.
    let after = std::fs::read(dst.join("f")).expect("read the destination after the failed push");
    assert_eq!(
        after.len(),
        previous.len(),
        "a failed push DESTROYED the previous snapshot: the destination is {} bytes, expected {}",
        after.len(),
        previous.len(),
    );
    assert_eq!(
        after, previous,
        "a failed push left the destination TORN: the old content was replaced by a partial write"
    );

    // THE FIX leaves no stray temp behind (the pre-fix code had no temp; the
    // post-fix atomic replace unlinks a failed temp).
    let mut temps: Vec<String> = std::fs::read_dir(&dst)
        .expect("list the destination")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.contains(".tmp."))
        .collect();
    temps.sort();
    assert!(
        temps.is_empty(),
        "a failed atomic replace must leave no temp behind, found {temps:?}"
    );
}
