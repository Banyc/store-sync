//! The small test helpers the ported suites share.
//!
//! The source crate's test utilities carry a whole application fixture
//! vocabulary; only the four environment/tmpdir/proptest helpers are generic,
//! and they are reproduced here. Add to this file rather than introducing a
//! second test-support surface.
//!
//! The module is test-only and shared by suites that land in separate waves,
//! so a helper no current suite calls is not a defect: the dead-code lint is
//! allowed here rather than letting one suite's unused helper fail another's
//! `-D warnings` gate.
#![allow(dead_code)]

use crate::env::SysEnv;

/// The environment snapshot the tests run against.
pub(crate) fn fixture_env() -> SysEnv {
    SysEnv::from_process()
}

/// A temporary directory under the snapshot's temp dir.
pub(crate) fn fixture_tmpdir(env: &SysEnv) -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new().tempdir_in(env.temp_dir())
}

/// Install `body` as an executable at `path` by writing it from a SHORT-LIVED
/// HELPER PROCESS, never from the test process itself.
///
/// libtest runs a binary's tests on many threads of ONE process, and every
/// `std::process::Command` spawn forks a child that COPIES the caller's
/// descriptor table. A direct `std::fs::write` opens `path` for writing, so a
/// sibling test's concurrent fork inherits that write fd; a FAILED `execve`
/// does not close `O_CLOEXEC` descriptors (a `PATH` search issues several), so
/// the inherited fd can outlive this test's own write, and a later `execve` of
/// `path` fails with `ETXTBSY` ("Text file busy") because the inode's
/// `i_writecount` is still positive.
///
/// Writing from a helper keeps the executable's write fd out of the test
/// process's descriptor table entirely, so no sibling fork can inherit it; the
/// helper stages the bytes under a private name and renames them into place so
/// `path` is never observed half-written.
pub(crate) fn write_executable(path: &std::path::Path, body: &[u8]) {
    use std::io::Write;
    std::fs::create_dir_all(path.parent().expect("executable path has a parent"))
        .expect("create the executable's directory");
    let mut child = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("cat > \"$1.tmp.$$\" && chmod 755 \"$1.tmp.$$\" && mv -f \"$1.tmp.$$\" \"$1\"")
        .arg("sh")
        .arg(path)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("spawn the executable-writing helper");
    child
        .stdin
        .take()
        .expect("the helper's piped stdin")
        .write_all(body)
        .expect("write the executable body to the helper");
    let status = child
        .wait()
        .expect("wait for the executable-writing helper");
    assert!(status.success(), "installing {path:?} failed: {status:?}");
}

/// Announce a SKIPPED test on the REAL console of a PLAIN `cargo test` run.
///
/// libtest CAPTURES `print!`/`eprintln!` per test and DISCARDS the captured
/// output of a PASSING test, so a skip message written with those macros is
/// invisible in the default gate: a skipped assertion is then
/// indistinguishable from a passing one. This writes a single
/// machine-greppable line DIRECTLY to file descriptor 1 (bypassing libtest's
/// capture) and names the test with the harness thread's name.
#[cfg(unix)]
pub(crate) fn announce_skip(reason: &str) {
    let test = std::thread::current()
        .name()
        .unwrap_or("<unknown test>")
        .to_string();
    let line = format!("STORE_SYNC_SKIP test={test} reason={reason}\n");
    unsafe {
        libc::write(1, line.as_ptr().cast::<libc::c_void>(), line.len());
    }
}

/// Non-Unix fallback: no raw-fd bypass is needed where the reproductions that
/// use it are `#[cfg(unix)]`.
#[cfg(not(unix))]
pub(crate) fn announce_skip(reason: &str) {
    let test = std::thread::current()
        .name()
        .unwrap_or("<unknown test>")
        .to_string();
    println!("STORE_SYNC_SKIP test={test} reason={reason}");
}

/// A property-test case count, reduced unless the full suites are requested.
pub(crate) fn proptest_cases(full: u32) -> u32 {
    if full_suites() {
        full
    } else {
        (full / 4).max(2)
    }
}

/// Whether the slow (real-process, exhaustive-property) suites run.
pub(crate) fn slow_tests_enabled() -> bool {
    full_suites()
}

fn full_suites() -> bool {
    matches!(
        std::env::var("STORE_SYNC_FULL_TESTS").as_deref(),
        Ok("1") | Ok("true")
    )
}
