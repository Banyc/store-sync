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
