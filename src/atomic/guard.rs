//! THE crate's one lock-record mutation guard, and the unforgeable
//! capability that any name-mutating operation must present.
//!
//! The single-holder guarantee of [`crate::lock::FileLock`] rests on the
//! lock record's INODE never changing under its path: a later acquisition
//! must flock the SAME inode the live holder holds. Any operation that
//! unlinks, replaces, renames, or truncates the record breaks that, so the
//! crate must have no reachable path to such a mutation.
//!
//! Four earlier passes each enumerated the call sites they could find and
//! missed one (a second symlink implementation, the raw rename primitive
//! under the guarded rename, a raw truncating open, and the Windows
//! transport's direct `std::fs` seams). Enumeration is the wrong shape.
//! This module makes the guard STRUCTURAL instead:
//!
//! * [`refuse_lock_record`] is the ONE spelling authority. Every
//!   name-mutating primitive in [`crate::atomic`] consults it.
//! * [`GuardedRel`] is an unforgeable proof that the guard ran. Its field is
//!   private to THIS module, so no other module — not [`super`] itself, not
//!   [`super::unix`] / [`super::windows`], not `transport` / `sync` — can
//!   build one except through [`GuardedRel::new`], which runs the guard.
//!   The rel-path mutators take one by value, so a NEW primitive cannot
//!   name a multi-component mutation without first proving it guarded.
//!
//! # What this does NOT cover (the honest residual)
//!
//! A developer who writes a brand-new direct `libc::unlinkat` /
//! `libc::renameat` / `libc::symlinkat` / `libc::openat` call into a module
//! that is not [`super::unix`] is not stopped by the type system: `libc` is
//! an ordinary dependency and Rust cannot forbid a call to it. That is why
//! the crate ALSO carries a source audit
//! (`atomic::tests::no_raw_name_mutating_syscall_outside_the_funnel`) that
//! fails the build when such a call appears anywhere outside the single
//! funnel module. Together the private funnel and the audit mean the
//! "obvious way" to add a mutation — calling the crate's own wrapper, or
//! reaching for a raw syscall — either presents the capability or fails a
//! test.

use crate::error::{Error, Result};
use std::path::{Component, Path};

/// Refuse `rel` when any component names one of the crate's LOCK-RECORD
/// spellings ([`crate::reserved::is_lock_record_name`]) — the application
/// lock record `operation.lock` or the sibling record
/// `.<name>.operation.lock`, byte-exact or case-alias form. The check
/// consults EVERY component, so a path that NAMES or descends THROUGH a
/// record is refused, not only a path whose final component is the record.
///
/// PRIVATE to this module by design: the only in-crate way to run it is
/// [`GuardedRel::new`], so a caller cannot consult the guard without minting
/// the capability the mutators demand.
fn refuse_lock_record(rel: &Path) -> Result<()> {
    for component in rel.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        if !name
            .to_str()
            .is_some_and(crate::reserved::is_lock_record_name)
        {
            continue;
        }
        return Err(Error::conflict(format!(
            "refusing to mutate the crate's lock record in {}: the record's stable inode is what \
             makes two simultaneous holders impossible, so removing, replacing, or renaming it \
             would admit a second holder",
            rel.display()
        )));
    }
    Ok(())
}

/// An unforgeable proof that [`refuse_lock_record`] ran on a root-relative
/// path. The wrapped field is PRIVATE to this module, so the only way to
/// obtain a value is [`GuardedRel::new`] (which runs the guard) — no other
/// module, including a future mutation primitive, can construct one
/// directly, and the rel-path mutators accept nothing else.
#[derive(Clone, Copy)]
pub(crate) struct GuardedRel<'a> {
    rel: &'a Path,
}

impl<'a> GuardedRel<'a> {
    /// THE ONLY constructor: run the guard on `rel`, then mint the proof.
    /// There is deliberately no unchecked constructor and no `Default`.
    ///
    /// COMPILE-LEVEL ARGUMENT: the wrapped field is private to this module,
    /// so a struct-literal construction (`GuardedRel { rel }`) anywhere else
    /// — including in [`super::unix`] / [`super::windows`] — is `E0451`
    /// ("field is private"), and no `unsafe`/`transmute` route exists in
    /// safe code. This is the ONLY function in the crate that calls
    /// `refuse_lock_record` (verified by the source audit), so a value of
    /// this type IS proof the guard ran.
    pub(crate) fn new(rel: &'a Path) -> Result<Self> {
        refuse_lock_record(rel)?;
        Ok(Self { rel })
    }

    /// The guarded root-relative path.
    pub(crate) fn as_path(self) -> &'a Path {
        self.rel
    }
}

#[cfg(test)]
mod tests {
    use super::GuardedRel;
    use std::path::Path;

    /// The ONE guard refuses every lock-record spelling — the application
    /// record, the sibling record, and their case aliases — in ANY component,
    /// and the capability cannot be minted for any of them. This is the
    /// authority every name-mutating primitive consults.
    #[test]
    fn the_guard_refuses_every_lock_record_spelling_in_any_component() {
        for bad in [
            "operation.lock",
            ".dest.operation.lock",
            "OPERATION.LOCK",
            ".DEST.OPERATION.LOCK",
            "a/operation.lock",
            "a/.dest.operation.lock/b",
            "operation.lock/c",
        ] {
            assert!(
                GuardedRel::new(Path::new(bad)).is_err(),
                "{bad:?} names the lock record and must be refused"
            );
        }
        for ok in [
            ".operation.lock.tmp.1.0",
            "snapshots/001/x",
            "operation.locked",
            "my.operation.lock",
        ] {
            assert!(
                GuardedRel::new(Path::new(ok)).is_ok(),
                "{ok:?} does not name the record and must be accepted"
            );
        }
    }

    /// STRUCTURAL AUDIT: the raw name-mutating `libc` syscalls may be issued
    /// from exactly ONE funnel module ([`super::super::unix`]) plus test-only
    /// files. A NEW primitive that reaches for `libc::unlinkat` /
    /// `renameat` / `symlinkat` / `linkat` / `mkdirat` / `openat` anywhere
    /// else FAILS this test — the mechanical replacement for the four
    /// earlier rounds of hand-enumerated call sites. The per-symbol counts in
    /// the funnel are pinned too, so a new raw call inside the funnel changes
    /// a count and forces review.
    #[test]
    fn no_raw_name_mutating_syscall_outside_the_funnel() {
        const SYSCALLS: [&str; 6] = [
            "libc::unlinkat(",
            "libc::renameat(",
            "libc::symlinkat(",
            "libc::linkat(",
            "libc::mkdirat(",
            "libc::openat(",
        ];
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs_files(&src, &mut files);
        assert!(files.len() > 10, "the audit must see the real source tree");

        // Test-only files are outside the production funnel.
        fn is_test_only(rel: &str) -> bool {
            rel.contains("tests")
                || rel.ends_with("regression.rs")
                || rel.ends_with("test_support.rs")
        }
        fn collect_rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("read src dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    collect_rs_files(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }

        let mut funnel_counts: std::collections::BTreeMap<&str, usize> =
            std::collections::BTreeMap::new();
        for file in &files {
            let rel = file
                .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")))
                .expect("strip manifest prefix")
                .to_string_lossy()
                .replace('\\', "/");
            // The audit file itself names the symbols it searches for; it
            // issues no syscall, so it is not part of the scan.
            if rel == "src/atomic/guard.rs" {
                continue;
            }
            let text = std::fs::read_to_string(file).expect("read source file");
            // Strip comment-only lines so doc text that MENTIONS a syscall is
            // not mistaken for a call.
            let code: String = text
                .lines()
                .filter(|line| {
                    let t = line.trim_start();
                    !(t.starts_with("//") || t.starts_with('*') || t.starts_with("/*"))
                })
                .collect::<Vec<_>>()
                .join("\n");
            for symbol in SYSCALLS {
                let count = code.matches(symbol).count();
                if count == 0 {
                    continue;
                }
                assert!(
                    rel == "src/atomic/unix.rs" || is_test_only(&rel),
                    "{rel} calls the raw mutating syscall {symbol} {count} time(s); name-mutating \
                     syscalls may be issued only from the guarded funnel (src/atomic/unix.rs) or \
                     test-only code"
                );
                if rel == "src/atomic/unix.rs" {
                    *funnel_counts.entry(symbol).or_default() += count;
                }
            }
        }
        // Pin the funnel's direct-call counts. A new raw syscall inside the
        // funnel changes a count and fails here, so it cannot land unreviewed.
        for (symbol, expected) in [
            ("libc::unlinkat(", 2usize),
            ("libc::renameat(", 1),
            ("libc::symlinkat(", 1),
            ("libc::linkat(", 1),
            ("libc::mkdirat(", 3),
            ("libc::openat(", 5),
        ] {
            assert_eq!(
                funnel_counts.get(symbol).copied().unwrap_or(0),
                expected,
                "the guarded funnel's {symbol} call count changed: a new raw syscall in \
                 src/atomic/unix.rs must be reviewed for the lock-record guard"
            );
        }
    }
}
