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
//!   name-mutating primitive in [`crate::atomic`] consults it, and it folds
//!   the spelling ALIASES (case; and the Win32 trailing dot/space) through the
//!   reserved-name authority, so a case or trailing-dot spelling cannot slip
//!   past it.
//! * [`GuardedRel`] is an unforgeable proof that the guard ran, carrying the
//!   [`GuardScope`] the guard authorized. Its fields are private to THIS
//!   module, so no other module — not [`super`] itself, not [`super::unix`] /
//!   [`super::windows`], not `transport` / `sync` — can build one except
//!   through [`GuardedRel::new`] or [`GuardedRel::new_for_owned_lock_record`],
//!   each of which runs the guard. The rel-path mutators take one by value, so
//!   a NEW primitive cannot name a multi-component mutation without first
//!   proving it guarded.
//!
//! # What this does NOT cover (the honest residual)
//!
//! A developer who writes a brand-new direct `libc::unlinkat` /
//! `libc::renameat` / `libc::open` / `libc::rmdir` call into a module that is
//! not [`super::unix`] is not stopped by the type system: `libc` is an ordinary
//! dependency and Rust cannot forbid a call to it. That is why the crate ALSO
//! carries source audits. They are TEXT audits, and their claim is exactly what
//! they catch:
//!
//! * `atomic::guard::tests::no_raw_name_mutating_syscall_outside_the_funnel` scans
//!   EVERY `.rs` file under the package directory (not only `src/`), tracks
//!   BOTH the `*at` and the non-`at` mutating `libc` symbols, follows a
//!   `use libc::name as alias;` / `use libc::name;` import (and fails a
//!   `use libc::*`), and refuses any such call outside `src/atomic/unix.rs` or
//!   a test-only file. The funnel's per-symbol counts are pinned.
//! * `atomic::guard::tests::std_fs_name_mutation_counts_are_pinned` pins the per-file
//!   per-symbol counts of the `std::fs` calls that can REMOVE or REPLACE a
//!   directory entry (`remove_file` / `remove_dir` / `remove_dir_all` /
//!   `rename` / `hard_link`) in every production file, so a new one changes a
//!   count and forces review.
//!
//! The residual holes a text audit CANNOT close, and which the claim above is
//! scoped NOT to include: code produced by a MACRO (`macro_rules!` or a proc
//! macro), code pulled in by `include!` from OUTSIDE the package directory, a
//! call made through a function POINTER / `dyn` dispatch, and any mutation that
//! preserves the entry's inode (`std::fs::write`, `std::fs::copy`,
//! `std::fs::set_permissions`, `std::fs::create_dir*`) — those cannot split a
//! holder because the flock is attached to the unchanged inode, so they are not
//! counted. A foreign process, or a raw `std::fs` call the caller writes
//! itself, is outside the crate entirely and is not stopped by any of this.
//! Together the private funnel and the audits mean the "obvious way" to add a
//! mutation — calling the crate's own wrapper, or reaching for a raw syscall or
//! `std::fs` removal — either presents the capability or fails a test.

use crate::error::{Error, Result};
use std::path::{Component, Path};

/// Refuse `rel` when any component names one of the crate's LOCK-RECORD
/// spellings ([`crate::reserved::is_lock_record_name`]) — the application
/// lock record `operation.lock` or the sibling record
/// `.<name>.operation.lock`, in byte-exact, case-alias, or trailing-dot/space
/// alias form. The check consults EVERY component, so a path that NAMES or
/// descends THROUGH a record is refused, not only a path whose final component
/// is the record.
///
/// PRIVATE to this module by design: the only in-crate ways to run it are the
/// two [`GuardedRel`] constructors, so a caller cannot consult the guard
/// without minting the capability the mutators demand.
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

/// The scope of a mutation the guard authorized: ordinary content, or the ONE
/// lock record the crate's own protocol OWNS ([`crate::transport::Layout::lock`]).
/// Carried by [`GuardedRel`] so a caller can pick the sidecar-serialized route
/// for the owned record without re-deriving the comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GuardScope {
    /// An ordinary path: not any lock record.
    Ordinary,
    /// The ONE lock record the protocol is authorized to break.
    OwnedLockRecord,
}

/// An unforgeable proof that the guard ran on a root-relative path, together
/// with the scope it authorized. The fields are PRIVATE to this module, so the
/// only way to obtain a value is one of the two constructors (each runs the
/// guard) — no other module, including a future mutation primitive, can
/// construct one directly, and the rel-path mutators accept nothing else.
#[derive(Clone, Copy)]
pub(crate) struct GuardedRel<'a> {
    rel: &'a Path,
    scope: GuardScope,
}

impl<'a> GuardedRel<'a> {
    /// THE ordinary-content constructor: run the guard on `rel`, then mint the
    /// proof. Refuses EVERY lock-record spelling. There is deliberately no
    /// unchecked constructor and no `Default`.
    ///
    /// COMPILE-LEVEL ARGUMENT: the fields are private to this module, so a
    /// struct-literal construction (`GuardedRel { rel, scope }`) anywhere else
    /// — including in [`super::unix`] / [`super::windows`] — is `E0451`
    /// ("field is private"), and no `unsafe`/`transmute` route exists in safe
    /// code. This is one of only TWO functions in the crate that run the guard
    /// (verified by the source audit), so a value of this type IS proof the
    /// guard ran.
    pub(crate) fn new(rel: &'a Path) -> Result<Self> {
        refuse_lock_record(rel)?;
        Ok(Self {
            rel,
            scope: GuardScope::Ordinary,
        })
    }

    /// The crate's OWN lock-protocol constructor. `owned` is the ONE record the
    /// protocol is authorized to break ([`crate::transport::Layout::lock`]);
    /// `rel` is recognized as that record ONLY when the reserved-name module's
    /// ONE fold says so ([`crate::reserved::is_same_lock_record_path`] — case,
    /// trailing dot, and trailing space aliases included). EVERY other
    /// lock-record spelling — a bare `operation.lock`, a nested
    /// `snapshots/.001.operation.lock`, an interior component, or any alias of
    /// a DIFFERENT record — is refused by the same [`refuse_lock_record`]
    /// authority the ordinary constructor uses. A future `*_if`-style
    /// primitive that reaches for this constructor therefore still cannot smash
    /// a foreign record, and one that reaches for [`Self::new`] cannot smash
    /// any.
    pub(crate) fn new_for_owned_lock_record(rel: &'a Path, owned: &Path) -> Result<Self> {
        if crate::reserved::is_same_lock_record_path(rel, owned) {
            return Ok(Self {
                rel,
                scope: GuardScope::OwnedLockRecord,
            });
        }
        refuse_lock_record(rel)?;
        Ok(Self {
            rel,
            scope: GuardScope::Ordinary,
        })
    }

    /// The guarded root-relative path.
    pub(crate) fn as_path(self) -> &'a Path {
        self.rel
    }

    /// Whether this proof is for the ONE owned lock record (the caller must
    /// serialize the mutation through the sidecar).
    pub(crate) fn is_owned_lock_record(self) -> bool {
        self.scope == GuardScope::OwnedLockRecord
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

    /// The name-mutating `libc` functions the audit tracks: BOTH the `*at`
    /// forms and the non-`at` forms the earlier six-symbol scan missed
    /// (`open` with `O_CREAT`/`O_TRUNC`, `rmdir`, `unlink`, `rename`,
    /// `symlink`, `link`, `mkdir`, `remove`).
    const MUTATING_LIBC_SYSCALLS: [&str; 14] = [
        "unlinkat",
        "renameat",
        "symlinkat",
        "linkat",
        "mkdirat",
        "openat",
        "unlink",
        "rename",
        "symlink",
        "link",
        "mkdir",
        "rmdir",
        "open",
        "remove",
    ];

    /// The `std::fs` calls that can REMOVE or REPLACE an existing directory
    /// entry — and therefore change or free a lock record's inode. Truncating
    /// or chmodding operations (`write`, `copy`, `set_permissions`) preserve the
    /// entry's inode, so they cannot split a holder and are deliberately NOT
    /// counted (see the audit's scope note).
    const FS_INODE_MUTATORS: [&str; 5] = [
        "remove_file",
        "remove_dir",
        "remove_dir_all",
        "rename",
        "hard_link",
    ];

    /// Walk the WHOLE crate directory (not only `src/`), skipping `target/` and
    /// hidden directories. Covers `build.rs`, `tests/**`, `benches/**`,
    /// `examples/**`, and any `#[path]`-included file that lives inside the
    /// package tree.
    fn collect_crate_rs_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read crate dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if name == "target" || name.starts_with('.') {
                    continue;
                }
                collect_crate_rs_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// The package-relative, `/`-separated path of a scanned file.
    fn crate_relative(file: &Path) -> String {
        file.strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")))
            .expect("strip manifest prefix")
            .to_string_lossy()
            .replace('\\', "/")
    }

    /// Test-only files are outside the production funnel: unit-test-only
    /// modules (`tests`, `*_regression.rs`, `test_support.rs`) and the
    /// integration-test / bench / example trees.
    fn is_test_only(rel: &str) -> bool {
        rel.contains("tests")
            || rel.ends_with("regression.rs")
            || rel.ends_with("test_support.rs")
            || rel.starts_with("tests/")
            || rel.starts_with("benches/")
            || rel.starts_with("examples/")
    }

    /// Strip comment-only lines so doc text that MENTIONS a symbol is not
    /// mistaken for a call. (An inline `// comment` after real code is kept —
    /// a call can sit before it — so the scan errs toward review.)
    fn code_lines(text: &str) -> String {
        text.lines()
            .filter(|line| {
                let t = line.trim_start();
                !(t.starts_with("//") || t.starts_with('*') || t.starts_with("/*"))
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The bound identifier of one import item (`name` or `name as alias`) when
    /// `name` is a tracked mutator.
    fn import_alias(item: &str) -> Option<String> {
        let mut parts = item.split_whitespace();
        let name = parts.next()?;
        let alias = if parts.next() == Some("as") {
            parts.next().unwrap_or(name)
        } else {
            name
        };
        MUTATING_LIBC_SYSCALLS
            .contains(&name)
            .then(|| alias.to_string())
    }

    /// The identifiers a `use libc::…;` statement binds to a MUTATING symbol:
    /// the bare form (`use libc::unlinkat;`), an alias (`use libc::unlinkat as
    /// u;`), or either inside a braced import
    /// (`use libc::{unlinkat as u, openat};`). A glob import is reported
    /// separately ([`libc_glob_import`]) because a text audit cannot follow it.
    fn libc_aliased_mutators(code: &str) -> Vec<String> {
        let mut aliases = Vec::new();
        let mut search_from = 0usize;
        while let Some(offset) = code[search_from..].find("use libc::") {
            let start = search_from + offset;
            let end = code[start..]
                .find(';')
                .map(|e| start + e)
                .unwrap_or(code.len());
            let body = code[start..end].trim_start_matches("use libc::");
            if let Some(inner) = body.strip_prefix('{') {
                for item in inner.trim_end_matches('}').split(',') {
                    if let Some(alias) = import_alias(item) {
                        aliases.push(alias);
                    }
                }
            } else if let Some(alias) = import_alias(body) {
                aliases.push(alias);
            }
            search_from = end.saturating_add(1);
            if search_from >= code.len() {
                break;
            }
        }
        aliases
    }

    /// Whether the file glob-imports `libc` (`use libc::*;`), which a text
    /// audit cannot follow and therefore refuses outright.
    fn libc_glob_import(code: &str) -> bool {
        code.contains("use libc::*;")
    }

    /// STRUCTURAL AUDIT (libc): a raw name-mutating `libc` call may be issued
    /// only from the ONE funnel module (`src/atomic/unix.rs`) or test-only code.
    /// BOTH the `*at` forms AND the non-`at` forms are tracked, and an alias
    /// import is followed, so the legacy literal-only scan can no longer be
    /// defeated by `use libc::unlinkat as u; u(...)`. The funnel's per-symbol
    /// counts are pinned, so a new raw call inside the funnel changes a count
    /// and forces review.
    #[test]
    fn no_raw_name_mutating_syscall_outside_the_funnel() {
        const FUNNEL: &str = "src/atomic/unix.rs";
        let mut files = Vec::new();
        collect_crate_rs_files(Path::new(env!("CARGO_MANIFEST_DIR")), &mut files);
        assert!(files.len() > 10, "the audit must see the real source tree");

        let mut funnel_counts: std::collections::BTreeMap<&str, usize> =
            std::collections::BTreeMap::new();
        for file in &files {
            let rel = crate_relative(file);
            // The audit file itself names the symbols it searches for; it
            // issues no syscall, so it is not part of the scan.
            if rel == "src/atomic/guard.rs" {
                continue;
            }
            let code = code_lines(&std::fs::read_to_string(file).expect("read source file"));
            let mut hits: Vec<String> = Vec::new();
            for symbol in MUTATING_LIBC_SYSCALLS {
                let literal = format!("libc::{symbol}(");
                let count = code.matches(&literal).count();
                if count > 0 {
                    hits.push(format!("{literal} x{count}"));
                    if rel == FUNNEL {
                        *funnel_counts.entry(symbol).or_default() += count;
                    }
                }
            }
            for alias in libc_aliased_mutators(&code) {
                let call = format!("{alias}(");
                if code.contains(&call) {
                    hits.push(format!("{call} (aliased mutating libc import)"));
                }
            }
            if libc_glob_import(&code) {
                hits.push("use libc::* (a glob import a text audit cannot follow)".to_string());
            }
            assert!(
                hits.is_empty() || rel == FUNNEL || is_test_only(&rel),
                "{rel} issues a raw name-mutating libc call: {hits:?}; name-mutating syscalls may \
                 be issued only from the guarded funnel ({FUNNEL}) or test-only code, and a \
                 `use libc::… as alias` does not exempt it"
            );
        }
        // Pin the funnel's direct-call counts, `*at` and non-`at` alike. A new
        // raw syscall (or an alias import) inside the funnel changes a count
        // and fails here, so it cannot land unreviewed.
        for (symbol, expected) in [
            ("unlinkat", 2usize),
            ("renameat", 1),
            ("symlinkat", 1),
            ("linkat", 1),
            ("mkdirat", 3),
            ("openat", 5),
            ("unlink", 0),
            ("rename", 0),
            ("symlink", 0),
            ("link", 0),
            ("mkdir", 0),
            ("rmdir", 1),
            ("open", 1),
            ("remove", 0),
        ] {
            assert_eq!(
                funnel_counts.get(symbol).copied().unwrap_or(0),
                expected,
                "the guarded funnel's libc::{symbol}( call count changed: a new raw syscall in \
                 src/atomic/unix.rs must be reviewed for the lock-record guard"
            );
        }
    }

    /// STRUCTURAL AUDIT (`std::fs`): the `std::fs` calls that can REMOVE or
    /// REPLACE a directory entry — the ones that can free or swap a lock
    /// record's inode — are pinned PER PRODUCTION FILE and PER SYMBOL, so a new
    /// one in any scanned production file changes a count and forces review.
    /// Test-only files are exempt. This closes the reviewer's probe (iii)
    /// (`std::fs::remove_file` outside the funnel was never scanned).
    ///
    /// SCOPE, stated exactly: the pin covers these five inode-mutating calls in
    /// every `.rs` file under the package directory EXCEPT test-only files
    /// (a path containing `tests`, ending `regression.rs` / `test_support.rs`,
    /// or under `tests/` / `benches/` / `examples/`). It does NOT cover a MACRO
    /// that expands to one of these calls, an `include!`d file OUTSIDE the
    /// package, or a call made through a function pointer / `dyn` dispatch.
    /// Inode-PRESERVING mutations (`std::fs::write`, `std::fs::copy`,
    /// `std::fs::set_permissions`, `std::fs::create_dir*`) are not pinned:
    /// they cannot split a holder because the flock stays on the unchanged
    /// inode.
    #[test]
    fn std_fs_name_mutation_counts_are_pinned() {
        let mut files = Vec::new();
        collect_crate_rs_files(Path::new(env!("CARGO_MANIFEST_DIR")), &mut files);
        let mut observed: std::collections::BTreeMap<(String, &str), usize> =
            std::collections::BTreeMap::new();
        for file in &files {
            let rel = crate_relative(file);
            if is_test_only(&rel) {
                continue;
            }
            let code = code_lines(&std::fs::read_to_string(file).expect("read source file"));
            for symbol in FS_INODE_MUTATORS {
                let count = code.matches(&format!("std::fs::{symbol}(")).count();
                if count > 0 {
                    observed.insert((rel.clone(), symbol), count);
                }
            }
        }
        let expected: &[(&str, &str, usize)] = &[
            ("src/atomic/mod.rs", "remove_file", 1),
            ("src/atomic/unix.rs", "remove_file", 3),
            ("src/atomic/unix.rs", "remove_dir", 1),
            ("src/atomic/unix.rs", "rename", 1),
            ("src/atomic/windows.rs", "remove_file", 6),
            ("src/atomic/windows.rs", "remove_dir", 2),
            ("src/atomic/windows.rs", "remove_dir_all", 1),
            ("src/atomic/windows.rs", "rename", 2),
            ("src/manifest/mod.rs", "hard_link", 2),
            ("src/transport/mod.rs", "remove_file", 9),
            ("src/transport/mod.rs", "remove_dir_all", 1),
            ("src/transport/mod.rs", "rename", 3),
            ("src/transport/mod.rs", "hard_link", 1),
            ("src/transport/rooted.rs", "remove_file", 1),
            ("src/transport/ssh/hostkey.rs", "remove_file", 1),
            ("src/transport/ssh/mod.rs", "remove_file", 1),
            ("src/transport/ssh/mod.rs", "hard_link", 1),
            ("src/transport/ssh/runner/mod.rs", "remove_dir", 1),
        ];
        let expected: std::collections::BTreeMap<(String, &str), usize> = expected
            .iter()
            .map(|(file, symbol, count)| (((*file).to_string(), *symbol), *count))
            .collect();
        assert_eq!(
            observed, expected,
            "the production `std::fs` removal/replace/rename counts changed: a new (or removed) \
             call must be reviewed for the lock-record guard — if the new call cannot name the \
             record, update this pin"
        );
    }
}
