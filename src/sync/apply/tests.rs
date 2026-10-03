use super::Extraneous::{Delete, Keep};
use super::*;
use crate::env::SysEnv;
use crate::manifest::canonicalize_tree;
use crate::sync::Residue;
use crate::test_support::fixture_tmpdir;
use crate::transport::{
    CreateNewVerdict, ExecOutcome, FsBytes, Layout, LocalTransport, RemoteEntry, RemoteMeta,
};
use std::fs;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

fn env() -> SysEnv {
    SysEnv::from_process()
}

fn transport(root: &Path) -> LocalTransport {
    LocalTransport::new(&env(), root.to_path_buf(), Layout::empty()).unwrap()
}

/// Run the OWNED path through the ONE entry point: acquire the destination's
/// operation lock with [`DestinationOwnership::lock`] — the ONLY way to obtain
/// `DestinationOwnership::Locked` — and then call [`sync`]. A refusal during
/// acquisition is surfaced as a `SyncResult` error exactly as `sync` surfaces
/// it, so an owned run's refusal and report are unchanged. Every non-weak call
/// site in this module uses this helper, so the tests exercise the ownership
/// axis rather than a per-variant entry point.
fn owned(
    direction: Direction,
    local_root: &Path,
    remote: &dyn Remote,
    policy: &dyn Policy,
    extraneous: Extraneous,
) -> SyncResult {
    match DestinationOwnership::lock(direction, local_root, remote) {
        Ok(ownership) => sync(direction, local_root, remote, policy, extraneous, ownership),
        Err(error) => Err(SyncError::from(error)),
    }
}

/// Run the WEAK path through the ONE entry point by NAMING the weaker
/// ownership at the call site ([`DestinationOwnership::Unowned`]).
fn unowned(
    direction: Direction,
    local_root: &Path,
    remote: &dyn Remote,
    policy: &dyn Policy,
    extraneous: Extraneous,
) -> SyncResult {
    sync(
        direction,
        local_root,
        remote,
        policy,
        extraneous,
        DestinationOwnership::Unowned,
    )
}

fn write(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, bytes).unwrap();
}

fn read(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap()
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

/// Build a CHAIN of `depth` nested directories under the (already existing)
/// directory `root`, via DESCRIPTOR-RELATIVE `mkdirat`/`openat`, so the depth is
/// bounded only by memory and never by `PATH_MAX`: a single `openat` of a
/// 10 000-component path would fail `ENAMETOOLONG` (macOS `PATH_MAX` is 1024),
/// while one syscall per level never spells the accumulated path. A regular
/// file is placed at the bottom so the deepest directory is NON-EMPTY and a
/// removal must descend the full depth.
#[cfg(unix)]
fn build_deep_chain(root: &Path, depth: usize) {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(root.as_os_str().as_bytes()).unwrap();
    let raw = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    assert!(
        raw >= 0,
        "open {}: {}",
        root.display(),
        std::io::Error::last_os_error()
    );
    let mut fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let name = c"c";
    for _ in 0..depth {
        let r = unsafe { libc::mkdirat(fd.as_raw_fd(), name.as_ptr(), 0o700) };
        assert_eq!(r, 0, "mkdirat: {}", std::io::Error::last_os_error());
        let child = unsafe {
            libc::openat(
                fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        assert!(child >= 0, "openat: {}", std::io::Error::last_os_error());
        fd = unsafe { OwnedFd::from_raw_fd(child) };
    }
    let leaf = c"leaf";
    let lf = unsafe {
        libc::openat(
            fd.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    assert!(lf >= 0, "create leaf: {}", std::io::Error::last_os_error());
    unsafe { libc::close(lf) };
}

/// Remove a chain built by [`build_deep_chain`] with an EXPLICIT-STACK,
/// descriptor-relative walk: descend holding the open directory fds (the
/// number of levels is bounded by [`RLIMIT_NOFILE`](libc::RLIMIT_NOFILE),
/// which is raised first), unlink the leaf, then `rmdir` each level
/// deepest-first. Used to clean up a deep tree after a test failure, where a
/// path-based recursive removal (`rm -rf`) would take minutes on a 10 000-deep
/// chain.
#[cfg(unix)]
fn remove_deep_chain(root: &Path) {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    // Raise the open-file limit so every level of the chain can stay open (the
    // hard limit on this host is far above the chain depth).
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 {
            lim.rlim_cur = lim.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
        }
    }
    let c = std::ffi::CString::new(root.as_os_str().as_bytes()).unwrap();
    let name = c"c";
    let raw = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return;
    }
    let mut stack: Vec<(OwnedFd, &'static std::ffi::CStr)> =
        vec![(unsafe { OwnedFd::from_raw_fd(raw) }, name)];
    let leaf = c"leaf";
    loop {
        let child = {
            let (fd, _) = stack.last().unwrap();
            // Remove the leaf if it is there (ignore absence).
            unsafe { libc::unlinkat(fd.as_raw_fd(), leaf.as_ptr(), 0) };
            unsafe {
                libc::openat(
                    fd.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            }
        };
        if child >= 0 {
            stack.push((unsafe { OwnedFd::from_raw_fd(child) }, name));
            continue;
        }
        // No child: rmdir this level relative to its parent and pop.
        if stack.len() == 1 {
            break;
        }
        let (f, n) = stack.pop().unwrap();
        drop(f);
        let (parent, _) = stack.last().unwrap();
        let r = unsafe { libc::unlinkat(parent.as_raw_fd(), n.as_ptr(), libc::AT_REMOVEDIR) };
        assert_eq!(r, 0, "rmdir: {}", std::io::Error::last_os_error());
    }
    // The chain's own root is now empty; remove it with a single, SHORT,
    // path-based rmdir (the deep levels were removed descriptor-relatively).
    unsafe { libc::rmdir(c.as_ptr()) };
}

/// Announce a SKIPPED test on the REAL console of a PLAIN `cargo test` run.
///
/// libtest CAPTURES `print!`/`eprintln!` per test and DISCARDS the captured
/// output of a passing test, so a skip message written with those macros is
/// invisible in the default gate: a skipped assertion is then
/// indistinguishable from a passing one. This writes a single
/// machine-greppable line DIRECTLY to file descriptor 1 (bypassing libtest's
/// capture) and names the test with the harness thread's name (libtest names
/// each test thread after the test). Grep a plain `cargo test` for
/// `STOREKIT_SKIP` to enumerate every skipped test.
#[cfg(unix)]
fn announce_skip(reason: &str) {
    let test = std::thread::current()
        .name()
        .unwrap_or("<unknown test>")
        .to_string();
    let line = format!("STOREKIT_SKIP test={test} reason={reason}\n");
    unsafe {
        libc::write(1, line.as_ptr().cast::<libc::c_void>(), line.len());
    }
}

/// Non-Unix fallback: no raw-fd bypass is needed where the reproductions that
/// use it are `#[cfg(unix)]`.
#[cfg(not(unix))]
fn announce_skip(reason: &str) {
    let test = std::thread::current()
        .name()
        .unwrap_or("<unknown test>")
        .to_string();
    println!("STOREKIT_SKIP test={test} reason={reason}");
}

/// Whether a mode-`0o555` directory ACTUALLY refuses a write for THIS process.
///
/// The documented read-only-destination-ROOT limitation (every top-level
/// mutation fails loudly) holds only when the process cannot write into a
/// `0o555` directory. Root, and any process holding `CAP_DAC_OVERRIDE`, bypasses
/// the permission bits, so the writes SUCCEED and the premise is untestable —
/// asserting the loud failure there would fail for a reason that has nothing to
/// do with this crate's code. Probe the premise with a REAL write rather than
/// asking `geteuid() == 0`: the probe also covers a filesystem that ignores
/// modes. Returns `true` when the write FAILED (the premise holds), and prints
/// the skip reason otherwise so a skipped run is never silent.
#[cfg(unix)]
fn a_read_only_dir_really_refuses_writes() -> bool {
    let dir = fixture_tmpdir(&env()).unwrap();
    let ro = dir.path().join("ro");
    fs::create_dir_all(&ro).unwrap();
    set_mode(&ro, 0o555);
    match fs::write(ro.join("probe"), b"probe") {
        Ok(()) => {
            let _ = fs::remove_file(ro.join("probe"));
            announce_skip(
                "this process can write into a mode-0o555 directory (effective uid 0 \
                 or CAP_DAC_OVERRIDE?), so the read-only-root premise is untestable here",
            );
            false
        }
        Err(_) => true,
    }
}

/// Whether this filesystem makes a `chmod` OBSERVABLE at all: a directory set
/// to a distinctive non-default mode must read back as that mode.
///
/// A mode-ignoring filesystem (some FUSE/overlay mounts) or one whose ACLs
/// override the POSIX bits makes every `mode_of` assertion in this file a
/// statement about the FILESYSTEM rather than about this crate's code: the test
/// sets a mode that was never stored, and the sync faithfully reports the mode
/// it actually saw. Probe with a REAL chmod + read-back instead of a platform
/// guess, and return `false` (printing the documented reason) when modes are not
/// honoured. `0o751` is deliberately neither `0o755` nor `0o700`, so a stored
/// umask default cannot be mistaken for an honoured chmod.
#[cfg(unix)]
fn the_filesystem_honours_modes() -> bool {
    let dir = fixture_tmpdir(&env()).unwrap();
    let probe = dir.path().join("mode-probe");
    fs::create_dir_all(&probe).unwrap();
    set_mode(&probe, 0o751);
    if mode_of(&probe) == 0o751 {
        return true;
    }
    announce_skip(
        "this filesystem does not report the mode a chmod set (a mode-ignoring or \
         ACL-based mount), so every `mode_of` assertion here would test the \
         filesystem rather than this crate",
    );
    false
}

/// `caf\u{e9}.txt` in NFC (precomposed `\u{e9}`).
const COMPOSED_NAME: &str = "caf\u{e9}.txt";
/// The same visible name in NFD (decomposed `e` + combining acute).
const DECOMPOSED_NAME: &str = "cafe\u{301}.txt";

/// Whether THIS filesystem PRESERVES a decomposed on-disk name, so a manifest
/// walk can observe a name that is not already NFC.
///
/// macOS APFS preserves the spelling (its lookups are normalization-insensitive,
/// but a directory listing returns the decomposed bytes); Linux/ext4 too. A
/// filesystem that normalizes a name on write would make the case
/// unrepresentable, so the reproductions below would be untestable there. Probe
/// with a REAL create + directory listing rather than a platform guess, and
/// print the documented skip reason otherwise.
#[cfg(unix)]
fn filesystem_preserves_a_decomposed_name() -> bool {
    let dir = fixture_tmpdir(&env()).unwrap();
    fs::write(dir.path().join(DECOMPOSED_NAME), b"probe").unwrap();
    let preserved = fs::read_dir(dir.path())
        .unwrap()
        .any(|entry| entry.unwrap().file_name().to_str() == Some(DECOMPOSED_NAME));
    if !preserved {
        announce_skip(
            "this filesystem normalizes a decomposed name on write, so a stored \
             spelling that differs from the on-disk name is unrepresentable here \
             and the unaddressable-name reproduction is untestable",
        );
    }
    preserved
}

/// Whether THIS filesystem treats the composed and decomposed spellings as
/// DISTINCT ENTRIES.
///
/// This is a strictly stronger property than
/// [`filesystem_preserves_a_decomposed_name`], and it is a DIFFERENT one:
/// preservation asks only what bytes a write + directory listing round-trips,
/// which says nothing about whether a LOOKUP of the other spelling resolves to
/// that entry. macOS APFS preserves the decomposed spelling but is
/// normalization-INSENSITIVE — a lookup of either spelling resolves to the same
/// inode — so it has preservation WITHOUT distinction; Linux/ext4 has both. The
/// reproductions that assert "no NFC twin exists beside the decomposed entry"
/// are only meaningful where the two spellings are distinct entries: on a
/// normalization-insensitive filesystem that assertion fails against the
/// ORIGINAL file rather than a twin, testing the filesystem instead of this
/// crate. Probe with a real create + cross-spelling lookup + a second create,
/// and print the documented skip reason otherwise.
#[cfg(unix)]
fn filesystem_distinguishes_normalization_forms() -> bool {
    let dir = fixture_tmpdir(&env()).unwrap();
    fs::write(dir.path().join(DECOMPOSED_NAME), b"probe").unwrap();
    // A normalization-insensitive filesystem resolves the composed spelling to
    // the decomposed entry that already exists, so this lookup SUCCEEDS there.
    let cross_spelling_lookup_fails = fs::symlink_metadata(dir.path().join(COMPOSED_NAME)).is_err();
    // Where the spellings are distinct, creating the second one must yield a
    // SECOND entry (two files), not overwrite the first.
    let second_create_yields_two_entries = fs::write(dir.path().join(COMPOSED_NAME), b"twin")
        .and_then(|()| fs::read_dir(dir.path()))
        .map(|entries| entries.count() == 2)
        .unwrap_or(false);
    let distinguishes = cross_spelling_lookup_fails && second_create_yields_two_entries;
    if !distinguishes {
        announce_skip(
            "this filesystem is normalization-insensitive (it preserves a decomposed \
             name on write yet resolves the composed spelling to the same entry, \
             e.g. macOS APFS), so the two spellings are not distinct entries and a \
             \"no NFC twin was created\" assertion would be a statement about the \
             filesystem rather than this crate",
        );
    }
    distinguishes
}

/// Whether THIS filesystem stores a symlink whose TARGET is not valid UTF-8.
///
/// A raw-byte link target is a POSIX capability that NOT every filesystem
/// offers: some refuse the `symlink(2)` outright, and others store a target
/// they cannot read back byte-identically. (macOS APFS DOES store and
/// round-trip one — the capability is filesystem- and version-dependent, not
/// platform-wide.) Probe with a REAL `symlink` + `read_link` round trip rather
/// than a platform guess, and announce the documented skip reason otherwise, so
/// a skipped run is never silent.
#[cfg(unix)]
fn filesystem_stores_a_non_utf8_symlink_target() -> bool {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let dir = fixture_tmpdir(&env()).unwrap();
    let link = dir.path().join("probe");
    let raw = b"a\xffb";
    if std::os::unix::fs::symlink(OsStr::from_bytes(raw), &link).is_err() {
        announce_skip(
            "this filesystem refuses a symlink target that is not valid UTF-8, so \
             the unrepresentable-target reproduction is untestable here",
        );
        return false;
    }
    match fs::read_link(&link) {
        Ok(back) if back.as_os_str().as_bytes() == raw => true,
        _ => {
            announce_skip(
                "this filesystem does not round-trip a symlink target's raw non-UTF-8 \
                 bytes, so the unrepresentable-target reproduction is untestable here",
            );
            false
        }
    }
}

/// Whether THIS filesystem stores an entry whose NAME is not valid UTF-8.
///
/// macOS refuses such a name (HFS+/APFS names are UTF-8/UTF-16), so the
/// unaddressable-wire-name reproductions are Linux-only. Probe with a REAL
/// create rather than a platform guess, and print the documented skip reason
/// otherwise.
#[cfg(unix)]
fn filesystem_stores_a_non_utf8_name() -> bool {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let dir = fixture_tmpdir(&env()).unwrap();
    match fs::write(dir.path().join(OsStr::from_bytes(b"bad\xffname")), b"probe") {
        Ok(()) => true,
        Err(_) => {
            announce_skip(
                "this filesystem refuses an entry name that is not valid UTF-8, so the \
                 unaddressable-wire-name reproduction is untestable here",
            );
            false
        }
    }
}

/// Whether THIS filesystem FOLDS `written` onto `lookup`: writing an entry
/// named `written` makes a subsequent lookup of the differently-spelled
/// `lookup` resolve to that entry.
///
/// The fold is SPELLED OUT by the caller, never assumed from "the filesystem is
/// case-insensitive". A filesystem can fold ASCII while leaving a Unicode pair
/// distinct — macOS FAT folds `Case-Probe`/`cASE-pROBE` but keeps
/// `Straße.txt`/`STRASSE.txt` and `ς`/`σ` as SEPARATE entries — so a Unicode-fold
/// reproduction that gated on the ASCII probe would RUN there and fail on an
/// environmental property, hiding real regressions behind noise. Gating on the
/// exact fold the fixture depends on skips a filesystem precisely when it cannot
/// exhibit the case under test.
///
/// This is a PURE predicate: it prints NOTHING. Each caller announces its OWN
/// truthful skip reason via [`announce_skip`] (a case-insensitive-only
/// reproduction and a case-sensitive-only one need opposite reasons).
#[cfg(unix)]
fn filesystem_folds(written: &str, lookup: &str) -> bool {
    let dir = fixture_tmpdir(&env()).unwrap();
    fs::write(dir.path().join(written), b"probe").unwrap();
    fs::symlink_metadata(dir.path().join(lookup)).is_ok()
}

/// Whether THIS filesystem is CASE-INSENSITIVE for the ASCII fold used by the
/// round-18 reproductions.
///
/// macOS APFS is case-insensitive; Linux ext4 is case-sensitive unless the
/// `casefold` feature is enabled. The reproductions that depend on an install
/// folding an ASCII manifest spelling onto a differently-spelled on-disk entry
/// are only meaningful where this holds; elsewhere they would be statements
/// about the filesystem rather than this crate. A reproduction that depends on a
/// UNICODE fold MUST NOT use this predicate — it must probe the exact fold with
/// [`filesystem_folds`] (see the round-19 fixtures).
///
/// This is a PURE predicate: it prints NOTHING. The two caller classes need
/// OPPOSITE skip reasons (a case-insensitive-only reproduction skips when this
/// is `false`; a case-sensitive-only one skips when this is `true`), so a
/// message baked in here is necessarily a lie for one of them — the round-18
/// defect F2. Each caller announces its OWN truthful reason via
/// [`announce_skip`].
#[cfg(unix)]
fn filesystem_is_case_insensitive() -> bool {
    filesystem_folds("Case-Probe", "cASE-pROBE")
}

/// The direct children of `dir`, as raw names, for a byte-identical assertion
/// that does not go through the (folding) address.
fn dir_names(dir: &Path) -> Vec<std::ffi::OsString> {
    let mut names: Vec<std::ffi::OsString> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort();
    names
}

/// A tree with a nested directory, a non-default file mode, a non-default
/// directory mode, a read-only empty directory, and an in-root symlink.
fn build_rich_tree(root: &Path) {
    write(&root.join("readme"), b"hello\n");
    write(&root.join("bin/tool"), b"#!/bin/sh\necho hi\n");
    fs::create_dir_all(root.join("empty")).unwrap();
    fs::create_dir_all(root.join("ro")).unwrap();
    #[cfg(unix)]
    {
        set_mode(&root.join("bin/tool"), 0o751);
        set_mode(&root.join("readme"), 0o640);
        set_mode(&root.join("empty"), 0o700);
        // A read-only directory with NO children: `Same` and untouched by a
        // transfer between equal trees.
        set_mode(&root.join("ro"), 0o555);
        std::os::unix::fs::symlink("bin/tool", root.join("tool-link")).unwrap();
    }
    #[cfg(windows)]
    {
        crate::platform::symlink(Path::new("bin/tool"), &root.join("tool-link")).unwrap();
    }
}

fn append_files(_rel: &str, kind: EntryKind) -> EntryPolicy {
    match kind {
        EntryKind::File => EntryPolicy::AppendTail,
        EntryKind::Dir | EntryKind::Symlink => EntryPolicy::Replace,
    }
}

/// Assert no claim-by-rename aside was left anywhere under `root`.
fn assert_no_aside(root: &Path) {
    for entry in walkdir::WalkDir::new(root) {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy();
        assert!(
            !name.starts_with(".sync-aside."),
            "a stray claim aside was left behind: {}",
            entry.path().display()
        );
    }
}

/// Assert the report's `residue` obeys the contract [`SyncReport::residue`]
/// documents: every named path still EXISTS under one of the given roots; the
/// set is reduced to TOPMOST paths (no residue names a path under another
/// residue); and a path containing a RESERVED `.sync-aside.` component has it as
/// its FINAL component (the aside holds the whole stranded subtree, so nothing
/// below it is named). Both documented kinds are allowed — a reserved aside and
/// an ordinary destination path the run refused to remove or displace — and the
/// helper deliberately does NOT require every path to be reserved (that was the
/// doc lie this pins). `assert_no_aside` cannot do this: it passes precisely
/// when the residue was DESTROYED, which is the data-loss defect this must
/// catch.
fn assert_residue_present(report: &SyncReport, roots: &[&Path]) {
    for residue in &report.residue {
        assert!(
            roots
                .iter()
                .any(|root| fs::symlink_metadata(root.join(residue)).is_ok()),
            "residue {residue} named by the report does not exist under {roots:?}"
        );
        for other in &report.residue {
            if other == residue {
                continue;
            }
            assert!(
                !Path::new(residue).starts_with(other),
                "residue {residue} is a strict DESCENDANT of {other}; residue is reduced \
                 to its topmost path"
            );
        }
        let components: Vec<_> = Path::new(residue).components().collect();
        for (index, component) in components.iter().enumerate() {
            if let std::path::Component::Normal(name) = component
                && is_reserved_name(name)
            {
                assert_eq!(
                    index,
                    components.len() - 1,
                    "residue {residue} names a path BELOW a reserved aside; a stranded \
                     aside is reduced to the aside itself"
                );
            }
        }
    }
}

/// Assert every `.sync-aside.*` path NAMED by a restore-failure message still
/// EXISTS under `root`. A message that says an entry "remains stranded at X"
/// while X does not exist contradicts the disk; the reconciliation reads the
/// entry's location back before it is named, so this holds by construction. The
/// aside path is whitespace-delimited in every message this module emits.
fn assert_restore_failures_name_existing_asides(error: &SyncError, root: &Path) {
    for failure in error.restore_failures() {
        for token in failure.split_whitespace() {
            if !token.contains(".sync-aside.") {
                continue;
            }
            let path = token.trim_matches(|c: char| matches!(c, ':' | ',' | ';' | '(' | ')'));
            assert!(
                fs::symlink_metadata(root.join(path)).is_ok(),
                "restore failure names a non-existent aside {path}: {failure}"
            );
        }
    }
}

/// Assert some regular file named `name` under `root` holds exactly `bytes`.
/// Used to prove a stranded original survived even when a claim moved it.
fn assert_file_somewhere(root: &Path, name: &str, bytes: &[u8]) {
    for entry in walkdir::WalkDir::new(root) {
        let entry = entry.unwrap();
        if entry.file_type().is_file() && entry.file_name() == name {
            assert_eq!(
                fs::read(entry.path()).unwrap(),
                bytes,
                "content of {}",
                entry.path().display()
            );
            return;
        }
    }
    panic!("no file named {name} under {}", root.display());
}

/// The four derived lists are pairwise disjoint; `transient_dirs` is disjoint
/// from `skipped`, `conflicts`, `extraneous`, and `residue` (it may share with
/// `applied` and with `verify_failures`); `residue` is disjoint from the four
/// lists AND from `verify_failures`; `verify_failures` is disjoint from the four
/// lists; and `indeterminate` is disjoint from EVERYTHING (a failed mutation may
/// have landed or not, so no other claim about the path can be made). Used on
/// the SUCCESS and the FAILURE path of a sync.
fn assert_report_lists_disjoint(report: &SyncReport) {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for path in report
        .applied
        .iter()
        .chain(report.skipped.iter())
        .chain(report.conflicts.iter().map(|c| &c.path))
        .chain(report.extraneous.iter())
    {
        *seen.entry(path.clone()).or_default() += 1;
    }
    assert!(
        seen.values().all(|count| *count == 1),
        "a path is in two contradictory lists: {seen:?}"
    );
    for path in &report.transient_dirs {
        assert!(!report.skipped.contains(path), "transient+skipped: {path}");
        assert!(
            !report.extraneous.contains(path),
            "transient+extraneous: {path}"
        );
        assert!(
            !report
                .conflicts
                .iter()
                .any(|conflict| &conflict.path == path),
            "transient+conflicts: {path}"
        );
        assert!(!report.residue.contains(path), "transient+residue: {path}");
        assert!(
            !report.indeterminate.contains(path),
            "transient+indeterminate: {path}"
        );
    }
    // `residue` is a terminal state (left in place), so it can never also be
    // `applied`/`skipped`/`extraneous`/`conflicts`/`verify_failures`.
    for path in &report.residue {
        assert!(!report.applied.contains(path), "residue+applied: {path}");
        assert!(!report.skipped.contains(path), "residue+skipped: {path}");
        assert!(
            !report.extraneous.contains(path),
            "residue+extraneous: {path}"
        );
        assert!(
            !report
                .conflicts
                .iter()
                .any(|conflict| &conflict.path == path),
            "residue+conflicts: {path}"
        );
        assert!(
            !report.verify_failures.contains(path),
            "residue+verify_failures: {path}"
        );
        assert!(
            !report.indeterminate.contains(path),
            "residue+indeterminate: {path}"
        );
    }
    // A path whose verification did not pass is never also reported applied,
    // skipped, extraneous, or conflicted.
    for path in &report.verify_failures {
        assert!(!report.applied.contains(path), "verify+applied: {path}");
        assert!(!report.skipped.contains(path), "verify+skipped: {path}");
        assert!(
            !report.extraneous.contains(path),
            "verify+extraneous: {path}"
        );
        assert!(
            !report
                .conflicts
                .iter()
                .any(|conflict| &conflict.path == path),
            "verify+conflicts: {path}"
        );
        assert!(
            !report.indeterminate.contains(path),
            "verify+indeterminate: {path}"
        );
    }
    // `indeterminate` wins over every other list: a failed mutation may have
    // landed or not, so every other claim about the path would be a guess.
    for path in &report.indeterminate {
        assert!(
            !report.applied.contains(path),
            "indeterminate+applied: {path}"
        );
        assert!(
            !report.skipped.contains(path),
            "indeterminate+skipped: {path}"
        );
        assert!(
            !report.extraneous.contains(path),
            "indeterminate+extraneous: {path}"
        );
        assert!(
            !report
                .conflicts
                .iter()
                .any(|conflict| &conflict.path == path),
            "indeterminate+conflicts: {path}"
        );
        assert!(
            !report.transient_dirs.contains(path),
            "indeterminate+transient: {path}"
        );
        assert!(
            !report.residue.contains(path),
            "indeterminate+residue: {path}"
        );
        assert!(
            !report.verify_failures.contains(path),
            "indeterminate+verify_failures: {path}"
        );
    }
    // `unsupported_destination` is an ANNOTATION over paths the partition
    // ALREADY names: it carries the reason a tolerated destination entry could
    // not be represented faithfully, and adds no path of its own. Every entry
    // must therefore already be named by some report list, and the list must be
    // sorted and unique (the same invariants the partition lists have).
    for entry in &report.unsupported_destination {
        assert!(
            report_names(report, &entry.path),
            "an unsupported-destination annotation must be attached to a path the report already \
             names (it adds no path to the partition): {entry:?}"
        );
        assert!(
            !entry.reason.is_empty(),
            "an unsupported-destination annotation must carry the strict rule's reason: {entry:?}"
        );
    }
    let unsupported_paths: Vec<&str> = report
        .unsupported_destination
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert!(
        unsupported_paths.windows(2).all(|pair| pair[0] < pair[1]),
        "the unsupported-destination annotation must be sorted by path and unique: \
         {unsupported_paths:?}"
    );
}

/// Whether ANY report list names `path`. The FAILURE-path coverage oracle: a
/// mutated path that appears in no list is invisible to the caller.
fn report_names(report: &SyncReport, path: &str) -> bool {
    report.applied.iter().any(|p| p == path)
        || report.skipped.iter().any(|p| p == path)
        || report.conflicts.iter().any(|c| c.path == path)
        || report.extraneous.iter().any(|p| p == path)
        || report.transient_dirs.iter().any(|p| p == path)
        || report.residue.iter().any(|p| p == path)
        || report.verify_failures.iter().any(|p| p == path)
        || report.indeterminate.iter().any(|p| p == path)
}

/// Assert the report NAMES `path` (in any list). This is the coverage assertion
/// the success path had (`the_report_lists_are_mutually_exclusive_and_cover_-
/// the_diff`) and the failure path lacked.
fn assert_report_names(report: &SyncReport, path: &str) {
    assert!(
        report_names(report, path),
        "the report must name the mutated path {path}: {report:?}"
    );
}

/// The conflict for `path`, asserted to be present. Order-independent, so a
/// legitimate extra `ParentRefused` cannot shift a position-indexed assertion.
fn conflict_at<'a>(report: &'a SyncReport, path: &str) -> &'a Conflict {
    report
        .conflicts
        .iter()
        .find(|conflict| conflict.path == path)
        .unwrap_or_else(|| panic!("no conflict for {path}: {:?}", report.conflicts))
}

/// The strict address-fidelity reason the report attached to `path` (asserted
/// to be present), for the tolerated-unsupported annotation.
fn unsupported_reason<'a>(report: &'a SyncReport, path: &str) -> &'a str {
    report
        .unsupported_destination
        .iter()
        .find(|entry| entry.path == path)
        .unwrap_or_else(|| {
            panic!(
                "no unsupported-destination annotation for {path}: {:?}",
                report.unsupported_destination
            )
        })
        .reason
        .as_str()
}

/// When a `drop_mode_for` seam may fire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DropModeWhen {
    /// Any matching call.
    Always,
    /// Only AFTER the first removal. By the documented ordering, transfers and
    /// verification complete before any removal and the removals' widenings are
    /// reverted by the single settle; so this identifies the settle RESTORE of
    /// a widened path — the `set_mode` call a NAMED-path+mode seam alone cannot
    /// separate from the identical finalize chmod.
    AfterRemoval,
}

/// Which `set_mode` call a test seam drops, named by identity rather than by
/// call ordinal so a position change cannot silently retarget the seam.
#[derive(Clone, Debug, PartialEq, Eq)]
enum DropModeTarget {
    /// Exactly this manifest-relative path.
    Path(String),
    /// Any path whose file name is in the RESERVED `.sync-aside.` namespace,
    /// whose exact spelling (pid + counter) is not predictable in a test.
    ReservedAside,
}

impl DropModeTarget {
    fn matches(&self, path: &str) -> bool {
        match self {
            DropModeTarget::Path(target) => path == target,
            DropModeTarget::ReservedAside => Path::new(path)
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(ASIDE_PREFIX)),
        }
    }
}

/// A destination mutation a [`RecordingRemote`] performs AFTER the Nth `write`
/// has LANDED: a mirrored or concurrent writer that changes the destination
/// between the install and the post-transfer verification, which the
/// pre-install gate cannot see. It is what makes the post-transfer checks
/// load-bearing rather than subsumed by the pre-install gate.
enum AfterWrite {
    /// Rename `from` to `to` under the destination root (a changed on-disk
    /// spelling of a parent, or of the entry itself).
    Rename(String, String),
    /// Create an empty regular file at `rel`: an entry no manifest names.
    CreateFile(String),
    /// Overwrite the regular file at `rel` with `bytes`.
    Overwrite(String, Vec<u8>),
    /// APPEND `bytes` to the regular file at `rel`: a writer that adds a line
    /// between a compare-and-append's read of the destination and its write
    /// (the A2 window). The bytes are appended, never replacing what is there.
    Append(String, Vec<u8>),
    /// DELETE the regular file at `rel`: a writer that removes the append
    /// target between the append's destination read and its compare. The
    /// documented contract calls the now-absent destination a MISMATCH; the
    /// compare's re-read sees the entry GONE.
    Delete(String),
    /// Create the parent directories of `rel` and write `bytes` there: a writer
    /// that materialises a NEW subtree (a directory plus a child no manifest
    /// spelling addresses) in one step.
    WriteTree(String, Vec<u8>),
    /// Replace the DIRECTORY at `rel` with an empty regular file: the same
    /// NAME, a different KIND. Reproduces a `Same` directory swapped under the
    /// run, which the name-only checks cannot see.
    ReplaceDirWithFile(String),
    /// (unix only) Create an empty regular file whose NAME is the given RAW
    /// bytes, under the destination root. Reproduces a destination listing view
    /// that cannot represent the name faithfully: a raw `0xFF` byte and an
    /// intended `U+FFFD` entry both render as `U+FFFD` through a lossy `String`
    /// view, so a name-only check sees a planned spelling where the destination
    /// holds an unaddressable one.
    #[cfg(unix)]
    RawName(Vec<u8>),
    /// (unix only) The same raw-name insertion as [`AfterWrite::RawName`], but
    /// inside the destination subdirectory at `rel`. A subdirectory the run did
    /// not install into is never listed by the verification pass, so the name
    /// is met only by the extraneous-removal pass: this makes that pass's
    /// fail-closed listing handling load-bearing.
    #[cfg(unix)]
    RawNameUnder(String, Vec<u8>),
    /// (unix only) Chmod the entry at `rel` to `mode`: a writer that makes a
    /// directory UNREADABLE after a transfer, so the final verification pass
    /// cannot enumerate it.
    #[cfg(unix)]
    Chmod(String, u32),
    /// Replace whatever is at `rel` with a DIRECTORY tree `rel/data/gc` holding
    /// `bytes`: a writer that swaps a regular FILE for a live DIRECTORY (the
    /// Finding-2 kind swap).
    ReplaceWithDirTree(String, Vec<u8>),
    /// Replace whatever is at `rel` with a DIRECTORY holding `child` (a
    /// relative path below the new directory) with `bytes`: a writer that swaps
    /// a live entry's KIND under a manifest snapshot and plants an entry no
    /// manifest spelling addresses (the Finding-1 stale-claim-kind swap).
    ReplaceWithDirTreeAt(String, String, Vec<u8>),
    /// (unix only) Replace the DIRECTORY at `rel` with a SYMLINK to `outside`:
    /// a writer that turns a directory POSITION into a door out of the tree
    /// AFTER an earlier transfer already confirmed it is a real directory.
    #[cfg(unix)]
    ReplaceDirWithSymlink(String, PathBuf),
}

impl AfterWrite {
    fn apply(&self, root: &Path) {
        match self {
            AfterWrite::Rename(from, to) => {
                fs::rename(root.join(from), root.join(to)).unwrap();
            }
            AfterWrite::CreateFile(rel) => write(&root.join(rel), b""),
            AfterWrite::Overwrite(rel, bytes) => {
                fs::write(root.join(rel), bytes).unwrap();
            }
            AfterWrite::Append(rel, bytes) => {
                use std::io::Write;
                let mut f = fs::OpenOptions::new()
                    .append(true)
                    .open(root.join(rel))
                    .unwrap();
                f.write_all(bytes).unwrap();
            }
            AfterWrite::Delete(rel) => {
                fs::remove_file(root.join(rel)).unwrap();
            }
            AfterWrite::WriteTree(rel, bytes) => {
                write(&root.join(rel), bytes);
            }
            AfterWrite::ReplaceDirWithFile(rel) => {
                let path = root.join(rel);
                fs::remove_dir_all(&path).unwrap();
                write(&path, b"");
            }
            #[cfg(unix)]
            AfterWrite::RawName(bytes) => {
                use std::os::unix::ffi::OsStrExt;
                write(&root.join(OsStr::from_bytes(bytes)), b"");
            }
            #[cfg(unix)]
            AfterWrite::RawNameUnder(rel, bytes) => {
                use std::os::unix::ffi::OsStrExt;
                write(&root.join(rel).join(OsStr::from_bytes(bytes)), b"");
            }
            #[cfg(unix)]
            AfterWrite::Chmod(rel, mode) => {
                set_mode(&root.join(rel), *mode);
            }
            AfterWrite::ReplaceWithDirTree(rel, bytes) => {
                let path = root.join(rel);
                match fs::symlink_metadata(&path) {
                    Ok(md) if md.is_dir() => fs::remove_dir_all(&path).unwrap(),
                    Ok(_) => fs::remove_file(&path).unwrap(),
                    Err(_) => {}
                }
                write(&path.join("data/gc"), bytes);
            }
            AfterWrite::ReplaceWithDirTreeAt(rel, child, bytes) => {
                let path = root.join(rel);
                match fs::symlink_metadata(&path) {
                    Ok(md) if md.is_dir() => fs::remove_dir_all(&path).unwrap(),
                    Ok(_) => fs::remove_file(&path).unwrap(),
                    Err(_) => {}
                }
                write(&path.join(child), bytes);
            }
            #[cfg(unix)]
            AfterWrite::ReplaceDirWithSymlink(rel, outside) => {
                let path = root.join(rel);
                fs::remove_dir_all(&path).unwrap();
                std::os::unix::fs::symlink(outside, &path).unwrap();
            }
        }
    }
}

/// A `Remote` wrapper that delegates to a [`LocalTransport`] but can declare
/// itself local (so `remote_manifest` takes the in-process branch), fail
/// writes, drop mode applications, script an exec failure, sabotage the
/// destination after an install, and record every mutating call.
struct RecordingRemote {
    inner: LocalTransport,
    is_local: bool,
    fail_writes: bool,
    /// Fail only the Nth `write` call (1-based), so a test can let an earlier
    /// file install succeed and then fail a later one.
    fail_nth_write: Option<usize>,
    /// Write the bytes through to disk and THEN return `Err` — the shape of a
    /// transport (or the local durable path) that publishes the entry and then
    /// fails its chmod/fsync/durability check.
    fail_write_after_write: bool,
    /// Fail only the Nth `set_mode` call (1-based).
    fail_nth_set_mode: Option<usize>,
    /// Fail `read` (the source read that precedes an install, so a PULL's
    /// install can be made to fail after the claim).
    fail_reads: bool,
    fail_create_dir_all: bool,
    /// Create the directory and THEN fail (exercises the partial-creation
    /// window of a kind-changing replacement).
    fail_create_dir_all_after_create: bool,
    fail_symlink: bool,
    /// Fail `remove_file` (the `drop_claim` deletion of a claimed file/symlink
    /// aside).
    fail_remove_file: bool,
    /// UNLINK the entry on the Nth `remove_file` call (1-based) and THEN return
    /// `Err` — the shape of a removal that LANDS before the failure is observed
    /// (a transport whose `rm`/unlink succeeds and whose runner then reports an
    /// error). Used to prove the leftover-aside message is gated on a read-back.
    fail_nth_remove_after_remove: Option<usize>,
    drop_modes: bool,
    /// Report `Ok` WITHOUT applying a `set_mode` call identified by a NAMED
    /// path (or the reserved `.sync-aside.` namespace), the requested mode, and
    /// an optional phase — POSITION-INDEPENDENT, so adding an earlier
    /// `set_mode` call cannot silently retarget it. `dropped_modes` records the
    /// exact `(path, mode)` calls hit so a test fails loudly when the target was
    /// never reached or was not the one intended.
    drop_mode_for: Option<(DropModeTarget, u32, DropModeWhen)>,
    dropped_modes: Mutex<Vec<(String, u32)>>,
    /// Removals recorded, used by `DropModeWhen::AfterRemoval`.
    removals: AtomicUsize,
    /// Ignore the mode argument of `write` (install bytes only).
    drop_write_mode: bool,
    /// Fail every metadata read AFTER the first `write` succeeded — the shape
    /// of a mode read that fails once the bytes have landed, which is exactly
    /// `transfer_file`'s `note_final` window.
    fail_metadata_after_write: bool,
    /// Make the Nth `rename` call (1-based) fail — used to fail a claim
    /// rollback after a failed install.
    fail_nth_rename: Option<usize>,
    /// Perform the Nth `rename` and THEN return `Err` — the shape of a rename
    /// that LANDS before the failure is observed (the far side's single atomic
    /// `rename(2)` executes and the connection drops before its outcome is
    /// read). Used to prove the report is reconciled against the disk.
    fail_nth_rename_after_rename: Option<usize>,
    /// DELETE the source entry on the Nth `rename` and THEN return `Err` — a
    /// move whose destination is NEITHER spelling, so both spellings probe
    /// absent (the `Ok(None)`-at-both-probes case).
    vanish_nth_rename: Option<usize>,
    /// Fail EVERY `metadata` read of a path in the reserved `.sync-aside.`
    /// namespace once at least one `rename` has happened: a degraded session
    /// where a landed rename's follow-up probe of the aside ALSO fails, so the
    /// location cannot be confirmed.
    fail_metadata_for_reserved_after_rename: bool,
    renames: AtomicUsize,
    /// `remove_file` calls seen, so `fail_nth_remove_after_remove` can target
    /// one by position.
    remove_files: AtomicUsize,
    /// The `to` spelling of every `rename` call, in order, so a test can name
    /// the aside a move created even though the reserved namespace makes the
    /// exact spelling (pid + counter) unpredictable.
    rename_targets: Mutex<Vec<String>>,
    set_mode_calls: AtomicUsize,
    exec_failure: Option<ExecOutcome>,
    /// `prepare_identity` calls seen, and the remote-request counter at the
    /// moment of each call: the F1 ordering instrument. A call that ran after
    /// the first remote request records a non-zero index.
    identity_calls: AtomicUsize,
    identity_op_index: Mutex<Vec<usize>>,
    /// A message to fail `prepare_identity` with: the F1 failure instrument.
    identity_failure: Option<String>,
    /// Every remote request (ANY trait operation, read or mutating), in order.
    /// `prepare_identity` is NOT a remote request: it PREPARES the transport.
    remote_requests: AtomicUsize,
    /// A crafted FAR-SIDE manifest, returned instead of running the perl
    /// verification script when `is_local` is false. It lets a test describe a
    /// source tree THIS host's filesystem cannot hold (a case-SENSITIVE source
    /// with both `Foo.txt` and `foo.txt`, e.g. on case-insensitive APFS).
    manifest_output: Option<String>,
    /// A destination mutation applied after the Nth `write` (1-based) lands.
    after_write: Option<(usize, AfterWrite)>,
    /// A destination mutation applied after the Nth `rename` (1-based) lands:
    /// a writer that diverges INSIDE a claim window (after the claim moved the
    /// original aside, before the install).
    after_rename: Option<(usize, AfterWrite)>,
    /// A destination mutation applied after the Nth successful removal (1-based,
    /// counting `remove_file`, `remove_dir`, and `remove_dir_all`): a writer
    /// that appears at the rollback target after the sync discarded its own
    /// partial.
    after_removal: Option<(usize, AfterWrite)>,
    /// A one-shot destination mutation applied BEFORE the FIRST trait operation
    /// the applier issues: replaces the directory in `.0` with a symlink to the
    /// outside directory in `.1`. Models a concurrent writer that swaps a
    /// destination directory for a link to an OUTSIDE tree after the
    /// destination manifest was read and before any operation touches it (the
    /// round-22 symlink-at-a-directory-position race).
    #[cfg(unix)]
    swap_dir_with_symlink_before_first_op: Option<(PathBuf, PathBuf)>,
    /// A one-shot destination mutation applied BEFORE the FIRST trait operation
    /// the applier issues: a concurrent writer that diverges after the
    /// destination manifest was read and before any operation touches it (the
    /// Finding-2 live-kind swap).
    mutate_before_first_op: Option<AfterWrite>,
    /// A writer on a PULL's LOCAL destination: after the Nth successful source
    /// `read` lands, apply `AfterWrite` to the stored root (the local tree).
    /// The confined `Side::Local` destination has no wrapper, so the source
    /// `read` is the only instrumented call inside the window — this is what
    /// makes the confined-local live-kind swap testable at all.
    pull_writer: Option<(usize, PathBuf, AfterWrite)>,
    /// A writer on the SOURCE: after the Nth successful source `read` lands,
    /// apply `AfterWrite` to the stored SOURCE root. This makes the
    /// SOURCE-quiescence precondition testable — the run must notice that the
    /// tree it planned against moved underneath it and fail closed, naming the
    /// path that changed.
    source_writer: Option<(usize, PathBuf, AfterWrite)>,
    /// The A2 WINDOW WRITER: after the Nth (1-based) successful read OF THE
    /// PATH named in `.0` lands, apply the `AfterWrite` to the stored
    /// destination root. Positioned by (path, count-within-that-path) because
    /// the destination manifest's own hash read of the same path comes FIRST —
    /// a global read counter cannot tell the manifest read from the append's
    /// read.
    dest_read_writer: Option<(String, usize, AfterWrite)>,
    /// Successful reads seen per destination path, for [`Self::dest_read_writer`].
    dest_read_counts: Mutex<BTreeMap<String, usize>>,
    /// The BEFORE-READ window writer: IMMEDIATELY BEFORE the Nth (1-based)
    /// `Remote::read` of the path named in `.0`, apply the `AfterWrite` to the
    /// stored destination root. The append's destination read is the first read
    /// of a file, so `.1 == 1` makes that read itself observe the mutation —
    /// the exact window between the live-kind read and the byte read.
    dest_read_before_writer: Option<(String, usize, AfterWrite)>,
    /// Read ATTEMPTS seen per destination path, for
    /// [`Self::dest_read_before_writer`] (kept separate from
    /// [`Self::dest_read_counts`], which counts SUCCESSFUL reads).
    dest_read_before_counts: Mutex<BTreeMap<String, usize>>,
    /// Successful `read` calls seen, so `pull_writer` and `source_writer` can
    /// target one by
    /// position.
    reads: AtomicUsize,
    /// Fail only the Nth read ATTEMPT (1-based): lets a run inject an install
    /// read failure on the confined-local path, where there is no destination
    /// write seam, so a claim rollback runs.
    fail_nth_read: Option<usize>,
    /// Fail every `read` of a SPECIFIC manifest path. Used by the D1(b)
    /// verification-read test to fail the `verify_claimed_untouched` re-read
    /// of one left-alone entry while the run's other reads succeed.
    fail_read_for: Option<String>,
    /// A destination mutation applied after the Nth `write` FAILS (returns
    /// `Err`): a writer that changes the destination KIND after a failed install
    /// and before the single settle restore (the Finding-2 restore case).
    mutate_after_failed_write: Option<(usize, AfterWrite)>,
    /// A destination mutation applied BEFORE the Nth DIRECTORY removal (counting
    /// `remove_dir` and `remove_dir_all` together): a writer that creates an
    /// entry in the window between the removal walk's enumeration and the
    /// directory's own removal. The removal must then REFUSE LOUDLY (ENOTEMPTY
    /// for the non-recursive primitive) instead of destroying the new entry.
    before_dir_removal: Option<(usize, AfterWrite)>,
    dir_removals: AtomicUsize,
    first_op_fired: AtomicBool,
    ops: AtomicUsize,
    writes: AtomicUsize,
    /// `list` calls seen: the LISTING-COUNT instrument for the F2 bound. A
    /// directory with N entries must cost O(1) listings, so this counts the
    /// delegation to the destination listing seam.
    list_calls: AtomicUsize,
    /// `metadata`/`metadata_opt` calls seen: the F1 instrument. `Side::kind_opt`
    /// and `Side::mode`/`mode_opt` on a `Side::Remote` destination both route
    /// through this one call, one per probed PATH, so a depth-D ancestry walk
    /// that re-probes every prefix per ancestor shows up here as O(D^2) while
    /// the memoized form is O(D).
    metadata_calls: AtomicUsize,
    calls: Mutex<Vec<(String, String)>>,
    set_modes: Mutex<Vec<(String, u32)>>,
}

impl RecordingRemote {
    fn over(inner: LocalTransport, is_local: bool) -> RecordingRemote {
        RecordingRemote {
            inner,
            is_local,
            fail_writes: false,
            fail_nth_write: None,
            fail_write_after_write: false,
            fail_nth_set_mode: None,
            fail_reads: false,
            fail_create_dir_all: false,
            fail_create_dir_all_after_create: false,
            fail_symlink: false,
            fail_remove_file: false,
            fail_nth_remove_after_remove: None,
            drop_modes: false,
            drop_mode_for: None,
            dropped_modes: Mutex::new(Vec::new()),
            removals: AtomicUsize::new(0),
            drop_write_mode: false,
            fail_metadata_after_write: false,
            fail_nth_rename: None,
            fail_nth_rename_after_rename: None,
            vanish_nth_rename: None,
            fail_metadata_for_reserved_after_rename: false,
            renames: AtomicUsize::new(0),
            remove_files: AtomicUsize::new(0),
            rename_targets: Mutex::new(Vec::new()),
            set_mode_calls: AtomicUsize::new(0),
            exec_failure: None,
            identity_calls: AtomicUsize::new(0),
            identity_op_index: Mutex::new(Vec::new()),
            identity_failure: None,
            remote_requests: AtomicUsize::new(0),
            manifest_output: None,
            after_write: None,
            after_rename: None,
            after_removal: None,
            #[cfg(unix)]
            swap_dir_with_symlink_before_first_op: None,
            mutate_before_first_op: None,
            pull_writer: None,
            source_writer: None,
            dest_read_writer: None,
            dest_read_counts: Mutex::new(BTreeMap::new()),
            dest_read_before_writer: None,
            dest_read_before_counts: Mutex::new(BTreeMap::new()),
            reads: AtomicUsize::new(0),
            fail_nth_read: None,
            fail_read_for: None,
            mutate_after_failed_write: None,
            before_dir_removal: None,
            dir_removals: AtomicUsize::new(0),
            first_op_fired: AtomicBool::new(false),
            ops: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            list_calls: AtomicUsize::new(0),
            metadata_calls: AtomicUsize::new(0),
            calls: Mutex::new(Vec::new()),
            set_modes: Mutex::new(Vec::new()),
        }
    }

    /// Return `output` as a successful perl verification-script run, so the
    /// far side is described by a crafted manifest instead of this host's tree.
    fn with_manifest_output(mut self, output: String) -> RecordingRemote {
        self.manifest_output = Some(output);
        self
    }

    /// Arm a one-shot swap of the directory at `dir` for a symlink to
    /// `outside`, applied before the first trait operation.
    #[cfg(unix)]
    fn swapping_before_first_op(mut self, dir: PathBuf, outside: PathBuf) -> RecordingRemote {
        self.swap_dir_with_symlink_before_first_op = Some((dir, outside));
        self
    }

    /// Fire the one-shot swap, at most once per transport.
    #[cfg(unix)]
    fn maybe_swap_before_first_op(&self) {
        self.note_remote_request();
        if self.first_op_fired.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some((dir, outside)) = &self.swap_dir_with_symlink_before_first_op {
            let _ = fs::remove_dir_all(dir);
            std::os::unix::fs::symlink(outside, dir).unwrap();
        }
        if let Some(action) = &self.mutate_before_first_op {
            action.apply(self.inner.root());
        }
    }
    #[cfg(not(unix))]
    fn maybe_swap_before_first_op(&self) {
        self.note_remote_request();
        if self.first_op_fired.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(action) = &self.mutate_before_first_op {
            action.apply(self.inner.root());
        }
    }

    fn ops(&self) -> usize {
        self.ops.load(Ordering::SeqCst)
    }

    fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    /// The number of destination listings (`Remote::list`) this run performed.
    fn lists(&self) -> usize {
        self.list_calls.load(Ordering::SeqCst)
    }

    /// The number of destination metadata probes (`Remote::metadata`, which is
    /// what `Side::kind_opt`/`Side::mode`/`Side::mode_opt` call on a remote
    /// destination) this run performed.
    fn metadata_probes(&self) -> usize {
        self.metadata_calls.load(Ordering::SeqCst)
    }

    /// The number of `prepare_identity` calls this transport saw (F1).
    fn identity_calls(&self) -> usize {
        self.identity_calls.load(Ordering::SeqCst)
    }

    /// The remote-request count observed at each `prepare_identity` call (F1):
    /// `[0]` means the identity was prepared before ANY remote request.
    fn identity_op_index(&self) -> Vec<usize> {
        self.identity_op_index.lock().unwrap().clone()
    }

    /// The number of remote requests (ANY trait operation) this transport saw.
    fn remote_requests(&self) -> usize {
        self.remote_requests.load(Ordering::SeqCst)
    }

    /// Count one remote request. Every trait operation that reaches the wire
    /// calls this; `prepare_identity` deliberately does NOT.
    fn note_remote_request(&self) {
        self.remote_requests.fetch_add(1, Ordering::SeqCst);
    }

    /// Run the failed-write writer, if this is the write it targets.
    fn maybe_mutate_after_failed_write(&self) {
        if let Some((nth, action)) = &self.mutate_after_failed_write
            && self.writes() == *nth
        {
            action.apply(self.inner.root());
        }
    }

    /// Fire the directory-removal writer, if this is the directory removal it
    /// targets. Counts `remove_dir` and `remove_dir_all` together, so the same
    /// hook wins the window whichever primitive the implementation uses.
    fn maybe_mutate_before_dir_removal(&self) {
        let nth = self.dir_removals.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some((target, action)) = &self.before_dir_removal
            && nth == *target
        {
            action.apply(self.inner.root());
        }
    }

    fn calls(&self) -> Vec<(String, String)> {
        self.calls.lock().unwrap().clone()
    }

    fn set_modes(&self) -> Vec<(String, u32)> {
        self.set_modes.lock().unwrap().clone()
    }

    /// The exact `(path, mode)` calls dropped by the named `drop_mode_for`
    /// seam. A test asserts this equals the ONE call it meant to drop, so a
    /// never-reached or retargeted seam fails loudly instead of passing
    /// vacuously.
    fn dropped_modes(&self) -> Vec<(String, u32)> {
        self.dropped_modes.lock().unwrap().clone()
    }

    /// The `to` spelling of every `rename` call, in order.
    fn rename_targets(&self) -> Vec<String> {
        self.rename_targets.lock().unwrap().clone()
    }

    fn record(&self, op: &str, rel: &RootedRelativePath) {
        self.ops.fetch_add(1, Ordering::SeqCst);
        if op == "write" {
            self.writes.fetch_add(1, Ordering::SeqCst);
        }
        self.calls
            .lock()
            .unwrap()
            .push((op.to_string(), rel.to_string()));
    }

    /// Shared claim/ordinary rename logic. `aside` selects the SANCTIONED
    /// residue-movement primitive on the inner transport (the engine's own
    /// claim-aside rename), while the fault accounting and recording are the
    /// SAME for both so the existing injections still fire.
    fn rename_impl(
        &self,
        from: &RootedRelativePath,
        to: &RootedRelativePath,
        aside: bool,
    ) -> Result<()> {
        self.maybe_swap_before_first_op();
        self.record("rename", from);
        self.rename_targets.lock().unwrap().push(to.to_string());
        let nth = self.renames.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_nth_rename == Some(nth) {
            return Err(Error::transport(format!("injected rename failure #{nth}")));
        }
        if self.fail_nth_rename_after_rename == Some(nth) {
            // Move the entry FIRST, then report the failure: the rename LANDED.
            if aside {
                self.inner.rename_aside(from, to)?;
            } else {
                self.inner.rename(from, to)?;
            }
            return Err(Error::transport(format!(
                "injected rename failure #{nth} after the entry moved"
            )));
        }
        if self.vanish_nth_rename == Some(nth) {
            // Remove the source entry and report failure: afterwards the entry
            // is at NEITHER the source nor the destination spelling.
            //
            // This models a FOREIGN `rename(2)` that unlinked the source, so it
            // DELIBERATELY bypasses the crate's guarded recursive removal: since
            // R1 that primitive REFUSES to destroy a subtree holding residue (a
            // source can hold a nested `.sync-aside.`), and a foreign rename is
            // exactly the case the guard does not and cannot cover.
            if let Ok(Some(meta)) = self.inner.metadata_opt(from) {
                let absolute = self.inner.root().join(from.as_path());
                if meta.is_dir {
                    let _ = std::fs::remove_dir_all(absolute);
                } else {
                    let _ = std::fs::remove_file(absolute);
                }
            }
            return Err(Error::transport(format!(
                "injected rename failure #{nth} after the entry vanished"
            )));
        }
        if aside {
            self.inner.rename_aside(from, to)?;
        } else {
            self.inner.rename(from, to)?;
        }
        if let Some((nth, action)) = &self.after_rename
            && self.renames.load(Ordering::SeqCst) == *nth
        {
            action.apply(self.inner.root());
        }
        Ok(())
    }

    /// Shared remove-file logic; `residue` selects the sanctioned claim-aside
    /// primitive on the inner transport, while the fault accounting and
    /// recording are the SAME so the existing injections still fire.
    fn remove_file_impl(&self, rel: &RootedRelativePath, residue: bool) -> Result<()> {
        self.maybe_swap_before_first_op();
        self.record("remove_file", rel);
        self.removals.fetch_add(1, Ordering::SeqCst);
        if let Some(nth) = self.fail_nth_remove_after_remove {
            let call = self.remove_files.fetch_add(1, Ordering::SeqCst) + 1;
            if call == nth {
                // Unlink FIRST, then report the failure: the entry is gone
                // while the caller sees an error.
                if residue {
                    self.inner.remove_residue_file(rel)?;
                } else {
                    self.inner.remove_file(rel)?;
                }
                return Err(Error::transport(format!(
                    "injected remove_file failure #{call} after the entry was unlinked"
                )));
            }
        }
        if self.fail_remove_file {
            return Err(Error::transport("injected remove_file failure"));
        }
        if residue {
            self.inner.remove_residue_file(rel)?;
        } else {
            self.inner.remove_file(rel)?;
        }
        if let Some((nth, action)) = &self.after_removal
            && self.removals.load(Ordering::SeqCst) == *nth
        {
            action.apply(self.inner.root());
        }
        Ok(())
    }

    /// Shared remove-dir logic; `residue` selects the sanctioned claim-aside
    /// primitive on the inner transport.
    fn remove_dir_impl(&self, rel: &RootedRelativePath, residue: bool) -> Result<()> {
        self.maybe_swap_before_first_op();
        self.record("remove_dir", rel);
        self.removals.fetch_add(1, Ordering::SeqCst);
        self.maybe_mutate_before_dir_removal();
        if residue {
            self.inner.remove_residue_dir(rel)?;
        } else {
            self.inner.remove_dir(rel)?;
        }
        if let Some((nth, action)) = &self.after_removal
            && self.removals.load(Ordering::SeqCst) == *nth
        {
            action.apply(self.inner.root());
        }
        Ok(())
    }
}

impl Remote for RecordingRemote {
    fn root(&self) -> &Path {
        self.inner.root()
    }
    fn is_local(&self) -> bool {
        self.is_local
    }
    fn prepare_identity(&self) -> Result<()> {
        self.identity_calls.fetch_add(1, Ordering::SeqCst);
        self.identity_op_index
            .lock()
            .unwrap()
            .push(self.remote_requests.load(Ordering::SeqCst));
        if let Some(message) = &self.identity_failure {
            return Err(Error::transport(message.clone()));
        }
        Ok(())
    }
    fn read(&self, rel: &RootedRelativePath) -> Result<Vec<u8>> {
        self.maybe_swap_before_first_op();
        if self.fail_reads {
            return Err(Error::transport("injected read failure"));
        }
        // `reads` counts read ATTEMPTS before the failure check so
        // `fail_nth_read` and `pull_writer` can address one position.
        let nth = self.reads.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_nth_read == Some(nth) {
            return Err(Error::transport(format!("injected read failure #{nth}")));
        }
        if let Some(path) = &self.fail_read_for
            && rel.as_path().to_string_lossy() == path.as_str()
        {
            return Err(Error::transport(format!(
                "injected read failure for {path}"
            )));
        }
        // The BEFORE-READ window writer: a concurrent deletion the append's own
        // byte read then observes as an error (not as absent bytes). Counted
        // separately from the after-read hook so the two can be armed together.
        if let Some((path, target, action)) = &self.dest_read_before_writer {
            let spelled = rel.as_path().to_string_lossy().into_owned();
            if &spelled == path {
                let mut counts = self.dest_read_before_counts.lock().unwrap();
                let count = counts.entry(spelled).or_insert(0);
                *count += 1;
                if *count == *target {
                    action.apply(self.inner.root());
                }
            }
        }
        let bytes = self.inner.read(rel)?;
        // After the Nth successful source read, run the pull-writer hook against
        // the LOCAL destination root: a writer on the confined `Side::Local`
        // tree, which no wrapper can intercept.
        if let Some((target, root, action)) = &self.pull_writer
            && nth == *target
        {
            action.apply(root);
        }
        // After the Nth successful source read, run the SOURCE-writer hook
        // against the stored SOURCE root: the tree the run planned against
        // changes underneath it.
        if let Some((target, root, action)) = &self.source_writer
            && nth == *target
        {
            action.apply(root);
        }
        // The A2 window writer: count reads of THIS path and fire on the
        // requested one. The destination manifest hash read is the first read
        // of a file, so the append's own destination read is a later count.
        if let Some((path, target, action)) = &self.dest_read_writer {
            let spelled = rel.as_path().to_string_lossy().into_owned();
            if &spelled == path {
                let mut counts = self.dest_read_counts.lock().unwrap();
                let count = counts.entry(spelled).or_insert(0);
                *count += 1;
                if *count == *target {
                    action.apply(self.inner.root());
                }
            }
        }
        Ok(bytes)
    }
    fn write(&self, rel: &RootedRelativePath, data: &[u8], mode: u32) -> Result<()> {
        self.maybe_swap_before_first_op();
        self.record("write", rel);
        if self.fail_writes {
            self.maybe_mutate_after_failed_write();
            return Err(Error::transport("injected write failure"));
        }
        if self.fail_nth_write == Some(self.writes()) {
            self.maybe_mutate_after_failed_write();
            return Err(Error::transport(format!(
                "injected write failure #{}",
                self.writes()
            )));
        }
        if self.drop_write_mode {
            // Install the bytes but ignore the requested mode (mode 0 makes the
            // LocalTransport skip its chmod), so a mode check must catch it.
            return self.inner.write(rel, data, 0);
        }
        if self.fail_write_after_write {
            // Publish the bytes and THEN fail: the entry is visible on disk
            // while the caller sees an error.
            self.inner.write(rel, data, mode)?;
            return Err(Error::transport(
                "injected write failure after the entry became visible",
            ));
        }
        self.inner.write(rel, data, mode)?;
        if let Some((nth, action)) = &self.after_write
            && self.writes() == *nth
        {
            action.apply(self.inner.root());
        }
        Ok(())
    }
    fn try_write_new(&self, rel: &RootedRelativePath, data: &[u8]) -> Result<CreateNewVerdict> {
        self.note_remote_request();
        self.record("try_write_new", rel);
        self.inner.try_write_new(rel, data)
    }
    fn create_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        self.note_remote_request();
        self.record("create_dir", rel);
        self.inner.create_dir(rel)
    }
    fn create_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
        self.maybe_swap_before_first_op();
        self.record("create_dir_all", rel);
        if self.fail_create_dir_all {
            return Err(Error::transport("injected create_dir_all failure"));
        }
        if self.fail_create_dir_all_after_create {
            // Create first, then fail: the caller must roll back its OWN
            // partial creation before restoring the claimed entry.
            self.inner.create_dir_all(rel)?;
            return Err(Error::transport(
                "injected create_dir_all failure after creation",
            ));
        }
        self.inner.create_dir_all(rel)
    }
    fn set_mode(&self, rel: &RootedRelativePath, mode: u32) -> Result<()> {
        self.maybe_swap_before_first_op();
        self.record("set_mode", rel);
        self.set_modes.lock().unwrap().push((rel.to_string(), mode));
        let nth = self.set_mode_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_nth_set_mode == Some(nth) {
            return Err(Error::transport(format!(
                "injected set_mode failure #{nth}"
            )));
        }
        if let Some((target, target_mode, when)) = &self.drop_mode_for
            && mode == *target_mode
            && target.matches(&rel.to_string())
            && (*when == DropModeWhen::Always || self.removals.load(Ordering::SeqCst) > 0)
        {
            // Report success but leave the mode unchanged, identified by the
            // PATH and the requested MODE rather than a call position.
            self.dropped_modes
                .lock()
                .unwrap()
                .push((rel.to_string(), mode));
            return Ok(());
        }
        if self.drop_modes {
            return Ok(());
        }
        self.inner.set_mode(rel, mode)
    }
    fn list(&self, rel: &RootedRelativePath) -> Result<Vec<RemoteEntry>> {
        self.maybe_swap_before_first_op();
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.list(rel)
    }
    fn rename(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
        self.rename_impl(from, to, false)
    }
    fn rename_aside(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
        self.rename_impl(from, to, true)
    }
    fn remove_residue_file(&self, rel: &RootedRelativePath) -> Result<()> {
        self.remove_file_impl(rel, true)
    }
    fn remove_residue_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        self.remove_dir_impl(rel, true)
    }
    fn symlink(&self, target: &Path, link: &RootedRelativePath) -> Result<()> {
        self.maybe_swap_before_first_op();
        self.record("symlink", link);
        if self.fail_symlink {
            return Err(Error::transport("injected symlink failure"));
        }
        self.inner.symlink(target, link)
    }
    fn read_link(&self, rel: &RootedRelativePath) -> Result<PathBuf> {
        self.note_remote_request();
        self.inner.read_link(rel)
    }
    fn remove_file(&self, rel: &RootedRelativePath) -> Result<()> {
        self.remove_file_impl(rel, false)
    }
    fn remove_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
        self.maybe_swap_before_first_op();
        self.record("remove_dir_all", rel);
        self.removals.fetch_add(1, Ordering::SeqCst);
        self.maybe_mutate_before_dir_removal();
        self.inner.remove_dir_all(rel)?;
        if let Some((nth, action)) = &self.after_removal
            && self.removals.load(Ordering::SeqCst) == *nth
        {
            action.apply(self.inner.root());
        }
        Ok(())
    }
    fn remove_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        self.remove_dir_impl(rel, false)
    }
    fn exists(&self, rel: &RootedRelativePath) -> bool {
        self.maybe_swap_before_first_op();
        self.inner.exists(rel)
    }
    fn metadata(&self, rel: &RootedRelativePath) -> Result<RemoteMeta> {
        self.metadata_calls.fetch_add(1, Ordering::SeqCst);
        self.maybe_swap_before_first_op();
        if self.fail_metadata_after_write && self.writes() > 0 {
            // The bytes are already on disk; the mode read that follows them
            // fails. `metadata_opt` propagates this (never a silent `None`).
            return Err(Error::transport(
                "injected metadata failure after a successful write",
            ));
        }
        if self.fail_metadata_for_reserved_after_rename
            && self.renames.load(Ordering::SeqCst) > 0
            && is_reserved_path(&rel.to_string())
        {
            // A degraded session: the rename has happened and the follow-up
            // probe of the reserved aside ALSO fails, so the entry's location
            // cannot be confirmed. `metadata_opt` propagates the error.
            return Err(Error::transport(
                "injected metadata failure for a reserved aside",
            ));
        }
        self.inner.metadata(rel)
    }
    fn exec(&self, argv: &[String], timeout: Duration) -> Result<ExecOutcome> {
        self.note_remote_request();
        if let Some(out) = &self.exec_failure {
            return Ok(out.clone());
        }
        if let Some(output) = &self.manifest_output
            && argv.first().is_some_and(|arg| arg == "perl")
        {
            return Ok(ExecOutcome {
                exit_code: 0,
                stdout: output.clone(),
                stderr: String::new(),
                timeout_cause: None,
            });
        }
        self.inner.exec(argv, timeout)
    }
    fn filesystem_bytes(&self) -> Result<FsBytes> {
        self.note_remote_request();
        self.inner.filesystem_bytes()
    }
}

/// A PATH-BASED [`Remote`] test double: every operation is the plain
/// `root.join(rel)` form backed by `std::fs`, so a symlink in ANY component is
/// FOLLOWED — the situation an [`SshTransport`](crate::transport::SshTransport)
/// far side presents, where the applier's preflight is the ONLY confinement.
/// The fd-confined [`LocalTransport`] refuses a swapped component itself, so it
/// cannot exercise this class of defect. `is_local()` is true so the manifest is
/// read in process.
///
/// `after_write` mirrors [`RecordingRemote`]'s hook: after the Nth successful
/// `write` the given [`AfterWrite`] runs against the root, so a test can swap a
/// directory for an out-of-tree symlink AFTER an earlier transfer already
/// confirmed it is a real directory.
#[cfg(unix)]
struct PathRemote {
    root: PathBuf,
    writes: AtomicUsize,
    after_write: Option<(usize, AfterWrite)>,
}

#[cfg(unix)]
impl PathRemote {
    fn over(root: &Path) -> PathRemote {
        PathRemote {
            root: root.to_path_buf(),
            writes: AtomicUsize::new(0),
            after_write: None,
        }
    }

    fn after_write(mut self, nth: usize, action: AfterWrite) -> PathRemote {
        self.after_write = Some((nth, action));
        self
    }

    fn path(&self, rel: &RootedRelativePath) -> PathBuf {
        self.root.join(rel.as_path())
    }
}

#[cfg(unix)]
impl Remote for PathRemote {
    fn root(&self) -> &Path {
        &self.root
    }

    fn is_local(&self) -> bool {
        true
    }

    fn read(&self, rel: &RootedRelativePath) -> Result<Vec<u8>> {
        std::fs::read(self.path(rel))
            .map_err(|e| Error::transport(format!("read {}: {e}", rel.display())))
    }

    fn write(&self, rel: &RootedRelativePath, data: &[u8], mode: u32) -> Result<()> {
        // PATH-BASED AND SYMLINK-FOLLOWING: exactly the far-side write the
        // preflight exists to confine.
        let path = self.path(rel);
        std::fs::write(&path, data)
            .map_err(|e| Error::transport(format!("write {}: {e}", rel.display())))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| Error::transport(format!("chmod {}: {e}", rel.display())))?;
        let nth = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
        if let Some((target, action)) = &self.after_write
            && nth == *target
        {
            action.apply(&self.root);
        }
        Ok(())
    }

    fn try_write_new(&self, rel: &RootedRelativePath, _data: &[u8]) -> Result<CreateNewVerdict> {
        // The sync path never calls create-new; a test double is honest about
        // that rather than emulating a primitive it is not exercising.
        Err(Error::transport(format!(
            "PathRemote::try_write_new is not exercised by the sync path ({})",
            rel.display()
        )))
    }

    fn create_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        match std::fs::create_dir(self.path(rel)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(Error::transport(format!(
                "create_dir {}: {e}",
                rel.display()
            ))),
        }
    }

    fn create_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
        std::fs::create_dir_all(self.path(rel))
            .map_err(|e| Error::transport(format!("create_dir_all {}: {e}", rel.display())))
    }

    fn set_mode(&self, rel: &RootedRelativePath, mode: u32) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(self.path(rel), std::fs::Permissions::from_mode(mode))
            .map_err(|e| Error::transport(format!("chmod {}: {e}", rel.display())))
    }

    fn list(&self, rel: &RootedRelativePath) -> Result<Vec<RemoteEntry>> {
        let dir = self.path(rel);
        let mut out = Vec::new();
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| Error::transport(format!("list {}: {e}", rel.display())))?;
        for entry in entries {
            let entry = entry
                .map_err(|e| Error::transport(format!("list entry in {}: {e}", rel.display())))?;
            let meta = std::fs::symlink_metadata(entry.path())
                .map_err(|e| Error::transport(format!("stat {}: {e}", entry.path().display())))?;
            out.push(RemoteEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                is_dir: meta.is_dir(),
                is_symlink: meta.file_type().is_symlink(),
                size: meta.len(),
                mode: crate::platform::metadata_mode(&meta) & 0o7777,
            });
        }
        Ok(out)
    }

    fn rename(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
        std::fs::rename(self.path(from), self.path(to)).map_err(|e| {
            Error::transport(format!(
                "rename {} -> {}: {e}",
                from.display(),
                to.display()
            ))
        })
    }

    fn symlink(&self, target: &Path, link: &RootedRelativePath) -> Result<()> {
        std::os::unix::fs::symlink(target, self.path(link))
            .map_err(|e| Error::transport(format!("symlink {}: {e}", link.display())))
    }

    fn read_link(&self, rel: &RootedRelativePath) -> Result<PathBuf> {
        std::fs::read_link(self.path(rel))
            .map_err(|e| Error::transport(format!("read_link {}: {e}", rel.display())))
    }

    fn remove_file(&self, rel: &RootedRelativePath) -> Result<()> {
        match std::fs::remove_file(self.path(rel)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::transport(format!(
                "remove_file {}: {e}",
                rel.display()
            ))),
        }
    }

    fn remove_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
        std::fs::remove_dir_all(self.path(rel))
            .map_err(|e| Error::transport(format!("remove_dir_all {}: {e}", rel.display())))
    }

    fn remove_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        std::fs::remove_dir(self.path(rel))
            .map_err(|e| Error::transport(format!("remove_dir {}: {e}", rel.display())))
    }

    fn exists(&self, rel: &RootedRelativePath) -> bool {
        self.path(rel).exists()
    }

    fn metadata(&self, rel: &RootedRelativePath) -> Result<RemoteMeta> {
        let path = self.path(rel);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => Ok(RemoteMeta {
                is_dir: meta.is_dir(),
                is_symlink: meta.file_type().is_symlink(),
                is_file: meta.is_file(),
                size: meta.len(),
                mode: crate::platform::metadata_mode(&meta) & 0o7777,
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::NotFound(format!("{}", rel.display())))
            }
            Err(e) => Err(Error::transport(format!("stat {}: {e}", rel.display()))),
        }
    }

    fn exec(&self, _argv: &[String], _timeout: Duration) -> Result<ExecOutcome> {
        Err(Error::transport("PathRemote does not exec"))
    }

    fn filesystem_bytes(&self) -> Result<FsBytes> {
        Ok(FsBytes {
            total: 0,
            available: u64::MAX,
        })
    }
}

#[test]
fn push_makes_destination_equal_to_source() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    build_rich_tree(&src);
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();
    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert_eq!(
        canonicalize_tree(&src).unwrap(),
        canonicalize_tree(&dst).unwrap()
    );
}

#[test]
fn pull_makes_local_equal_to_remote() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    build_rich_tree(&remote_root);
    let local = dir.path().join("local");
    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &ReplaceAll,
        Keep,
    )
    .unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert_eq!(
        canonicalize_tree(&local).unwrap(),
        canonicalize_tree(&remote_root).unwrap()
    );
}

/// B1 end to end: a source holding `dir/link -> ../other` (an in-root relative
/// target that walks up out of the link's directory) is snapshotted and
/// round-trips through a PUSH and a PULL, and the destination holds the link as
/// a RELATIVE link with the SAME target, resolving to the copied `other`.
/// Pre-fix the source manifest refused the whole tree as an escaping symlink,
/// so nothing could be pushed or pulled at all.
#[cfg(unix)]
#[test]
fn an_in_root_relative_symlink_round_trips_through_push_and_pull() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    fs::create_dir_all(src.join("dir")).unwrap();
    fs::create_dir_all(src.join("other")).unwrap();
    write(&src.join("other/file"), b"payload");
    std::os::unix::fs::symlink("../other", src.join("dir/link")).unwrap();

    // PUSH into a fresh local root.
    let dst = dir.path().join("dst");
    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert!(report.conflicts.is_empty(), "{report:?}");
    let link = dst.join("dir/link");
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the pushed entry is a link, never followed"
    );
    assert_eq!(
        fs::read_link(&link).unwrap(),
        PathBuf::from("../other"),
        "the in-root relative target is preserved as a relative link"
    );
    assert_eq!(
        read(&link.join("file")),
        b"payload",
        "the link resolves into the copied tree"
    );

    // PULL the same source into another fresh local root.
    let pulled = dir.path().join("pulled");
    let report = owned(
        Direction::Pull,
        &pulled,
        &transport(&src),
        &ReplaceAll,
        Keep,
    )
    .unwrap();
    assert!(report.conflicts.is_empty(), "{report:?}");
    let plink = pulled.join("dir/link");
    assert!(
        fs::symlink_metadata(&plink)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_link(&plink).unwrap(), PathBuf::from("../other"));
    assert_eq!(read(&plink.join("file")), b"payload");
    assert_eq!(
        canonicalize_tree(&src).unwrap(),
        canonicalize_tree(&pulled).unwrap()
    );
}

/// The reviewer's escape tree must be refused by a REAL push and a REAL pull,
/// not only by `canonicalize_tree`: the strict SOURCE manifest is the gate and
/// it fires before any mutation. `src/dir/sub -> ../other` is an accepted
/// in-root link, and `src/dir/link -> sub/../../outside` walks THROUGH it, so
/// the kernel reaches `../outside/secret` even though the lexical collapse
/// says `<root>/outside`. The link really does escape on the live tree, and the
/// sync must refuse rather than reproduce it.
#[cfg(unix)]
#[test]
fn an_escaping_symlink_target_is_refused_by_push_and_pull() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let outside = dir.path().join("outside");
    fs::create_dir_all(src.join("dir")).unwrap();
    fs::create_dir_all(src.join("other")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    write(&src.join("other/file"), b"payload");
    write(&outside.join("secret"), b"SECRET");
    std::os::unix::fs::symlink("../other", src.join("dir/sub")).unwrap();
    std::os::unix::fs::symlink("sub/../../outside", src.join("dir/link")).unwrap();
    assert_eq!(
        read(&src.join("dir/link/secret")),
        b"SECRET",
        "the escape is real on the live source before the sync runs"
    );

    // PUSH: refused at the source manifest; nothing is materialized.
    let dst = dir.path().join("dst");
    let err = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap_err();
    assert!(
        err.to_string().contains("escaping symlink"),
        "push must refuse the escaping link, got: {err}"
    );
    assert!(
        fs::symlink_metadata(dst.join("dir/link")).is_err(),
        "the escaping link must never be materialized"
    );
    assert_eq!(read(&outside.join("secret")), b"SECRET");

    // PULL: the same source as the far side, the same refusal.
    let pulled = dir.path().join("pulled");
    let err = owned(
        Direction::Pull,
        &pulled,
        &transport(&src),
        &ReplaceAll,
        Keep,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("escaping symlink"),
        "pull must refuse the escaping link, got: {err}"
    );
    assert!(
        fs::symlink_metadata(pulled.join("dir/link")).is_err(),
        "the escaping link must never be materialized"
    );
}

/// G2: the containment answer must be a property of the RESULT, not of the
/// SOURCE alone. The source here holds `dir/link -> sub/../../outside` with NO
/// `dir/sub` (so the SOURCE rule lawfully accepts it: the walk reaches no
/// symlink and never pops above the root), while the DESTINATION already holds
/// `dir/sub -> ../other` (an in-root symlink the tolerant destination model
/// enumerates). Under the default `Extraneous::Keep` that destination entry
/// survives the run, the installed `dir/link` walks THROUGH it, and
/// `read(dst/dir/link/secret)` returned the outside canary.
///
/// Pre-fix the run reported `Ok` and the link escaped. Post-fix the run is
/// REFUSED before any transfer, naming the destination component; nothing is
/// materialized.
#[cfg(unix)]
#[test]
fn a_destination_resident_symlink_component_makes_the_run_refuse() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    let outside = dir.path().join("outside");
    fs::create_dir_all(src.join("dir")).unwrap();
    write(&src.join("dir/keep"), b"payload");
    // No `src/dir/sub`, so the SOURCE rule accepts this link.
    std::os::unix::fs::symlink("sub/../../outside", src.join("dir/link")).unwrap();
    fs::create_dir_all(dst.join("dir/other")).unwrap();
    std::os::unix::fs::symlink("../other", dst.join("dir/sub")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    write(&outside.join("secret"), b"SECRET");

    let err = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("escaping symlink") && msg.contains("dir/sub"),
        "the run must refuse, naming the destination component, got: {msg}"
    );
    assert!(
        fs::symlink_metadata(dst.join("dir/link")).is_err(),
        "the escaping link must never be materialized: {err}"
    );
    assert_eq!(read(&outside.join("secret")), b"SECRET");

    // CONTROL A: the SAME source, with `dir/sub` a REAL destination directory,
    // is lawful and must still succeed.
    let dst_real = dir.path().join("dst-real");
    fs::create_dir_all(dst_real.join("dir/sub")).unwrap();
    fs::create_dir_all(dst_real.join("dir/other")).unwrap();
    let report = owned(
        Direction::Push,
        &src,
        &transport(&dst_real),
        &ReplaceAll,
        Keep,
    )
    .expect("a real destination directory at the traversed component is lawful");
    assert!(report.conflicts.is_empty(), "{report:?}");
    assert_eq!(read(&dst_real.join("dir/keep")), b"payload");
    assert!(
        fs::symlink_metadata(dst_real.join("dir/link"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the in-root link is installed"
    );
}

/// G2, control B: `Extraneous::Delete` removes the destination-only symlink at
/// the traversed component, so the same source link no longer escapes and the
/// sanctioned removal still runs.
#[cfg(unix)]
#[test]
fn extraneous_delete_neutralizes_the_destination_resident_symlink_component() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(src.join("dir")).unwrap();
    write(&src.join("dir/keep"), b"payload");
    std::os::unix::fs::symlink("sub/../../outside", src.join("dir/link")).unwrap();
    fs::create_dir_all(dst.join("dir/other")).unwrap();
    std::os::unix::fs::symlink("../other", dst.join("dir/sub")).unwrap();

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete)
        .expect("the sanctioned deletion removes the traversed destination symlink");
    assert!(report.conflicts.is_empty(), "{report:?}");
    assert!(
        fs::symlink_metadata(dst.join("dir/sub")).is_err(),
        "the destination-only symlink at the traversed component is removed: {report:?}"
    );
    assert_eq!(read(&dst.join("dir/keep")), b"payload");
    assert!(
        fs::symlink_metadata(dst.join("dir/link"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the link is installed and now dangles instead of escaping"
    );
    assert!(
        fs::symlink_metadata(dst.join("dir/link/secret")).is_err(),
        "the link must not resolve to the outside canary"
    );
}

/// G2, the UNSUPPORTED variant: the destination holds `dir/sub ->
/// ../../outside` (an escaping symlink, so it is listed in
/// `unsupported_destination`) and the source does not hold `dir/sub`. Pre-fix
/// the report named the entry as unsupported yet the sync SUCCEEDED and the
/// installed link still escaped. The result-containment preflight now refuses
/// it, so an unsupported destination entry can never be the component a source
/// link escapes through.
#[cfg(unix)]
#[test]
fn an_unsupported_destination_symlink_component_cannot_be_escaped_through() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    let outside = dir.path().join("outside");
    fs::create_dir_all(src.join("dir")).unwrap();
    write(&src.join("dir/keep"), b"payload");
    std::os::unix::fs::symlink("sub/../../outside", src.join("dir/link")).unwrap();
    // The destination component escapes the destination root.
    fs::create_dir_all(dst.join("dir")).unwrap();
    std::os::unix::fs::symlink("../../outside", dst.join("dir/sub")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    write(&outside.join("secret"), b"SECRET");

    let err = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("escaping symlink") && msg.contains("dir/sub"),
        "the run must refuse, naming the unsupported destination component, got: {msg}"
    );
    assert!(
        fs::symlink_metadata(dst.join("dir/link")).is_err(),
        "the escaping link must never be materialized"
    );
    assert_eq!(read(&outside.join("secret")), b"SECRET");
}

#[test]
fn equal_trees_perform_zero_transfers() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    build_rich_tree(&src);
    build_rich_tree(&dst);
    let before = canonicalize_tree(&dst).unwrap();

    let remote = RecordingRemote::over(transport(&dst), true);
    let report = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap();
    assert_eq!(report.transfers, 0, "no destination mutation may run");
    assert_eq!(remote.ops(), 0, "the transport saw no mutating call");
    assert!(report.applied.is_empty());
    assert!(report.transient_dirs.is_empty());
    assert!(report.conflicts.is_empty());
    assert_eq!(report.skipped.len(), before.entries.len());
    assert_eq!(canonicalize_tree(&dst).unwrap(), before);

    let local = dir.path().join("local");
    build_rich_tree(&local);
    let before_local = canonicalize_tree(&local).unwrap();
    let remote_src = RecordingRemote::over(transport(&src), true);
    let report = owned(Direction::Pull, &local, &remote_src, &ReplaceAll, Keep).unwrap();
    assert_eq!(report.transfers, 0);
    assert_eq!(remote_src.ops(), 0);
    assert_eq!(canonicalize_tree(&local).unwrap(), before_local);
}

#[test]
fn refuse_leaves_destination_byte_identical_and_reports_a_conflict() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"new-bytes");
    write(&dst.join("f"), b"old-bytes");
    let before = read(&dst.join("f"));

    let remote = RecordingRemote::over(transport(&dst), true);
    let refuse = |_: &str, _: EntryKind| EntryPolicy::Refuse;
    let report = owned(Direction::Push, &src, &remote, &refuse, Keep).unwrap();

    assert!(report.applied.is_empty());
    assert_eq!(report.transfers, 0);
    assert_eq!(remote.ops(), 0);
    assert_eq!(report.conflicts.len(), 1);
    assert_eq!(report.conflicts[0].path, "f");
    assert_eq!(report.conflicts[0].reason, ConflictReason::Refused);
    assert_eq!(
        read(&dst.join("f")),
        before,
        "Refuse must leave the destination byte-identical"
    );
}

/// A `Refuse` on an EXISTING directory does not block its children and does
/// NOT change its own mode.
#[cfg(unix)]
#[test]
fn refuse_on_an_existing_directory_leaves_its_mode_untouched_while_children_proceed() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    for (root, a, b) in [
        (&src, &b"new-a"[..], &b"new-b"[..]),
        (&dst, &b"old-a"[..], &b"old-b"[..]),
    ] {
        write(&root.join("d/a"), a);
        write(&root.join("d/b"), b);
    }
    set_mode(&src.join("d"), 0o755);
    // The destination directory is writable, so the children can proceed
    // without widening it.
    set_mode(&dst.join("d"), 0o700);

    let refuse_d = |path: &str, _: EntryKind| {
        if path == "d" {
            EntryPolicy::Refuse
        } else {
            EntryPolicy::Replace
        }
    };
    let remote = RecordingRemote::over(transport(&dst), true);
    let report = owned(Direction::Push, &src, &remote, &refuse_d, Keep).unwrap();

    assert_eq!(report.conflicts.len(), 1);
    assert_eq!(report.conflicts[0].path, "d");
    assert_eq!(report.conflicts[0].reason, ConflictReason::Refused);
    assert_eq!(read(&dst.join("d/a")), b"new-a", "the child proceeds");
    assert_eq!(read(&dst.join("d/b")), b"new-b", "the child proceeds");
    assert_eq!(
        mode_of(&dst.join("d")),
        0o700,
        "the refused directory's own mode is left untouched"
    );
    assert!(
        !report.applied.contains(&"d".to_string()),
        "a refused directory is not applied"
    );
    assert!(
        !report.transient_dirs.contains(&"d".to_string()),
        "a refused directory is never widened"
    );
    assert!(
        remote.set_modes().iter().all(|(path, _)| path != "d"),
        "the refused directory is never chmodded: {:?}",
        remote.set_modes()
    );
}

#[test]
fn refusing_a_missing_directory_blocks_its_children_in_both_directions() {
    let refuse_dir = |path: &str, _: EntryKind| {
        if path == "d" {
            EntryPolicy::Refuse
        } else {
            EntryPolicy::Replace
        }
    };

    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("d/f"), b"x");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();
    let remote = RecordingRemote::over(transport(&dst), true);
    let report = owned(Direction::Push, &src, &remote, &refuse_dir, Keep).unwrap();
    assert!(report.applied.is_empty());
    assert_eq!(report.transfers, 0, "nothing is mutated");
    assert_eq!(remote.ops(), 0);
    assert!(!dst.join("d").exists());
    assert_eq!(report.conflicts.len(), 2);
    assert_eq!(conflict_at(&report, "d").reason, ConflictReason::Refused);
    assert_eq!(
        conflict_at(&report, "d/f").reason,
        ConflictReason::ParentRefused
    );

    let remote_root = dir.path().join("remote");
    write(&remote_root.join("d/f"), b"x");
    let local = dir.path().join("local");
    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &refuse_dir,
        Keep,
    )
    .unwrap();
    assert!(report.applied.is_empty());
    assert_eq!(report.transfers, 0);
    assert!(!local.exists(), "a refused pull creates nothing");
    assert_eq!(report.conflicts.len(), 2);
    assert_eq!(
        conflict_at(&report, "d/f").reason,
        ConflictReason::ParentRefused
    );
}

/// A `Refuse` on an existing READ-ONLY directory blocks the children it would
/// have to widen for (reported `ParentRefused`), rather than failing the sync
/// or mutating the refused path's mode.
#[cfg(unix)]
#[test]
fn refuse_on_a_read_only_existing_directory_blocks_its_children_without_mutating_it() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    for (root, content, mode) in [(&src, &b"new"[..], 0o755), (&dst, &b"old"[..], 0o555)] {
        write(&root.join("d/f"), content);
        set_mode(&root.join("d"), mode);
    }

    let refuse_d = |path: &str, _: EntryKind| {
        if path == "d" {
            EntryPolicy::Refuse
        } else {
            EntryPolicy::Replace
        }
    };
    let report = owned(Direction::Push, &src, &transport(&dst), &refuse_d, Keep).unwrap();
    assert_eq!(report.conflicts.len(), 2, "{:?}", report.conflicts);
    assert_eq!(conflict_at(&report, "d").reason, ConflictReason::Refused);
    assert_eq!(
        conflict_at(&report, "d/f").reason,
        ConflictReason::ParentRefused
    );
    assert_eq!(report.transfers, 0, "nothing is mutated");
    assert_eq!(
        mode_of(&dst.join("d")),
        0o555,
        "the refused mode is untouched"
    );
    assert_eq!(read(&dst.join("d/f")), b"old", "the child is untouched");
}

/// MED (round 15): a DIRECTORY over an EXISTING directory is a MODE-only change
/// — `transfer_dir` queues `pending_final` and `finalize` chmods the CHILD, so
/// nothing is written into the parent. Such a transfer needs TRAVERSE on a
/// refused ancestor, never write, so a refused READ-ONLY (traversable)
/// directory admits it; a refused directory WITHOUT traverse still blocks it.
#[cfg(unix)]
#[test]
fn a_directory_mode_change_under_a_refused_read_only_directory_is_not_refused() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let refuse_d = |path: &str, _: EntryKind| {
        if path == "d" {
            EntryPolicy::Refuse
        } else {
            EntryPolicy::Replace
        }
    };

    // PUSH: `d` is refused at 0o555 (traversable), so its `d/sub` mode change
    // (0755 -> 0700) applies; `d` itself is never widened and keeps 0o555.
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/sub/f"), b"new");
    write(&dst.join("d/sub/f"), b"new");
    set_mode(&src.join("d"), 0o755);
    set_mode(&src.join("d/sub"), 0o700);
    set_mode(&dst.join("d"), 0o555);
    set_mode(&dst.join("d/sub"), 0o755);
    let report = owned(Direction::Push, &src, &transport(&dst), &refuse_d, Keep).unwrap();
    assert_eq!(report.conflicts.len(), 1, "{:?}", report.conflicts);
    assert_eq!(conflict_at(&report, "d").reason, ConflictReason::Refused);
    assert!(
        report.applied.contains(&"d/sub".to_string()),
        "the directory mode change is applied through the refused traversable directory: {report:?}"
    );
    assert_eq!(mode_of(&dst.join("d/sub")), 0o700, "the child mode landed");
    assert_eq!(
        mode_of(&dst.join("d")),
        0o555,
        "the refused mode is untouched"
    );
    assert!(
        report.transient_dirs.is_empty(),
        "nothing under the refused directory is widened: {report:?}"
    );
    assert_report_lists_disjoint(&report);

    // PULL: the same shape through the confined local write path.
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    write(&remote_root.join("d/sub/f"), b"new");
    write(&local.join("d/sub/f"), b"new");
    set_mode(&remote_root.join("d"), 0o755);
    set_mode(&remote_root.join("d/sub"), 0o700);
    set_mode(&local.join("d"), 0o555);
    set_mode(&local.join("d/sub"), 0o755);
    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &refuse_d,
        Keep,
    )
    .unwrap();
    assert_eq!(report.conflicts.len(), 1, "{:?}", report.conflicts);
    assert_eq!(conflict_at(&report, "d").reason, ConflictReason::Refused);
    assert!(
        report.applied.contains(&"d/sub".to_string()),
        "the directory mode change is applied on the pull too: {report:?}"
    );
    assert_eq!(
        mode_of(&local.join("d/sub")),
        0o700,
        "the child mode landed"
    );
    assert_eq!(
        mode_of(&local.join("d")),
        0o555,
        "the refused mode is untouched"
    );
    assert_report_lists_disjoint(&report);
}

/// A child under a refused ancestor that is NOT an existing directory (here a
/// destination symlink) is refused rather than written THROUGH the symlink.
#[cfg(unix)]
#[test]
fn a_child_under_a_refused_non_directory_ancestor_is_not_written_through_it() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/f"), b"new");
    fs::create_dir_all(dst.join("other")).unwrap();
    std::os::unix::fs::symlink("other", dst.join("d")).unwrap();

    let refuse_d = |path: &str, _: EntryKind| {
        if path == "d" {
            EntryPolicy::Refuse
        } else {
            EntryPolicy::Replace
        }
    };
    let report = owned(Direction::Push, &src, &transport(&dst), &refuse_d, Keep).unwrap();
    assert_eq!(report.conflicts.len(), 2, "{:?}", report.conflicts);
    assert_eq!(conflict_at(&report, "d").reason, ConflictReason::Refused);
    assert_eq!(
        conflict_at(&report, "d/f").reason,
        ConflictReason::ParentRefused
    );
    assert!(
        !dst.join("other/f").exists(),
        "nothing is written through the symlinked parent"
    );
    assert!(
        fs::symlink_metadata(dst.join("d")).unwrap().is_symlink(),
        "the destination symlink is untouched"
    );
}

#[test]
fn append_tail_appends_the_missing_tail_and_writes_a_missing_file() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("grow"), b"abcdef");
    write(&src.join("fresh"), b"brand-new");
    write(&src.join("empty"), b"");
    write(&dst.join("grow"), b"abc");
    let before_dest = read(&dst.join("grow"));

    let report = owned(Direction::Push, &src, &transport(&dst), &append_files, Keep).unwrap();

    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    let after = read(&dst.join("grow"));
    assert!(after.starts_with(&before_dest));
    assert_eq!(after, b"abcdef", "the source tail is appended");
    assert_eq!(read(&dst.join("fresh")), b"brand-new");
    assert!(
        dst.join("empty").exists(),
        "a MISSING destination with a ZERO-LENGTH source is still created"
    );
    assert_eq!(read(&dst.join("empty")), b"");
    assert_eq!(
        canonicalize_tree(&dst).unwrap(),
        canonicalize_tree(&src).unwrap()
    );
}

#[test]
fn append_tail_writes_nothing_when_the_source_is_a_prefix() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"abc");
    write(&dst.join("f"), b"abcdef");

    let report = owned(Direction::Push, &src, &transport(&dst), &append_files, Keep).unwrap();

    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(report.applied.is_empty());
    assert_eq!(report.transfers, 0);
    assert!(report.skipped.contains(&"f".to_string()));
    assert_eq!(read(&dst.join("f")), b"abcdef", "never truncated");
}

#[test]
fn append_tail_diverged_reports_a_conflict_and_changes_nothing() {
    for (source, dest) in [
        (&b"abcdef"[..], &b"abcXYZ"[..]),
        (&b"abcd"[..], &b"abX"[..]),
    ] {
        let dir = fixture_tmpdir(&env()).unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        write(&src.join("f"), source);
        write(&dst.join("f"), dest);

        let report = owned(Direction::Push, &src, &transport(&dst), &append_files, Keep).unwrap();

        assert!(report.applied.is_empty());
        assert_eq!(report.transfers, 0);
        assert_eq!(report.conflicts.len(), 1);
        assert_eq!(report.conflicts[0].reason, ConflictReason::Diverged);
        assert_eq!(read(&dst.join("f")), dest);
    }
}

#[cfg(unix)]
#[test]
fn append_tail_no_op_applies_a_changed_mode_without_writing_bytes() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"same");
    write(&dst.join("f"), b"same");
    set_mode(&src.join("f"), 0o644);
    set_mode(&dst.join("f"), 0o600);

    let remote = RecordingRemote::over(transport(&dst), true);
    let report = owned(Direction::Push, &src, &remote, &append_files, Keep).unwrap();

    assert_eq!(remote.writes(), 0, "no bytes are written");
    assert!(report.transfers >= 1, "at least the mode application");
    assert!(report.applied.contains(&"f".to_string()));
    assert_eq!(mode_of(&dst.join("f")), 0o644);
}

#[test]
fn extraneous_is_reported_and_survives_then_is_removed_with_the_flag() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"x");
    write(&dst.join("f"), b"x");
    write(&dst.join("extra"), b"y");

    let kept = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert_eq!(kept.extraneous, vec!["extra".to_string()]);
    assert!(
        dst.join("extra").exists(),
        "default sync never deletes extraneous"
    );

    let removed = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert_eq!(removed.extraneous, vec!["extra".to_string()]);
    assert!(removed.transfers >= 1, "at least one removal");
    assert!(!dst.join("extra").exists());
}

#[test]
fn extraneous_directory_tree_is_removed_children_before_dirs() {
    // This pins `remove_extraneous`'s deepest-first ORDER and its END STATE for
    // a multi-level extraneous tree, plus that each reported extraneous path is
    // unlinked exactly once. It does NOT pin `remove_subtree`'s recursion:
    // because `remove_extraneous` itself walks deepest-first, this test passes
    // even if the recursion is replaced by a single per-entry call. The recursion
    // is pinned by `a_kind_changing_replacement_removes_a_read_only_subtree`,
    // where the claimed aside is never an extraneous entry and its nested
    // children can only be removed by `remove_subtree` itself.
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"x");
    write(&dst.join("f"), b"x");
    write(&dst.join("extra/a"), b"1");
    write(&dst.join("extra/sub/b"), b"2");

    let remote = RecordingRemote::over(transport(&dst), true);
    let report = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert_eq!(
        report.extraneous,
        vec![
            "extra".to_string(),
            "extra/a".to_string(),
            "extra/sub".to_string(),
            "extra/sub/b".to_string(),
        ]
    );
    assert!(!dst.join("extra").exists());
    assert!(report.residue.is_empty(), "{report:?}");
    let calls = remote.calls();
    let removals: Vec<&str> = calls
        .iter()
        .filter(|(op, _)| op == "remove_file" || op == "remove_dir" || op == "remove_dir_all")
        .map(|(_, path)| path.as_str())
        .collect();
    // The removal SET must equal the reported extraneous set, each path exactly
    // once (do not pin the per-entry implementation with a hardcoded count).
    let mut removed_once = removals.clone();
    removed_once.sort_unstable();
    let mut expected: Vec<&str> = report.extraneous.iter().map(String::as_str).collect();
    expected.sort_unstable();
    assert_eq!(
        removed_once, expected,
        "every extraneous entry is removed exactly once"
    );
    let index = |needle: &str| {
        removals
            .iter()
            .position(|path| *path == needle)
            .unwrap_or_else(|| panic!("{needle} was not removed"))
    };
    for (child, parent) in [
        ("extra/a", "extra"),
        ("extra/sub", "extra"),
        ("extra/sub/b", "extra/sub"),
    ] {
        assert!(
            index(child) < index(parent),
            "child {child} must be removed before its parent {parent}"
        );
    }
    // End state: the whole extraneous subtree is gone.
    assert!(!dst.join("extra").exists());
}

#[test]
fn extraneous_below_blocks_a_directory_replacement_until_sanctioned() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"file");
    write(&dst.join("p/keep"), b"keep");

    let blocked = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert!(blocked.applied.is_empty());
    assert_eq!(blocked.conflicts.len(), 1);
    assert_eq!(blocked.conflicts[0].reason, ConflictReason::ExtraneousBelow);
    assert!(dst.join("p").is_dir());
    assert_eq!(read(&dst.join("p/keep")), b"keep");

    let sanctioned = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(
        sanctioned.conflicts.is_empty(),
        "{:?}",
        sanctioned.conflicts
    );
    assert!(sanctioned.extraneous.contains(&"p/keep".to_string()));
    assert!(dst.join("p").is_file());
    assert_eq!(read(&dst.join("p")), b"file");
}

#[cfg(unix)]
#[test]
fn symlink_and_non_default_modes_round_trip() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    build_rich_tree(&src);
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();

    owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();

    assert_eq!(
        canonicalize_tree(&src).unwrap(),
        canonicalize_tree(&dst).unwrap(),
        "modes and symlinks round-trip faithfully"
    );
    assert_eq!(mode_of(&dst.join("bin/tool")), 0o751);
    assert_eq!(
        fs::read_link(dst.join("tool-link")).unwrap(),
        PathBuf::from("bin/tool"),
        "the symlink is created, never followed"
    );
    assert_eq!(read(&dst.join("bin/tool")), read(&src.join("bin/tool")));
}

#[cfg(unix)]
#[test]
fn push_replaces_a_read_only_destination_file() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"new");
    write(&dst.join("f"), b"old");
    set_mode(&src.join("f"), 0o640);
    set_mode(&dst.join("f"), 0o444);

    let remote = RecordingRemote::over(transport(&dst), true);
    let report = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert_eq!(read(&dst.join("f")), b"new");
    assert_eq!(
        mode_of(&dst.join("f")),
        0o640,
        "the source mode is applied after the overwrite"
    );
    assert_eq!(
        report.transient_dirs,
        vec!["f".to_string()],
        "the read-only file was transiently widened"
    );
    assert!(!report.skipped.contains(&"f".to_string()));
}

/// An extraneous removal under a read-only `Same` parent widens the parent
/// through the choke point and restores it; the mutated parent is NOT
/// `skipped` and IS named in `transient_dirs`.
#[cfg(unix)]
#[test]
fn extraneous_removal_under_a_read_only_same_parent_is_named_not_skipped() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    for root in [&src, &dst] {
        fs::create_dir_all(root.join("d")).unwrap();
    }
    write(&src.join("d/f"), b"same");
    write(&dst.join("d/f"), b"same");
    write(&dst.join("d/extra"), b"e");
    for root in [&src, &dst] {
        set_mode(&root.join("d"), 0o555);
    }

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(!dst.join("d/extra").exists());
    assert_eq!(
        mode_of(&dst.join("d")),
        0o555,
        "the parent mode is restored"
    );
    assert!(
        report.transient_dirs.contains(&"d".to_string()),
        "the widened parent `d` is named transient: {:?}",
        report.transient_dirs
    );
    assert!(
        !report.skipped.contains(&"d".to_string()),
        "a mutated directory is not skipped: {:?}",
        report.skipped
    );
    assert!(report.transfers >= 3, "widen + remove + restore");
}

#[test]
fn a_failed_write_is_reported_never_a_success() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();
    write(&src.join("d/f"), b"data");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_writes = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();
    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    assert!(
        dst.join("d").is_dir(),
        "the parent was created before the write"
    );
    assert!(
        !dst.join("d/f").exists(),
        "the failed write must not be reported as a success"
    );
    assert!(!err.report().applied.contains(&"d/f".to_string()));
    // COVERAGE (failure after a directory was created): `transfer_dir` created
    // and COUNTED `d`, but queued no verify item and `finalize` never ran. It
    // used to be in NO report list (`applied` empty, nothing else named it), so
    // a caller could not learn it exists. It is now named, because a
    // `Transferred` path that did not reach a verified final state is reported
    // in `verify_failures`.
    assert!(
        err.report().verify_failures.contains(&"d".to_string()),
        "the created directory is named: {:?}",
        err.report()
    );
    assert_report_names(err.report(), "d");
    assert_report_lists_disjoint(err.report());
}

/// FAILURE-path coverage (a failure after a file was written): the first file
/// installs successfully (so it is `applied`), the second fails. Every path the
/// run mutated — the created directory AND the written file — is NAMED, and the
/// lists stay disjoint.
#[test]
fn the_report_covers_a_failure_after_a_file_was_written() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();
    write(&src.join("d/a"), b"one");
    write(&src.join("d/b"), b"two");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // The first write (`d/a`) succeeds; the second (`d/b`) fails.
    remote.fail_nth_write = Some(2);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();
    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    assert_eq!(err.report().applied, vec!["d/a".to_string()]);
    assert_report_names(err.report(), "d/a");
    // The created directory whose `finalize` never ran is NAMED too.
    assert!(
        err.report().verify_failures.contains(&"d".to_string()),
        "the created directory is named: {:?}",
        err.report()
    );
    assert_report_names(err.report(), "d");
    assert_report_lists_disjoint(err.report());
}

#[test]
fn only_changed_entries_transfer() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("same"), b"same");
    write(&src.join("changed"), b"new");
    write(&dst.join("same"), b"same");
    write(&dst.join("changed"), b"old");

    let remote = RecordingRemote::over(transport(&dst), true);
    let report = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap();

    assert_eq!(report.applied, vec!["changed".to_string()]);
    assert_eq!(report.skipped, vec!["same".to_string()]);
    assert!(report.transfers >= 1);
    assert_eq!(remote.ops(), 1);
}

#[cfg(unix)]
#[test]
fn mode_only_change_does_not_rewrite_content() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"same");
    write(&dst.join("f"), b"same");
    set_mode(&src.join("f"), 0o644);
    set_mode(&dst.join("f"), 0o600);

    let remote = RecordingRemote::over(transport(&dst), true);
    let report = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap();

    assert_eq!(report.applied, vec!["f".to_string()]);
    assert!(report.transfers >= 1, "only the mode is applied");
    assert_eq!(remote.ops(), 1);
    assert_eq!(remote.writes(), 0, "the content is NOT rewritten");
    assert!(
        remote.calls().iter().all(|(op, _)| op == "set_mode"),
        "no op besides the mode application: {:?}",
        remote.calls()
    );
    assert_eq!(mode_of(&dst.join("f")), 0o644);
    assert_eq!(read(&dst.join("f")), b"same");
}

/// A mode-only file change whose chmod never lands must FAIL verification.
#[cfg(unix)]
#[test]
fn a_dropped_mode_only_change_fails_verification() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"same");
    write(&dst.join("f"), b"same");
    set_mode(&src.join("f"), 0o644);
    set_mode(&dst.join("f"), 0o600);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.drop_modes = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();
    assert!(
        matches!(err.error(), Error::Integrity(_)),
        "a dropped mode must fail verification, got {err:?}"
    );
    assert_eq!(mode_of(&dst.join("f")), 0o600, "the mode is unchanged");
    // The mutated path is NAMED machine-readably, not only in the error string.
    assert!(
        err.report().verify_failures.contains(&"f".to_string()),
        "the dropped-mode path is named in verify_failures: {:?}",
        err.report()
    );
    assert!(!err.report().applied.contains(&"f".to_string()), "{err:?}");
    assert_report_lists_disjoint(err.report());
}

/// A `Missing` directory child under a read-only `Same` parent is installed by
/// widening the parent from its CURRENT mode and restoring it — push and pull.
#[cfg(unix)]
#[test]
fn a_missing_child_under_a_read_only_parent_is_installed_and_the_parent_restored() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();

    // PUSH.
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    for root in [&src, &dst] {
        fs::create_dir_all(root.join("d")).unwrap();
    }
    write(&src.join("d/new"), b"new");
    for root in [&src, &dst] {
        set_mode(&root.join("d"), 0o555);
    }
    let remote = RecordingRemote::over(transport(&dst), true);
    let report = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert_eq!(
        read(&dst.join("d/new")),
        b"new",
        "the missing child IS created"
    );
    assert_eq!(
        mode_of(&dst.join("d")),
        0o555,
        "the parent mode is restored"
    );
    assert!(
        report.transient_dirs.contains(&"d".to_string()),
        "the widened parent `d` is named transient: {:?}",
        report.transient_dirs
    );
    assert!(!report.skipped.contains(&"d".to_string()));
    assert!(report.transfers >= 3, "widen + write + restore");
    assert!(
        remote
            .set_modes()
            .iter()
            .any(|(path, mode)| path == "d" && mode & 0o200 != 0),
        "the parent was widened: {:?}",
        remote.set_modes()
    );

    // PULL.
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    for root in [&remote_root, &local] {
        fs::create_dir_all(root.join("d")).unwrap();
    }
    write(&remote_root.join("d/new"), b"pulled");
    for root in [&remote_root, &local] {
        set_mode(&root.join("d"), 0o555);
    }
    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &ReplaceAll,
        Keep,
    )
    .unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert_eq!(read(&local.join("d/new")), b"pulled");
    assert_eq!(mode_of(&local.join("d")), 0o555);
    assert!(
        report.transient_dirs.contains(&"d".to_string()),
        "the widened parent `d` is named transient: {:?}",
        report.transient_dirs
    );
    assert!(report.transfers >= 3);
}

/// An extraneous removal under a read-only parent must widen that parent first
/// (previously the flag was unusable against a read-only parent) and leave no
/// unrestored mode behind.
#[cfg(unix)]
#[test]
fn extraneous_removal_under_a_read_only_parent_widens_and_removes() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"x");
    write(&dst.join("f"), b"x");
    write(&dst.join("extra/old"), b"y");
    set_mode(&dst.join("extra"), 0o555);

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert_eq!(
        report.extraneous,
        vec!["extra".to_string(), "extra/old".to_string()]
    );
    assert!(!dst.join("extra").exists(), "the read-only tree is removed");
    assert!(
        report.transient_dirs.is_empty(),
        "a removed path left no transient mode to restore: {:?}",
        report.transient_dirs
    );
}

/// The read-only `Same` parent of a CHANGED child is widened, counted, named,
/// absent from `skipped`, and restored.
#[cfg(unix)]
#[test]
fn a_read_only_same_directory_is_transiently_widened_counted_and_restored() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    for (root, content) in [(&src, &b"new"[..]), (&dst, &b"old"[..])] {
        fs::create_dir_all(root.join("d")).unwrap();
        write(&root.join("d/f"), content);
        set_mode(&root.join("d"), 0o555);
    }

    let remote = RecordingRemote::over(transport(&dst), true);
    let report = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert_eq!(read(&dst.join("d/f")), b"new");
    assert!(report.transfers >= 3, "widen + write + restore");
    assert!(
        report.transient_dirs.contains(&"d".to_string()),
        "the widened parent `d` is named transient: {:?}",
        report.transient_dirs
    );
    assert!(!report.skipped.contains(&"d".to_string()));
    assert_eq!(mode_of(&dst.join("d")), 0o555);
    assert_eq!(
        remote
            .set_modes()
            .last()
            .map(|(path, mode)| (path.as_str(), *mode)),
        Some(("d", 0o555)),
        "the widen is restored last: {:?}",
        remote.set_modes()
    );
}

/// The widen decision uses the DESTINATION's current mode, and a widen that the
/// directory's own final mode supersedes is NOT restored over it.
#[cfg(unix)]
#[test]
fn a_changed_directory_is_widened_from_its_current_mode_and_its_final_mode_wins() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/f"), b"new");
    write(&dst.join("d/f"), b"old");
    // The source mode (0755) differs from the destination's CURRENT mode
    // (0500), so a destination-derived widen (0500 | 0300 = 0700) cannot be
    // confused with a source-derived one (0755).
    set_mode(&src.join("d"), 0o755);
    set_mode(&dst.join("d"), 0o500);

    let remote = RecordingRemote::over(transport(&dst), true);
    let report = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert_eq!(read(&dst.join("d/f")), b"new", "the child IS written");
    assert_eq!(
        mode_of(&dst.join("d")),
        0o755,
        "the directory ends at the source's final mode, not the widened state"
    );
    assert!(report.applied.contains(&"d".to_string()));
    assert!(
        report.transient_dirs.contains(&"d".to_string()),
        "the widened parent `d` is named transient: {:?}",
        report.transient_dirs
    );
    // The widen came from the DESTINATION's 0500 (0500|0300 = 0700), NOT from
    // the source's 0755: a source-derived widen would never produce 0700.
    let d_modes: Vec<u32> = remote
        .set_modes()
        .iter()
        .filter(|(path, _)| path == "d")
        .map(|(_, mode)| *mode)
        .collect();
    assert!(
        d_modes.contains(&0o700),
        "the widen is derived from the destination's current mode: {d_modes:?}"
    );
    assert_eq!(
        d_modes.last(),
        Some(&0o755),
        "the final mode wins: {d_modes:?}"
    );
    // widen + write + finalize; the widen and final differ, so both chmods are
    // required (no redundant one is allowed here).
    assert!(report.transfers >= 3, "widen + write + finalize");
}

/// A failed sync restores the widened parent AND reports the partial progress
/// honestly: the widened directory is named in `transient_dirs`, is NOT
/// `skipped`, and is NOT `applied` (its final mode never landed).
#[cfg(unix)]
#[test]
fn a_failed_write_restores_the_parent_and_reports_transient_dirs_honestly() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/f"), b"new");
    write(&dst.join("d/f"), b"old");
    set_mode(&src.join("d"), 0o755);
    set_mode(&dst.join("d"), 0o555);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_writes = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();

    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    assert_eq!(
        mode_of(&dst.join("d")),
        0o555,
        "the widened parent is restored when the sync fails"
    );
    assert!(
        err.restore_failures().is_empty(),
        "{:?}",
        err.restore_failures()
    );
    let report = err.report();
    assert!(
        report.transient_dirs.contains(&"d".to_string()),
        "the widened parent `d` is named transient: {:?}",
        report.transient_dirs
    );
    assert!(!report.skipped.contains(&"d".to_string()));
    assert!(
        !report.applied.contains(&"d".to_string()),
        "a directory whose final mode never landed is not applied: {report:?}"
    );
    // The restore is COUNTED: a regression that dropped the `touch()` in
    // `restore` would leave this at 1.
    assert!(
        report.transfers >= 2,
        "the widen and the restore are both counted"
    );
    assert_eq!(
        read(&dst.join("d/f")),
        b"old",
        "the failed write changed nothing"
    );
}

/// `applied` waits for the final mode: a directory whose final chmod never
/// lands fails verification and is never reported applied.
#[cfg(unix)]
#[test]
fn applied_waits_for_the_final_mode() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(src.join("d")).unwrap();
    fs::create_dir_all(dst.join("d")).unwrap();
    set_mode(&src.join("d"), 0o755);
    set_mode(&dst.join("d"), 0o700);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.drop_modes = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();
    assert!(
        matches!(err.error(), Error::Integrity(_)),
        "an unapplied directory mode must fail verification, got {err:?}"
    );
    assert!(
        !err.report().applied.contains(&"d".to_string()),
        "a directory whose final mode did not land is not applied: {:?}",
        err.report()
    );
    // The CONTRACT of `verify_failures` names every mutated path whose final
    // mode did not land: a DIRECTORY is named exactly like a file.
    assert!(
        err.report().verify_failures.contains(&"d".to_string()),
        "the unapplied directory mode names the directory in verify_failures: {:?}",
        err.report()
    );
}

#[test]
fn fully_refused_pull_leaves_the_destination_root_absent() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    write(&remote_root.join("f"), b"new");
    let local = dir.path().join("local");
    assert!(!local.exists());

    let refuse = |_: &str, _: EntryKind| EntryPolicy::Refuse;
    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &refuse,
        Keep,
    )
    .unwrap();
    assert!(report.applied.is_empty());
    assert_eq!(report.transfers, 0);
    assert_eq!(report.conflicts.len(), 1);
    assert!(
        !local.exists(),
        "a fully-refused pull creates NOTHING, not even the destination root"
    );
}

#[test]
fn refused_pull_beside_a_written_sibling_creates_only_the_parent() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    write(&remote_root.join("d/a"), b"1");
    write(&remote_root.join("d/b"), b"2");
    let local = dir.path().join("local");
    assert!(!local.exists());

    let refuse_b = |path: &str, _: EntryKind| {
        if path == "d/b" {
            EntryPolicy::Refuse
        } else {
            EntryPolicy::Replace
        }
    };
    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &refuse_b,
        Keep,
    )
    .unwrap();
    assert!(report.applied.contains(&"d".to_string()));
    assert!(report.applied.contains(&"d/a".to_string()));
    assert_eq!(report.conflicts.len(), 1);
    assert_eq!(report.conflicts[0].path, "d/b");
    assert_eq!(read(&local.join("d/a")), b"1");
    assert!(!local.join("d/b").exists());
}

#[cfg(unix)]
#[test]
fn directory_mode_verification_catches_an_unapplied_mode() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(src.join("d")).unwrap();
    fs::create_dir_all(dst.join("d")).unwrap();
    set_mode(&src.join("d"), 0o755);
    set_mode(&dst.join("d"), 0o700);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.drop_modes = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();
    assert!(matches!(err.error(), Error::Integrity(_)), "got {err:?}");
    // The directory is NAMED in `verify_failures`, not only described by the
    // error string: the report is the machine-readable contract.
    assert!(
        err.report().verify_failures.contains(&"d".to_string()),
        "the unapplied directory mode names the directory in verify_failures: {:?}",
        err.report()
    );
    assert!(!err.report().applied.contains(&"d".to_string()), "{err:?}");
    // The directory is left at its ORIGINAL mode, not the unapplied target:
    // `drop_modes` dropped the chmod, so the sync must not have silently
    // applied the source's 0o755 and must not have left a transient widen in
    // place either.
    assert_eq!(
        mode_of(&dst.join("d")),
        0o700,
        "the directory keeps its ORIGINAL mode, not the unapplied target"
    );
}

#[test]
fn a_failed_sync_leaves_extraneous_entries_present() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/f"), b"new");
    write(&dst.join("d/f"), b"old");
    write(&dst.join("extra"), b"y");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_writes = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();
    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    assert!(
        dst.join("extra").exists(),
        "a failed sync must not delete sanctioned extraneous entries"
    );
    assert_eq!(err.report().extraneous, vec!["extra".to_string()]);
}

#[test]
fn remote_manifest_hashes_the_far_side_and_missing_perl_is_an_error() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let root = dir.path().join("remote");
    build_rich_tree(&root);

    let remote = RecordingRemote::over(transport(&root), false);
    let via_script = crate::sync::diff::remote_manifest(&remote).unwrap();
    assert_eq!(via_script, canonicalize_tree(&root).unwrap());

    let mut broken = RecordingRemote::over(transport(&root), false);
    broken.exec_failure = Some(ExecOutcome {
        exit_code: 127,
        stdout: String::new(),
        stderr: "perl: command not found".to_string(),
        timeout_cause: None,
    });
    let err = crate::sync::diff::remote_manifest(&broken).unwrap_err();
    let msg = err.to_string();
    // NOT `msg.contains("perl")`: that string is hardcoded in the transport's
    // own error and proves nothing. The load-bearing assertion is that the
    // error names the FAR-SIDE root, so the caller knows WHICH tree failed.
    assert!(
        msg.contains(&root.display().to_string()),
        "the error names the far side: {msg}"
    );
}

#[test]
fn push_over_a_missing_source_root_is_an_error() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let missing = dir.path().join("missing");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();
    let before = canonicalize_tree(&dst).unwrap();
    let remote = RecordingRemote::over(transport(&dst), true);
    let err = owned(Direction::Push, &missing, &remote, &ReplaceAll, Keep).unwrap_err();
    assert!(
        matches!(err.error(), Error::Materialization(_)),
        "a missing source root is a materialization error, got {err:?}"
    );
    assert!(!missing.exists());
    assert_eq!(remote.ops(), 0);
    assert_eq!(canonicalize_tree(&dst).unwrap(), before);
}

#[test]
fn push_to_an_absent_destination_root_is_an_error_not_a_delete() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("f"), b"x");
    let dst = dir.path().join("dst");
    assert!(!dst.exists());

    let remote = RecordingRemote::over(transport(&dst), true);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();
    // The absent ROOT is the TYPED absence condition (gap 5), consistent with
    // how the crate reports absence elsewhere; it is still an ERROR (no
    // delete), which is what this test exists to pin.
    assert!(matches!(err.error(), Error::NotFound(_)), "got {err:?}");
    assert_eq!(remote.ops(), 0);
    assert!(!dst.exists());
}

#[test]
fn syncing_two_empty_directories_is_a_no_op() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    let remote = RecordingRemote::over(transport(&dst), true);
    let report = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap();
    assert!(report.applied.is_empty());
    assert!(report.conflicts.is_empty());
    assert_eq!(report.transfers, 0);
    assert_eq!(remote.ops(), 0);
}

// ---------------------------------------------------------------------------
// F1: OVERLAPPING ROOTS. `sync` used to relate the two roots nowhere, so a
// destination nested inside the source (or vice versa) put the run on both
// sides of an overlap: a self-copy that grew without bound, and — with
// `delete_extraneous` — the destruction of the SOURCE. The refusal reuses
// `crate::root::roots_overlap` (the rule `OwnedRoot::parse` enforces) and runs
// BEFORE any mutation; EQUAL roots stay a no-op.
// ---------------------------------------------------------------------------

/// The refusal, asserted to have happened BEFORE any mutation: the error names
/// both roots, no transport call ran, and the tree is byte-identical.
fn assert_overlapping_roots_refused(err: &SyncError, local: &Path, remote_path: &Path) {
    assert!(
        matches!(err.error(), Error::Materialization(_)),
        "an overlapping-root refusal is a materialization error, got {err:?}"
    );
    let message = err.error().to_string();
    assert!(
        message.contains("must be disjoint"),
        "the refusal names the disjointness rule: {message}"
    );
    assert!(
        message.contains(&local.display().to_string())
            && message.contains(&remote_path.display().to_string()),
        "the refusal names BOTH roots ({local:?} and {remote_path:?}): {message}"
    );
}

/// A destination nested inside the source, with `delete_extraneous`: pre-fix the
/// run DESTROYED the source entry `src/sub/x` (it looked destination-only) and
/// wrote a self-copy at `src/sub/sub/x`.
#[test]
fn a_destination_inside_the_source_is_refused_and_the_source_is_not_destroyed() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = src.join("sub");
    write(&src.join("top"), b"TOP");
    write(&src.join("sub/x"), b"SOURCE-X");

    let remote = RecordingRemote::over(transport(&dst), true);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();

    assert_overlapping_roots_refused(&err, &src, &dst);
    assert_eq!(remote.ops(), 0, "the refusal is before every mutation");
    assert_eq!(
        read(&src.join("sub/x")),
        b"SOURCE-X",
        "the source entry must not be destroyed"
    );
    assert!(
        fs::symlink_metadata(src.join("sub/sub")).is_err(),
        "no self-copy may be created"
    );
    assert_eq!(read(&src.join("top")), b"TOP");
}

/// The reverse nesting: the SOURCE is inside the destination, with
/// `delete_extraneous`. Pre-fix the destination manifest enumerated the source
/// (`dst/sub`, `dst/sub/x`), classified it extraneous, and DESTROYED it.
#[test]
fn a_source_inside_the_destination_is_refused_and_the_source_is_not_destroyed() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let dst = dir.path().join("dst");
    let src = dst.join("sub");
    write(&dst.join("other"), b"OTHER");
    write(&dst.join("sub/x"), b"SOURCE-X");

    let remote = RecordingRemote::over(transport(&dst), true);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();

    assert_overlapping_roots_refused(&err, &src, &dst);
    assert_eq!(remote.ops(), 0, "the refusal is before every mutation");
    assert_eq!(
        read(&dst.join("sub/x")),
        b"SOURCE-X",
        "the source root must not be destroyed"
    );
    assert_eq!(read(&dst.join("other")), b"OTHER");
}

/// A destination nested inside the source WITHOUT `delete_extraneous`: pre-fix
/// this was the silent self-copy `src/sub/sub/x`, which adds one directory
/// level per run (a disk-fill).
#[test]
fn a_destination_inside_the_source_is_refused_without_delete_extraneous() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = src.join("sub");
    write(&src.join("sub/x"), b"SOURCE-X");
    write(&src.join("top"), b"TOP");

    let remote = RecordingRemote::over(transport(&dst), true);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();

    assert_overlapping_roots_refused(&err, &src, &dst);
    assert_eq!(remote.ops(), 0, "the refusal is before every mutation");
    assert_eq!(read(&src.join("sub/x")), b"SOURCE-X");
    assert!(
        fs::symlink_metadata(src.join("sub/sub")).is_err(),
        "no unbounded self-copy may start"
    );
}

/// The PULL direction of the same overlap: the LOCAL destination is nested
/// inside the REMOTE source. Pre-fix the local tree's entries were classified
/// extraneous and destroyed under `delete_extraneous`.
#[test]
fn a_pull_into_a_destination_inside_the_remote_source_is_refused() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    let local = remote_root.join("sub");
    write(&remote_root.join("sub/x"), b"SOURCE-X");
    write(&remote_root.join("top"), b"TOP");

    let remote = RecordingRemote::over(transport(&remote_root), true);
    let err = owned(Direction::Pull, &local, &remote, &ReplaceAll, Delete).unwrap_err();

    assert_overlapping_roots_refused(&err, &local, &remote_root);
    assert_eq!(remote.ops(), 0, "the refusal is before every mutation");
    assert_eq!(read(&remote_root.join("sub/x")), b"SOURCE-X");
    assert_eq!(read(&remote_root.join("top")), b"TOP");
}

/// NEGATIVE CONTROL: EQUAL roots are the idempotent no-op, NOT an overlap.
/// `OwnedRoot::parse` refuses equal roots for two simultaneous OWNERS, but a
/// sync of a tree with itself has identical manifests, an empty diff, and no
/// mutation — so the refusal must carve equality out. Exercised with a
/// trailing separator and a `..` spelling, both of which name the same tree.
#[test]
fn equal_roots_are_not_refused_and_are_an_idempotent_no_op() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let tree = dir.path().join("tree");
    write(&tree.join("a/f"), b"SAME");
    write(&tree.join("b/g"), b"SAME");
    let before = canonicalize_tree(&tree).unwrap();

    let remote = RecordingRemote::over(transport(&tree), true);
    for spelling in [
        tree.clone(),
        PathBuf::from(format!("{}/", tree.display())),
        tree.join("..").join("tree"),
    ] {
        let report = owned(Direction::Push, &spelling, &remote, &ReplaceAll, Keep)
            .unwrap_or_else(|err| panic!("{spelling:?} must be a no-op, got {err:?}"));
        assert_eq!(report.transfers, 0, "{spelling:?} must not mutate");
        assert!(report.applied.is_empty());
        assert!(!report.skipped.is_empty());
        assert_eq!(remote.ops(), 0, "{spelling:?} saw no mutating call");
        assert_eq!(canonicalize_tree(&tree).unwrap(), before, "{spelling:?}");
    }
}

/// NEGATIVE CONTROL: a root reached through a SYMLINKED ANCESTOR is
/// canonicalized before the comparison, so a genuinely DISJOINT pair is not
/// refused as an overlap (and a symlinked FINAL component is still refused by
/// [`LocalSide::open`], as `root_spelling_normalizes_and_refuses_a_symlinked_root`
/// pins).
#[cfg(unix)]
#[test]
fn a_disjoint_pair_reached_through_a_symlinked_ancestor_is_not_refused() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let real_src = dir.path().join("real-src");
    let dst = dir.path().join("dst");
    write(&real_src.join("sub/f"), b"FROM-SOURCE");
    fs::create_dir_all(&dst).unwrap();
    let mid = dir.path().join("mid");
    std::os::unix::fs::symlink(&real_src, &mid).unwrap();

    // The local root is spelled through the symlinked ancestor; it canonicalizes
    // to `real-src` and is disjoint from `dst`.
    let through_link = mid.join("sub");
    let remote = RecordingRemote::over(transport(&dst), true);
    let report = owned(Direction::Push, &through_link, &remote, &ReplaceAll, Keep)
        .expect("a disjoint pair must not be refused");
    assert_eq!(read(&dst.join("f")), b"FROM-SOURCE");
    assert!(
        report.applied.iter().any(|path| path == "f"),
        "the transfer applied: {report:?}"
    );
}

/// The ABSENT-ROOT canonicalizer resolves up to the FILESYSTEM ROOT even when
/// no ancestor BELOW it exists: the step-up must try the root itself, not stop
/// because the root's own parent is `None`. Pure (nothing is created), so it
/// pins the resolution order directly.
#[cfg(unix)]
#[test]
fn an_absent_root_with_only_the_filesystem_root_as_ancestor_still_resolves() {
    let missing = format!("/nonexistent-sync-root-{}/sub", std::process::id(),);
    assert!(!Path::new(&missing).exists());
    let resolved = canonicalize_with_missing_tail(Path::new(&missing)).unwrap();
    assert_eq!(
        resolved,
        PathBuf::from(&missing),
        "an absent tail under `/` resolves to itself"
    );
}

// ---------------------------------------------------------------------------
// F2: SUPERLINEAR DIRECTORY ENUMERATION. Three per-entry sites re-listed the
// parent directory with no cache, so a wide directory cost O(N) listings (and
// O(N^2) time). The ONE run-scoped listing cache makes a directory cost O(1)
// listings per verify pass, and this test BOUNDS the count: it is what makes
// the defect impossible to reintroduce, independent of wall-clock.
// ---------------------------------------------------------------------------

/// Sync a source/destination pair of `n` identical entries with ONE changed
/// file, returning `(destination listings, skipped count, listing elements
/// materialized by cached consultations)`.
fn measure_wide_sync(n: usize) -> (usize, usize, usize) {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    for i in 0..n {
        let name = format!("f{i:04}");
        write(&src.join(&name), format!("same-{i}").as_bytes());
        write(&dst.join(&name), format!("same-{i}").as_bytes());
    }
    // Exactly one entry differs, so the wide directory is TOUCHED and every
    // other entry is a `Skipped` candidate.
    write(&src.join("f0000"), b"CHANGED");

    let remote = RecordingRemote::over(transport(&dst), true);
    super::listing_elements::reset();
    let report = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap();
    let materialized = super::listing_elements::get();
    assert_eq!(
        read(&dst.join("f0000")),
        b"CHANGED",
        "the one change landed"
    );
    (remote.lists(), report.skipped.len(), materialized)
}

/// The LISTING-COUNT BOUND: the number of destination listings must not grow
/// with the number of entries in the directory. Pre-fix `verify_claimed_-
/// untouched` re-listed the parent once per `Skipped` entry, so the 2N case
/// cost about twice the N case; the shared cache makes the two counts EQUAL.
///
/// It ALSO pins the WORK, not only the calls: `listing_elements` counts the
/// listing ENTRIES (name bytes included) a cached consultation copies. The
/// cache once kept the fetch count O(1) while still deep-cloning the `Vec` per
/// consultation, so the call count stayed flat against an O(N^2) run. The
/// mutation (reinstating the per-call deep clone) leaves `large_lists ==
/// small_lists` true and makes `large_elements` grow with the width, which is
/// exactly the defect these assertions now catch.
#[test]
fn enumerating_a_wide_directory_costs_a_constant_number_of_listings() {
    let (small_lists, small_skipped, small_elements) = measure_wide_sync(32);
    let (large_lists, large_skipped, large_elements) = measure_wide_sync(64);
    assert!(
        large_skipped > small_skipped,
        "the fixture must actually be wider (non-vacuous): {small_skipped} vs {large_skipped}"
    );
    assert_eq!(
        large_lists, small_lists,
        "listing the destination must cost O(1) per directory, not O(entries): \
         32 entries -> {small_lists} listings, 64 entries -> {large_lists} listings"
    );
    // A small absolute bound too, so the count cannot be a large constant that
    // merely happens not to grow.
    assert!(
        small_lists <= 8,
        "a one-directory sync needs only a handful of listings, got {small_lists}"
    );
    // THE WORK BOUND: handing a cached listing to each of the N `Skipped`
    // candidates must COPY nothing, so the materialized-element count is the
    // same for both widths (and zero). Pre-fix/mutation this is ~N per cached
    // consultation and the 2N case is about four times the N case.
    assert_eq!(
        large_elements, small_elements,
        "the work of consulting the cached listing must not scale with the \
         directory width: 32 entries materialized {small_elements} elements, \
         64 entries materialized {large_elements}"
    );
    assert!(
        small_elements <= 8,
        "sharing the cached listing must copy no entry; 32 entries copied \
         {small_elements} elements"
    );
}

/// Build a source and destination CHAIN of `depth` directories with ONE changed
/// file at the bottom, sync it with `Keep`, and return `(destination metadata
/// probes, destination listings)`. Every destination ancestor must be probed by
/// the ancestry/guard walk, so this is the fixture that exposes the O(D^3)
/// same-prefix re-walk.
#[cfg(unix)]
fn measure_deep_chain_sync(depth: usize) -> (usize, usize) {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    let mut src_leaf = src.clone();
    let mut dst_leaf = dst.clone();
    for _ in 0..depth {
        src_leaf = src_leaf.join("c");
        dst_leaf = dst_leaf.join("c");
    }
    write(&src_leaf.join("leaf"), b"NEW");
    write(&dst_leaf.join("leaf"), b"old");

    let remote = RecordingRemote::over(transport(&dst), true);
    let report = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap();
    assert_eq!(
        read(&dst_leaf.join("leaf")),
        b"NEW",
        "the one deep change landed: {report:?}"
    );
    (remote.metadata_probes(), remote.lists())
}

/// F1 DEPTH BOUND: a depth-D chain with ONE change must cost O(D) ancestry
/// probes, not O(D^2) (and not O(D^3) `openat`: a probe resolves a path
/// component-wise, so D probes of a depth-D prefix is D^2 `openat` and a
/// per-ancestor re-walk of every prefix is D of those). This fixture uses a
/// PATH-BASED destination, where NO ancestry memo is allowed (the preflight is
/// the confinement; see [`Applier::ancestry_dirs`]), so the linearity pinned
/// here comes ENTIRELY from verifying a path's ancestry ONCE per operation: the
/// deepest guard already walks every prefix, so `widen_ancestors` performs one
/// ancestry walk for the whole chain and each widen re-checks nothing. Both
/// assertions below fail against the pre-fix code: its depth-32 count is 669
/// probes and its depth-64 count is 2349 (measured), not a small multiple of
/// the depth, and it grows QUADRATICALLY when the depth doubles. Measured after
/// the per-operation restructuring (no memo, path-based destination): 173 ->
/// 333, i.e. a 5*D growth in the count, linear in the depth.
///
/// The bound is on the number of OPERATIONS, not on wall time: each probe of a
/// PATH-BASED destination resolves its prefix component-wise, so the local
/// wall time is O(D^2) (measured ~5x per doubling). For a REMOTE destination
/// each probe is one ssh round trip, so the round-trip count IS the linear
/// operation count; `sync`'s "Cost of verifying a path" states the real bound
/// per destination kind.
#[cfg(unix)]
#[test]
fn a_deep_chain_costs_linear_ancestry_probes() {
    let depth = 32usize;
    let (shallow, shallow_lists) = measure_deep_chain_sync(depth);
    let (deep, deep_lists) = measure_deep_chain_sync(2 * depth);

    // Non-vacuous: the chain really was walked (every level probed at least
    // once) and the fixture did not silently flatten.
    assert!(
        shallow >= depth,
        "the depth-{depth} chain must be walked, got {shallow} probes"
    );

    // ABSOLUTE BOUND: O(D), not O(D^2). A small constant multiple of the depth,
    // plus a constant for the manifest/verification probes that do not scale
    // with D. Measured: pre-fix the depth-32 count is 669; post-fix it is 173.
    assert!(
        shallow <= 8 * depth + 64,
        "a depth-{depth} chain must cost O(D) ancestry probes, not O(D^2): got \
         {shallow} (bound {})",
        8 * depth + 64
    );

    // ADDITIVE GROWTH: doubling the depth must add only a LINEAR amount, so the
    // count is independent of a large multiplication of D. Measured: post-fix
    // 173 -> 333 (adds 160 for 32 more levels, exactly 5*D); pre-fix 669 -> 2349
    // (adds 1680).
    assert!(
        deep <= shallow + 6 * depth,
        "doubling the depth must add O(D) probes, not multiply them: \
         depth {depth} -> {shallow}, depth {} -> {deep}",
        2 * depth
    );

    // The destination is listed once per directory of the chain, never once per
    // path per ancestor; the chain is linear in its length.
    assert!(
        deep_lists <= 2 * shallow_lists + 4,
        "listings must stay linear in the chain length: {shallow_lists} vs {deep_lists}"
    );
}

/// Build a source-empty / destination-wide fixture with `n` extraneous FILES in
/// ONE directory, run the given extraneous policy, and return `(applier listing
/// reads, destination listings)`.
fn measure_wide_delete(n: usize, policy: Extraneous) -> (usize, usize) {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    for i in 0..n {
        write(&dst.join(format!("x{i:05}")), b"e");
    }
    let remote = RecordingRemote::over(transport(&dst), true);
    super::listing_reads::reset();
    let report = owned(Direction::Push, &src, &remote, &ReplaceAll, policy).unwrap();
    let consumed = super::listing_reads::get();
    assert_eq!(
        report.extraneous.len(),
        n,
        "the fixture must be entirely extraneous: {report:?}"
    );
    assert!(report.conflicts.is_empty(), "{report:?}");
    (consumed, remote.lists())
}

/// F2 WIDTH BOUND: the REMOVAL pass must consume a parent directory's listing
/// O(1) times, not once per extraneous entry. This mirrors
/// [`enumerating_a_wide_directory_costs_a_constant_number_of_listings`], which
/// pins the SKIPPED path; this pins the REMOVAL path. The `Keep` run is the
/// control: it performs the SAME two post-transfer verification passes (which
/// legitimately consult the parent listing once per candidate and therefore grow
/// with the entry count), so `Delete - Keep` isolates exactly what
/// `remove_extraneous` itself consumed. Pre-fix that delta is one listing clone
/// per entry (it grows with `n`); post-fix it is the ONE per-parent listing the
/// pass now fetches, independent of `n`.
#[test]
fn removing_a_wide_directory_costs_a_constant_number_of_listing_reads() {
    let small = 64usize;
    let (small_keep, small_keep_lists) = measure_wide_delete(small, Keep);
    let (small_delete, small_delete_lists) = measure_wide_delete(small, Delete);
    let (large_keep, large_keep_lists) = measure_wide_delete(2 * small, Keep);
    let (large_delete, large_delete_lists) = measure_wide_delete(2 * small, Delete);

    // The verification passes are the control's cost and are identical for the
    // two policies; assert the control really is non-trivial so the subtraction
    // below is meaningful rather than `0 - 0`.
    assert!(
        small_keep > 0 && large_keep > small_keep,
        "the control run must actually verify the wide directory: {small_keep} vs {large_keep}"
    );

    let small_removal = small_delete.saturating_sub(small_keep);
    let large_removal = large_delete.saturating_sub(large_keep);

    // ABSOLUTE BOUND: one directory is consumed O(1) times by the removal pass.
    // Pre-fix this is >= the entry count.
    assert!(
        small_removal <= 4,
        "the removal pass must consume one directory's listing O(1) times, not \
         once per entry: {small} entries consumed it {small_removal} times"
    );
    // NO GROWTH: doubling the entry count must not change the removal pass's
    // listing consumption. Pre-fix 64 entries -> 64 and 128 -> 128.
    assert_eq!(
        large_removal,
        small_removal,
        "listing consumption must be independent of the entry count: \
         {small} entries -> {small_removal}, {} entries -> {large_removal}",
        2 * small
    );

    // The raw destination fetch count stays flat too: the run-scoped cache
    // already makes a directory cost O(1) raw listings, and the removal pass
    // adds none beyond the one it shares.
    assert!(
        small_delete_lists <= small_keep_lists + 2,
        "the removal pass must not add a per-entry destination listing: \
         keep {small_keep_lists}, delete {small_delete_lists}"
    );
    assert!(
        large_delete_lists <= large_keep_lists + 2,
        "the removal pass must not add a per-entry destination listing: \
         keep {large_keep_lists}, delete {large_delete_lists}"
    );
}

#[cfg(unix)]
#[test]
fn root_spelling_normalizes_and_refuses_a_symlinked_root() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let real = dir.path().join("real");
    fs::create_dir_all(real.join("sub")).unwrap();
    let with_slash = PathBuf::from(format!("{}/", real.display()));

    let plain = LocalSide::open(&real, false).unwrap();
    let slashed = LocalSide::open(&with_slash, false).unwrap();
    assert_eq!(plain.root_path, slashed.root_path);
    assert_eq!(plain.manifest().unwrap(), slashed.manifest().unwrap());

    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let link_slash = PathBuf::from(format!("{}/", link.display()));
    for spelling in [&link, &link_slash] {
        assert!(
            matches!(
                LocalSide::open(spelling, false),
                Err(Error::Materialization(_))
            ),
            "{spelling:?} must refuse a symlinked root"
        );
    }
}

#[cfg(unix)]
#[test]
fn parent_component_symlink_refuses_a_local_symlink_target_read() {
    use std::os::unix::fs::symlink;
    let dir = fixture_tmpdir(&env()).unwrap();
    let local_root = dir.path().join("local-root");
    fs::create_dir_all(&local_root).unwrap();
    let outside = dir.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    const OUTSIDE_TARGET: &str = "OUTSIDE-KNOWN-TARGET";
    symlink(OUTSIDE_TARGET, outside.join("link")).unwrap();
    symlink(&outside, local_root.join("sub")).unwrap();
    symlink("legit-target", local_root.join("good")).unwrap();

    let local = LocalSide::open(&local_root, true).unwrap();
    let err = local
        .read_link(&RootedRelativePath::parse(Path::new("sub/link")).unwrap())
        .expect_err("a parent-component symlink must refuse the target read");
    assert!(matches!(err, Error::Store(_)), "got {err:?}");
    assert!(!err.to_string().contains(OUTSIDE_TARGET), "got {err}");
    assert_eq!(
        local
            .read_link(&RootedRelativePath::parse(Path::new("good")).unwrap())
            .unwrap(),
        PathBuf::from("legit-target")
    );
}

/// The two derived lists `applied`/`skipped`/`conflicts`/`extraneous` are
/// mutually exclusive and cover every path in the diff; `transient_dirs` is
/// disjoint from `skipped`.
#[cfg(unix)]
#[test]
fn the_report_lists_are_mutually_exclusive_and_cover_the_diff() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("same"), b"same");
    write(&src.join("changed"), b"new");
    write(&src.join("missing"), b"m");
    write(&dst.join("same"), b"same");
    write(&dst.join("changed"), b"old");
    write(&dst.join("extra"), b"e");
    // A read-only `Same` directory that admits a changed child: it is named in
    // `transient_dirs` ONLY (it is not in any of the four lists).
    fs::create_dir_all(src.join("ro")).unwrap();
    fs::create_dir_all(dst.join("ro")).unwrap();
    write(&src.join("ro/f"), b"new");
    write(&dst.join("ro/f"), b"old");
    set_mode(&src.join("ro"), 0o555);
    set_mode(&dst.join("ro"), 0o555);
    // A `Changed` DIRECTORY (its mode differs) that is ALSO widened to admit a
    // changed child: it legitimately appears in BOTH `applied` and
    // `transient_dirs`. The ASCII contract explicitly allows that overlap.
    fs::create_dir_all(src.join("cd")).unwrap();
    fs::create_dir_all(dst.join("cd")).unwrap();
    write(&src.join("cd/f"), b"new");
    write(&dst.join("cd/f"), b"old");
    set_mode(&src.join("cd"), 0o755);
    set_mode(&dst.join("cd"), 0o555);

    // Capture the run's OWN decision surface BEFORE the sync: the diff computed
    // from the two manifests with no mutation yet. Recomputing it from the
    // POST-sync trees would describe a DIFFERENT input (`changed`, `missing`,
    // `ro/f`, and `cd/f` now all match), so the coverage loop would check
    // "every path is listed" for the wrong diff instead of that THIS run
    // classified THIS diff correctly. The counts make a degenerate diff fail
    // loudly rather than pass vacuously.
    let pre_src = canonicalize_tree(&src).unwrap();
    let pre_dst = canonicalize_tree(&dst).unwrap();
    let diff = crate::sync::diff::diff_trees(&pre_src, &pre_dst);
    assert_eq!(diff.count(EntryDiff::Changed), 4, "{diff:?}");
    assert_eq!(diff.count(EntryDiff::Missing), 1, "{diff:?}");
    assert_eq!(diff.count(EntryDiff::Extraneous), 1, "{diff:?}");
    assert!(diff.count(EntryDiff::Same) >= 1, "{diff:?}");

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();

    // The TRUE rule: `applied`/`skipped`/`conflicts`/`extraneous` are pairwise
    // disjoint.
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for path in report
        .applied
        .iter()
        .chain(report.skipped.iter())
        .chain(report.conflicts.iter().map(|c| &c.path))
        .chain(report.extraneous.iter())
    {
        *seen.entry(path.clone()).or_default() += 1;
    }
    assert!(
        seen.values().all(|count| *count == 1),
        "a path is in two contradictory lists: {seen:?}"
    );
    // `transient_dirs` is disjoint from `skipped`, `conflicts`, and
    // `extraneous`; it MAY share a path with `applied`.
    assert_eq!(
        report.transient_dirs,
        vec!["cd".to_string(), "ro".to_string()]
    );
    for path in &report.transient_dirs {
        assert!(
            !report.skipped.contains(path),
            "a transient path is reported skipped: {path}"
        );
        assert!(
            !report
                .conflicts
                .iter()
                .any(|conflict| &conflict.path == path),
            "a transient path is reported conflicted: {path}"
        );
        assert!(
            !report.extraneous.contains(path),
            "a transient path is reported extraneous: {path}"
        );
    }
    // The `applied ∩ transient_dirs` overlap is real and exercised by `cd`.
    assert!(
        report.applied.contains(&"cd".to_string()),
        "the changed widened directory is applied: {report:?}"
    );
    assert!(
        report.transient_dirs.contains(&"cd".to_string()),
        "the changed widened directory is transient: {report:?}"
    );
    assert!(
        !report.applied.contains(&"ro".to_string()),
        "a `Same` widened directory is not applied: {report:?}"
    );
    // Every PRE-RUN diff entry is in one of the four lists OR in
    // `transient_dirs` (`diff` is the pre-run diff captured above).
    let transient: BTreeSet<&str> = report.transient_dirs.iter().map(String::as_str).collect();
    for (path, _) in &diff.entries {
        let in_four = seen.contains_key(path);
        let in_transient = transient.contains(path.as_str());
        assert!(
            in_four || in_transient,
            "{path} must be in one of the four lists or in `transient_dirs` (four={in_four}, transient={in_transient})"
        );
    }
    assert!(report.residue.is_empty(), "a clean sync has no residue");
    assert!(
        report.verify_failures.is_empty(),
        "a clean sync has no verification failures: {report:?}"
    );
    assert_report_lists_disjoint(&report);
}

/// Item 1: a write that installs bytes but ignores the requested mode must
/// fail verification AND must not be reported `applied` — `applied` requires
/// content AND mode verified.
#[cfg(unix)]
#[test]
fn a_mode_ignoring_write_is_not_reported_applied() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"new");
    write(&dst.join("f"), b"old");
    set_mode(&src.join("f"), 0o640);
    // A 0444 destination so `make_overwritable` actually widens (a 0600 one
    // never reaches the widen/restore path).
    set_mode(&dst.join("f"), 0o444);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.drop_write_mode = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();
    assert!(
        matches!(err.error(), Error::Integrity(_)),
        "the dropped mode must fail verification, got {err:?}"
    );
    // A DISTINCTIVE token, not a bare character: `contains('f')` was satisfied
    // by the "f" in "failed", so a message that named no path at all passed.
    assert!(
        err.error()
            .to_string()
            .contains("post-transfer verification failed for f:"),
        "the error names the path: {err}"
    );
    assert!(
        !err.report().applied.contains(&"f".to_string()),
        "a path whose mode check failed is NOT applied: {:?}",
        err.report()
    );
    // The dropped mode is NOT silently repaired: the restore returns the
    // ORIGINAL 0444, not the intended 0640.
    assert_eq!(
        mode_of(&dst.join("f")),
        0o444,
        "a dropped mode must not be masked by repairing it to the intended one"
    );
}

/// Item 2(a): a directory whose read-only final mode was reinstated by
/// `finalize` must be widened AGAIN for an extraneous removal (the journal's
/// `widened` bit is not a "currently widened" test).
#[cfg(unix)]
#[test]
fn extraneous_removal_after_finalize_rewidens_a_read_only_changed_parent() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();

    // PUSH.
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/child"), b"new");
    write(&dst.join("d/child"), b"old");
    write(&dst.join("d/extra"), b"e");
    set_mode(&src.join("d"), 0o555);
    set_mode(&dst.join("d"), 0o500);
    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(
        !dst.join("d/extra").exists(),
        "the extraneous entry is removed"
    );
    assert_eq!(read(&dst.join("d/child")), b"new");
    assert_eq!(mode_of(&dst.join("d")), 0o555, "the final mode wins");
    assert!(
        report.transient_dirs.contains(&"d".to_string()),
        "the widened parent `d` is named transient: {:?}",
        report.transient_dirs
    );

    // PULL.
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    write(&remote_root.join("d/child"), b"new");
    write(&local.join("d/child"), b"old");
    write(&local.join("d/extra"), b"e");
    set_mode(&remote_root.join("d"), 0o555);
    set_mode(&local.join("d"), 0o500);
    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &ReplaceAll,
        Delete,
    )
    .unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(!local.join("d/extra").exists());
    assert_eq!(read(&local.join("d/child")), b"new");
    assert_eq!(mode_of(&local.join("d")), 0o555);
}

/// Item 2(b): a source file replacing a read-only, POPULATED destination
/// directory must widen the TARGET directory before the recursive removal.
#[cfg(unix)]
#[test]
fn a_file_replacing_a_read_only_populated_directory_is_sanctioned() {
    let dir = fixture_tmpdir(&env()).unwrap();

    // PUSH.
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"file");
    write(&dst.join("p/keep"), b"keep");
    set_mode(&dst.join("p"), 0o555);
    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(
        dst.join("p").is_file(),
        "the directory is replaced by a file"
    );
    assert_eq!(read(&dst.join("p")), b"file");
    assert!(
        report.applied.contains(&"p".to_string()),
        "the replacement is reported applied: {report:?}"
    );
    assert!(report.extraneous.contains(&"p/keep".to_string()));

    // PULL.
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    write(&remote_root.join("p"), b"file");
    write(&local.join("p/keep"), b"keep");
    set_mode(&local.join("p"), 0o555);
    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &ReplaceAll,
        Delete,
    )
    .unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(local.join("p").is_file());
    assert_eq!(read(&local.join("p")), b"file");
    assert!(
        report.applied.contains(&"p".to_string()),
        "the replacement is reported applied: {report:?}"
    );
}

/// Item 1: a FAILED kind-changing replacement must leave the destination
/// subtree byte-identical (the stale entry is claimed aside, not removed) and
/// leave no stray aside — push.
#[cfg(unix)]
#[test]
fn a_failed_file_replacement_of_a_directory_leaves_the_subtree_byte_identical() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    write(&dst.join("p/keep"), b"keep");
    set_mode(&dst.join("p"), 0o555);
    let before = canonicalize_tree(&dst).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_writes = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();
    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    assert!(dst.join("p").is_dir(), "the directory survives the failure");
    assert_eq!(read(&dst.join("p/keep")), b"keep");
    assert_eq!(
        canonicalize_tree(&dst).unwrap(),
        before,
        "the destination subtree is BYTE-IDENTICAL after a failed replacement"
    );
    assert_no_aside(&dst);
    assert!(
        err.report().applied.is_empty(),
        "a failed replacement is not applied: {:?}",
        err.report()
    );
}

/// Item 1, pull: the source read fails after the claim, so the rollback runs on
/// the confined local destination. Byte-identical, no aside.
///
/// SCOPE: `fail_reads` fails the SOURCE READ, which happens BEFORE any
/// destination write, so this covers only the PRE-WRITE half of the
/// byte-identity claim. A local durable write failure (a dot-temp left behind by
/// `crate::atomic::write_atomic_replace_fd`) is NOT reachable from here because
/// `LocalSide::write_file` has no fault seam; the atomic-level tests in
/// `src/atomic/unix.rs` pin that the primitive unlinks its temp on every
/// failure path. The `canonicalize_tree` equality below DOES include any stray
/// dot-temp, so it is the assertion that will catch a leak once a seam exists.
#[cfg(unix)]
#[test]
fn a_failed_file_replacement_of_a_directory_leaves_the_subtree_byte_identical_on_pull() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    write(&remote_root.join("p"), b"new");
    write(&local.join("p/keep"), b"keep");
    set_mode(&local.join("p"), 0o555);
    let before = canonicalize_tree(&local).unwrap();

    let mut remote = RecordingRemote::over(transport(&remote_root), true);
    remote.fail_reads = true;
    let err = owned(Direction::Pull, &local, &remote, &ReplaceAll, Delete).unwrap_err();
    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    assert!(
        local.join("p").is_dir(),
        "the directory survives the failure"
    );
    assert_eq!(read(&local.join("p/keep")), b"keep");
    assert_eq!(
        canonicalize_tree(&local).unwrap(),
        before,
        "the local subtree is BYTE-IDENTICAL after a failed replacement"
    );
    assert_no_aside(&local);
}

/// Item 1: a SUCCESSFUL kind-changing replacement removes the stale subtree,
/// installs the new entry, and leaves no aside — push and pull.
#[cfg(unix)]
#[test]
fn a_successful_file_replacement_of_a_directory_leaves_no_aside() {
    let dir = fixture_tmpdir(&env()).unwrap();

    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"file");
    write(&dst.join("p/keep"), b"keep");
    set_mode(&dst.join("p"), 0o555);
    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(dst.join("p").is_file());
    assert_eq!(read(&dst.join("p")), b"file");
    assert!(report.applied.contains(&"p".to_string()));
    assert!(report.extraneous.contains(&"p/keep".to_string()));
    assert!(report.residue.is_empty(), "{report:?}");
    assert_no_aside(&dst);

    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    write(&remote_root.join("p"), b"file");
    write(&local.join("p/keep"), b"keep");
    set_mode(&local.join("p"), 0o555);
    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &ReplaceAll,
        Delete,
    )
    .unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(local.join("p").is_file());
    assert_eq!(read(&local.join("p")), b"file");
    assert!(report.applied.contains(&"p".to_string()));
    assert!(report.residue.is_empty(), "{report:?}");
    assert_no_aside(&local);
}

/// Item 1: a failed SYMLINK replacement of a directory rolls back.
#[cfg(unix)]
#[test]
fn a_failed_symlink_replacement_of_a_directory_leaves_the_subtree_byte_identical() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    std::os::unix::fs::symlink("target", src.join("p")).unwrap();
    write(&dst.join("p/keep"), b"keep");
    set_mode(&dst.join("p"), 0o555);
    let before = canonicalize_tree(&dst).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_symlink = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();
    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    assert!(dst.join("p").is_dir());
    assert_eq!(
        canonicalize_tree(&dst).unwrap(),
        before,
        "the destination subtree is BYTE-IDENTICAL after a failed symlink replacement"
    );
    assert_no_aside(&dst);
}

/// Item 1: a failed DIRECTORY replacement of a file rolls back.
#[cfg(unix)]
#[test]
fn a_failed_directory_replacement_of_a_file_leaves_the_entry_byte_identical() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p/f"), b"new");
    write(&dst.join("p"), b"old");
    let before = canonicalize_tree(&dst).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_create_dir_all = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();
    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    assert!(dst.join("p").is_file(), "the file survives the failure");
    assert_eq!(read(&dst.join("p")), b"old");
    assert_eq!(canonicalize_tree(&dst).unwrap(), before);
    assert_no_aside(&dst);
}

/// Item 1: if the ROLLBACK itself fails, the destination could not be restored
/// and that failure is reported alongside the original error.
#[cfg(unix)]
#[test]
fn a_failed_claim_rollback_is_reported_in_restore_failures() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    write(&dst.join("p/keep"), b"keep");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_writes = true;
    // rename #1 is the claim, #2 is the rollback.
    remote.fail_nth_rename = Some(2);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();
    assert!(
        err.restore_failures()
            .iter()
            .any(|f| f.contains("could not be restored")),
        "a failed rollback is reported: {:?}",
        err.restore_failures()
    );
    // A TRANSFER IS COUNTED PER ATTEMPTED mutation step, so all three steps
    // here are counted even though two of them FAILED:
    //   1. the claim-by-rename that moved `p` aside (succeeded),
    //   2. the `write_file` install of the new `p` (failed; the bytes may or
    //      may not be visible),
    //   3. the rollback rename of the aside back to `p` (failed; the original
    //      may or may not have moved back).
    // The exact count IS the contract here: `transfers` must record every
    // ATTEMPTED mutation, not only the successful ones, or a partially-applied
    // mutation would leave the count at 0 and break the "nothing was mutated"
    // oracle. (No widen is counted: `p` is top-level, so it has no ancestor.)
    assert_eq!(
        err.report().transfers,
        3,
        "exactly the claim, the failed install, and the failed rollback are \
         counted: {:?}",
        err.report()
    );
    // ATTEMPT-FIRST: `p` had two failed mutating calls (the install and the
    // rollback), so its state is UNKNOWN and it is named in `indeterminate`
    // (the highest-precedence list) rather than in any weaker list.
    assert!(
        err.report().indeterminate.contains(&"p".to_string()),
        "a failed install and a failed rollback leave `p` indeterminate: {:?}",
        err.report()
    );
    // COVERAGE (a failed claim rollback): the stranded original is NAMED as
    // residue, the destination-only child is NAMED as extraneous, and the
    // lists stay disjoint on the failure path.
    let aside = find_residue(&dst);
    assert!(
        err.report().residue.contains(&aside),
        "the stranded aside is named: {:?}",
        err.report()
    );
    assert_report_names(err.report(), &aside);
    assert_report_names(err.report(), "p/keep");
    assert_report_lists_disjoint(err.report());
    assert_residue_present(err.report(), &[&dst]);
    // The aside the rollback message names EXISTS: a message that claimed a
    // stranded path which is gone would be a lie about the tree.
    assert_restore_failures_name_existing_asides(&err, &dst);
}

/// HIGH (round 11): a CLAIM rename that LANDS and then reports failure must
/// name the aside. Before the fix `claim_aside` returned BEFORE
/// `re_root_residue`, so the caller's only copy sat at the aside and was named
/// NOWHERE — not in `residue`, not in `restore_failures`. `fail_nth_rename_-
/// after_rename` moves the entry and THEN fails, the shape a far-side
/// `rename(2)` whose connection drops before the outcome is observed exposes.
#[cfg(unix)]
#[test]
fn a_claim_rename_that_lands_and_reports_failure_names_the_aside() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    write(&dst.join("p/keep"), b"keep");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // rename #1 is the claim; it MOVES `p` aside and then reports failure.
    remote.fail_nth_rename_after_rename = Some(1);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();

    // The rename LANDED: the real path is gone and the aside holds the tree.
    assert!(
        !dst.join("p").exists(),
        "the landed claim rename moved `p` aside"
    );
    let aside = find_residue(&dst);
    assert_eq!(
        read(&dst.join(&aside).join("keep")),
        b"keep",
        "the aside holds the caller's only copy"
    );
    assert!(
        err.report().residue.contains(&aside),
        "the landed aside is named as residue: {:?}",
        err.report()
    );
    assert!(
        err.restore_failures().iter().any(|f| f.contains(&aside)),
        "the landed aside is a reported restore failure: {:?}",
        err.restore_failures()
    );
    // Every named path EXISTS (by construction, not by inspection).
    assert_residue_present(err.report(), &[&dst]);
    assert_restore_failures_name_existing_asides(&err, &dst);
    assert_file_somewhere(&dst, "keep", b"keep");
    assert_report_names(err.report(), &aside);
    assert_report_names(err.report(), "p");
    assert_report_lists_disjoint(err.report());
}

/// HIGH (round 11): a ROLLBACK rename that LANDS and then reports failure must
/// NOT leave the report claiming the entry "remains stranded at the aside".
/// The entry is back at its real path and the aside no longer exists, so naming
/// it as residue would point at a path that is gone.
#[cfg(unix)]
#[test]
fn a_rollback_rename_that_lands_and_reports_failure_claims_no_stranded_aside() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    write(&dst.join("p/keep"), b"keep");
    set_mode(&dst.join("p"), 0o555);
    let before = canonicalize_tree(&dst).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // The install fails, so the rollback runs: rename #1 is the claim (lands
    // normally), rename #2 is the ROLLBACK, which moves the entry back and THEN
    // reports failure.
    remote.fail_writes = true;
    remote.fail_nth_rename_after_rename = Some(2);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();

    // The rollback LANDED: the original is back at `p`, byte-identical, and no
    // aside exists anywhere.
    assert!(dst.join("p").is_dir(), "the directory is restored");
    assert_eq!(read(&dst.join("p/keep")), b"keep");
    assert_eq!(
        canonicalize_tree(&dst).unwrap(),
        before,
        "the destination is byte-identical after a rollback that landed"
    );
    assert_no_aside(&dst);
    assert!(
        err.report().residue.is_empty(),
        "a rollback that landed strands nothing: {:?}",
        err.report()
    );
    assert!(
        err.restore_failures().is_empty(),
        "a rollback that landed is not a restore failure: {:?}",
        err.restore_failures()
    );
    assert_residue_present(err.report(), &[&dst]);
    assert_restore_failures_name_existing_asides(&err, &dst);
    assert_report_lists_disjoint(err.report());
}

/// Item 2: a source symlink replacing a populated destination directory (with
/// `delete_extraneous`) is reported `applied`, not dropped from every list.
#[cfg(unix)]
#[test]
fn a_symlink_replacing_a_populated_directory_is_reported_applied() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    std::os::unix::fs::symlink("target", src.join("p")).unwrap();
    write(&dst.join("p/keep"), b"keep");
    // Read-only, so the removal has to widen it and therefore records a
    // journal entry the symlink must not inherit.
    set_mode(&dst.join("p"), 0o555);

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(fs::symlink_metadata(dst.join("p")).unwrap().is_symlink());
    assert!(
        report.applied.contains(&"p".to_string()),
        "the symlink replacement is reported applied: {report:?}"
    );
    assert!(report.residue.is_empty(), "{report:?}");
    assert_no_aside(&dst);
}

/// Item 2: a source symlink replacing an EMPTY read-only directory (with
/// `delete_extraneous=false`) is likewise reported `applied`.
#[cfg(unix)]
#[test]
fn a_symlink_replacing_an_empty_read_only_directory_is_reported_applied() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    std::os::unix::fs::symlink("target", src.join("p")).unwrap();
    fs::create_dir_all(dst.join("p")).unwrap();
    set_mode(&dst.join("p"), 0o555);

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert!(fs::symlink_metadata(dst.join("p")).unwrap().is_symlink());
    assert!(
        report.applied.contains(&"p".to_string()),
        "the symlink replacement is reported applied: {report:?}"
    );
    assert!(report.residue.is_empty(), "{report:?}");
    assert_no_aside(&dst);
}

/// Item 3: if a descriptor was pinned and the path then disappears, the empty
/// tree must not be synthesized.
#[test]
fn manifest_refuses_a_pinned_root_that_disappeared() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let root = dir.path().join("root");
    fs::create_dir_all(&root).unwrap();
    let side = LocalSide::open(&root, true).unwrap();
    fs::remove_dir_all(&root).unwrap();
    assert!(
        matches!(side.manifest(), Err(Error::Materialization(_))),
        "a pinned root that disappeared is an error, not an empty tree"
    );
}

/// Item 4: the refuse rule is uniform (a refused directory is never widened);
/// on the confined pull side a directory not already at `0o700` blocks its
/// children with `ParentRefused`, while one at `0o700` admits them.
#[cfg(unix)]
#[test]
fn the_refuse_rule_is_uniform_for_a_confined_pull() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    write(&remote_root.join("d/f"), b"new");
    set_mode(&remote_root.join("d"), 0o555);
    let refuse_d = |path: &str, _: EntryKind| {
        if path == "d" {
            EntryPolicy::Refuse
        } else {
            EntryPolicy::Replace
        }
    };

    // A refused directory that the confined write would have to chmod to 0700
    // blocks its child; nothing is mutated.
    let local = dir.path().join("blocked");
    write(&local.join("d/f"), b"old");
    set_mode(&local.join("d"), 0o755);
    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &refuse_d,
        Keep,
    )
    .unwrap();
    assert_eq!(report.transfers, 0, "nothing is mutated");
    assert_eq!(report.conflicts.len(), 2, "{:?}", report.conflicts);
    assert_eq!(
        conflict_at(&report, "d/f").reason,
        ConflictReason::ParentRefused
    );
    assert_eq!(read(&local.join("d/f")), b"old");
    assert_eq!(
        mode_of(&local.join("d")),
        0o755,
        "the refused mode is untouched"
    );

    // A refused directory already at 0700 needs no widen, so the child proceeds
    // while the directory's own mode stays untouched.
    let local = dir.path().join("admitted");
    write(&local.join("d/f"), b"old");
    set_mode(&local.join("d"), 0o700);
    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &refuse_d,
        Keep,
    )
    .unwrap();
    assert_eq!(report.conflicts.len(), 1, "{:?}", report.conflicts);
    assert_eq!(read(&local.join("d/f")), b"new", "the child proceeds");
    assert_eq!(
        mode_of(&local.join("d")),
        0o700,
        "the refused mode is untouched"
    );
}

/// Item 6: a `Changed` DIRECTORY child under a read-only destination parent
/// (the child replaces a file) must widen the parent to be created.
#[cfg(unix)]
#[test]
fn a_changed_directory_child_under_a_read_only_parent_is_created() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();

    // PUSH.
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/sub/f"), b"new");
    write(&dst.join("d/sub"), b"old");
    set_mode(&src.join("d"), 0o555);
    set_mode(&dst.join("d"), 0o555);
    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(dst.join("d/sub").is_dir());
    assert_eq!(read(&dst.join("d/sub/f")), b"new");
    assert_eq!(mode_of(&dst.join("d")), 0o555, "the parent is restored");
    assert!(
        report.transient_dirs.contains(&"d".to_string()),
        "the widened parent `d` is named transient: {:?}",
        report.transient_dirs
    );

    // PULL.
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    write(&remote_root.join("d/sub/f"), b"new");
    write(&local.join("d/sub"), b"old");
    set_mode(&remote_root.join("d"), 0o555);
    set_mode(&local.join("d"), 0o555);
    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &ReplaceAll,
        Keep,
    )
    .unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(local.join("d/sub").is_dir());
    assert_eq!(read(&local.join("d/sub/f")), b"new");
    assert_eq!(mode_of(&local.join("d")), 0o555);
}

/// Item 6: `AppendTail` selected for a non-file (a directory, or a file over a
/// symlink) is `AppendNotAFile`, never a destructive substitute.
#[cfg(unix)]
#[test]
fn append_tail_on_a_non_file_is_a_conflict() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();

    // A DIRECTORY entry under AppendTail.
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(src.join("d")).unwrap();
    fs::create_dir_all(dst.join("d")).unwrap();
    set_mode(&src.join("d"), 0o755);
    set_mode(&dst.join("d"), 0o700);
    let append_all = |_: &str, _: EntryKind| EntryPolicy::AppendTail;
    let report = owned(Direction::Push, &src, &transport(&dst), &append_all, Keep).unwrap();
    assert_eq!(report.conflicts.len(), 1, "{:?}", report.conflicts);
    assert_eq!(report.conflicts[0].reason, ConflictReason::AppendNotAFile);
    assert_eq!(mode_of(&dst.join("d")), 0o700, "the directory is untouched");

    // A regular file over a destination SYMLINK.
    let src = dir.path().join("src2");
    let dst = dir.path().join("dst2");
    write(&src.join("f"), b"payload");
    fs::create_dir_all(&dst).unwrap();
    std::os::unix::fs::symlink("target", dst.join("f")).unwrap();
    let report = owned(Direction::Push, &src, &transport(&dst), &append_files, Keep).unwrap();
    assert_eq!(report.conflicts.len(), 1, "{:?}", report.conflicts);
    assert_eq!(report.conflicts[0].reason, ConflictReason::AppendNotAFile);
    assert!(
        fs::symlink_metadata(dst.join("f")).unwrap().is_symlink(),
        "the destination symlink is untouched"
    );
}

/// Item 6: a source SYMLINK replacing a populated destination directory is
/// refused without `delete_extraneous`; the children survive.
#[cfg(unix)]
#[test]
fn a_source_symlink_replacing_a_populated_directory_conflicts() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    std::os::unix::fs::symlink("target", src.join("p")).unwrap();
    write(&dst.join("p/keep"), b"keep");

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert_eq!(report.conflicts.len(), 1, "{:?}", report.conflicts);
    assert_eq!(report.conflicts[0].path, "p");
    assert_eq!(report.conflicts[0].reason, ConflictReason::ExtraneousBelow);
    assert!(dst.join("p").is_dir(), "the directory survives");
    assert_eq!(read(&dst.join("p/keep")), b"keep");
    assert!(report.extraneous.contains(&"p/keep".to_string()));
}

/// Item 6: pull writes must go through `crate::atomic`, which publishes by
/// rename (the destination inode changes). A bare `fs::write` would truncate in
/// place and keep the inode.
#[cfg(unix)]
#[test]
fn a_pull_publishes_by_atomic_rename_not_an_in_place_write() {
    use std::os::unix::fs::MetadataExt;
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    write(&remote_root.join("f"), b"new");
    write(&local.join("f"), b"old");
    let before = fs::symlink_metadata(local.join("f")).unwrap().ino();

    owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &ReplaceAll,
        Keep,
    )
    .unwrap();

    assert_eq!(read(&local.join("f")), b"new");
    let after = fs::symlink_metadata(local.join("f")).unwrap().ino();
    assert_ne!(
        before, after,
        "the pull must publish a new inode (atomic rename), not write in place"
    );
}

/// Item 7: a non-empty destination root that appeared after the path was
/// described as absent must not be silently adopted.
#[test]
fn a_racily_created_non_empty_destination_root_is_not_adopted() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let root = dir.path().join("root");
    let side = LocalSide::open(&root, true).unwrap();
    // The manifest pass describes the absent destination as the empty tree.
    assert!(side.manifest().unwrap().entries.is_empty());
    // A racer creates a NON-EMPTY directory at the path.
    write(&root.join("racer"), b"x");
    assert!(
        matches!(side.root_for_mutation(), Err(Error::Materialization(_))),
        "a non-empty racer-created root must be refused, not adopted"
    );

    // An EMPTY racer-created directory is exactly what the sync would create.
    let empty_root = dir.path().join("empty-root");
    let side = LocalSide::open(&empty_root, true).unwrap();
    assert!(side.manifest().unwrap().entries.is_empty());
    fs::create_dir_all(&empty_root).unwrap();
    assert!(side.root_for_mutation().is_ok(), "an empty root is adopted");
}

/// Item 4: a directory blocked by ANY conflict reason (here `AppendNotAFile`)
/// is never widened to install a child.
#[cfg(unix)]
#[test]
fn a_directory_blocked_by_an_append_conflict_is_never_widened() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/f"), b"abcdef");
    write(&dst.join("d/f"), b"abc");
    // The directory is Changed (mode differs), so its policy IS consulted.
    set_mode(&src.join("d"), 0o755);
    set_mode(&dst.join("d"), 0o555);

    let append_all = |_: &str, _: EntryKind| EntryPolicy::AppendTail;
    let report = owned(Direction::Push, &src, &transport(&dst), &append_all, Keep).unwrap();

    assert_eq!(report.transfers, 0, "nothing is mutated");
    assert!(
        report.transient_dirs.is_empty(),
        "a blocked directory is never widened: {:?}",
        report.transient_dirs
    );
    assert!(
        report
            .conflicts
            .iter()
            .any(|c| c.path == "d" && c.reason == ConflictReason::AppendNotAFile),
        "the directory is the conflict: {:?}",
        report.conflicts
    );
    assert!(
        report
            .conflicts
            .iter()
            .any(|c| c.path == "d/f" && c.reason == ConflictReason::ParentRefused),
        "the child is ParentRefused: {:?}",
        report.conflicts
    );
    assert_eq!(
        mode_of(&dst.join("d")),
        0o555,
        "the blocked mode is untouched"
    );
    assert_eq!(read(&dst.join("d/f")), b"abc", "the child is untouched");
}

/// Item 7: an `AppendTail` child that needs NO parent write (the source is a
/// prefix of the destination) is NOT `ParentRefused` under a refused read-only
/// parent.
#[cfg(unix)]
#[test]
fn a_no_write_append_under_a_refused_read_only_parent_is_not_parent_refused() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    // The source is a PREFIX of the destination: nothing is appended.
    write(&src.join("d/f"), b"abc");
    write(&dst.join("d/f"), b"abcdef");
    set_mode(&src.join("d/f"), 0o644);
    set_mode(&dst.join("d/f"), 0o644);
    set_mode(&src.join("d"), 0o755);
    set_mode(&dst.join("d"), 0o555);

    let policy = |path: &str, kind: EntryKind| {
        if path == "d" {
            EntryPolicy::Refuse
        } else if kind == EntryKind::File {
            EntryPolicy::AppendTail
        } else {
            EntryPolicy::Replace
        }
    };
    let report = owned(Direction::Push, &src, &transport(&dst), &policy, Keep).unwrap();
    assert_eq!(report.transfers, 0, "nothing is mutated");
    assert!(
        report.conflicts.iter().all(|c| c.path == "d"),
        "only the refused directory conflicts; the no-write append does not: {:?}",
        report.conflicts
    );
    assert_eq!(read(&dst.join("d/f")), b"abcdef", "never truncated");
    assert_eq!(mode_of(&dst.join("d")), 0o555);

    // An append that DOES write is still blocked.
    let src2 = dir.path().join("src2");
    let dst2 = dir.path().join("dst2");
    write(&src2.join("d/f"), b"abcdef");
    write(&dst2.join("d/f"), b"abc");
    set_mode(&src2.join("d/f"), 0o644);
    set_mode(&dst2.join("d/f"), 0o644);
    set_mode(&src2.join("d"), 0o755);
    set_mode(&dst2.join("d"), 0o555);
    let report = owned(Direction::Push, &src2, &transport(&dst2), &policy, Keep).unwrap();
    assert!(
        report
            .conflicts
            .iter()
            .any(|c| c.path == "d/f" && c.reason == ConflictReason::ParentRefused),
        "a writing append under the refused read-only parent is ParentRefused: {:?}",
        report.conflicts
    );
    assert_eq!(read(&dst2.join("d/f")), b"abc", "unchanged");
}

/// A2: the append's read→write window. A concurrent writer APPENDS to the
/// destination between the append's destination read and its write. Pre-fix
/// the append wrote the WHOLE source unconditionally, so the writer's bytes
/// were overwritten, the post-transfer hash matched the source, and the run
/// returned `Ok` with empty `conflicts` — silent loss. The compare-and-append
/// now refuses the write (the live content no longer matches the bytes it
/// read), re-reads, finds the streams diverged, and reports a `Diverged`
/// conflict; the writer's bytes survive on disk.
#[test]
fn an_append_write_that_races_a_concurrent_appender_conflicts_and_preserves_it() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    // The destination is `a\n`; our append carries `a\nb\n` (the destination
    // is a prefix, so a write is due). The writer appends `CONCURRENT\n` right
    // after the append's destination read.
    write(&src.join("f"), b"a\nb\n");
    write(&dst.join("f"), b"a\n");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // The append's own destination read is the FIRST `Remote::read` of `f`: a
    // LOCAL remote's manifest is canonicalized in-process and never reads
    // through the transport.
    remote.dest_read_writer = Some((
        "f".to_string(),
        1,
        AfterWrite::Append("f".to_string(), b"CONCURRENT\n".to_vec()),
    ));
    let policy = |path: &str, _: EntryKind| {
        if path == "f" {
            EntryPolicy::AppendTail
        } else {
            EntryPolicy::Replace
        }
    };
    let result = owned(Direction::Push, &src, &remote, &policy, Keep);
    let report = match &result {
        Ok(report) => report,
        Err(error) => error.report(),
    };

    // THE DEFECT: a silent overwrite of the concurrent writer's bytes.
    assert_eq!(
        read(&dst.join("f")),
        b"a\nCONCURRENT\n",
        "the concurrent appender's bytes must not be overwritten: {report:?}"
    );
    assert!(
        !report.applied.contains(&"f".to_string()),
        "a raced append must NOT be reported applied: {report:?}"
    );
    assert!(
        report
            .conflicts
            .iter()
            .any(|c| c.path == "f" && c.reason == ConflictReason::Diverged),
        "the raced append must be a Diverged conflict, never a silent success: {report:?}"
    );
    assert_report_lists_disjoint(report);
}

/// F1: a concurrent DELETION of the append target. The writer unlinks `f`
/// immediately after the append's destination read, so the compare-and-append's
/// re-read finds the entry GONE. The documented contract: a live entry the
/// caller read but that is now ABSENT is a MISMATCH, never an error — the retry
/// re-reads, sees the live kind is `None`, takes the absent-destination branch,
/// CREATES `f = "a\nb\n"`, and reports it applied.
///
/// Pre-fix `Side::write_file_if_match` matched ONLY `Err(Error::NotFound(_))`,
/// which NO transport's `read` returns (both wrap ENOENT as a transport error),
/// so the deletion surfaced as
/// `Err(Transport("read f: ... No such file or directory"))` and the run
/// returned `Err` with `f` indeterminate instead of creating it.
#[test]
fn an_append_whose_target_is_deleted_during_the_compare_creates_it() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    // The destination is `a\n`; our append carries `a\nb\n` (a prefix). The
    // writer DELETES `f` right after the append's destination read, before the
    // compare's re-read.
    write(&src.join("f"), b"a\nb\n");
    write(&dst.join("f"), b"a\n");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // The append's own destination read is the FIRST `Remote::read` of `f`: a
    // LOCAL remote's manifest is canonicalized in-process and never reads
    // through the transport.
    remote.dest_read_writer = Some(("f".to_string(), 1, AfterWrite::Delete("f".to_string())));
    let policy = |path: &str, _: EntryKind| {
        if path == "f" {
            EntryPolicy::AppendTail
        } else {
            EntryPolicy::Replace
        }
    };
    let report = owned(Direction::Push, &src, &remote, &policy, Keep)
        .expect("a deleted append target is a mismatch, never an error");

    // The retry re-reads, sees the live kind is `None`, and CREATES the source
    // bytes; the deletion is reported neither as an error nor as a conflict.
    assert_eq!(
        read(&dst.join("f")),
        b"a\nb\n",
        "the retry must create the source bytes at the deleted target: {report:?}"
    );
    assert!(
        report.applied.contains(&"f".to_string()),
        "the created append target is applied: {report:?}"
    );
    assert!(
        report.conflicts.is_empty(),
        "a deleted-then-recreated append must not conflict: {report:?}"
    );
    assert_report_lists_disjoint(&report);
}

/// F3: a concurrent DELETION between the LIVE-KIND read and the BYTE read.
/// The writer unlinks `f` IMMEDIATELY BEFORE the append's own `Remote::read` of
/// `f` (the first read of that path), so the read itself fails with ENOENT.
/// The documented contract is the SAME one the compare's re-read follows: an
/// entry that has become ABSENT is a MISMATCH, never an error — the retry
/// re-reads, sees the live kind is `None`, takes the absent-destination branch,
/// CREATES `f = "a\nb\n"`, and reports it applied.
///
/// Pre-fix the append's first read was `Some(EntryKind::File) =>
/// self.dest.read(rel)?`, which propagated the missing file as a hard error:
/// `Err(Transport("read f: store error: openat f: No such file or directory
/// (os error 2)"))` with `f` in NONE of the report lists. The neighbouring
/// `an_append_whose_target_is_deleted_during_the_compare_creates_it` pins the
/// compare's re-read window; this pins the FIRST read.
#[test]
fn an_append_whose_target_is_deleted_before_the_byte_read_is_created() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    // The destination is `a\n`; our append carries `a\nb\n` (a prefix). The
    // writer DELETES `f` immediately before the append's own byte read, so the
    // read observes ENOENT rather than the bytes.
    write(&src.join("f"), b"a\nb\n");
    write(&dst.join("f"), b"a\n");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // The append's destination read is the FIRST `Remote::read` of `f` (a
    // LOCAL remote's manifest is canonicalized in-process and never reads
    // through the transport); the live-kind probe uses `metadata`, not `read`,
    // so this fires in the exact window between the kind and the bytes.
    remote.dest_read_before_writer =
        Some(("f".to_string(), 1, AfterWrite::Delete("f".to_string())));
    let policy = |path: &str, _: EntryKind| {
        if path == "f" {
            EntryPolicy::AppendTail
        } else {
            EntryPolicy::Replace
        }
    };
    let report = owned(Direction::Push, &src, &remote, &policy, Keep)
        .expect("an append target deleted before the byte read is a mismatch, never an error");

    assert_eq!(
        read(&dst.join("f")),
        b"a\nb\n",
        "the retry must create the source bytes at the deleted target: {report:?}"
    );
    assert!(
        report.applied.contains(&"f".to_string()),
        "the created append target is applied: {report:?}"
    );
    assert!(
        report.conflicts.is_empty(),
        "a deleted-then-recreated append must not conflict: {report:?}"
    );
    assert_report_lists_disjoint(&report);
}

/// F3 (the adjacent window): a concurrent DELETION between the append's byte
/// read and the `append_settle_mode` kind re-read. Here NO byte write is due
/// (the source `a\n` is a PREFIX of the destination `a\nb\n`), so the settle
/// path runs — and the destination vanished in the window.
///
/// Pre-fix `append_settle_mode` mapped the vanished entry (`kind_opt` is
/// `None`) to an `AppendNotAFile` CONFLICT, discarding the source: the very
/// same absence the first read now reports as a mismatch was treated as a
/// non-file kind. After the fix absence is `AppendAttempt::Changed`, so the
/// retry takes the absent-destination branch and creates the source bytes.
#[test]
fn an_append_settle_whose_target_is_deleted_after_the_byte_read_is_created() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    // The source `a\n` is a PREFIX of the destination `a\nb\n`, so the append
    // rule writes NO bytes and settles through `append_settle_mode`.
    write(&src.join("f"), b"a\n");
    write(&dst.join("f"), b"a\nb\n");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // After the append's byte read lands, the writer deletes `f`, so the settle
    // path's kind re-read sees the entry GONE.
    remote.dest_read_writer = Some(("f".to_string(), 1, AfterWrite::Delete("f".to_string())));
    let policy = |path: &str, _: EntryKind| {
        if path == "f" {
            EntryPolicy::AppendTail
        } else {
            EntryPolicy::Replace
        }
    };
    let report = owned(Direction::Push, &src, &remote, &policy, Keep)
        .expect("a settled append target deleted in the window is a mismatch, never an error");

    assert!(
        report.conflicts.is_empty(),
        "a deleted-then-recreated settle must not conflict (pre-fix it maps the absent entry to \
         AppendNotAFile and discards the source): {report:?}"
    );
    assert!(
        report.applied.contains(&"f".to_string()),
        "the created append target is applied: {report:?}"
    );
    assert_eq!(
        read(&dst.join("f")),
        b"a\n",
        "the retry must create the source bytes at the deleted target: {report:?}"
    );
    assert_report_lists_disjoint(&report);
}

/// A4: a parent sync must NEVER destroy a held nested lock record. The nested
/// store's record is `destination_lock_path(snapshots/001)` =
/// `snapshots/.001.operation.lock`, which lies INSIDE the parent store's judged
/// tree. Before the fix it was an ordinary destination-only entry and a
/// sanctioned `Extraneous::Delete` removed it — breaking the STABLE-INODE
/// discipline (the lock file is created once and never removed) so a second
/// acquisition while the first holder was alive SUCCEEDED, giving two live
/// holders of one logical lock. The record spelling is now reserved, so it is
/// stripped from the diff, reported as residue, and left on disk.
#[cfg(unix)]
#[test]
fn a_parent_sync_never_destroys_a_held_nested_lock_record() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    // The snapshot subtree is identical on both sides, so the ONLY
    // destination-only entry is the nested lock record.
    write(&src.join("snapshots/001/f"), b"SNAP");
    write(&dst.join("snapshots/001/f"), b"SNAP");

    // Hold the NESTED store's record for the whole run.
    let nested_root = dst.join("snapshots/001");
    let lock_path =
        destination_lock_path(&nested_root).expect("the nested record location derives");
    assert_eq!(
        lock_path.file_name().and_then(|n| n.to_str()),
        Some(".001.operation.lock"),
        "the record spelling this test pins"
    );
    let held = FileLock::acquire(&lock_path, "the test's nested holder").expect("hold the record");
    assert!(lock_path.exists(), "the held record exists before the run");

    // A SANCTIONED parent sync: the whole-store push with deletion enabled.
    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();

    assert!(
        lock_path.exists(),
        "a parent sync MUST NOT destroy a held nested lock record: {report:?}"
    );
    assert!(
        report
            .residue
            .contains(&"snapshots/.001.operation.lock".to_string()),
        "the surviving record must be NAMED as residue: {report:?}"
    );
    assert!(
        !report
            .extraneous
            .contains(&"snapshots/.001.operation.lock".to_string()),
        "a reserved record is never classified as extraneous content: {report:?}"
    );
    // The exclusion must still hold: a second acquisition while the first
    // holder is alive is REFUSED (the pre-fix removal made it succeed).
    let second = FileLock::acquire(&lock_path, "the second holder");
    assert!(
        second.is_err(),
        "two live holders of the same logical lock must be impossible"
    );
    drop(held);
}

/// F1: the crate's own `sync` must not carry the lock record over a live
/// holder's inode. Pre-fix `is_reserved_path` consulted only the byte-exact
/// reserved spellings, which do NOT include the application lock record
/// `operation.lock`, so a source entry `state/operation.lock` was neither
/// stripped nor treated as residue and was applied as ordinary content: the
/// record's inode changed and a SECOND `FileLock::acquire` SUCCEEDED while the
/// first holder was alive. The manifest-path model now consults the SAME
/// authority the id rule does, so the source collision is a `ReservedName`
/// conflict, the destination record is residue, and the inode never moves.
#[cfg(unix)]
#[test]
fn a_push_cannot_carry_the_lock_record_over_a_live_holder() {
    use std::os::unix::fs::MetadataExt;
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    // The SOURCE holds the record spelling (the `Layout::empty().lock` path).
    write(&src.join("normal"), b"payload");
    write(&src.join("state/operation.lock"), b"evil");
    // A live holder of the destination's record.
    std::fs::create_dir_all(dst.join("state")).unwrap();
    let record = dst.join("state/operation.lock");
    let held = FileLock::acquire(&record, "the test's holder").expect("hold the record");
    let inode_before = std::fs::metadata(&record).unwrap().ino();

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();

    assert!(
        !report.applied.contains(&"state/operation.lock".to_string()),
        "the record must never be transferred: {report:?}"
    );
    assert!(
        report
            .conflicts
            .iter()
            .any(|c| c.path == "state/operation.lock" && c.reason == ConflictReason::ReservedName),
        "the source collision must be REPORTED as a reserved name, not silently skipped: {report:?}"
    );
    // The record is recognized internally as DESTINATION residue too; the
    // report's precedence gives the source conflict (a higher-precedence list)
    // the path, but the record must still be left on disk and named somewhere.
    assert!(
        report.residue.contains(&"state/operation.lock".to_string())
            || report
                .conflicts
                .iter()
                .any(|c| c.path == "state/operation.lock"),
        "the destination record must be named (residue or the higher-precedence conflict): {report:?}"
    );
    assert_eq!(
        std::fs::metadata(&record).unwrap().ino(),
        inode_before,
        "the record must keep the holder's stable inode"
    );
    let second = match FileLock::acquire(&record, "the second holder") {
        Ok(_) => panic!("a second holder must not acquire while the first is alive"),
        Err(e) => e,
    };
    assert!(
        matches!(second, Error::LockContended(_)),
        "the second acquisition must be typed contention: {second:?}"
    );
    drop(held);
}

/// F1, ALIAS form: every spelling that can ALIAS the record is stripped too.
/// A source entry whose final component is a case alias of `operation.lock`
/// (`.STATE/OPERATION.LOCK`) is a collision and is never transferred.
#[cfg(unix)]
#[test]
fn a_push_strips_a_case_alias_of_the_lock_record() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("normal"), b"payload");
    write(&src.join("STATE/OPERATION.LOCK"), b"evil");
    std::fs::create_dir_all(&dst).unwrap();

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert!(
        !report
            .applied
            .iter()
            .any(|p| p.to_lowercase().ends_with("operation.lock")),
        "a case alias of the record must never be transferred: {report:?}"
    );
    assert!(
        report
            .conflicts
            .iter()
            .any(|c| c.path == "STATE/OPERATION.LOCK"),
        "the alias collision must be reported: {report:?}"
    );
}

/// F6: a bare destination `operation.lock` is RESIDUE, not a failed deletion.
/// Pre-fix `Extraneous::Delete` over the record hard-errored with a transport
/// conflict and `indeterminate=["state/operation.lock"]` (or `["operation.lock"]`
/// for the root-level spelling); the record is now recognized as residue (the
/// same authority gap as F1), left in place, and named in the report so a
/// caller learns it is there. Both the in-root `state/operation.lock` and the
/// bare root-level `operation.lock` are covered (G2).
#[cfg(unix)]
#[test]
fn extraneous_delete_spares_and_names_the_lock_record() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(dst.join("state")).unwrap();
    let record = dst.join("state/operation.lock");
    std::fs::write(&record, b"held").unwrap();
    // The BARE application lock record at the destination root too (G2).
    let bare = dst.join("operation.lock");
    std::fs::write(&bare, b"held").unwrap();

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete)
        .expect("deleting extraneous content must not abort on the lock record");
    assert!(
        record.exists() && bare.exists(),
        "both lock-record spellings must survive a sanctioned deletion: {report:?}"
    );
    for spelling in ["state/operation.lock", "operation.lock"] {
        assert!(
            report.residue.contains(&spelling.to_string()),
            "the surviving record {spelling} must be NAMED as residue: {report:?}"
        );
        assert!(
            !report.extraneous.contains(&spelling.to_string()),
            "the record {spelling} is never extraneous content: {report:?}"
        );
    }
    assert!(
        report.indeterminate.is_empty(),
        "no failed mutation may be recorded for a record: {report:?}"
    );
}

/// G1: a far-side `mktemp` temp is a CRATE TEMP, not a held-aside, so
/// `Extraneous::Delete` removes it. Pre-fix `is_crate_temp_name` required an
/// all-digit `<pid>.<counter>` tail, so `.sync-aside.foo.tmp.aB3xY9` (the
/// far-side six-alphanumeric tail) was classified as residue, was never
/// removable, and was misreported as holding the original.
#[cfg(unix)]
#[test]
fn a_farside_mktemp_temp_is_extraneous_not_residue() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("a"), b"payload");
    std::fs::create_dir_all(&dst).unwrap();
    let temp = dst.join(".sync-aside.foo.tmp.aB3xY9");
    std::fs::write(&temp, b"partial payload").unwrap();

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(
        report
            .extraneous
            .contains(&".sync-aside.foo.tmp.aB3xY9".to_string()),
        "a crashed far-side temp must be reachable as extraneous: {report:?}"
    );
    assert!(
        !report
            .residue
            .contains(&".sync-aside.foo.tmp.aB3xY9".to_string()),
        "a far-side temp holds no original and must NOT be residue: {report:?}"
    );
    assert!(!temp.exists(), "a sanctioned deletion removes the temp");
}

/// G3: on a case-insensitive filesystem a CASE ALIAS of a reserved spelling is
/// the SAME INODE, so `Extraneous::Delete` must not destroy it — matching the
/// README's "a reserved spelling is never destroyed by `Extraneous::Delete`".
/// The destination residue classifier consults the SAME unaddressable
/// authority as the id rule, so the alias is residue. The reproduction needs a
/// case-folding filesystem (macOS APFS by default); on a case-sensitive one the
/// two spellings are distinct and the test skips with an announced reason.
#[cfg(unix)]
#[test]
fn extraneous_delete_spares_a_case_alias_of_a_reserved_spelling() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&dst).unwrap();
    // Create the entry under its CASE-ALIAS spelling: APFS preserves the case
    // used at creation, so the on-disk name is the alias.
    std::fs::write(dst.join(".SYNC-ASIDE.1"), b"held original").unwrap();
    if std::fs::symlink_metadata(dst.join(".sync-aside.1")).is_err() {
        crate::test_support::announce_skip(
            "this filesystem is case-SENSITIVE, so `.SYNC-ASIDE.1` and `.sync-aside.1` are distinct \
             entries and the on-disk alias reproduction is untestable here",
        );
        return;
    }
    // The alias resolves to the SAME inode as the lowercase spelling.
    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete)
        .expect("deleting extraneous content must not abort on a reserved alias");
    assert!(
        dst.join(".SYNC-ASIDE.1").exists(),
        "the aliased reserved entry must survive a sanctioned deletion: {report:?}"
    );
    assert!(
        report.residue.contains(&".SYNC-ASIDE.1".to_string()),
        "the surviving reserved alias must be NAMED as residue: {report:?}"
    );
    assert!(
        !report.extraneous.contains(&".SYNC-ASIDE.1".to_string()),
        "a reserved alias is never extraneous content: {report:?}"
    );
    println!(
        "G3 case-alias probe ran on platform={} (the filesystem folds case)",
        std::env::consts::OS
    );
}

/// F5: the derived lock-record name is BOUNDED to `NAME_MAX`. Pre-fix
/// `destination_lock_path` built `.` + the full destination component +
/// `.operation.lock`, so a 240-byte component produced a 256-byte record name
/// and `FileLock::acquire` failed `ENAMETOOLONG`. The embedded component is
/// bounded by the SAME authority that bounds temp names, so the record fits
/// and the derivation stays deterministic.
#[cfg(unix)]
#[test]
fn the_derived_lock_record_name_is_bounded_to_name_max() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let long = "n".repeat(240);
    let root = dir.path().join(&long);
    std::fs::create_dir_all(&root).unwrap();
    let record = destination_lock_path(&root).expect("a sibling record location");
    let name = record
        .file_name()
        .and_then(|n| n.to_str())
        .expect("the record names a UTF-8 file");
    assert!(
        name.len() <= crate::atomic::NAME_MAX,
        "the record name for a 240-byte destination must be <= NAME_MAX, got {} bytes: {name}",
        name.len()
    );
    assert!(
        crate::reserved::is_reserved_name(name),
        "the bounded record must still be a reserved spelling: {name}"
    );
    // Deterministic: the same root derives the same record, so the
    // port-keyed stable-inode property holds.
    assert_eq!(
        destination_lock_path(&root),
        Some(record.clone()),
        "the record derivation must be deterministic"
    );
    let held = FileLock::acquire(&record, "bounded holder")
        .expect("the bounded record name must be acquirable");
    drop(held);
}

/// F-C: two DISTINCT sibling destinations must derive DISTINCT lock records.
/// Pre-fix `bounded_temp_trunk` returned a name VERBATIM whenever it merely
/// fit, so a 240-byte destination derived a 239-byte hash-truncated trunk and a
/// destination NAMED that trunk then returned it verbatim — `trunk(trunk(B))
/// == trunk(B)`. Both destinations derived the SAME record, so two independent
/// `sync::push`es contended spuriously (and a hard `ENAMETOOLONG` became a
/// silent lock alias). The branches now occupy disjoint length ranges.
///
/// LOAD-BEARING BY MUTATION: removing the hash from the truncation makes the
/// two records equal and fails this test.
#[cfg(unix)]
#[test]
fn distinct_destinations_never_share_a_lock_record() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let long_root = dir.path().join("b".repeat(240));
    let long_record = destination_lock_path(&long_root).expect("a record for the long root");
    let trunk = long_record
        .file_name()
        .and_then(|n| n.to_str())
        .expect("the record names UTF-8")
        .strip_prefix('.')
        .and_then(|n| n.strip_suffix(OPERATION_LOCK_SUFFIX))
        .expect("the record is `.<trunk>.operation.lock`")
        .to_string();
    let alias_root = dir.path().join(&trunk);
    let alias_record =
        destination_lock_path(&alias_root).expect("a record for the trunk-named root");
    assert_ne!(
        long_record, alias_record,
        "the long destination and the destination NAMED its truncated trunk must NOT share a lock \
         record"
    );
}

/// B2: a run REFUSED for an unrepresentable SOURCE must create NOTHING. The
/// pre-fix order provisioned the destination (creating the root) and took the
/// destination lock (creating the sibling record) BEFORE the source manifest
/// was read, so a push of a source containing a hard link left a destination
/// root behind — a `list_snapshots()` above it would report a snapshot that
/// does not exist. The source manifest is now read (strictly) before ownership
/// is established and before the destination is provisioned.
#[cfg(unix)]
#[test]
fn a_refused_source_creates_no_destination_root_or_lock_record() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    // A hard link is unrepresentable in the manifest model, so the STRICT
    // source manifest refuses the run.
    write(&src.join("hard-a"), b"PAYLOAD");
    fs::hard_link(src.join("hard-a"), src.join("hard-b")).unwrap();
    assert!(!dst.exists(), "the destination root starts absent");
    let lock = destination_lock_path(&dst).expect("the record location derives");
    assert!(!lock.exists(), "the lock record starts absent");

    let result = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep);
    assert!(
        result.is_err(),
        "a hard-linked source must be refused: {result:?}"
    );
    assert!(
        !dst.exists(),
        "a refused run must NOT create the destination root"
    );
    assert!(
        !lock.exists(),
        "a refused run must NOT create the destination lock record"
    );
}

/// Item 5: an extraneous removal under a refused read-only ancestor reports a
/// `ParentRefused` conflict instead of an opaque permission error, and the
/// entry is reported in `conflicts` (not duplicated in `extraneous`).
#[cfg(unix)]
#[test]
fn a_blocked_extraneous_removal_reports_a_conflict() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/f"), b"new");
    write(&dst.join("d/f"), b"old");
    write(&dst.join("d/extra"), b"e");
    set_mode(&src.join("d"), 0o755);
    set_mode(&dst.join("d"), 0o555);

    let refuse_d = |path: &str, _: EntryKind| {
        if path == "d" {
            EntryPolicy::Refuse
        } else {
            EntryPolicy::Replace
        }
    };
    let report = owned(Direction::Push, &src, &transport(&dst), &refuse_d, Delete).unwrap();
    assert!(
        dst.join("d/extra").exists(),
        "the blocked removal leaves the entry"
    );
    assert!(
        report
            .conflicts
            .iter()
            .any(|c| c.path == "d/extra" && c.reason == ConflictReason::ParentRefused),
        "the blocked removal is reported as a conflict: {:?}",
        report.conflicts
    );
    assert!(
        !report.extraneous.contains(&"d/extra".to_string()),
        "a path reported as a conflict is not duplicated in `extraneous`: {:?}",
        report.extraneous
    );
    assert_eq!(
        mode_of(&dst.join("d")),
        0o555,
        "the refused mode is untouched"
    );
}

#[test]
fn widen_target_is_derived_from_the_current_mode() {
    // Private, non-confined: the target is the CURRENT mode plus owner
    // write+traverse — never the source mode.
    assert_eq!(widen_target(0o500, true, ParentNeed::Private, false), 0o700);
    assert_eq!(widen_target(0o555, true, ParentNeed::Private, false), 0o755);
    assert_ne!(
        widen_target(0o500, true, ParentNeed::Private, false),
        0o755,
        "a 0500 destination must NOT be widened to a 0755 source mode"
    );
    // Traverse-only (a directory-over-directory mode change): the target adds
    // ONLY owner traverse, never owner write, so a refused 0555 directory is
    // left exactly as it is.
    assert_eq!(
        widen_target(0o555, true, ParentNeed::Traverse, false),
        0o555
    );
    assert_eq!(
        widen_target(0o500, true, ParentNeed::Traverse, false),
        0o500
    );
    assert_eq!(
        widen_target(0o444, true, ParentNeed::Traverse, false),
        0o544,
        "a directory with no owner traverse is the only traverse-only widen"
    );
}

#[test]
fn path_ancestry_is_component_wise() {
    assert_eq!(ancestor_paths("a"), Vec::<String>::new());
    assert_eq!(
        ancestor_paths("a/b/c"),
        vec!["a".to_string(), "a/b".to_string()]
    );
    assert!(is_strict_descendant("p/x", "p"));
    assert!(is_strict_descendant("p/x/y", "p/x"));
    assert!(!is_strict_descendant("p", "p"));
    assert!(
        !is_strict_descendant("px", "p"),
        "a shared prefix is not a child"
    );
    assert!(
        !is_strict_descendant("ab/c", "a"),
        "a sibling is not a child"
    );
}

/// The manifest-relative path of the first `.sync-aside.*` entry under `root`.
fn find_residue(root: &Path) -> String {
    for entry in walkdir::WalkDir::new(root) {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy();
        if name.starts_with(".sync-aside.") {
            return entry
                .path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
        }
    }
    panic!("no residue (.sync-aside.*) under {}", root.display());
}

/// Item 1 (HIGH, regression): a symlink destination is classified by KIND
/// without following it, so a pull can REPLACE it with a file. Before the fix
/// `path_state_fd`'s `O_NOFOLLOW` open returned `ELOOP`, the claim-by-rename
/// repair had already installed the file and leaked the aside, and
/// `restore_failures` was empty.
#[cfg(unix)]
#[test]
fn a_pull_replaces_a_symlink_destination_and_leaves_no_aside() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    write(&remote_root.join("f"), b"new");
    fs::create_dir_all(&local).unwrap();
    std::os::unix::fs::symlink("target", local.join("f")).unwrap();

    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &ReplaceAll,
        Keep,
    )
    .unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(
        local.join("f").is_file(),
        "the symlink is replaced by a regular file"
    );
    assert_eq!(read(&local.join("f")), b"new");
    assert!(report.applied.contains(&"f".to_string()), "{report:?}");
    assert!(report.residue.is_empty(), "{report:?}");
    assert_no_aside(&local);
}

/// Item 1: an EXTRANEOUS symlink is removed by a pull with
/// `delete_extraneous` (the removal classifies the entry by kind without
/// following it).
#[cfg(unix)]
#[test]
fn a_pull_removes_an_extraneous_symlink() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    write(&remote_root.join("f"), b"x");
    fs::create_dir_all(&local).unwrap();
    write(&local.join("f"), b"x");
    std::os::unix::fs::symlink("target", local.join("extra")).unwrap();

    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &ReplaceAll,
        Delete,
    )
    .unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(
        report.extraneous.contains(&"extra".to_string()),
        "{report:?}"
    );
    assert!(fs::symlink_metadata(local.join("extra")).is_err());
    assert_no_aside(&local);
}

/// Item 1 + item 5: a FAILED pull replacement of a symlink leaves the
/// destination byte-identical, leaves NO aside, and reports the failure
/// honestly (the rollback succeeded, so neither `restore_failures` nor
/// `residue` claims a leftover).
///
/// SCOPE: `fail_reads` fails the SOURCE READ before any destination write, so
/// this covers the PRE-WRITE failure only; see the sibling pull test for the
/// atomic-level reference for a local durable write failure.
#[cfg(unix)]
#[test]
fn a_failed_pull_replacement_of_a_symlink_leaves_it_byte_identical() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    write(&remote_root.join("f"), b"new");
    fs::create_dir_all(&local).unwrap();
    std::os::unix::fs::symlink("target", local.join("f")).unwrap();
    let before = canonicalize_tree(&local).unwrap();

    let mut remote = RecordingRemote::over(transport(&remote_root), true);
    remote.fail_reads = true;
    let err = owned(Direction::Pull, &local, &remote, &ReplaceAll, Keep).unwrap_err();
    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    assert!(
        fs::symlink_metadata(local.join("f")).unwrap().is_symlink(),
        "the original symlink is restored"
    );
    assert_eq!(
        canonicalize_tree(&local).unwrap(),
        before,
        "the local tree is BYTE-IDENTICAL after a failed replacement"
    );
    assert_no_aside(&local);
    assert!(err.report().residue.is_empty(), "{:?}", err.report());
    assert!(
        err.restore_failures().is_empty(),
        "a successful rollback is not a restore failure: {:?}",
        err.restore_failures()
    );
}

/// Item 2 (MED): a kind-changing replacement whose stale directory contains a
/// read-only subdirectory is removed by ONE deepest-first, widening removal —
/// push and pull. Before the fix a single-shot `remove_dir_all` failed on the
/// nested `0555` directory AFTER installing the new entry.
#[cfg(unix)]
#[test]
fn a_kind_changing_replacement_removes_a_read_only_subtree() {
    let dir = fixture_tmpdir(&env()).unwrap();

    // PUSH.
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"file");
    write(&dst.join("p/ro/child"), b"keep");
    set_mode(&dst.join("p/ro"), 0o555);
    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(dst.join("p").is_file());
    assert_eq!(read(&dst.join("p")), b"file");
    assert!(!dst.join("p/ro").exists(), "the read-only subtree is gone");
    assert!(report.applied.contains(&"p".to_string()), "{report:?}");
    assert!(report.residue.is_empty(), "{report:?}");
    // The claimed aside is never an extraneous manifest entry, so its nested
    // `ro/child` can only have been removed by `remove_subtree`'s OWN recursion:
    // this test pins the ONE unified removal implementation.
    assert_no_aside(&dst);

    // PULL (the confined local removal).
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    write(&remote_root.join("p"), b"file");
    write(&local.join("p/ro/child"), b"keep");
    set_mode(&local.join("p/ro"), 0o555);
    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &ReplaceAll,
        Delete,
    )
    .unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(local.join("p").is_file());
    assert_eq!(read(&local.join("p")), b"file");
    assert!(!local.join("p/ro").exists());
    assert!(report.applied.contains(&"p".to_string()), "{report:?}");
    assert!(report.residue.is_empty(), "{report:?}");
    assert_no_aside(&local);
}

/// Item 2 + item 5: a FAILED install in the read-only-subtree shape leaves the
/// destination byte-identical with NO aside.
#[cfg(unix)]
#[test]
fn a_failed_replacement_of_a_read_only_subtree_leaves_it_byte_identical() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"file");
    write(&dst.join("p/ro/child"), b"keep");
    set_mode(&dst.join("p/ro"), 0o555);
    let before = canonicalize_tree(&dst).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_writes = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();
    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    assert_eq!(
        canonicalize_tree(&dst).unwrap(),
        before,
        "the stale subtree is BYTE-IDENTICAL after a failed replacement"
    );
    assert!(err.report().residue.is_empty(), "{:?}", err.report());
    assert_no_aside(&dst);

    // PULL (the confined local destination): the source read fails after the
    // claim, so the rollback runs against the local tree. This is the PRE-WRITE
    // failure only (the read precedes any local write); the atomic-level tests
    // cover the durable write's own failure paths.
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    write(&remote_root.join("p"), b"file");
    write(&local.join("p/ro/child"), b"keep");
    set_mode(&local.join("p/ro"), 0o555);
    let before_local = canonicalize_tree(&local).unwrap();
    let mut remote = RecordingRemote::over(transport(&remote_root), true);
    remote.fail_reads = true;
    let err = owned(Direction::Pull, &local, &remote, &ReplaceAll, Delete).unwrap_err();
    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    assert_eq!(
        canonicalize_tree(&local).unwrap(),
        before_local,
        "the local stale subtree is BYTE-IDENTICAL after a failed replacement"
    );
    assert!(err.report().residue.is_empty(), "{:?}", err.report());
    assert_no_aside(&local);
}

/// Item 2 / addendum A (HIGH, data loss): a source FILE over a destination
/// DIRECTORY under `AppendTail` is a conflict; the conflicted directory is
/// off-limits to DELETION mode-INDEPENDENTLY, so a WRITABLE (0o755) directory's
/// child must survive `delete_extraneous`. The round-6 test used 0o555 and so
/// passed for the wrong reason (the mode-based widen check).
#[cfg(unix)]
#[test]
fn append_tail_file_over_a_writable_directory_does_not_delete_its_children() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();

    // PUSH.
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"file");
    write(&dst.join("p/keep"), b"keep");
    set_mode(&dst.join("p"), 0o755);

    let report = owned(
        Direction::Push,
        &src,
        &transport(&dst),
        &append_files,
        Delete,
    )
    .unwrap();
    assert_eq!(
        conflict_at(&report, "p").reason,
        ConflictReason::AppendNotAFile
    );
    assert_eq!(
        conflict_at(&report, "p/keep").reason,
        ConflictReason::ParentRefused
    );
    assert!(
        !report.extraneous.iter().any(|path| path == "p/keep"),
        "a refused deletion is not also reported extraneous: {report:?}"
    );
    assert!(report.transient_dirs.is_empty(), "{report:?}");
    assert_eq!(report.transfers, 0, "nothing is mutated");
    assert!(dst.join("p").is_dir(), "the directory survives");
    assert_eq!(
        read(&dst.join("p/keep")),
        b"keep",
        "a WRITABLE conflicted directory must not have its child deleted"
    );
    assert_eq!(mode_of(&dst.join("p")), 0o755, "the mode is untouched");
    assert_no_aside(&dst);

    // PULL.
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    write(&remote_root.join("p"), b"file");
    write(&local.join("p/keep"), b"keep");
    set_mode(&local.join("p"), 0o755);
    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &append_files,
        Delete,
    )
    .unwrap();
    assert_eq!(
        conflict_at(&report, "p").reason,
        ConflictReason::AppendNotAFile
    );
    assert_eq!(
        conflict_at(&report, "p/keep").reason,
        ConflictReason::ParentRefused
    );
    assert!(report.transfers == 0, "nothing is mutated: {report:?}");
    assert_eq!(read(&local.join("p/keep")), b"keep");
    assert_no_aside(&local);
}

/// The read-only (0o555) variant of the same rule: it blocked for the mode
/// reason before, and must still block.
#[cfg(unix)]
#[test]
fn append_tail_file_over_a_read_only_directory_does_not_delete_its_children() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"file");
    write(&dst.join("p/keep"), b"keep");
    set_mode(&dst.join("p"), 0o555);

    let report = owned(
        Direction::Push,
        &src,
        &transport(&dst),
        &append_files,
        Delete,
    )
    .unwrap();
    assert_eq!(
        conflict_at(&report, "p").reason,
        ConflictReason::AppendNotAFile
    );
    assert_eq!(
        conflict_at(&report, "p/keep").reason,
        ConflictReason::ParentRefused
    );
    assert!(
        report.transient_dirs.is_empty(),
        "a conflicted directory is never widened: {:?}",
        report.transient_dirs
    );
    assert_eq!(report.transfers, 0, "nothing is mutated");
    assert!(dst.join("p").is_dir(), "the directory survives");
    assert_eq!(read(&dst.join("p/keep")), b"keep");
    assert_eq!(mode_of(&dst.join("p")), 0o555, "the mode is untouched");
    assert_no_aside(&dst);
}

/// HIGH (round 8, data loss): a source SYMLINK over a destination DIRECTORY
/// under `AppendTail` reports `AppendNotAFile` just like the `Dir` and `File`
/// arms, so the conflict-derived prohibition must cover the directory's subtree
/// for the SYMLINK arm TOO. Before the fix only the `Dir` and `File` arms
/// inserted into the parallel `blocked` set, so with `delete_extraneous` the
/// destination-only child was destroyed.
#[cfg(unix)]
#[test]
fn append_tail_symlink_over_a_directory_does_not_delete_its_children() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();

    // PUSH.
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    std::os::unix::fs::symlink("target", src.join("p")).unwrap();
    write(&dst.join("p/keep"), b"keep");
    set_mode(&dst.join("p"), 0o755);

    let append_all = |_: &str, _: EntryKind| EntryPolicy::AppendTail;
    let report = owned(Direction::Push, &src, &transport(&dst), &append_all, Delete).unwrap();
    assert_eq!(
        conflict_at(&report, "p").reason,
        ConflictReason::AppendNotAFile
    );
    assert_eq!(
        conflict_at(&report, "p/keep").reason,
        ConflictReason::ParentRefused
    );
    assert!(
        !report.extraneous.iter().any(|path| path == "p/keep"),
        "a refused deletion is not also reported extraneous: {report:?}"
    );
    assert!(report.transient_dirs.is_empty(), "{report:?}");
    assert_eq!(report.transfers, 0, "nothing is mutated");
    assert!(dst.join("p").is_dir(), "the directory survives");
    assert_eq!(
        read(&dst.join("p/keep")),
        b"keep",
        "a source SYMLINK's AppendNotAFile must protect the destination subtree"
    );
    assert_eq!(mode_of(&dst.join("p")), 0o755, "the mode is untouched");
    assert_no_aside(&dst);
    assert_report_names(&report, "p");
    assert_report_names(&report, "p/keep");
    assert_report_lists_disjoint(&report);

    // PULL.
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    fs::create_dir_all(&remote_root).unwrap();
    std::os::unix::fs::symlink("target", remote_root.join("p")).unwrap();
    write(&local.join("p/keep"), b"keep");
    set_mode(&local.join("p"), 0o755);
    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &append_all,
        Delete,
    )
    .unwrap();
    assert_eq!(
        conflict_at(&report, "p").reason,
        ConflictReason::AppendNotAFile
    );
    assert_eq!(
        conflict_at(&report, "p/keep").reason,
        ConflictReason::ParentRefused
    );
    assert_eq!(report.transfers, 0, "nothing is mutated: {report:?}");
    assert_eq!(read(&local.join("p/keep")), b"keep");
    assert_no_aside(&local);
    assert_report_names(&report, "p/keep");
    assert_report_lists_disjoint(&report);
}

/// Item B (MED, crash window): a stranded aside is RESIDUE, not content. After
/// a failed install AND failed rollback it must never be transferred, never
/// deleted by `delete_extraneous`, and always reported in `residue` (and a
/// source-side collision is a named conflict).
#[cfg(unix)]
#[test]
fn a_stranded_aside_is_residue_never_transferred_or_deleted() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    write(&dst.join("p/keep"), b"keep");

    // Strand an aside: the install and its rollback both fail.
    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_writes = true;
    remote.fail_nth_rename = Some(2);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();
    assert!(!err.restore_failures().is_empty(), "{err:?}");
    let residue = find_residue(&dst);

    // (i) A later push with `delete_extraneous=false` keeps it and reports it
    // as residue, NOT as ordinary extraneous content.
    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert!(report.residue.contains(&residue), "{report:?}");
    assert!(
        !report
            .extraneous
            .iter()
            .any(|path| path.starts_with(".sync-aside.")),
        "residue is not ordinary extraneous content: {report:?}"
    );
    assert!(dst.join(&residue).exists(), "residue is kept");
    assert_residue_present(&report, &[&dst]);

    // (iii) A later push with `delete_extraneous=true` does NOT delete it.
    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(report.residue.contains(&residue), "{report:?}");
    assert!(
        dst.join(&residue).exists(),
        "residue survives delete_extraneous"
    );
    assert_residue_present(&report, &[&dst]);

    // (ii) A later PULL does not transfer the residue into the other tree; a
    // SOURCE collision with the reserved namespace is a conflict.
    let other = dir.path().join("other");
    let report = owned(Direction::Pull, &other, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert!(
        report
            .conflicts
            .iter()
            .any(|c| c.path == residue && c.reason == ConflictReason::ReservedName),
        "the source collision is a ReservedName conflict: {:?}",
        report.conflicts
    );
    assert!(
        !report.residue.contains(&residue),
        "a source collision is a conflict, not destination residue: {report:?}"
    );
    assert!(
        fs::symlink_metadata(other.join(&residue)).is_err(),
        "residue is never transferred"
    );
    assert!(
        fs::symlink_metadata(dst.join(&residue)).is_ok(),
        "the source-side stranded aside still exists"
    );
    assert_residue_present(&report, &[&dst, &other]);
    assert_report_lists_disjoint(&report);

    // NESTED: the aside lives INSIDE the entry (not beside it). The unstripped
    // residue set must make `p` look non-childless, so a NON-sanctioned
    // replacement is refused and the nested original survives.
    let src2 = dir.path().join("src2");
    let dst2 = dir.path().join("dst2");
    write(&src2.join("p"), b"new");
    write(&dst2.join("p/keep"), b"keep");
    write(&dst2.join("p/.sync-aside.999.0/stranded"), b"precious");
    let report = owned(Direction::Push, &src2, &transport(&dst2), &ReplaceAll, Keep).unwrap();
    assert!(
        report.residue.contains(&"p/.sync-aside.999.0".to_string()),
        "{report:?}"
    );
    assert_eq!(
        read(&dst2.join("p/.sync-aside.999.0/stranded")),
        b"precious",
        "a nested stranded original survives"
    );
    assert_residue_present(&report, &[&dst2]);
}

/// R2: a stranded claim-aside left by a KILLED run (reproduced deterministically
/// as the exact on-disk state a `SIGKILL` leaves: the install fails, then the
/// rollback rename fails, so the aside survives holding the original) can be
/// RECOVERED to the path it belongs at, or DISCARDED deliberately. Before this
/// surface existed the only documented action was `remove_dir_all`, which
/// destroyed the caller's only copy of the original.
///
/// Cases: (d) `Extraneous::Delete` still refuses the strand; (a) recovery
/// restores it byte-identically; (b) recovery into an OCCUPIED path fails
/// closed leaving both intact; (c) explicit discard removes it.
#[cfg(unix)]
#[test]
fn a_stranded_aside_can_be_recovered_or_deliberately_discarded() {
    /// Build the exact strand a killed kind-changing replacement leaves: the
    /// destination holds a DIRECTORY at `p`, the source a FILE.
    fn strand(dir: &Path) -> (PathBuf, PathBuf, String) {
        let src = dir.join("src");
        let dst = dir.join("dst");
        write(&src.join("p"), b"new");
        write(&dst.join("p/keep"), b"keep");
        let mut remote = RecordingRemote::over(transport(&dst), true);
        remote.fail_writes = true;
        remote.fail_nth_rename = Some(2);
        let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();
        assert!(!err.restore_failures().is_empty(), "{err:?}");
        let residue = find_residue(&dst);
        (src, dst, residue)
    }

    // (a) Recovery restores the original byte-identically. The install never
    // landed, so the real path is absent first.
    let dir = fixture_tmpdir(&env()).unwrap();
    let (src, dst, residue_path) = strand(dir.path());
    let residue = Residue::detect(&dst, &residue_path).unwrap();
    assert!(
        fs::symlink_metadata(dst.join("p")).is_err(),
        "the failed install left no entry at the real path"
    );
    residue.recover_to(Path::new("p")).unwrap();
    assert_eq!(
        read(&dst.join("p/keep")),
        b"keep",
        "the original is restored"
    );
    assert!(
        fs::symlink_metadata(dst.join(residue.aside())).is_err(),
        "the aside is gone after recovery"
    );
    // The destination now converges cleanly: no residue remains.
    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(report.residue.is_empty(), "{report:?}");

    // (d) A later `Extraneous::Delete` sync still REFUSES a strand and reports
    // it (the original path it would have installed over is not the strand).
    let dir = fixture_tmpdir(&env()).unwrap();
    let (src, dst, residue_path) = strand(dir.path());
    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(report.residue.contains(&residue_path), "{report:?}");
    assert!(
        dst.join(&residue_path).exists(),
        "delete_extraneous spares residue"
    );

    // (b) Recovery into an OCCUPIED path fails closed: the occupant and the
    // aside BOTH survive. This is the ambiguous case — the target may itself
    // hold data — so the crate never overwrites it silently.
    let dir = fixture_tmpdir(&env()).unwrap();
    let (_src, dst, residue_path) = strand(dir.path());
    let residue = Residue::detect(&dst, &residue_path).unwrap();
    write(&dst.join("p"), b"occupant");
    let err = residue.recover_to(Path::new("p")).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Reserved {
                reason: crate::error::ReservedKind::RecoverTargetOccupied,
                ..
            }
        ),
        "{err:?}"
    );
    assert!(
        err.to_string().contains(crate::reserved::RESIDUE_BELOW),
        "{err}"
    );
    assert_eq!(
        read(&dst.join("p")),
        b"occupant",
        "the occupant is untouched"
    );
    assert!(
        dst.join(residue.aside()).exists(),
        "the aside is untouched by the refused recovery"
    );

    // (c) Explicit discard removes the strand.
    let dir = fixture_tmpdir(&env()).unwrap();
    let (_src, dst, residue_path) = strand(dir.path());
    let residue = Residue::detect(&dst, &residue_path).unwrap();
    residue.discard().unwrap();
    assert!(fs::symlink_metadata(dst.join(residue.aside())).is_err());
}

/// R6: every sync leaves an unremovable sibling lock record
/// (`.<name>.operation.lock`), so a many-snapshot store accumulates one per
/// snapshot forever. `retire_destination_lock` is the sanctioned break: it
/// reuses the ownership authority (identity, not spelling) and REFUSES while
/// the record is HELD or its destination still lives. Evidence: 5 snapshots ->
/// 5 records; prune 2 and retire theirs -> 3 records; a held record survives.
#[cfg(unix)]
#[test]
fn retiring_an_obsolete_snapshot_lock_record_is_explicit_and_refuses_a_held_one() {
    use crate::lock::FileLock;

    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let snapshots = dir.path().join("snapshots");
    write(&src.join("f"), b"x");
    fs::create_dir_all(&snapshots).unwrap();

    let roots: Vec<PathBuf> = (0..5).map(|i| snapshots.join(format!("s{i}"))).collect();
    for root in &roots {
        fs::create_dir_all(root).unwrap();
        owned(Direction::Push, &src, &transport(root), &ReplaceAll, Keep).unwrap();
    }
    let record_count = |dir: &Path| -> usize {
        fs::read_dir(dir)
            .unwrap()
            .filter(|e| {
                let name = e
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .into_owned();
                crate::reserved::is_lock_record_name(&name)
            })
            .count()
    };
    assert_eq!(record_count(&snapshots), 5, "one record per snapshot");

    // Prune two snapshots (remove their roots) and RETIRE their records.
    for root in &roots[3..] {
        fs::remove_dir_all(root).unwrap();
        assert_eq!(
            retire_destination_lock(root).unwrap(),
            RetireOutcome::Retired
        );
    }
    assert_eq!(
        record_count(&snapshots),
        3,
        "the record count tracks the snapshots that remain"
    );

    // A LIVE destination keeps its record.
    assert_eq!(
        retire_destination_lock(&roots[0]).unwrap(),
        RetireOutcome::DestinationLive
    );
    assert!(destination_lock_path(&roots[0]).unwrap().exists());
    // Retiring an already-gone record is idempotent.
    assert_eq!(
        retire_destination_lock(&roots[4]).unwrap(),
        RetireOutcome::Absent
    );

    // A HELD record is never retired.
    let held_path = destination_lock_path(&roots[2]).unwrap();
    let holder = FileLock::acquire(&held_path, "test-holder").unwrap();
    fs::remove_dir_all(&roots[2]).unwrap();
    assert_eq!(
        retire_destination_lock(&roots[2]).unwrap(),
        RetireOutcome::Held,
        "a live holder must refuse retirement"
    );
    assert!(held_path.exists(), "a held record survives the refusal");
    drop(holder);
    assert_eq!(
        retire_destination_lock(&roots[2]).unwrap(),
        RetireOutcome::Retired
    );
    assert!(!held_path.exists());
}

/// A5: `retire_destination_lock` FAILS CLOSED when it cannot DETERMINE whether
/// the destination or the record exists. PRE-FIX any `symlink_metadata` error
/// (an EACCES on a `000` parent) read as "gone"/"no record" (`Absent`), which
/// contradicts the crate's fail-closed doctrine. A genuinely-absent path still
/// returns `Absent`.
#[cfg(unix)]
#[test]
fn retire_destination_lock_fails_closed_when_presence_cannot_be_determined() {
    use std::os::unix::fs::PermissionsExt;
    let dir = fixture_tmpdir(&env()).unwrap();
    let parent = dir.path().join("locked");
    fs::create_dir(&parent).unwrap();
    let dest = parent.join("snap0");
    // The record exists and the destination does not; the parent denies all
    // access, so NEITHER presence probe can be answered.
    write(&parent.join(".snap0.operation.lock"), b"record");
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o000)).unwrap();

    let err = retire_destination_lock(&dest).unwrap_err();
    assert!(
        matches!(err, Error::Preflight(_)),
        "an undeterminable presence is a typed failure, never a silent Absent: {err:?}"
    );
    assert!(
        err.reserved_kind().is_none(),
        "it is not a reserved-spelling refusal: {err:?}"
    );

    // Restore so the fixture can be cleaned up; the genuinely-absent case still
    // returns `Absent`.
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_file(parent.join(".snap0.operation.lock")).unwrap();
    assert_eq!(
        retire_destination_lock(&dest).unwrap(),
        RetireOutcome::Absent
    );
}

/// R1 at the PUBLIC transport surface: `Remote::remove_dir_all` is the
/// primitive a consumer's `prune` names, and it refused nothing before the
/// fix, so it destroyed the stranded aside. It now carries the substrate's
/// residue refusal.
#[cfg(unix)]
#[test]
fn the_transport_recursive_removal_refuses_a_stranded_aside() {
    use crate::transport::RootedRelativePath;

    let dir = fixture_tmpdir(&env()).unwrap();
    let dst = dir.path().join("dst");
    write(&dst.join("victim/.sync-aside.1234.0/stranded"), b"precious");
    let rel = RootedRelativePath::parse(Path::new("victim/.sync-aside.1234.0")).unwrap();
    let err = transport(&dst).remove_dir_all(&rel).unwrap_err();
    assert!(
        err.to_string().contains(crate::reserved::RESIDUE_BELOW),
        "the transport surfaces the ResidueBelow refusal: {err}"
    );
    assert_eq!(
        read(&dst.join("victim/.sync-aside.1234.0/stranded")),
        b"precious",
        "the stranded original survives the refused removal"
    );
}

/// Item B: residue nested inside a destination-only directory must not be
/// destroyed by `delete_extraneous`; the whole guarded subtree is refused and
/// reported as `ResidueBelow` rather than silently removed.
#[cfg(unix)]
#[test]
fn residue_nested_under_an_extraneous_directory_is_never_deleted() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"x");
    write(&dst.join("f"), b"x");
    write(&dst.join("x/keep"), b"keep");
    write(&dst.join("x/.sync-aside.999.0/stranded"), b"precious");

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(
        report.residue.contains(&"x/.sync-aside.999.0".to_string()),
        "{report:?}"
    );
    assert!(
        dst.join("x/keep").exists(),
        "the guarded subtree is not removed"
    );
    assert_eq!(read(&dst.join("x/.sync-aside.999.0/stranded")), b"precious");
    assert!(
        report
            .conflicts
            .iter()
            .any(|c| c.path == "x" && c.reason == ConflictReason::ResidueBelow),
        "the guarded directory is a conflict: {:?}",
        report.conflicts
    );
    assert!(
        !report.extraneous.iter().any(|p| p.starts_with("x")),
        "a refused extraneous subtree is not duplicated in `extraneous`: {:?}",
        report.extraneous
    );
    assert_residue_present(&report, &[&dst]);
}

/// F2: a STALE TEMP whose destination name begins `sync-aside.` inherits the
/// reserved `.sync-aside.` prefix, so the applier used to classify it as
/// RESERVED residue — contradicting the report doc, which promises a stale temp
/// is reported as `extraneous` and that recovery is a removal of each
/// `extraneous` path matching the temp pattern. A crashed temp holds NO original
/// entry, so calling it residue (which "HOLDS THE ORIGINAL ENTRY, so inspect it
/// before discarding it") is wrong and leaves it unreachable by the documented
/// sweep. Pre-fix the two reserved-namespaced temps below were in `residue` and
/// absent from `extraneous`.
#[cfg(unix)]
#[test]
fn a_stale_temp_in_the_aside_namespace_is_extraneous_not_residue() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"x");
    write(&dst.join("f"), b"x");

    fn temp_name(dest: &str) -> String {
        crate::atomic::temp_name_for(Path::new(dest))
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    // The SHORT temp for destination `sync-aside.foo`, exactly what
    // `crate::atomic::temp_name_for` produces.
    let short = temp_name("sync-aside.foo");
    // The LONG (hash-truncated) temp for a 240-byte `sync-aside.` destination.
    let long = temp_name(&format!("sync-aside.{}", "n".repeat(240)));
    // The CONTROL: destination `sync-aside-foo` (no trailing dot) yields a temp
    // OUTSIDE the reserved namespace, which was already `extraneous`.
    let control = temp_name("sync-aside-foo");

    // Premise: the two reserved-namespaced names really ARE reserved spellings
    // (so the id rule still refuses them and a source collision is still a
    // conflict), and the authority recognises all three as its own temp names.
    for name in [&short, &long] {
        assert!(
            crate::reserved::is_reserved_name(name),
            "premise: {name} is in the reserved namespace"
        );
        assert!(
            crate::atomic::is_crate_temp_name(name),
            "premise: {name} carries the temp-name authority's suffix"
        );
    }
    assert!(!crate::reserved::is_reserved_name(&control));
    assert!(crate::atomic::is_crate_temp_name(&control));

    // The classification itself: a reserved-namespaced TEMP is NOT residue,
    // while a genuine claim-aside (no authority suffix) IS — and an ordinary
    // reservation-free name is outside this predicate entirely.
    assert!(!crate::reserved::is_residue_path(&short));
    assert!(!crate::reserved::is_residue_path(&long));
    assert!(!crate::reserved::is_residue_path(&control));
    assert!(crate::reserved::is_residue_path(".sync-aside.999.0"));
    assert!(crate::reserved::is_residue_path(
        ".sync-aside.case-probe.1.2"
    ));
    assert!(crate::reserved::is_residue_path(
        "nested/.001.operation.lock"
    ));
    assert!(!crate::reserved::is_residue_path("notes.tmp.1.2"));

    for name in [&short, &long, &control] {
        write(&dst.join(name.as_str()), b"stale temp");
    }

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    for name in [&short, &long, &control] {
        assert!(
            report.extraneous.contains(name),
            "a stale temp must be reachable as `extraneous` (the doc's documented sweep): \
             {name} missing from {:?}",
            report.extraneous
        );
        assert!(
            !report.residue.contains(name),
            "a stale temp holds no original and must NOT be residue: {name} in {:?}",
            report.residue
        );
    }
    // Nothing was destroyed under `Keep`.
    for name in [&short, &long, &control] {
        assert!(dst.join(name.as_str()).exists(), "{name} survives Keep");
    }

    // And a GENUINE claim-aside is STILL residue: the reserved-spelling
    // guarantee for a held-aside is not weakened, only a temp is told apart.
    write(&dst.join(".sync-aside.999.0/stranded"), b"precious");
    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert!(
        report.residue.contains(&".sync-aside.999.0".to_string()),
        "a genuine claim-aside stays residue: {report:?}"
    );
    assert!(
        !report.extraneous.iter().any(|p| p == ".sync-aside.999.0"),
        "a genuine claim-aside is never extraneous: {:?}",
        report.extraneous
    );
    assert_eq!(read(&dst.join(".sync-aside.999.0/stranded")), b"precious");
    assert_residue_present(&report, &[&dst]);
}

/// F3: the REMOTE live-kind classifier must agree with the LOCAL one. Both map
/// `is_dir`/`is_symlink`/`is_file` explicitly and REFUSE anything else
/// (fifo/socket/device), instead of the remote side mapping "not dir, not
/// symlink" to `File` while the local side returned `Err`. The two transports
/// already agree on the METADATA (`RemoteMeta.is_file`), and this pins that the
/// classification built from it agrees too. Pre-fix
/// `Side::Remote::kind_opt` returned `Ok(Some(File))` for the fifo below while
/// `Side::Local::kind_opt` returned `Err`, so the two live-kind classifiers
/// disagreed for exactly the entries the metadata change was made to unify.
#[cfg(unix)]
#[test]
fn the_remote_and_local_live_kind_classifiers_agree_on_a_fifo() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let dir = fixture_tmpdir(&env()).unwrap();
    let root = dir.path().join("dest");
    fs::create_dir_all(&root).unwrap();
    let fifo = root.join("pipe");
    let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: `c` is a valid NUL-terminated path.
    let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(
        rc,
        0,
        "mkfifo {}: {}",
        fifo.display(),
        std::io::Error::last_os_error()
    );

    let local = LocalSide::open(&root, false).unwrap();
    let local_side = Side::Local(&local);
    // A PATH-BASED `Side::Remote`: the same shape the SSH transport has (a
    // non-confined, path-based destination) without a live sshd.
    let remote = PathRemote::over(&root);
    let remote_side = Side::Remote(&remote);

    let fifo_rel = RootedRelativePath::parse(Path::new("pipe")).unwrap();
    let local_kind = local_side.kind_opt(&fifo_rel);
    let remote_kind = remote_side.kind_opt(&fifo_rel);
    assert!(
        local_kind.is_err(),
        "the local classifier refuses a fifo: {local_kind:?}"
    );
    assert!(
        remote_kind.is_err(),
        "the remote classifier must refuse a fifo too, not call it a File: {remote_kind:?}"
    );

    // AGREEMENT on the three supported kinds and on absence.
    write(&root.join("file"), b"x");
    fs::create_dir_all(root.join("sub")).unwrap();
    std::os::unix::fs::symlink("file", root.join("link")).unwrap();
    for (name, expected) in [
        ("file", EntryKind::File),
        ("sub", EntryKind::Dir),
        ("link", EntryKind::Symlink),
    ] {
        let rel = RootedRelativePath::parse(Path::new(name)).unwrap();
        assert_eq!(local_side.kind_opt(&rel).unwrap(), Some(expected), "{name}");
        assert_eq!(
            remote_side.kind_opt(&rel).unwrap(),
            Some(expected),
            "{name}"
        );
    }
    let missing = RootedRelativePath::parse(Path::new("nope")).unwrap();
    assert_eq!(local_side.kind_opt(&missing).unwrap(), None);
    assert_eq!(remote_side.kind_opt(&missing).unwrap(), None);
}

/// F2 (cont.): the same distinction inside the CLAIMED-subtree removal walk. A
/// kind-changing replacement claims the stale directory aside and removes it
/// deepest-first; a reserved-namespaced TEMP inside it is a leftover, not a
/// held-aside, so the walk must take it and NOT stop and name it residue
/// (pre-fix it stopped, leaving the stale temp reported as residue).
#[cfg(unix)]
#[test]
fn a_stale_temp_inside_a_claimed_subtree_is_removed_not_left_as_residue() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"now a file");
    write(&dst.join("p/f"), b"stale child");
    write(&dst.join("p/.sync-aside.x.tmp.7.0"), b"stale temp");

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(
        !report
            .residue
            .iter()
            .any(|p| p.contains(".sync-aside.x.tmp.")),
        "a crate temp must not be reported as residue: {report:?}"
    );
    assert!(
        fs::symlink_metadata(dst.join("p"))
            .expect("the replacement landed")
            .is_file(),
        "the kind-changing replacement installs the file"
    );
    assert!(report.applied.contains(&"p".to_string()), "{report:?}");
}

/// Addendum A (HIGH, data loss): `dir_replace_is_sanctioned` scanned the
/// STRIPPED diff, so a directory whose only child is an aside looked childless
/// and was replaced by a source file EVEN with `delete_extraneous == false`.
/// With the RAW residue set consulted, the replacement is refused.
#[cfg(unix)]
#[test]
fn a_directory_holding_residue_is_never_treated_as_childless() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"file");
    write(&dst.join("p/.sync-aside.999.0/stranded"), b"precious");

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert_eq!(
        conflict_at(&report, "p").reason,
        ConflictReason::ExtraneousBelow
    );
    assert!(dst.join("p").is_dir(), "the directory survives");
    assert_eq!(
        read(&dst.join("p/.sync-aside.999.0/stranded")),
        b"precious",
        "the stranded original survives a non-sanctioned replacement"
    );
    assert!(
        report.residue.contains(&"p/.sync-aside.999.0".to_string()),
        "{report:?}"
    );
    assert_residue_present(&report, &[&dst]);
}

/// Item 1 (HIGH, data loss): a reserved child must ACTUALLY survive the removal
/// that is supposed to skip it. The removal recursion skips the reserved child
/// and then must NOT hand the directory to a recursive `remove_dir_all`; it is
/// left in place and reported. Push and pull, `delete_extraneous` false and
/// true.
///
/// It also covers the ABANDONED-vs-REMOVED distinction: the claimed directory is
/// READ-ONLY, so the removal widens it before discovering the reserved child.
/// Because the directory is left in place (abandoned, not removed), that widen
/// is RESTORED — the residue ends at its ORIGINAL mode.
#[cfg(unix)]
#[test]
fn a_sanctioned_replacement_leaves_a_nested_aside_in_place() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();

    // PUSH, delete_extraneous=true: the replacement IS sanctioned, so the stale
    // directory is claimed; the removal must stop at the reserved child and
    // leave the claimed directory in place.
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"file");
    write(&dst.join("p/.sync-aside.999.0/stranded"), b"precious");
    set_mode(&dst.join("p"), 0o555);
    let err = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap_err();
    assert!(
        err.report().applied.contains(&"p".to_string()),
        "the replacement itself was installed: {:?}",
        err.report()
    );
    assert!(
        !err.report().residue.is_empty(),
        "the leftover aside is reported: {:?}",
        err.report()
    );
    assert_residue_present(err.report(), &[&dst]);
    assert_file_somewhere(&dst, "stranded", b"precious");
    let push_residue = find_residue(&dst);
    assert!(
        !err.report().transient_dirs.contains(&push_residue),
        "residue is not also transient: {:?}",
        err.report()
    );
    assert_eq!(
        mode_of(&dst.join(&push_residue)),
        0o555,
        "a widened residue directory is RESTORED to its original mode: {push_residue}"
    );
    assert_report_lists_disjoint(err.report());

    // PULL.
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    write(&remote_root.join("p"), b"file");
    write(&local.join("p/.sync-aside.999.0/stranded"), b"precious");
    set_mode(&local.join("p"), 0o555);
    let err = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &ReplaceAll,
        Delete,
    )
    .unwrap_err();
    assert!(err.report().applied.contains(&"p".to_string()), "{err:?}");
    assert_residue_present(err.report(), &[&local]);
    assert_file_somewhere(&local, "stranded", b"precious");
    let pull_residue = find_residue(&local);
    assert_eq!(
        mode_of(&local.join(&pull_residue)),
        0o555,
        "a widened residue directory is RESTORED on the pull too: {pull_residue}"
    );
    assert_report_lists_disjoint(err.report());
}

/// The report lists PARTITION under the documented precedence. A residue path
/// whose widen-RESTORE silently fails (the chmod reports `Ok` but the mode does
/// not change) sits in BOTH `residue` and `verify_failures` before the
/// precedence filter — this fixture VIOLATED `assert_report_lists_disjoint`
/// under the old, unfiltered derivation. `residue` outranks `verify_failures`,
/// so the path is reported in exactly one list and the split is not silently
/// duplicated.
#[cfg(unix)]
#[test]
fn a_residue_mode_restore_failure_is_residue_not_a_verify_failure() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"file");
    write(&dst.join("p/.sync-aside.999.0/stranded"), b"precious");
    set_mode(&dst.join("p"), 0o555);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // Drop the RESTORE of the widened (read-only) claimed aside — the only
    // `set_mode` call that requests the aside's original mode 0o555 — so the
    // residue stays at its widened mode and the post-restore mode verification
    // must catch it. Keyed on the reserved-aside PATH and the MODE, not a call
    // ordinal, so an added earlier `set_mode` call cannot retarget it.
    remote.drop_mode_for = Some((DropModeTarget::ReservedAside, 0o555, DropModeWhen::Always));
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();
    let residue = find_residue(&dst);
    assert_eq!(
        remote.dropped_modes(),
        vec![(residue.clone(), 0o555)],
        "the named restore of the residue was actually dropped (else vacuous)"
    );
    assert!(
        err.report().residue.contains(&residue),
        "the residue path is machine-readable: {:?}",
        err.report()
    );
    assert_eq!(
        mode_of(&dst.join(&residue)),
        0o755,
        "the dropped restore left the residue widened: {residue}"
    );
    assert!(
        !err.report().verify_failures.contains(&residue),
        "residue outranks verify_failures in the partition: {:?}",
        err.report()
    );
    assert!(
        !err.report().indeterminate.contains(&residue),
        "the restore reported Ok, so the path is not indeterminate: {:?}",
        err.report()
    );
    assert_report_names(err.report(), &residue);
    assert_report_lists_disjoint(err.report());
}

/// Addendum B (MED/HIGH): a FAILED rollback must report the stranded original as
/// machine-readable residue AND name it in the message; it is not enough to say
/// only "something went wrong".
#[cfg(unix)]
#[test]
fn a_failed_rollback_reports_the_stranded_aside_as_residue() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    write(&dst.join("p/keep"), b"keep");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_writes = true;
    remote.fail_nth_rename = Some(2);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();
    let aside = find_residue(&dst);
    assert!(
        err.report().residue.contains(&aside),
        "the stranded aside is residue: {:?}",
        err.report()
    );
    assert_residue_present(err.report(), &[&dst]);
    assert!(
        err.restore_failures()
            .iter()
            .any(|message| message.contains(&aside)),
        "the failure names the aside {aside}: {:?}",
        err.restore_failures()
    );
}

/// Item C (MED): a `create_dir_all` that creates the directory and THEN fails
/// must not strand the claimed original: the sync removes its own partial
/// creation before renaming the aside back, so the tree stays byte-identical.
///
/// The PULL case is not testable with the current seams: in a pull the
/// destination is the confined `LocalSide` (not a `Remote`), and `LocalSide` has
/// no fault-injection hook — `RecordingRemote` is the SOURCE side, so it can
/// only fail reads, never the destination's `create_dir_all`. The push case
/// exercises the same `rollback_claim`/`discard_partial` code path, which is
/// direction-agnostic (it operates on `self.dest`).
#[cfg(unix)]
#[test]
fn a_partially_created_directory_replacement_is_rolled_back() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p/f"), b"new");
    write(&dst.join("p"), b"old");
    let before = canonicalize_tree(&dst).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_create_dir_all_after_create = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();
    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    assert!(dst.join("p").is_file(), "the file is restored");
    assert_eq!(read(&dst.join("p")), b"old");
    assert_eq!(
        canonicalize_tree(&dst).unwrap(),
        before,
        "the entry is BYTE-IDENTICAL after the partial-creation rollback"
    );
    assert_no_aside(&dst);
    assert!(
        err.restore_failures().is_empty(),
        "the rollback succeeded: {:?}",
        err.restore_failures()
    );
}

/// Item D (MED): when `drop_claim` fails AFTER a successful install the entry
/// IS installed and verified, so it is reported `applied`, and the leftover
/// aside is machine-readable `indeterminate` (its own removal was attempted and
/// failed, so it may or may not have landed) plus a reported restore failure —
/// not only an error string.
#[cfg(unix)]
#[test]
fn a_failed_drop_claim_reports_the_entry_applied_and_the_leftover_aside() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    fs::create_dir_all(&dst).unwrap();
    std::os::unix::fs::symlink("target", dst.join("p")).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_remove_file = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();
    assert!(
        err.report().applied.contains(&"p".to_string()),
        "the install succeeded, so it is applied: {:?}",
        err.report()
    );
    let aside = find_residue(&dst);
    // ATTEMPT-FIRST: the leftover aside was the target of a FAILED removal, so
    // its own state is unknown (the unlink may or may not have landed) and the
    // highest-precedence list names it. `residue` is reserved for a path KNOWN
    // to remain — the nested case, where the removal stopped at a reserved
    // child and the directory itself was never handed to the removal primitive
    // (see `a_leftover_aside_is_not_also_reported_transient`).
    assert!(
        err.report().indeterminate.contains(&aside),
        "the failed removal of the aside leaves it indeterminate: {:?}",
        err.report()
    );
    assert!(
        !err.report().residue.contains(&aside),
        "an indeterminate path is not also residue (the lists partition): {:?}",
        err.report()
    );
    // The side of the precedence filter THIS test pins: the aside IS a residue
    // candidate (its removal was attempted and failed), but because that same
    // removal makes it `indeterminate`, the partition drops it from `residue`
    // entirely — so `residue` is EMPTY, not merely free of this one path. (The
    // vacuous `assert_residue_present` that used to sit here iterated that
    // empty list and so could not fail.)
    assert!(
        err.report().residue.is_empty(),
        "the only residue candidate is routed to `indeterminate`: {:?}",
        err.report()
    );
    assert!(
        err.restore_failures()
            .iter()
            .any(|failure| failure.contains("could not be removed")),
        "the leftover aside is a reported failure: {:?}",
        err.restore_failures()
    );
    // The contract is the SEQUENCE, not "some mutation": the claim-by-rename
    // of the stale symlink (1), the file install (2), and the FAILED removal of
    // the leftover aside (3). The exact count is the oracle that catches a
    // dropped `begin_mutation` at any of the three sites.
    assert_eq!(
        err.report().transfers,
        3,
        "claim rename + install + failed aside removal: {:?}",
        err.report()
    );
    // COVERAGE (a failed drop_claim): the installed entry and the leftover
    // aside are both NAMED, and the lists stay disjoint.
    assert_report_names(err.report(), "p");
    assert_report_names(err.report(), &aside);
    assert_report_lists_disjoint(err.report());
}

/// FAILURE PATH COVERAGE: a transport whose `write` PUBLISHES the entry and
/// THEN returns `Err` — the shape of a chmod/fsync/durability check that fails
/// after the bytes are visible, which is exactly `LocalSide::write_file`'s
/// `ReplacedDurabilityUnknown` branch — must be NAMED and COUNTED. Before
/// attempt-first the entry was mutated but appeared in NO list and left
/// `transfers` at 0, so a caller reading the report could not tell a partially
/// mutated destination from an untouched one. (`LocalSide` has no fault seam,
/// so the PULL-specific branch is covered by inspection: `install_file` and
/// `append_write` call `begin_mutation` BEFORE `dest.write_file`, and the local
/// write returns `Err` only after `write_atomic_replace_fd` published the
/// replacement, so a pull records the same indeterminate path.)
#[cfg(unix)]
#[test]
fn a_transport_that_publishes_an_entry_and_then_fails_names_and_counts_it() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    fs::create_dir_all(&dst).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_write_after_write = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();
    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    // The entry IS on disk: the mutation happened before the error.
    assert_eq!(read(&dst.join("p")), b"new");
    // ...so the report must NAME it (the highest-precedence `indeterminate`)
    // and COUNT the attempt.
    assert!(
        err.report().indeterminate.contains(&"p".to_string()),
        "a published-then-failed write is indeterminate: {:?}",
        err.report()
    );
    assert_eq!(
        err.report().transfers,
        1,
        "exactly the attempted (and published) write is counted: {:?}",
        err.report()
    );
    assert_report_names(err.report(), "p");
    assert_report_lists_disjoint(err.report());
}

/// FAILURE PATH COVERAGE: a directory CREATED and then abandoned by a LATER
/// failure is NAMED (a `Transferred` path whose final mode never landed is a
/// `verify_failure`) and its create is COUNTED. Before attempt-first, a
/// directory left behind by a failed run could vanish from every list.
#[cfg(unix)]
#[test]
fn a_created_directory_is_named_when_a_later_entry_fails() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/f"), b"new");
    fs::create_dir_all(&dst).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_writes = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();
    assert!(dst.join("d").is_dir(), "the directory was created");
    assert!(
        err.report().verify_failures.contains(&"d".to_string()),
        "the created directory is named: {:?}",
        err.report()
    );
    assert!(
        err.report().indeterminate.contains(&"d/f".to_string()),
        "the failed write names its path: {:?}",
        err.report()
    );
    // The directory create and the attempted (failed) write are the two
    // counted steps; the failure aborts BEFORE `finalize`.
    assert_eq!(
        err.report().transfers,
        2,
        "the create and the attempted write are counted: {:?}",
        err.report()
    );
    assert_report_names(err.report(), "d");
    assert_report_names(err.report(), "d/f");
    assert_report_lists_disjoint(err.report());
}

/// FAILURE PATH COVERAGE: a file whose bytes LANDED and whose run then failed
/// on a LATER entry is NAMED and its write is counted. Settle's post-failure
/// `verify(true)` re-reads the landed file, so it reaches a verified final state
/// and is truthfully `applied` even though the run failed; the failed `b` is
/// `indeterminate`. Before attempt-first, a landed file could be invisible on
/// the failure path.
#[cfg(unix)]
#[test]
fn a_written_file_is_named_when_a_later_entry_fails() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("a"), b"one");
    write(&src.join("b"), b"two");
    fs::create_dir_all(&dst).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // The FIRST write (`a`) lands; the SECOND (`b`) fails.
    remote.fail_nth_write = Some(2);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();
    assert_eq!(read(&dst.join("a")), b"one", "the first write landed");
    assert!(
        err.report().applied.contains(&"a".to_string()),
        "the landed (and post-failure verified) file is named: {:?}",
        err.report()
    );
    assert!(
        err.report().indeterminate.contains(&"b".to_string()),
        "the failed second write names its path: {:?}",
        err.report()
    );
    assert_eq!(
        err.report().transfers,
        2,
        "both the landed and the attempted write are counted: {:?}",
        err.report()
    );
    assert_report_names(err.report(), "a");
    assert_report_names(err.report(), "b");
    assert_report_lists_disjoint(err.report());
}

/// FAILURE PATH COVERAGE (`transfer_file`'s fallible `note_final`): the bytes
/// LAND, then the mode READ fails. The path is mutated but no final mode was
/// recorded, so it must be NAMED (in `verify_failures`) and its write COUNTED.
/// The old order recorded the outcome only AFTER `note_final` returned, so a
/// read failure dropped the path from every list even though it was written.
#[cfg(unix)]
#[test]
fn a_mode_read_failure_after_a_write_names_the_mutated_file() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    write(&dst.join("p"), b"old");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_metadata_after_write = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();
    assert_eq!(read(&dst.join("p")), b"new", "the bytes landed");
    assert!(
        err.report().verify_failures.contains(&"p".to_string()),
        "the mutated file is named even though the mode read failed: {:?}",
        err.report()
    );
    assert!(
        !err.report().applied.contains(&"p".to_string()),
        "a path whose final mode never landed is not applied: {:?}",
        err.report()
    );
    assert_eq!(
        err.report().transfers,
        1,
        "the landed write is counted exactly once: {:?}",
        err.report()
    );
    assert_report_names(err.report(), "p");
    assert_report_lists_disjoint(err.report());
}

/// Addendum C (MED): a path that becomes residue must not ALSO be reported in
/// `transient_dirs`. It is recorded ABANDONED (not removed): it still exists, so
/// the widen `drop_claim` performed on it IS restored, but it is reported in
/// `residue` and never in `transient_dirs`.
#[cfg(unix)]
#[test]
fn a_leftover_aside_is_not_also_reported_transient() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    write(&dst.join("p/keep"), b"keep");
    set_mode(&dst.join("p"), 0o555);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_remove_file = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();
    let aside = find_residue(&dst);
    assert!(err.report().residue.contains(&aside), "{:?}", err.report());
    assert!(
        !err.report().transient_dirs.contains(&aside),
        "a residue path must not also be transient: {:?}",
        err.report()
    );
    assert_report_lists_disjoint(err.report());
    assert_residue_present(err.report(), &[&dst]);
}

/// Addendum D (MED): the report-list invariant must hold on the FAILURE path
/// too. A removal that fails after a widen used to report the directory in BOTH
/// `extraneous` and `transient_dirs`; the transient list is now filtered to
/// paths that are not destination-only.
#[cfg(unix)]
#[test]
fn the_report_lists_stay_disjoint_on_a_removal_failure() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"x");
    write(&dst.join("f"), b"x");
    write(&dst.join("x/child"), b"c");
    set_mode(&dst.join("x"), 0o555);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_remove_file = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();
    assert!(
        err.report().extraneous.contains(&"x".to_string()),
        "the un-removed directory is still destination-only: {:?}",
        err.report()
    );
    assert!(
        !err.report().transient_dirs.contains(&"x".to_string()),
        "a destination-only path is not also transient: {:?}",
        err.report()
    );
    // ATTEMPT-FIRST (a failed extraneous removal): the CHILD removal was
    // attempted and failed, so its own state is unknown and the
    // highest-precedence list names it; the parent directory was never handed
    // to the removal primitive (its child blocked it), so it stays exactly
    // `extraneous`.
    assert!(
        err.report().indeterminate.contains(&"x/child".to_string()),
        "the failed child removal is indeterminate: {:?}",
        err.report()
    );
    // COVERAGE (a failed extraneous removal): every destination-only path the
    // run acted on is NAMED, on the failure path too.
    assert_report_names(err.report(), "x");
    assert_report_names(err.report(), "x/child");
    assert_report_lists_disjoint(err.report());
}

/// Addendum F (LOW): a path whose content was written but whose verification
/// failed must be machine-readable, not only present in the error string.
#[cfg(unix)]
#[test]
fn a_written_but_unverified_path_is_named_in_the_report() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"new");
    write(&dst.join("f"), b"old");
    set_mode(&src.join("f"), 0o640);
    set_mode(&dst.join("f"), 0o444);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.drop_write_mode = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();
    assert!(
        err.report().verify_failures.contains(&"f".to_string()),
        "the written-but-unverified path is machine-readable: {:?}",
        err.report()
    );
    assert!(
        !err.report().applied.contains(&"f".to_string()),
        "{:?}",
        err.report()
    );
}

/// Addendum G: an ORDINARY caller file whose name carries the reserved prefix on
/// the SOURCE side is a conflict, never transferred and never silently skipped.
/// The SAME name is ALSO stranded on the destination, so the fixture would
/// report the path in BOTH `conflicts` (source collision) and `residue`
/// (destination leftover) if the report were not partitioned: the
/// `!residue.contains` clause below is therefore NOT vacuous.
#[test]
fn a_source_entry_in_the_reserved_namespace_is_a_conflict() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join(".sync-aside.foo"), b"user data");
    write(&dst.join(".sync-aside.foo"), b"stranded on the destination");
    fs::create_dir_all(&dst).unwrap();

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert_eq!(
        conflict_at(&report, ".sync-aside.foo").reason,
        ConflictReason::ReservedName
    );
    assert!(
        !report.applied.contains(&".sync-aside.foo".to_string()),
        "{report:?}"
    );
    // The source reserved name is never TRANSFERRED: the destination's own
    // `.sync-aside.foo` still holds the destination bytes, not the source's.
    assert_eq!(
        read(&dst.join(".sync-aside.foo")),
        b"stranded on the destination",
        "a source reserved name is never transferred over the destination aside"
    );
    assert!(
        fs::symlink_metadata(src.join(".sync-aside.foo")).is_ok(),
        "a source reserved name is never destroyed either"
    );
    // A SOURCE collision is a `ReservedName` CONFLICT, not destination residue:
    // residue is the abandoned DESTINATION state (a path this sync left in
    // place), and the caller has nothing to recover here. The destination ALSO
    // strands a `.sync-aside.foo`, so both lists carry the path before the
    // precedence filter; `conflicts` outranks `residue`, so residue is empty
    // and the report still partitions. Keeping the source collision out of
    // `residue` is what lets residue stay disjoint from `conflicts`.
    assert!(
        !report.residue.contains(&".sync-aside.foo".to_string()),
        "a source collision is a conflict, not destination residue: {report:?}"
    );
    assert!(
        fs::symlink_metadata(dst.join(".sync-aside.foo")).is_ok(),
        "the stranded destination aside is left in place, not destroyed by the \
         source-side conflict: {report:?}"
    );
    assert_report_lists_disjoint(&report);
}

/// Addendum G: an ORDINARY caller file whose name carries the reserved prefix on
/// the DESTINATION side is residue: it survives `delete_extraneous` and is not
/// reported as ordinary extraneous content.
#[test]
fn a_destination_entry_in_the_reserved_namespace_is_residue() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"x");
    write(&dst.join("f"), b"x");
    write(&dst.join(".sync-aside.foo"), b"user data");

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(
        report.residue.contains(&".sync-aside.foo".to_string()),
        "{report:?}"
    );
    assert!(
        !report.extraneous.contains(&".sync-aside.foo".to_string()),
        "{report:?}"
    );
    assert_eq!(read(&dst.join(".sync-aside.foo")), b"user data");
    assert_residue_present(&report, &[&dst]);
}

/// Addendum G: a NESTED reserved name under an ordinary directory is residue and
/// survives a `delete_extraneous` sync.
#[test]
fn a_nested_reserved_name_is_residue() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/f"), b"x");
    write(&dst.join("d/f"), b"x");
    write(&dst.join("d/.sync-aside.foo"), b"user data");

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete).unwrap();
    assert!(
        report.residue.contains(&"d/.sync-aside.foo".to_string()),
        "{report:?}"
    );
    assert_eq!(read(&dst.join("d/.sync-aside.foo")), b"user data");
    assert_residue_present(&report, &[&dst]);
}

/// Addendum G: names that merely RESEMBLE the reserved namespace are ordinary
/// entries and must transfer normally. The prefix is anchored on the trailing
/// dot and on the leading component.
#[test]
fn names_resembling_the_reserved_namespace_transfer_normally() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    // `.sync-aside` has no trailing dot; `foo.sync-aside.bar` does not start
    // with the prefix. Neither is reserved.
    write(&src.join(".sync-aside"), b"one");
    write(&src.join("foo.sync-aside.bar"), b"two");
    fs::create_dir_all(&dst).unwrap();

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(report.residue.is_empty(), "{report:?}");
    assert!(
        report.applied.contains(&".sync-aside".to_string()),
        "{report:?}"
    );
    assert!(
        report.applied.contains(&"foo.sync-aside.bar".to_string()),
        "{report:?}"
    );
    assert_eq!(read(&dst.join(".sync-aside")), b"one");
    assert_eq!(read(&dst.join("foo.sync-aside.bar")), b"two");
}

/// `compute_tree_digest` hashes the serialized metadata INCLUDING
/// `tree_sha256`, so a producer that does not blank the field before
/// recomputing hashes the OLD digest into the new one. `strip_reserved` must
/// therefore produce the CANONICAL digest of the stripped metadata — the same
/// value `canonicalize_tree` computes for the remaining content — and must be
/// idempotent. Both clauses fail if the field is not cleared first: the
/// survivor digest depends on the pre-strip value.
#[test]
fn strip_reserved_recomputes_the_canonical_digest() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let with_aside = dir.path().join("with-aside");
    let without_aside = dir.path().join("without-aside");
    write(&with_aside.join("f"), b"content");
    write(&with_aside.join("d/g"), b"more");
    write(&with_aside.join(".sync-aside.foo"), b"reserved");
    write(&without_aside.join("f"), b"content");
    write(&without_aside.join("d/g"), b"more");

    let full = canonicalize_tree(&with_aside).unwrap();
    // The tree WITHOUT the reserved entry, canonicalized directly: this is the
    // exact metadata (entries and digest) `strip_reserved` must produce.
    let expected = canonicalize_tree(&without_aside).unwrap();
    assert!(
        full.entries.iter().any(|e| is_reserved_path(&e.path)),
        "the fixture must actually contain a reserved entry: {full:?}"
    );

    // (a) Stripping the reserved entry yields the canonical metadata of the
    //     remaining tree, digest included.
    let stripped = crate::sync::diff::strip_reserved(full.clone(), is_reserved_path);
    assert_eq!(
        stripped, expected,
        "stripping the reserved entry must yield the canonical metadata of the \
         remaining tree, digest included"
    );

    // (b) A manifest with NO reserved entries strips to ITSELF: the digest
    //     `canonicalize_tree` produced must survive the (identity) strip.
    let untouched = crate::sync::diff::strip_reserved(expected.clone(), is_reserved_path);
    assert_eq!(
        untouched.tree_sha256, expected.tree_sha256,
        "stripping a manifest with no reserved entries must leave the canonical \
         digest unchanged"
    );

    // (c) Idempotence: a second strip sees a digest already equal to the
    //     canonical one and must not drift again.
    assert_eq!(
        crate::sync::diff::strip_reserved(stripped.clone(), is_reserved_path),
        stripped,
        "strip_reserved must be idempotent"
    );
}

/// Item 2/3: a refused WRITABLE directory admits a TRANSFERRED (`Changed`) child
/// but is still off-limits to DELETION, so `delete_extraneous` must not remove
/// its destination-only child. This is the transfer-vs-destruction distinction.
#[cfg(unix)]
#[test]
fn a_refused_writable_directory_admits_a_transfer_but_not_a_deletion() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/f"), b"new");
    write(&dst.join("d/f"), b"old");
    write(&dst.join("d/extra"), b"e");
    set_mode(&src.join("d"), 0o755);
    set_mode(&dst.join("d"), 0o750);

    let refuse_d = |path: &str, _: EntryKind| {
        if path == "d" {
            EntryPolicy::Refuse
        } else {
            EntryPolicy::Replace
        }
    };
    let report = owned(Direction::Push, &src, &transport(&dst), &refuse_d, Delete).unwrap();
    assert_eq!(conflict_at(&report, "d").reason, ConflictReason::Refused);
    assert_eq!(
        conflict_at(&report, "d/extra").reason,
        ConflictReason::ParentRefused
    );
    assert!(
        report.applied.contains(&"d/f".to_string()),
        "the Changed child is TRANSFERRED through the refused writable directory: {report:?}"
    );
    assert_eq!(read(&dst.join("d/f")), b"new");
    assert_eq!(
        read(&dst.join("d/extra")),
        b"e",
        "the destination-only child SURVIVES: deletion is refused"
    );
    assert!(!report.extraneous.contains(&"d/extra".to_string()));
    assert_eq!(
        mode_of(&dst.join("d")),
        0o750,
        "the refused mode is untouched"
    );
    assert_no_aside(&dst);
}

/// The PULL counterpart of the test above: the destination is LOCAL, so the
/// write path is the durable fd-confined primitives rather than [`Remote`]. A
/// refused WRITABLE destination directory must admit the `Changed` child and
/// still forbid destroying the destination-only child — the same
/// transfer-vs-destruction distinction, on the other write path.
///
/// The destination directory is `0o700`, NOT the push case's `0o750`: the
/// confined local durable write narrows its immediate parent to `0o700`, so a
/// refused directory at any other mode does not satisfy that need and blocks
/// the child. `0o700` is the pull-side analogue of the push case's `0o750` —
/// the mode at which installing the child needs NO change to the refused
/// directory. The blocked half is pinned by the test immediately below.
#[cfg(unix)]
#[test]
fn a_refused_writable_directory_on_a_pull_admits_a_transfer_but_not_a_deletion() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    // For a PULL the source is the REMOTE and the destination is LOCAL.
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/f"), b"new");
    write(&dst.join("d/f"), b"old");
    write(&dst.join("d/extra"), b"e");
    set_mode(&src.join("d"), 0o755);
    // `0o700` is exactly what the local durable write needs of its immediate
    // parent, so the refused directory need not be touched to install the child.
    set_mode(&dst.join("d"), 0o700);

    let refuse_d = |path: &str, _: EntryKind| {
        if path == "d" {
            EntryPolicy::Refuse
        } else {
            EntryPolicy::Replace
        }
    };
    let report = owned(Direction::Pull, &dst, &transport(&src), &refuse_d, Delete).unwrap();
    assert_eq!(conflict_at(&report, "d").reason, ConflictReason::Refused);
    assert_eq!(
        conflict_at(&report, "d/extra").reason,
        ConflictReason::ParentRefused
    );
    assert!(
        report.applied.contains(&"d/f".to_string()),
        "the Changed child is TRANSFERRED through the refused writable directory: {report:?}"
    );
    assert_eq!(read(&dst.join("d/f")), b"new");
    assert_eq!(
        read(&dst.join("d/extra")),
        b"e",
        "the destination-only child SURVIVES: deletion is refused"
    );
    assert!(!report.extraneous.contains(&"d/extra".to_string()));
    assert_eq!(
        mode_of(&dst.join("d")),
        0o700,
        "the refused mode is untouched"
    );
    assert_no_aside(&dst);
}

/// The DELIBERATELY ASYMMETRIC half of the pair above, pinned so the asymmetry
/// is a contract rather than an accident: the confined local durable write
/// narrows its immediate parent to `0o700` (see `ParentNeed::Private`), so a
/// refused destination directory at `0o750` does NOT satisfy that need.
/// Installing the `Changed` child therefore WOULD chmod the refused path, which
/// the prohibition forbids — the child is reported `ParentRefused` and nothing
/// is mutated. The refusal is not a license to chmod the refused directory even
/// transiently: the atomic write would leave it at `0o700` with no journal
/// entry to restore it. The destination-only child is likewise protected.
#[cfg(unix)]
#[test]
fn a_refused_directory_a_local_write_must_re_mode_on_a_pull_blocks_the_child() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/f"), b"new");
    write(&dst.join("d/f"), b"old");
    write(&dst.join("d/extra"), b"e");
    set_mode(&src.join("d"), 0o755);
    set_mode(&dst.join("d"), 0o750);

    let refuse_d = |path: &str, _: EntryKind| {
        if path == "d" {
            EntryPolicy::Refuse
        } else {
            EntryPolicy::Replace
        }
    };
    let report = owned(Direction::Pull, &dst, &transport(&src), &refuse_d, Delete).unwrap();
    assert_eq!(conflict_at(&report, "d").reason, ConflictReason::Refused);
    assert_eq!(
        conflict_at(&report, "d/f").reason,
        ConflictReason::ParentRefused,
        "a refused 0o750 directory does not satisfy the local write's 0o700 need: {report:?}"
    );
    assert!(!report.applied.contains(&"d/f".to_string()), "{report:?}");
    assert_eq!(
        read(&dst.join("d/f")),
        b"old",
        "the child is NOT transferred"
    );
    assert_eq!(read(&dst.join("d/extra")), b"e", "the child SURVIVES");
    assert_eq!(
        mode_of(&dst.join("d")),
        0o750,
        "the refused mode is untouched — not even transiently"
    );
    assert_no_aside(&dst);
}

/// MED (round 8): the deletion prohibition must NOT be applied to the sync's OWN
/// claimed aside. A kind-changing replacement admitted through a refused but
/// WRITABLE directory claims the stale entry aside and then must be able to
/// delete that aside; the old ancestry guard over-blocked it, so the transfer
/// installed the new entry, failed cleanup, and stranded residue under a
/// directory the caller had merely refused. Under [`Sanction::OwnClaim`] the
/// aside is deletable by construction, so the run SUCCEEDS with no residue.
#[cfg(unix)]
#[test]
fn a_claim_aside_under_a_refused_writable_directory_is_still_deletable() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    // `d` differs only in mode, so its policy IS consulted and it is refused;
    // `d/f` is a source FILE replacing a destination DIRECTORY.
    write(&src.join("d/f"), b"new");
    write(&dst.join("d/f/keep"), b"keep");
    set_mode(&src.join("d"), 0o755);
    set_mode(&dst.join("d"), 0o750);

    let refuse_d = |path: &str, _: EntryKind| {
        if path == "d" {
            EntryPolicy::Refuse
        } else {
            EntryPolicy::Replace
        }
    };
    let report = owned(Direction::Push, &src, &transport(&dst), &refuse_d, Delete)
        .expect("the sync's own claim aside must not be blocked by the prohibition");
    assert_eq!(conflict_at(&report, "d").reason, ConflictReason::Refused);
    assert!(
        report.applied.contains(&"d/f".to_string()),
        "the admitted replacement is applied: {report:?}"
    );
    assert_eq!(read(&dst.join("d/f")), b"new");
    assert!(
        !dst.join("d/f/keep").exists(),
        "the claimed subtree was removed, not stranded"
    );
    assert!(
        report.residue.is_empty(),
        "the sync's own claim is deletable BY CONSTRUCTION, so no residue is stranded: {report:?}"
    );
    assert_eq!(
        mode_of(&dst.join("d")),
        0o750,
        "the refused mode is untouched"
    );
    assert_no_aside(&dst);
    assert_report_lists_disjoint(&report);
}

/// The latent `re_root_residue` spelling bug: joining an EMPTY child name must
/// return the parent unchanged. A trailing separator is not a valid manifest
/// spelling (`canonicalize_tree` never emits one), so `parent/` would fail to
/// match the path's canonical form and could hide a re-rooted residue path from
/// a later bookkeeping lookup.
#[test]
fn joining_an_empty_name_never_emits_a_trailing_separator() {
    assert_eq!(join_manifest_path("a/b", OsStr::new("")), "a/b".to_string());
    assert_eq!(join_manifest_path("", OsStr::new("")), "".to_string());
    assert_eq!(
        join_manifest_path("a/b", OsStr::new("c")),
        "a/b/c".to_string()
    );
    assert_eq!(join_manifest_path("", OsStr::new("c")), "c".to_string());
}

/// Assert `rel` exists under `root` as a regular file holding exactly `bytes`
/// with exactly `mode`. `SyncReport::applied` claims content AND mode, so a
/// FAILURE-path test must check the report AGAINST DISK, not only for internal
/// consistency: `assert_report_lists_disjoint` cannot catch a path named in the
/// wrong list when it IS named in a list.
#[cfg(unix)]
fn assert_file_on_disk(root: &Path, rel: &str, bytes: &[u8], mode: u32) {
    let path = root.join(rel);
    assert_eq!(read(&path), bytes, "content of {rel} on disk");
    assert_eq!(mode_of(&path), mode, "mode of {rel} on disk: {path:?}");
}

/// Assert `rel` exists under `root` as a directory with exactly `mode`.
#[cfg(unix)]
fn assert_dir_on_disk(root: &Path, rel: &str, mode: u32) {
    assert!(root.join(rel).is_dir(), "{rel} must be a directory on disk");
    assert_eq!(mode_of(&root.join(rel)), mode, "mode of {rel} on disk");
}

/// HIGH (round 10): `applied` must mean "EVERY post-transfer verification check
/// passed", including the post-`settle` pass. `verify(false)` runs in
/// `run_steps` and `settle` runs `verify(true)` AFTER the restore; a path that
/// passed the first pass and FAILS the second used to stay in the cumulative
/// `verified` set, so `derive_report`'s `applied` gate admitted it and the
/// `applied` > `verify_failures` precedence DELETED the genuine failure. The
/// dropped settle RESTORE of `d` is exactly that shape.
#[cfg(unix)]
#[test]
fn a_path_that_fails_the_post_settle_verification_is_not_reported_applied() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/child"), b"new");
    write(&dst.join("d/child"), b"old");
    write(&dst.join("d/extra"), b"e");
    // Set the source child's mode EXPLICITLY: `write` creates it `0o666 & ~umask`,
    // so the expected installed mode would otherwise depend on the process umask
    // (0644 under 0022, 0664 under 0002) and the assertion would fail on a host
    // with Ubuntu's default 0002.
    set_mode(&src.join("d/child"), 0o644);
    set_mode(&src.join("d"), 0o555);
    set_mode(&dst.join("d"), 0o500);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // Drop `d`'s SETTLE RESTORE — the only `set_mode` call that requests the
    // ORIGINAL mode 0o500 (the widen requests 0o700 and the final mode is
    // 0o555). Keying on the (path, mode) pair is POSITION-INDEPENDENT: adding
    // an earlier `set_mode` call cannot silently retarget the seam. The
    // `dropped_modes()` assertion below fails loudly if the target is missed.
    remote.drop_mode_for = Some((
        DropModeTarget::Path("d".to_string()),
        0o555,
        DropModeWhen::AfterRemoval,
    ));
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();
    assert_eq!(
        remote.dropped_modes(),
        vec![("d".to_string(), 0o555)],
        "the named settle restore was actually dropped (else this test is vacuous)"
    );
    assert!(
        matches!(err.error(), Error::Integrity(_)),
        "the error is the post-settle verification failure, got {err:?}"
    );

    assert!(
        err.report().verify_failures.contains(&"d".to_string()),
        "the dropped restore is a genuine verify failure: {:?}",
        err.report()
    );
    assert!(
        !err.report().applied.contains(&"d".to_string()),
        "a path that failed the post-settle verification is NOT applied: {:?}",
        err.report()
    );
    assert!(
        err.report().applied.contains(&"d/child".to_string()),
        "the verified child IS applied: {:?}",
        err.report()
    );
    // The report is checked AGAINST DISK: `applied` claims content AND mode, so
    // `d/child` must hold the source bytes at its intended mode, and `d` must be
    // at the mode the dropped restore left it at (0755, NOT its intended 0555).
    assert_file_on_disk(&dst, "d/child", b"new", 0o644);
    assert_dir_on_disk(&dst, "d", 0o755);
    assert_report_names(err.report(), "d");
    assert_report_lists_disjoint(err.report());
}

/// MED (round 10): a CONTENT write that publishes bytes and THEN fails leaves
/// the path's content unknown. A PRESENT destination is widened first, so
/// `settle`'s restore re-chmods it; that restore used to clear the attempt
/// unconditionally, dropping the path from `indeterminate` and leaving only
/// `transient_dirs` (a mode-only adjustment), so the caller could not tell that
/// the content may have changed. The attempt KIND now decides: only a MODE-only
/// attempt is cleared by a restore.
#[cfg(unix)]
#[test]
fn a_published_write_that_fails_stays_indeterminate_after_a_mode_restore() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    write(&dst.join("p"), b"old");
    set_mode(&src.join("p"), 0o644);
    set_mode(&dst.join("p"), 0o444);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_write_after_write = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();

    // The bytes ARE visible and the mode IS restored...
    assert_eq!(
        read(&dst.join("p")),
        b"new",
        "the write published the bytes"
    );
    assert_eq!(mode_of(&dst.join("p")), 0o444, "the widen is restored");
    // ...but the CONTENT may or may not have landed, so the path must stay
    // INDETERMINATE even though its mode was re-established.
    assert!(
        err.report().indeterminate.contains(&"p".to_string()),
        "a failed content write stays indeterminate after a mode restore: {:?}",
        err.report()
    );
    assert!(
        !err.report().transient_dirs.contains(&"p".to_string()),
        "an indeterminate path is not also named transient: {:?}",
        err.report()
    );
    // The widen, the attempted write, and the restore are all counted.
    assert_eq!(
        err.report().transfers,
        3,
        "widen + attempted write + restore: {:?}",
        err.report()
    );
    assert_report_names(err.report(), "p");
    assert_report_lists_disjoint(err.report());
}

/// Addendum B (round 10): a CHANGED symlink child under a read-only
/// manifest-entry parent. The existing `a_missing_child_under_a_read_only_-
/// parent_is_installed_and_the_parent_restored` test exercises a `Missing`
/// child, never a `Changed` SYMLINK — the widen-then-replace-a-symlink path.
#[cfg(unix)]
#[test]
fn a_changed_symlink_child_under_a_read_only_parent_is_replaced_and_the_parent_restored() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    for root in [&src, &dst] {
        fs::create_dir_all(root.join("d")).unwrap();
    }
    std::os::unix::fs::symlink("new-target", src.join("d/link")).unwrap();
    std::os::unix::fs::symlink("old-target", dst.join("d/link")).unwrap();
    for root in [&src, &dst] {
        set_mode(&root.join("d"), 0o555);
    }

    let remote = RecordingRemote::over(transport(&dst), true);
    let report = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert_eq!(
        fs::read_link(dst.join("d/link")).unwrap(),
        Path::new("new-target"),
        "the changed symlink is replaced on disk"
    );
    assert_eq!(
        mode_of(&dst.join("d")),
        0o555,
        "the read-only parent is restored"
    );
    assert!(
        report.transient_dirs.contains(&"d".to_string()),
        "the widened parent `d` is named transient: {:?}",
        report.transient_dirs
    );
    assert!(
        !report.skipped.contains(&"d".to_string()),
        "a widened parent is never skipped: {report:?}"
    );
    assert!(
        report.applied.contains(&"d/link".to_string()),
        "the replaced symlink is applied: {report:?}"
    );
    assert!(report.transfers >= 3, "widen + symlink + restore");
    assert_report_lists_disjoint(&report);
}

/// Addendum B (round 10): the "every diff entry is accounted for" clause on the
/// FAILURE path. The success-path version lives in
/// `the_report_lists_are_mutually_exclusive_and_cover_the_diff`; the per-path
/// `assert_report_names` calls elsewhere do not cover a NOVEL failure shape that
/// drops a mutated path from every list.
#[cfg(unix)]
#[test]
fn the_failure_path_report_accounts_for_every_diff_entry() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("same"), b"same");
    write(&src.join("changed"), b"new");
    write(&dst.join("same"), b"same");
    write(&dst.join("changed"), b"old");
    write(&dst.join("extra"), b"e");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // Fail the extraneous removal at the END of the run, so every entry has
    // been processed and the report must still account for every diff entry.
    remote.fail_remove_file = true;
    // Capture the run's OWN decision surface BEFORE the sync: the diff it
    // computes from the two manifests before any mutation. Recomputing it from
    // the POST-failure trees would describe a DIFFERENT input — `changed` now
    // matches the rewritten bytes and `extra` survives the failed removal — so
    // the coverage loop would silently shrink to a single entry.
    let pre_src = canonicalize_tree(&src).unwrap();
    let pre_dst = canonicalize_tree(&dst).unwrap();
    let diff = crate::sync::diff::diff_trees(&pre_src, &pre_dst);
    // The fixture is non-trivial, so a loop that degenerated to one entry fails
    // loudly here instead of passing vacuously.
    assert_eq!(diff.count(EntryDiff::Changed), 1, "{diff:?}");
    assert_eq!(diff.count(EntryDiff::Extraneous), 1, "{diff:?}");
    assert!(diff.count(EntryDiff::Same) >= 1, "{diff:?}");
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();

    let transient: BTreeSet<&str> = err
        .report()
        .transient_dirs
        .iter()
        .map(String::as_str)
        .collect();
    for (path, _) in &diff.entries {
        assert!(
            report_names(err.report(), path) || transient.contains(path.as_str()),
            "{path} must be named by the failure-path report or in `transient_dirs`: {:?}",
            err.report()
        );
    }
    assert_report_lists_disjoint(err.report());
}

/// Addendum A (round 10): the destination ROOT is the one directory the widen
/// machinery does not cover, so a READ-ONLY destination root is NOT transiently
/// widened. This is a documented limitation (see the module doc): every
/// top-level mutation fails LOUDLY — counted and named `indeterminate` — the
/// root keeps its mode, and nothing is destroyed. This test PINS that contract;
/// it is also the only test that sets the destination ROOT's mode.
#[cfg(unix)]
#[test]
fn a_read_only_destination_root_on_a_pull_fails_loudly_and_stays_unchanged() {
    // The premise (a `0o555` root refuses writes) is a property of the ambient
    // identity, not of this crate: under root the writes SUCCEED, so skip
    // rather than assert a behaviour the uid, not the code, decides.
    if !a_read_only_dir_really_refuses_writes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();

    // A top-level CHANGED file.
    let remote_root = dir.path().join("remote");
    write(&remote_root.join("f"), b"new");
    let local = dir.path().join("local");
    write(&local.join("f"), b"old");
    set_mode(&local, 0o555);
    let err = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &ReplaceAll,
        Keep,
    )
    .unwrap_err();
    assert_eq!(mode_of(&local), 0o555, "the root mode is untouched");
    assert_eq!(read(&local.join("f")), b"old", "nothing was written");
    assert!(
        err.report().indeterminate.contains(&"f".to_string()),
        "the top-level mutation is named: {:?}",
        err.report()
    );
    assert_eq!(err.report().transfers, 1);
    set_mode(&local, 0o755);

    // A top-level MISSING directory.
    let remote2 = dir.path().join("remote2");
    write(&remote2.join("d/x"), b"x");
    let local2 = dir.path().join("local2");
    fs::create_dir_all(&local2).unwrap();
    set_mode(&local2, 0o555);
    let err = owned(
        Direction::Pull,
        &local2,
        &transport(&remote2),
        &ReplaceAll,
        Keep,
    )
    .unwrap_err();
    assert_eq!(mode_of(&local2), 0o555, "the root mode is untouched");
    assert!(!local2.join("d").exists(), "the directory was not created");
    assert!(
        err.report().indeterminate.contains(&"d".to_string()),
        "the failed top-level create is named: {:?}",
        err.report()
    );
    set_mode(&local2, 0o755);

    // A top-level CHANGED symlink.
    let remote3 = dir.path().join("remote3");
    fs::create_dir_all(&remote3).unwrap();
    std::os::unix::fs::symlink("new-target", remote3.join("link")).unwrap();
    let local3 = dir.path().join("local3");
    fs::create_dir_all(&local3).unwrap();
    std::os::unix::fs::symlink("old-target", local3.join("link")).unwrap();
    set_mode(&local3, 0o555);
    let err = owned(
        Direction::Pull,
        &local3,
        &transport(&remote3),
        &ReplaceAll,
        Keep,
    )
    .unwrap_err();
    assert_eq!(mode_of(&local3), 0o555, "the root mode is untouched");
    assert_eq!(
        fs::read_link(local3.join("link")).unwrap(),
        Path::new("old-target"),
        "the symlink is unchanged"
    );
    assert!(
        err.report().indeterminate.contains(&"link".to_string()),
        "the failed top-level symlink install is named: {:?}",
        err.report()
    );
    set_mode(&local3, 0o755);
}

/// Addendum A (round 10): the same documented root limitation on the PUSH side,
/// where the destination root is the REMOTE. A read-only destination root makes
/// a top-level `Missing` file fail loudly; the root keeps its mode.
#[cfg(unix)]
#[test]
fn a_read_only_destination_root_on_a_push_fails_loudly_and_stays_unchanged() {
    // Same identity-dependent premise as the pull case above: skip when a
    // `0o555` root is actually writable (root / CAP_DAC_OVERRIDE).
    if !a_read_only_dir_really_refuses_writes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("f"), b"new");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();
    set_mode(&dst, 0o555);

    let err = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap_err();
    assert_eq!(mode_of(&dst), 0o555, "the root mode is untouched");
    assert!(!dst.join("f").exists(), "nothing was written");
    assert!(
        err.report().indeterminate.contains(&"f".to_string()),
        "the top-level mutation is named: {:?}",
        err.report()
    );
    assert_eq!(err.report().transfers, 1);
    set_mode(&dst, 0o755);
}

/// Every restore failure that names `aside` must mark it as a POSSIBILITY
/// ("could not be confirmed"), never assert that it exists. This is what the
/// read-back guard plus the report-time residue reconciliation buy: a move
/// whose location could not be confirmed is never reported as if its aside
/// were present.
fn assert_aside_only_named_as_possible(error: &SyncError, aside: &str) {
    for failure in error.restore_failures() {
        if failure.contains(aside) {
            assert!(
                failure.contains("could not be confirmed"),
                "an unconfirmed aside is named as if it existed: {failure}"
            );
        }
    }
}

/// HIGH (round 12): a CLAIM rename that LANDS and reports failure whose
/// location CANNOT be confirmed (the follow-up probe of the aside also fails,
/// the shape of a degraded session) must not name the PRE-MOVE residue
/// spelling — the landed move took it away — and must not leave the caller's
/// only copy invisible. The report names as `residue` only paths whose
/// existence is CONFIRMED at report time; the unconfirmed state is routed to
/// `indeterminate` and to a restore failure naming BOTH possible spellings.
#[cfg(unix)]
#[test]
fn a_claim_rename_whose_location_cannot_be_confirmed_names_both_possibilities() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    // A stranded aside INSIDE the destination directory `p`: the pre-move
    // residue spelling `p/.sync-aside.999.0` is carried under the new aside by
    // the landed claim.
    write(&dst.join("p/.sync-aside.999.0/stranded"), b"precious");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // rename #1 is the claim: it MOVES `p` aside and then reports failure.
    remote.fail_nth_rename_after_rename = Some(1);
    // The follow-up probe of the aside ALSO fails, so the location cannot be
    // confirmed.
    remote.fail_metadata_for_reserved_after_rename = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();

    // The claim LANDED: the real path is gone and the aside holds the copy.
    assert!(!dst.join("p").exists(), "the landed claim moved `p` aside");
    let aside = remote.rename_targets().into_iter().next().unwrap();
    assert_eq!(
        read(&dst.join(&aside).join(".sync-aside.999.0/stranded")),
        b"precious",
        "the aside holds the caller's only copy"
    );
    // The PRE-MOVE spelling no longer exists, so it must NOT be named residue.
    assert!(
        !err.report()
            .residue
            .contains(&"p/.sync-aside.999.0".to_string()),
        "residue must not name a path that no longer exists: {:?}",
        err.report()
    );
    assert!(err.report().residue.is_empty(), "{:?}", err.report());
    // (The vacuous `assert_residue_present` that used to sit here is gone: it
    // iterated an empty list after the assertion above, so it could not fail.)
    // The unconfirmed location is a restore failure naming BOTH spellings...
    let failures = err.restore_failures().join(" | ");
    assert!(
        failures.contains("p/.sync-aside.999.0"),
        "the pre-move possibility is named: {failures}"
    );
    assert!(
        failures.contains(&format!("{aside}/.sync-aside.999.0")),
        "the post-move possibility is named: {failures}"
    );
    // ...explicitly as UNCONFIRMED, never as an assertion of existence.
    assert!(
        failures.contains("could not be confirmed"),
        "the location is marked unconfirmed: {failures}"
    );
    assert_aside_only_named_as_possible(&err, &aside);
    // The attempted path is named in the highest-precedence list.
    assert!(
        err.report().indeterminate.contains(&"p".to_string()),
        "{:?}",
        err.report()
    );
    assert_report_lists_disjoint(err.report());
}

/// HIGH (round 12): the same unconfirmed state when the entry is at NEITHER
/// spelling (`Ok(None)` at both probes): nothing may be named as residue, and
/// the caller must still be told the two places to look.
#[cfg(unix)]
#[test]
fn a_claim_rename_whose_entry_vanished_names_both_possibilities() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    write(&dst.join("p/.sync-aside.999.0/stranded"), b"precious");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // rename #1 DELETES the source entry and reports failure: neither spelling
    // now exists.
    remote.vanish_nth_rename = Some(1);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();

    assert!(!dst.join("p").exists(), "the source spelling is gone");
    assert_no_aside(&dst);
    assert!(err.report().residue.is_empty(), "{:?}", err.report());
    // (The vacuous `assert_residue_present` that used to sit here is gone.)
    let failures = err.restore_failures().join(" | ");
    assert!(failures.contains("could not be confirmed"), "{failures}");
    // Both possible spellings of the (vanished) stranded copy are named.
    let aside = remote.rename_targets().into_iter().next().unwrap();
    assert!(failures.contains("p/.sync-aside.999.0"), "{failures}");
    assert!(
        failures.contains(&format!("{aside}/.sync-aside.999.0")),
        "{failures}"
    );
    assert!(
        err.report().indeterminate.contains(&"p".to_string()),
        "{:?}",
        err.report()
    );
    assert_report_lists_disjoint(err.report());
}

/// COVERAGE (round 12): a CLAIM rename that fails WITHOUT landing leaves the
/// destination byte-identical, names the attempted path `indeterminate`, and
/// records NO residue, NO aside, and NO restore failure. This test ALSO
/// falsifies `record_stranded_entry`'s confirmed-presence guard: the aside is
/// ABSENT, so deleting the guard would record a nonexistent path and a
/// restore failure that asserts it exists.
#[cfg(unix)]
#[test]
fn a_claim_rename_that_fails_without_landing_records_no_stranded_aside() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    write(&dst.join("p/keep"), b"keep");
    let before = canonicalize_tree(&dst).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // rename #1 is the claim; it fails WITHOUT moving anything.
    remote.fail_nth_rename = Some(1);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();

    assert_eq!(
        canonicalize_tree(&dst).unwrap(),
        before,
        "a claim that did not land leaves the destination byte-identical"
    );
    assert_no_aside(&dst);
    assert!(err.report().residue.is_empty(), "{:?}", err.report());
    assert!(
        err.report().indeterminate.contains(&"p".to_string()),
        "the failed claim names its path: {:?}",
        err.report()
    );
    assert_eq!(err.report().transfers, 1, "{:?}", err.report());
    assert!(
        err.restore_failures().is_empty(),
        "a move that did not land strands nothing and asserts nothing: {:?}",
        err.restore_failures()
    );
    // The RIGHT-list check this test is about: the claim did NOT land, so the
    // attempted aside is named in NO report list at all. `assert_no_aside`
    // above only inspects the DISK, and the vacuous `assert_residue_present`
    // that used to sit here iterated an EMPTY `residue` and could not fail.
    let aside = remote.rename_targets().into_iter().next().unwrap();
    assert!(
        !report_names(err.report(), &aside),
        "a claim that did not land must not name its aside anywhere: {:?}",
        err.report()
    );
    assert_restore_failures_name_existing_asides(&err, &dst);
    assert_report_lists_disjoint(err.report());
}

/// COVERAGE (round 12): a read-only destination FILE that was transiently
/// widened, WRITTEN successfully, and whose final mode landed (`applied`) is
/// NOT reverted to its original mode by `settle` when a LATER entry fails: a
/// final mode that landed supersedes the raw widen.
#[cfg(unix)]
#[test]
fn a_widened_file_whose_write_succeeded_is_not_reverted_by_a_later_failure() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"new");
    write(&dst.join("f"), b"old");
    write(&src.join("z"), b"new-z");
    set_mode(&src.join("f"), 0o640);
    set_mode(&dst.join("f"), 0o444);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // `f` (the first path-ordered entry) is written; `z` fails after it.
    remote.fail_nth_write = Some(2);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();

    assert_eq!(read(&dst.join("f")), b"new", "the first write landed");
    assert_eq!(
        mode_of(&dst.join("f")),
        0o640,
        "the landed final mode supersedes the raw widen and is not reverted: {:?}",
        err.report()
    );
    assert!(
        err.report().applied.contains(&"f".to_string()),
        "the landed file is applied: {:?}",
        err.report()
    );
    assert_report_lists_disjoint(err.report());
}

/// COVERAGE (round 12): a PULL-direction CHANGED file and CHANGED symlink
/// under a read-only manifest-entry parent both widen the parent through the
/// confined local write path, install, and restore the parent's mode.
#[cfg(unix)]
#[test]
fn a_pull_changed_file_and_symlink_under_a_read_only_parent_transfer_and_restore() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    for root in [&remote_root, &local] {
        fs::create_dir_all(root.join("d")).unwrap();
    }
    write(&remote_root.join("d/f"), b"new");
    write(&local.join("d/f"), b"old");
    std::os::unix::fs::symlink("new-target", remote_root.join("d/link")).unwrap();
    std::os::unix::fs::symlink("old-target", local.join("d/link")).unwrap();
    for root in [&remote_root, &local] {
        set_mode(&root.join("d"), 0o555);
    }

    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &ReplaceAll,
        Keep,
    )
    .unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert_eq!(read(&local.join("d/f")), b"new");
    assert_eq!(
        fs::read_link(local.join("d/link")).unwrap(),
        Path::new("new-target")
    );
    assert_eq!(mode_of(&local.join("d")), 0o555, "the parent is restored");
    assert!(
        report.transient_dirs.contains(&"d".to_string()),
        "the widened parent `d` is named transient: {:?}",
        report.transient_dirs
    );
    assert!(report.applied.contains(&"d/f".to_string()), "{report:?}");
    assert!(report.applied.contains(&"d/link".to_string()), "{report:?}");
    assert!(
        !report.skipped.contains(&"d".to_string()),
        "a widened parent is never skipped: {report:?}"
    );
    assert_report_lists_disjoint(&report);
}

/// COVERAGE (round 12): an UNREADABLE far-side root is an ERROR, never read as
/// an empty tree. Otherwise a `delete_extraneous` pull would see "nothing is
/// there" and destroy the local tree.
#[test]
fn an_unreadable_far_side_root_is_an_error_and_destroys_nothing() {
    let dir = fixture_tmpdir(&env()).unwrap();
    // The local destination holds content an "empty remote" would delete.
    let local = dir.path().join("local");
    write(&local.join("keep"), b"keep");
    let remote_root = dir.path().join("remote");
    fs::create_dir_all(&remote_root).unwrap();
    let before = canonicalize_tree(&local).unwrap();

    let mut remote = RecordingRemote::over(transport(&remote_root), false);
    remote.exec_failure = Some(ExecOutcome {
        exit_code: 1,
        stdout: String::new(),
        stderr: format!("cannot open {}: Permission denied", remote_root.display()),
        timeout_cause: None,
    });
    let err = owned(Direction::Pull, &local, &remote, &ReplaceAll, Delete).unwrap_err();
    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    assert!(
        err.error().to_string().contains("Permission denied"),
        "the far-side failure is reported: {err:?}"
    );
    assert_eq!(
        canonicalize_tree(&local).unwrap(),
        before,
        "nothing is destroyed when the far side cannot be described"
    );
    assert_eq!(remote.ops(), 0, "no mutation was attempted");
}

/// COVERAGE (round 12): a source FILE over a destination read-only DIRECTORY
/// under `AppendTail` on a PULL reports `AppendNotAFile` for the file and
/// `ParentRefused` for its destination-only child; the read-only directory is
/// never widened and its child is never deleted, even with `delete_extraneous`.
#[cfg(unix)]
#[test]
fn append_tail_file_over_a_read_only_directory_on_a_pull_destroys_nothing() {
    if !the_filesystem_honours_modes() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    write(&remote_root.join("p"), b"file");
    write(&local.join("p/keep"), b"keep");
    set_mode(&local.join("p"), 0o555);

    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &append_files,
        Delete,
    )
    .unwrap();
    assert_eq!(
        conflict_at(&report, "p").reason,
        ConflictReason::AppendNotAFile
    );
    assert_eq!(
        conflict_at(&report, "p/keep").reason,
        ConflictReason::ParentRefused
    );
    assert!(report.transient_dirs.is_empty(), "{report:?}");
    assert_eq!(report.transfers, 0, "nothing is mutated: {report:?}");
    assert!(local.join("p").is_dir(), "the directory survives");
    assert_eq!(read(&local.join("p/keep")), b"keep");
    assert_eq!(mode_of(&local.join("p")), 0o555, "the mode is untouched");
    assert_no_aside(&local);
    assert_report_lists_disjoint(&report);
}

/// LOW (round 12): the documented precedence applies to `conflicts` too. A
/// conflict records the caller's decision surface and `indeterminate` the
/// least-certain claim, so a path in BOTH must be reported only in
/// `indeterminate`. This is unreachable through the public API today (a
/// conflict leaves its path alone while `indeterminate` means a mutation on it
/// was attempted and failed), so the partition is a pure function and is pinned
/// directly: removing the `conflicts.retain` line in `apply_precedence` fails
/// this test.
#[test]
fn the_precedence_partition_drops_a_conflict_named_indeterminate() {
    let indeterminate: BTreeSet<String> = ["p".to_string()].into_iter().collect();
    let mut conflicts = vec![Conflict {
        path: "p".to_string(),
        kind: EntryKind::File,
        policy: EntryPolicy::Replace,
        reason: ConflictReason::Refused,
        on_disk: None,
    }];
    let mut residue: BTreeSet<String> = ["p".to_string()].into_iter().collect();
    let mut applied: BTreeSet<String> = ["p".to_string()].into_iter().collect();
    let mut skipped: BTreeSet<String> = ["p".to_string()].into_iter().collect();
    let mut extraneous: BTreeSet<String> = ["p".to_string()].into_iter().collect();
    let mut verify_failures: BTreeSet<String> = ["p".to_string()].into_iter().collect();

    apply_precedence(
        &indeterminate,
        &mut conflicts,
        &mut residue,
        &mut applied,
        &mut skipped,
        &mut extraneous,
        &mut verify_failures,
    );

    // `indeterminate` wins: the conflict is dropped and every lower list is
    // emptied, so the path is named exactly once.
    assert!(
        conflicts.is_empty(),
        "a conflict named `indeterminate` is dropped: {conflicts:?}"
    );
    assert!(residue.is_empty(), "{residue:?}");
    assert!(applied.is_empty(), "{applied:?}");
    assert!(skipped.is_empty(), "{skipped:?}");
    assert!(extraneous.is_empty(), "{extraneous:?}");
    assert!(verify_failures.is_empty(), "{verify_failures:?}");
    assert_eq!(indeterminate.len(), 1);
}

/// HIGH (round 12): the ROLLBACK variant of the unconfirmed location. The claim
/// lands, the install fails, the rollback rename fails WITHOUT landing, and the
/// probe of the reserved aside ALSO fails: the re-rooted residue candidates may
/// be at the aside or back at the real path, so `residue` must name NEITHER
/// unconfirmed spelling and the restore failures must name BOTH.
#[cfg(unix)]
#[test]
fn a_rollback_rename_whose_location_cannot_be_confirmed_names_both_possibilities() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    write(&dst.join("p/.sync-aside.999.0/stranded"), b"precious");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // The install fails, so the rollback runs; rename #2 (the rollback) fails
    // WITHOUT landing (rename #1, the claim, succeeded).
    remote.fail_writes = true;
    remote.fail_nth_rename = Some(2);
    // The probe of the reserved aside then fails too.
    remote.fail_metadata_for_reserved_after_rename = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();

    let aside = remote.rename_targets().into_iter().next().unwrap();
    // The rollback did not land, so the real path is still gone.
    assert!(!dst.join("p").exists(), "the rollback did not land");
    // Neither unconfirmed spelling may be named as residue.
    assert!(err.report().residue.is_empty(), "{:?}", err.report());
    // (The vacuous `assert_residue_present` that used to sit here is gone.)
    let failures = err.restore_failures().join(" | ");
    assert!(
        failures.contains(&format!("{aside}/.sync-aside.999.0")),
        "the aside spelling is named: {failures}"
    );
    assert!(
        failures.contains("p/.sync-aside.999.0"),
        "the real-path spelling is named: {failures}"
    );
    assert!(failures.contains("could not be confirmed"), "{failures}");
    assert_aside_only_named_as_possible(&err, &aside);
    assert_report_lists_disjoint(err.report());
}

/// HIGH (round 13): an unconfirmed move of a RESIDUE-FREE subtree must still be
/// surfaced. `reconcile_residue` used to consume `unconfirmed_moves` only WHILE
/// ITERATING residue candidates, so a move whose subtree held no residue
/// produced NO message at all and the caller's only copy (the LANDED aside) was
/// named nowhere: not in `residue`, not in `restore_failures`, only the real
/// path in `indeterminate`. The possibility channel is now iterated in its own
/// right, so both spellings are surfaced.
#[cfg(unix)]
#[test]
fn an_unconfirmed_move_of_a_residue_free_subtree_names_both_possibilities() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    // A source FILE over a destination DIRECTORY whose only child is ordinary
    // content (NOT reserved): the destination has NO residue candidate at all.
    write(&src.join("p"), b"new");
    write(&dst.join("p/keep"), b"keep");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // rename #1 is the claim: it MOVES `p` aside and then reports failure.
    remote.fail_nth_rename_after_rename = Some(1);
    // The follow-up probe of the aside ALSO fails, so the location cannot be
    // confirmed.
    remote.fail_metadata_for_reserved_after_rename = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();

    let aside = remote.rename_targets().into_iter().next().unwrap();
    // The claim LANDED: the real path is gone and the aside holds the copy.
    assert!(!dst.join("p").exists(), "the landed claim moved `p` aside");
    assert_eq!(
        read(&dst.join(&aside).join("keep")),
        b"keep",
        "the aside holds the caller's only copy"
    );
    // No residue survives, precisely because there was none to begin with.
    assert!(err.report().residue.is_empty(), "{:?}", err.report());
    // (a) The aside (and the real path) are named in a list that asserts no
    // location.
    assert!(
        err.report().indeterminate.contains(&aside),
        "the aside spelling is named in `indeterminate`: {:?}",
        err.report()
    );
    assert!(
        err.report().indeterminate.contains(&"p".to_string()),
        "the real path is named in `indeterminate`: {:?}",
        err.report()
    );
    // (b) A restore failure names BOTH spellings as possibilities, explicitly
    // marked unconfirmed.
    let failures = err.restore_failures().join(" | ");
    assert!(
        failures.contains(&format!("of p to {aside}")),
        "the move's two spellings are named: {failures}"
    );
    assert!(
        failures.contains(&format!("at p or {aside}")),
        "both possible locations are named: {failures}"
    );
    assert!(
        failures.contains("could not be confirmed"),
        "the location is marked unconfirmed: {failures}"
    );
    assert_aside_only_named_as_possible(&err, &aside);
    assert_report_lists_disjoint(err.report());
}

/// MED (round 13): `record_leftover_aside` used to ASSERT that the aside still
/// holds the original without a read-back. When the removal LANDED and then
/// reported failure, `residue` was correctly emptied by the reconciliation but
/// the message remained, naming a path that does not exist. The message is now
/// gated on a read-back: a confirmed-gone aside is described as gone and named
/// nowhere, so `assert_restore_failures_name_existing_asides` holds.
#[cfg(unix)]
#[test]
fn a_leftover_aside_removal_that_lands_and_reports_failure_names_no_absent_aside() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"new");
    fs::create_dir_all(&dst).unwrap();
    // A source FILE over a destination SYMLINK: the claim moves the symlink
    // aside and `drop_claim` deletes it with `remove_file`.
    std::os::unix::fs::symlink("target", dst.join("p")).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // The install succeeds; deleting the aside UNLINKS it and THEN reports
    // failure — the removal landed.
    remote.fail_nth_remove_after_remove = Some(1);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();

    // The destination is correct and no aside survives.
    assert_eq!(read(&dst.join("p")), b"new");
    assert_no_aside(&dst);
    assert!(err.report().residue.is_empty(), "{:?}", err.report());
    let aside = remote.rename_targets().into_iter().next().unwrap();
    assert!(
        err.report().indeterminate.contains(&aside),
        "the attempted removal leaves the aside indeterminate: {:?}",
        err.report()
    );
    // Every aside named by a restore failure EXISTS: the reading is truthful
    // for a removal, not only for a rename.
    assert_restore_failures_name_existing_asides(&err, &dst);
    let failures = err.restore_failures().join(" | ");
    assert!(
        !failures.contains("still holds the original"),
        "a gone aside is never asserted to hold the original: {failures}"
    );
    assert!(
        !failures.contains(&aside),
        "a gone aside is not named by any message: {failures}"
    );
    assert!(
        failures.contains("GONE"),
        "the read-back is described: {failures}"
    );
    assert_report_lists_disjoint(err.report());
}

/// MED (round 14): the `record_stranded_entry` PROBE-FAILURE case. The claim
/// lands, the install fails, the discard of the partial replacement fails, and
/// the read-back probe of the claimed aside ALSO fails. The caller's only copy
/// sits at the aside, but before the fix `record_stranded_entry` had only the
/// `Ok(Some(_))` branch, so the `Err(probe)` case recorded NOTHING: `residue`
/// was empty and `restore_failures` was empty, and the aside was named NOWHERE.
/// The candidate now goes through the report-time reconciliation
/// ([`Applier::reconcile_residue`]), which names the unconfirmable aside in
/// `indeterminate` (a list that asserts no location) AND in a restore failure
/// explicitly marked unconfirmed — never as confirmed residue.
#[cfg(unix)]
#[test]
fn a_stranded_aside_whose_probe_fails_is_named_as_a_possibility() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    // A source FILE over a destination DIRECTORY: a kind-changing replacement.
    write(&src.join("p"), b"new");
    write(&dst.join("p/keep"), b"keep");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // (1) The install PUBLISHES `p` and then errors, so the rollback runs.
    remote.fail_write_after_write = true;
    // (2) Discarding that partial `p` fails, so the rollback cannot restore the
    //     original from the aside.
    remote.fail_remove_file = true;
    // (3) The read-back probe of the claimed aside fails too, so its presence
    //     cannot be confirmed.
    remote.fail_metadata_for_reserved_after_rename = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();

    // The claim landed: the original tree is at the aside and holds the copy.
    let aside = remote.rename_targets().into_iter().next().unwrap();
    assert!(!dst.join("p").is_dir(), "the claim moved `p` aside");
    assert_eq!(
        read(&dst.join(&aside).join("keep")),
        b"keep",
        "the aside holds the caller's only copy"
    );
    // The probe failed, so NOTHING is asserted as an existing residue path.
    assert!(err.report().residue.is_empty(), "{:?}", err.report());
    // The aside IS named — in a list that asserts no location...
    assert!(
        err.report().indeterminate.contains(&aside),
        "the stranded aside is named in `indeterminate`: {:?}",
        err.report()
    );
    // ...and in a restore failure explicitly marked UNCONFIRMED.
    let failures = err.restore_failures().join(" | ");
    assert!(failures.contains(&aside), "the aside is named: {failures}");
    assert!(
        failures.contains("could not be confirmed"),
        "the aside is marked unconfirmed: {failures}"
    );
    assert_aside_only_named_as_possible(&err, &aside);
    assert_report_lists_disjoint(err.report());
}

/// HIGH (round 17): a manifest stores entry paths in NFC and `sync::apply`
/// ADDRESSES the file by the stored spelling. On a normalization-sensitive
/// filesystem (Linux/ext4) a source name that is NOT already NFC is stored in a
/// spelling that does not exist on disk, so `install_file`'s source read fails
/// with a bare `open ...: No such file or directory` (`Error::Store`, not a
/// materialization refusal); on macOS both spellings resolve to one entry, so
/// the same sync silently SUCCEEDS. The canonicalizer now REFUSES such a tree,
/// so the refusal happens at MANIFEST time: a loud error naming the offending
/// path, and NOTHING is mutated, on every platform.
#[cfg(unix)]
#[test]
fn a_decomposed_source_name_is_refused_at_manifest_time_and_mutates_nothing() {
    if !filesystem_preserves_a_decomposed_name() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    write(&src.join(DECOMPOSED_NAME), b"new");

    let remote = RecordingRemote::over(transport(&dst), true);
    let err = match owned(Direction::Push, &src, &remote, &ReplaceAll, Keep) {
        Ok(report) => {
            panic!("a source name that is not NFC must be REFUSED, not synced: {report:?}")
        }
        Err(err) => err,
    };
    assert!(
        matches!(err.error(), Error::Materialization(_)),
        "a canonicalization refusal is a materialization error, not a source-read \
         failure: {err:?}"
    );
    assert!(
        err.error().to_string().contains("caf"),
        "the refusal names the offending path: {err}"
    );
    assert_eq!(
        err.report().transfers,
        0,
        "a manifest-time refusal mutates nothing: {err:?}"
    );
    assert!(err.report().applied.is_empty(), "{err:?}");
    assert!(err.report().residue.is_empty(), "{err:?}");
    // Nothing was created at the destination under EITHER spelling.
    assert!(fs::symlink_metadata(dst.join(COMPOSED_NAME)).is_err());
    assert!(fs::symlink_metadata(dst.join(DECOMPOSED_NAME)).is_err());
    // The source still holds the caller's entry, untouched.
    assert_eq!(read(&src.join(DECOMPOSED_NAME)), b"new");
}

/// HIGH (round 17): with the source PRECOMPOSED and the destination
/// DECOMPOSED (two distinct files on Linux), the destination manifest stored the
/// destination's NFC spelling, the diff read that as `Missing`, and `install_file`
/// wrote a SECOND entry at the NFC name — leaving BOTH files. `sync` returned
/// `Ok applied=["café.txt"] transfers=1` even though `canonicalize_tree(dst)`
/// then fails with `duplicate normalized path`, so the destination could never be
/// synced again. The canonicalizer now refuses the decomposed destination up
/// front: `Err`, nothing mutated, and no `Ok` that leaves the destination
/// inconsistent.
#[cfg(unix)]
#[test]
fn a_decomposed_destination_name_is_refused_instead_of_landing_a_second_entry() {
    if !filesystem_distinguishes_normalization_forms() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    // DIFFERENT bytes, so pre-fix the diff is `Changed` and the transfer runs.
    write(&src.join(COMPOSED_NAME), b"new");
    write(&dst.join(DECOMPOSED_NAME), b"old");

    let remote = RecordingRemote::over(transport(&dst), true);
    let err = match owned(Direction::Push, &src, &remote, &ReplaceAll, Keep) {
        Ok(report) => panic!(
            "a destination name that is not NFC must be REFUSED, not synced into a \
             second entry: {report:?}"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err.error(), Error::Materialization(_)),
        "a canonicalization refusal is a materialization error: {err:?}"
    );
    assert_eq!(
        err.report().transfers,
        0,
        "a manifest-time refusal mutates nothing: {err:?}"
    );
    // No second (NFC) entry was created beside the decomposed original.
    assert!(
        fs::symlink_metadata(dst.join(COMPOSED_NAME)).is_err(),
        "the sync must not create the NFC twin that canonicalize_tree then rejects"
    );
    assert_eq!(read(&dst.join(DECOMPOSED_NAME)), b"old");
    let names: Vec<std::ffi::OsString> = fs::read_dir(&dst)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names.len(), 1, "the destination is unchanged: {names:?}");
    // COVERAGE: the pre-existing decomposed name still makes the destination
    // tree uncanonicalizable, so no `Ok` from this run could have left it
    // "synced". (This also holds pre-fix, where the `Ok` existed.)
    assert!(canonicalize_tree(&dst).is_err());
}

/// HIGH (round 17): `delete_extraneous=true` used to silently spare a
/// destination-only entry whose on-disk name is decomposed: the removal
/// addressed the stored NFC spelling, which does not exist on Linux, and the
/// transport's `remove_file` treats a confirmed absence as SUCCESS. `sync`
/// returned `Ok` while the entry survived, with nothing signalling it. The
/// canonicalizer now refuses the destination up front, so the run fails closed
/// and the entry is untouched rather than reported as deleted.
#[cfg(unix)]
#[test]
fn delete_extraneous_never_silently_spares_a_decomposed_destination_entry() {
    if !filesystem_distinguishes_normalization_forms() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    write(&dst.join(DECOMPOSED_NAME), b"extra");

    let remote = RecordingRemote::over(transport(&dst), true);
    let err = match owned(Direction::Push, &src, &remote, &ReplaceAll, Delete) {
        Ok(report) => panic!(
            "delete_extraneous must not report success while a decomposed entry it \
             addressed by its NFC spelling survives: {report:?}"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err.error(), Error::Materialization(_)),
        "a canonicalization refusal is a materialization error: {err:?}"
    );
    assert_eq!(
        err.report().transfers,
        0,
        "a manifest-time refusal mutates nothing: {err:?}"
    );
    assert_eq!(
        read(&dst.join(DECOMPOSED_NAME)),
        b"extra",
        "the extraneous entry is untouched, not silently \"deleted\""
    );
    assert!(fs::symlink_metadata(dst.join(COMPOSED_NAME)).is_err());
}

/// MED (round 17): `record_leftover_aside`'s confirmed-present branch said a
/// claimed aside "still holds the original" based only on the aside PATH
/// existing. For a claimed DIRECTORY aside whose descendant unlink LANDED and
/// then failed, the directory remains while a child is already gone, so the
/// message asserted content the read-back never confirmed. The branch now
/// distinguishes a file/symlink aside (whose presence IS the original) from a
/// directory aside (whose presence confirms only that the directory exists).
/// Pre-fix the message says "still holds the original" for the directory.
#[cfg(unix)]
#[test]
fn a_leftover_directory_aside_does_not_claim_to_still_hold_the_original() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    // A source FILE over a destination DIRECTORY: a kind-changing replacement
    // whose claimed aside is a DIRECTORY. `delete_extraneous` sanctions it.
    write(&src.join("p"), b"new");
    write(&dst.join("p/child"), b"child");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // The FIRST descendant unlink LANDS and then reports failure, so the aside
    // directory remains with `child` already gone.
    remote.fail_nth_remove_after_remove = Some(1);
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete).unwrap_err();

    assert!(
        err.report().applied.contains(&"p".to_string()),
        "the install succeeded, so it is applied: {:?}",
        err.report()
    );
    let aside = find_residue(&dst);
    // The aside DIRECTORY is confirmed present, so it is residue...
    assert!(err.report().residue.contains(&aside), "{:?}", err.report());
    assert!(fs::symlink_metadata(dst.join(&aside)).is_ok());
    // ...but its child was already unlinked before the failure.
    assert!(
        fs::symlink_metadata(dst.join(&aside).join("child")).is_err(),
        "the child unlink landed before the failure"
    );
    let failures = err.restore_failures().join(" | ");
    assert!(failures.contains(&aside), "the aside is named: {failures}");
    assert!(
        !failures.contains("still holds the original"),
        "a directory aside whose child is already gone must not be asserted to \
         still hold the original: {failures}"
    );
    assert_restore_failures_name_existing_asides(&err, &dst);
    assert_report_lists_disjoint(err.report());
}

/// HIGH (round 18): the manifest is the cross-module contract and the remote
/// verification wire is TAB-separated, so a SYMLINK TARGET containing a tab
/// cannot round-trip. `canonicalize_tree` used to copy such a target verbatim,
/// so a local push installed the link and returned `Ok` — the same tree
/// described over the wire truncates the target at the tab, so the local walk
/// and the wire accepted different trees. The canonicalizer now REFUSES the
/// target at MANIFEST time: a loud error and NOTHING mutated.
#[cfg(unix)]
#[test]
fn a_tab_in_a_source_symlink_target_is_refused_at_manifest_time() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    std::os::unix::fs::symlink("a\tb", src.join("l")).unwrap();

    let remote = RecordingRemote::over(transport(&dst), true);
    let err = match owned(Direction::Push, &src, &remote, &ReplaceAll, Keep) {
        Ok(report) => panic!(
            "a symlink target containing a tab cannot be represented on the \
             tab-separated wire and must be REFUSED, not synced: {report:?}"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err.error(), Error::Materialization(_)),
        "a canonicalization refusal is a materialization error: {err:?}"
    );
    assert_eq!(
        err.report().transfers,
        0,
        "a manifest-time refusal mutates nothing: {err:?}"
    );
    assert!(err.report().applied.is_empty(), "{err:?}");
    assert_eq!(remote.ops(), 0, "the transport saw no mutating call");
    assert!(
        fs::symlink_metadata(dst.join("l")).is_err(),
        "no link is created from a target that cannot be represented"
    );
    // The source link is untouched, tab and all.
    assert_eq!(fs::read_link(src.join("l")).unwrap(), Path::new("a\tb"));
}

/// HIGH (round 18, F1): a REMOTE symlink target containing a tab is truncated
/// by the tab-separated wire (`a\tb` -> `a`), so the assembler stored the
/// truncated target, the diff read it as `Missing`, `transfer_symlink`
/// installed the WRONG target, verification hashed the truncated target the
/// assembler had itself stored, and the pull returned
/// `Ok applied=["l"] transfers=1 verify_failures=[]`. The remote canonicalizer
/// now refuses the tree, so the pull fails closed with nothing installed.
#[cfg(unix)]
#[test]
fn a_tab_in_a_remote_symlink_target_is_refused_not_installed_truncated() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    let local = dir.path().join("local");
    fs::create_dir_all(&remote_root).unwrap();
    fs::create_dir_all(&local).unwrap();
    std::os::unix::fs::symlink("a\tb", remote_root.join("l")).unwrap();

    // is_local = false so the FAR-SIDE script (not the in-process walk)
    // describes the source tree: that is the path where the tab truncates.
    let remote = RecordingRemote::over(transport(&remote_root), false);
    let err = match owned(Direction::Pull, &local, &remote, &ReplaceAll, Keep) {
        Ok(report) => panic!(
            "a remote symlink target containing a tab must be REFUSED, not \
             installed with a truncated target: {report:?}"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err.error(), Error::Materialization(_) | Error::Transport(_)),
        "the refusal is a manifest-time error (the far-side walk or the \
         assembler), never a post-mutation verification failure: {err:?}"
    );
    assert_eq!(err.report().transfers, 0, "{err:?}");
    assert!(err.report().applied.is_empty(), "{err:?}");
    assert!(
        fs::symlink_metadata(local.join("l")).is_err(),
        "no link is created, so no link holds the truncated target"
    );
}

/// HIGH (round 18, F1/F2): the wire assembler stored a truncated target, so a
/// destination symlink whose REAL target is `a\tb` was described as target
/// `a`. A source whose target IS `a` then compared EQUAL, the diff read the
/// entry as `Same`, and the push returned `Ok` with the entry skipped while
/// the two trees genuinely differ. The remote canonicalizer now refuses the
/// destination tree: an error, and the destination link is byte-identical.
#[cfg(unix)]
#[test]
fn a_tab_in_a_remote_destination_symlink_target_is_refused_not_read_as_same() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let remote_root = dir.path().join("remote");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&remote_root).unwrap();
    // The source's target is exactly what the wire TRUNCATES `a\tb` to.
    std::os::unix::fs::symlink("a", src.join("l")).unwrap();
    std::os::unix::fs::symlink("a\tb", remote_root.join("l")).unwrap();

    let remote = RecordingRemote::over(transport(&remote_root), false);
    let err = match unowned(Direction::Push, &src, &remote, &ReplaceAll, Keep) {
        Ok(report) => panic!(
            "the destination's real target `a\\tb` must not be silently \
             addressed as `a` (which reads as `Same`): {report:?}"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err.error(), Error::Materialization(_) | Error::Transport(_)),
        "the refusal is a manifest-time error: {err:?}"
    );
    assert_eq!(err.report().transfers, 0, "{err:?}");
    assert!(err.report().applied.is_empty(), "{err:?}");
    // The destination link is untouched: still the tab-bearing target.
    assert_eq!(
        fs::read_link(remote_root.join("l")).unwrap(),
        Path::new("a\tb")
    );
}

/// HIGH (round 18, F3): a non-UTF-8 symlink TARGET was stored with
/// `from_utf8_lossy` while the RAW bytes were hashed, so `transfer_symlink`
/// installed a REWRITTEN link and only THEN failed verification — the
/// destination was MUTATED to a different target before the error surfaced.
/// The canonicalizer now refuses the raw target at MANIFEST time, so the
/// destination is never touched.
#[cfg(unix)]
#[test]
fn a_non_utf8_symlink_target_is_refused_at_manifest_time_and_mutates_nothing() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    if !filesystem_stores_a_non_utf8_symlink_target() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    let raw: &[u8] = b"a\xffb";
    std::os::unix::fs::symlink(OsStr::from_bytes(raw), src.join("l")).unwrap();

    let remote = RecordingRemote::over(transport(&dst), true);
    let err = match owned(Direction::Push, &src, &remote, &ReplaceAll, Keep) {
        Ok(report) => panic!(
            "a symlink target that is not valid UTF-8 cannot be stored \
             faithfully and must be REFUSED, not synced: {report:?}"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err.error(), Error::Materialization(_)),
        "a canonicalization refusal is a materialization error, not the \
         post-mutation verification failure a rewritten target produced: {err:?}"
    );
    assert_eq!(
        err.report().transfers,
        0,
        "a manifest-time refusal mutates nothing: {err:?}"
    );
    assert!(err.report().applied.is_empty(), "{err:?}");
    assert!(
        fs::symlink_metadata(dst.join("l")).is_err(),
        "no link may be installed from an unrepresentable target (pre-fix the \
         destination held the lossy-rewritten target before the error surfaced)"
    );
    assert_eq!(
        fs::read_dir(&dst).unwrap().count(),
        0,
        "the destination is byte-identical: still the empty directory"
    );
    // The source link still holds the caller's raw bytes.
    assert_eq!(
        fs::read_link(src.join("l")).unwrap().as_os_str().as_bytes(),
        raw
    );
}

/// HIGH (round 18, F2): the far-side walk printed the raw bytes of a name that
/// is not valid UTF-8 and the runner decoded the wire with `from_utf8_lossy`,
/// so the assembler stored a U+FFFD spelling that addresses NOTHING while
/// `canonicalize_tree` (the local walk) would refuse the same tree. With
/// `delete_extraneous=true` the push reported
/// `Ok extraneous=["bad\u{fffd}name"] transfers=1` and the REAL entry
/// survived. The remote canonicalizer now refuses the tree, so the push fails
/// closed and the entry is untouched.
#[cfg(unix)]
#[test]
fn a_non_utf8_remote_destination_name_is_refused_instead_of_silently_spared() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    if !filesystem_stores_a_non_utf8_name() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let remote_root = dir.path().join("remote");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&remote_root).unwrap();
    let raw_name = OsStr::from_bytes(b"bad\xffname");
    write(&remote_root.join(raw_name), b"extra");

    // The far-side script describes the REMOTE destination tree.
    let remote = RecordingRemote::over(transport(&remote_root), false);
    let err = match unowned(Direction::Push, &src, &remote, &ReplaceAll, Delete) {
        Ok(report) => panic!(
            "a destination name that is not valid UTF-8 must be REFUSED, not \
             reported `Ok` with a surviving entry: {report:?}"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err.error(), Error::Materialization(_) | Error::Transport(_)),
        "the refusal is a manifest-time error: {err:?}"
    );
    assert_eq!(err.report().transfers, 0, "{err:?}");
    assert!(
        !err.report()
            .extraneous
            .iter()
            .any(|path| path.contains('\u{fffd}')),
        "no entry is addressed by a lossy spelling: {err:?}"
    );
    // The real entry survives, byte-for-byte and alone.
    assert_eq!(read(&remote_root.join(raw_name)), b"extra");
    assert_eq!(fs::read_dir(&remote_root).unwrap().count(), 1);
}

/// HIGH (round 18): a manifest entry is an ADDRESS, but on a case-insensitive
/// destination a spelling can alias a DIFFERENTLY-SPELLED on-disk entry, so the
/// address does not name what the sync thinks. Source `Foo.txt` versus
/// destination `foo.txt` pre-fix returned `Ok`, `applied=["Foo.txt"]`, with the
/// on-disk name still `foo.txt` and `canonicalize_tree(dst) !=
/// canonicalize_tree(src)`: a silent non-convergence that repeats on every run.
/// The install is now followed by a BYTE-IDENTICAL parent-listing check, and the
/// entry is a `NameNotFaithful` conflict instead of a false `applied`.
#[cfg(unix)]
#[test]
fn a_case_folded_source_name_is_reported_not_silently_applied() {
    if !filesystem_is_case_insensitive() {
        announce_skip(
            "this filesystem is case-SENSITIVE, so a spelling cannot fold onto a \
             differently-spelled entry and the case-aliasing reproduction is \
             untestable here",
        );
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    write(&src.join("Foo.txt"), b"new");
    write(&dst.join("foo.txt"), b"old");

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    let src_tree = canonicalize_tree(&src).unwrap();
    let dst_tree = canonicalize_tree(&dst).unwrap();
    if report.conflicts.is_empty() {
        assert_eq!(
            dst_tree, src_tree,
            "`Ok` with no conflict must mean the destination matches the source"
        );
    } else {
        assert!(
            report.conflicts.iter().any(|c| c.path == "Foo.txt"),
            "the conflict names the source entry: {:?}",
            report.conflicts
        );
        assert!(
            !report.applied.iter().any(|path| path == "Foo.txt"),
            "a path whose on-disk name is not faithful is not applied: {:?}",
            report.applied
        );
    }
    // The destination's on-disk spelling is not silently rewritten under the
    // source's spelling: exactly one entry remains, under the name it had.
    assert_eq!(dir_names(&dst), vec![std::ffi::OsString::from("foo.txt")]);
}

/// HIGH (round 18): the same fixture with `delete_extraneous=true` lost DATA.
/// The transfer wrote through the folded name (so `foo.txt` held the source
/// content), and the extraneous pass then removed `foo.txt` — destroying the
/// entry that had just been transferred and leaving the destination EMPTY
/// (pre-fix: `Err`, `transfers=2`, zero entries). The extraneous removal is now
/// identity-aware: an on-disk spelling an installed source entry aliases is
/// reported, never removed, so nothing is lost.
#[cfg(unix)]
#[test]
fn delete_extraneous_never_destroys_a_case_aliased_transfer() {
    if !filesystem_is_case_insensitive() {
        announce_skip(
            "this filesystem is case-SENSITIVE, so a spelling cannot fold onto a \
             differently-spelled entry and the case-aliased-removal reproduction is \
             untestable here",
        );
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    write(&src.join("Foo.txt"), b"new");
    write(&dst.join("foo.txt"), b"old");

    let result = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete);
    // The sanctioned removal must not destroy the destination-only spelling that
    // is the source entry's folded alias: the destination is not left empty.
    assert_eq!(
        dir_names(&dst),
        vec![std::ffi::OsString::from("foo.txt")],
        "the aliased destination entry must survive `delete_extraneous`: {result:?}"
    );
    let report = match result {
        Ok(report) => report,
        Err(err) => err.into_parts().1,
    };
    assert!(
        report
            .conflicts
            .iter()
            .any(|conflict| conflict.path == "Foo.txt"),
        "the alias is reported, not silently removed: {report:?}"
    );
    assert!(
        !report.applied.iter().any(|path| path == "Foo.txt"),
        "{report:?}"
    );
}

/// HIGH (round 18): a case-SENSITIVE source holding BOTH `Foo.txt` and
/// `foo.txt` synced into a case-INsensitive destination used to end with ONE
/// entry, `Ok`, `applied=["Foo.txt","foo.txt"]`, `transfers=2` — one entry
/// silently gone. The unrepresentable pair is now detected BEFORE any mutation
/// (a case-sensitivity probe of the destination) and the member that cannot
/// exist is reported as a conflict; the representable member still transfers.
#[cfg(unix)]
#[test]
fn a_case_colliding_source_pair_is_reported_not_silently_lost() {
    if !filesystem_is_case_insensitive() {
        announce_skip(
            "this filesystem is case-SENSITIVE, so a case-colliding source pair IS \
             representable and the unrepresentable-pair reproduction is untestable \
             here",
        );
        return;
    }
    // The crafted manifest encodes a mode (`1a4`), so a mode-ignoring filesystem
    // would fail the run on a mode mismatch before the collision is asserted:
    // the collision assertion must not depend on mode preservation.
    if !the_filesystem_honours_modes() {
        announce_skip(
            "this filesystem does not report a chmod, so the crafted manifest's \
             mode cannot be preserved and the case-collision reproduction would \
             fail on mode before reaching its assertion",
        );
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    // The SOURCE is a case-SENSITIVE tree holding BOTH `Foo.txt` and `foo.txt`.
    // THIS host's filesystem cannot hold both (it is case-insensitive), so the
    // source is described by a crafted FAR-SIDE manifest (the `Pull` direction);
    // the DESTINATION is this host's local directory, which IS case-insensitive.
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    write(&src.join("Foo.txt"), b"same");
    // Identical content on both sides, so pre-fix the single surviving entry
    // satisfies BOTH verifications and the run returns `Ok` with both spellings
    // reported `applied` — the silent loss, not a verification failure.
    let content_hash = crate::digest::sha256_bytes(b"same");
    let manifest =
        format!("Foo.txt\tf\t1a4\t1\t{content_hash}\t\nfoo.txt\tf\t1a4\t1\t{content_hash}\t\n");
    let remote = RecordingRemote::over(transport(&src), false).with_manifest_output(manifest);

    let report = owned(Direction::Pull, &dst, &remote, &ReplaceAll, Keep).unwrap();
    assert!(
        !report.conflicts.is_empty(),
        "one member of a case-colliding pair cannot exist and must be reported: {report:?}"
    );
    assert!(
        report
            .conflicts
            .iter()
            .any(|conflict| conflict.path == "foo.txt" || conflict.path == "Foo.txt"),
        "{report:?}"
    );
    // No entry is silently lost: exactly one representable entry survives, it is
    // one of the two source spellings, and it holds that spelling's bytes.
    let names = dir_names(&dst);
    assert_eq!(
        names.len(),
        1,
        "one representable entry survives: {names:?}"
    );
    let surviving = names[0].to_string_lossy().into_owned();
    assert!(
        surviving == "Foo.txt" || surviving == "foo.txt",
        "the survivor is one of the source spellings: {surviving:?}"
    );
    let bytes = read(&dst.join(&surviving));
    assert_eq!(bytes, b"same");
}

/// The capability must not be LOST where it is legitimate: on a case-SENSITIVE
/// destination the pair is two distinct entries and both transfer normally, with
/// no conflict introduced.
#[cfg(unix)]
#[test]
fn a_case_differing_source_pair_transfers_on_a_case_sensitive_destination() {
    if filesystem_is_case_insensitive() {
        announce_skip(
            "this filesystem is CASE-INSENSITIVE, so the two spellings are one entry \
             and the case-sensitive-transfer non-regression is untestable here",
        );
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    write(&src.join("Foo.txt"), b"upper");
    write(&src.join("foo.txt"), b"lower");

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert!(
        report.conflicts.is_empty(),
        "a case-sensitive destination represents both entries: {:?}",
        report.conflicts
    );
    assert!(
        report.applied.iter().any(|path| path == "Foo.txt"),
        "{report:?}"
    );
    assert!(
        report.applied.iter().any(|path| path == "foo.txt"),
        "{report:?}"
    );
    assert_eq!(read(&dst.join("Foo.txt")), b"upper");
    assert_eq!(read(&dst.join("foo.txt")), b"lower");
    assert_eq!(
        canonicalize_tree(&dst).unwrap(),
        canonicalize_tree(&src).unwrap()
    );
}

/// The plain same-case transfer is unchanged: it still reports `applied`, still
/// passes verification, and introduces NO conflict — the name check must not
/// manufacture false conflicts.
#[test]
fn a_plain_same_case_transfer_is_still_reported_applied() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    write(&src.join("f"), b"new");
    write(&dst.join("f"), b"old");

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(report.applied.iter().any(|path| path == "f"), "{report:?}");
    assert!(
        report.verify_failures.is_empty(),
        "{:?}",
        report.verify_failures
    );
    assert_eq!(read(&dst.join("f")), b"new");
    assert_eq!(
        canonicalize_tree(&dst).unwrap(),
        canonicalize_tree(&src).unwrap()
    );
}

/// The report SURFACE of a fold: the conflict names the SOURCE entry and the
/// destination's ACTUAL on-disk spelling, so the caller can find what the
/// address really names. (This exercises the post-fix `Conflict::on_disk` field,
/// which the pre-fix code did not have.)
#[cfg(unix)]
#[test]
fn a_name_conflict_names_the_on_disk_spelling() {
    if !filesystem_is_case_insensitive() {
        announce_skip(
            "this filesystem is case-SENSITIVE, so no fold exists to name and the \
             on-disk-spelling reproduction is untestable here",
        );
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    write(&src.join("Foo.txt"), b"new");
    write(&dst.join("foo.txt"), b"old");

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep).unwrap();
    let conflict = conflict_at(&report, "Foo.txt");
    assert_eq!(conflict.reason, ConflictReason::NameNotFaithful);
    assert_eq!(
        conflict.on_disk.as_deref(),
        Some("foo.txt"),
        "the conflict names the destination's actual spelling: {conflict:?}"
    );
}

/// The NESTED form of the alias: the fold happens in a subdirectory, so the
/// protection must be keyed on the full manifest path, not a bare file name.
/// `src/d/Foo.txt` against `dst/d/foo.txt` with `delete_extraneous=true` used to
/// transfer through the fold and then remove `d/foo.txt`, leaving `d` empty.
#[cfg(unix)]
#[test]
fn delete_extraneous_never_destroys_a_nested_case_aliased_transfer() {
    if !filesystem_is_case_insensitive() {
        announce_skip(
            "this filesystem is case-SENSITIVE, so a nested spelling cannot fold onto \
             a differently-spelled entry and the nested aliased-removal reproduction \
             is untestable here",
        );
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    write(&src.join("d").join("Foo.txt"), b"new");
    write(&dst.join("d").join("foo.txt"), b"old");

    let result = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete);
    assert_eq!(
        dir_names(&dst.join("d")),
        vec![std::ffi::OsString::from("foo.txt")],
        "the nested aliased entry must survive `delete_extraneous`: {result:?}"
    );
    let report = match result {
        Ok(report) => report,
        Err(err) => err.into_parts().1,
    };
    assert!(
        report
            .conflicts
            .iter()
            .any(|conflict| conflict.path == "d/Foo.txt"),
        "the nested alias is reported: {report:?}"
    );
}

// ---------------------------------------------------------------------------
// Round 19: the fold a `to_lowercase` model MISSES.
//
// macOS APFS (and ext4 with `casefold`) folds `Straße.txt` onto `STRASSE.txt`,
// `ﬁ.txt` onto `fi.txt`, and `ς` onto `σ`, while `str::to_lowercase` keeps
// those pairs DISTINCT. The pre-transfer case-pair grouping therefore missed
// the fold, the install landed THROUGH it, `alias_in` could not name the
// target, and a destination entry the report called `Skipped`/`Extraneous` was
// silently destroyed. The structural fix is per-directory, byte-exact name
// verification of every TOUCHED directory (plus a pre-install
// `exists`-but-not-in-listing gate), never a bigger fold table.
// ---------------------------------------------------------------------------

/// F1: a fold `to_lowercase` does not model (`ß`/`ss`) must never overwrite the
/// destination entry it folds onto. The two spellings carry DIFFERING content —
/// the round-18 fixture used identical content, which is exactly why it missed
/// this — so a destroyed victim is observable as changed BYTES, not merely a
/// changed name.
#[cfg(unix)]
#[test]
fn a_unicode_case_fold_never_overwrites_a_destination_entry() {
    if !filesystem_folds("Straße.txt", "STRASSE.txt") {
        announce_skip(
            "this filesystem does not fold `Straße.txt` onto `STRASSE.txt` (it may \
             fold ASCII and still keep this Unicode pair distinct, like macOS FAT), \
             so the Unicode-fold reproduction is untestable here",
        );
        return;
    }
    // The fixture's manifest encodes a mode (`1a4`), so a mode-ignoring
    // filesystem would fail the run on a mode mismatch BEFORE the fold is ever
    // exercised: the fold assertion must not depend on mode preservation.
    if !the_filesystem_honours_modes() {
        announce_skip(
            "this filesystem does not report a chmod, so the crafted manifest's \
             mode cannot be preserved and the Unicode-fold reproduction would fail \
             on mode before reaching its fold assertion",
        );
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    write(&dst.join("STRASSE.txt"), b"BBBB");
    set_mode(&dst.join("STRASSE.txt"), 0o644);
    // A third source entry installs into the SAME directory, so the run touches
    // it and the per-directory backstop actually runs.
    let stra_e = crate::digest::sha256_bytes(b"AAAA");
    let strasse = crate::digest::sha256_bytes(b"BBBB");
    let other = crate::digest::sha256_bytes(b"CCCC");
    let manifest = format!(
        "Straße.txt\tf\t1a4\t1\t{stra_e}\t\nSTRASSE.txt\tf\t1a4\t1\t{strasse}\t\nother.txt\tf\t1a4\t1\t{other}\t\n"
    );
    // The two folded spellings share one on-disk entry on this host, so the
    // source bytes for the folded spelling are fabricated by the manifest and
    // read through the address (as a real far-side read would return them).
    // `other.txt` is genuinely installed and forces the directory to be touched.
    write(&src.join("Straße.txt"), b"AAAA");
    write(&src.join("other.txt"), b"CCCC");
    let remote = RecordingRemote::over(transport(&src), false).with_manifest_output(manifest);

    let report = owned(Direction::Pull, &dst, &remote, &ReplaceAll, Keep).unwrap();

    // The victim's CONTENT is unchanged, byte-for-byte: a `Skipped` entry
    // needed no mutation at all.
    assert_eq!(
        read(&dst.join("STRASSE.txt")),
        b"BBBB",
        "a fold must not destroy the content of the entry it lands through: {report:?}"
    );
    assert_eq!(
        dir_names(&dst),
        vec![
            std::ffi::OsString::from("STRASSE.txt"),
            std::ffi::OsString::from("other.txt"),
        ],
        "the failing spelling must not appear on disk: {report:?}"
    );
    // A conflict names the fold, with the destination's actual spelling.
    let conflict = conflict_at(&report, "Straße.txt");
    assert_eq!(
        conflict.reason,
        ConflictReason::NameNotFaithful,
        "{report:?}"
    );
    assert_eq!(
        conflict.on_disk.as_deref(),
        Some("STRASSE.txt"),
        "the conflict names BOTH spellings: {report:?}"
    );
    assert!(
        !report.applied.iter().any(|p| p == "Straße.txt"),
        "a folded install is never applied: {report:?}"
    );
    assert!(
        report.verify_failures.is_empty(),
        "the backstop must not have to fire once the gate refuses the install: {report:?}"
    );
    assert_eq!(read(&dst.join("other.txt")), b"CCCC");
}

/// F1 with `delete_extraneous=true`: the destination-only spelling the fold
/// would land through is sanctioned for REMOVAL, but it must not be destroyed
/// by the fold (its bytes are the only content that exists) and the report must
/// not claim the run left it alone while replacing its content.
#[cfg(unix)]
#[test]
fn delete_extraneous_never_destroys_a_unicode_case_aliased_transfer() {
    if !filesystem_folds("Straße.txt", "STRASSE.txt") {
        announce_skip(
            "this filesystem does not fold `Straße.txt` onto `STRASSE.txt` (it may \
             fold ASCII and still keep this Unicode pair distinct, like macOS FAT), \
             so the Unicode-fold reproduction is untestable here",
        );
        return;
    }
    // The crafted manifest encodes a mode (`1a4`), so a mode-ignoring filesystem
    // would fail the run on a mode mismatch before the fold is exercised.
    if !the_filesystem_honours_modes() {
        announce_skip(
            "this filesystem does not report a chmod, so the crafted manifest's \
             mode cannot be preserved and the Unicode-fold reproduction would fail \
             on mode before reaching its fold assertion",
        );
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    write(&dst.join("STRASSE.txt"), b"BBBB");
    set_mode(&dst.join("STRASSE.txt"), 0o644);
    let stra_e = crate::digest::sha256_bytes(b"AAAA");
    let manifest = format!("Straße.txt\tf\t1a4\t1\t{stra_e}\t\n");
    write(&src.join("Straße.txt"), b"AAAA");
    let remote = RecordingRemote::over(transport(&src), false).with_manifest_output(manifest);

    let result = owned(Direction::Pull, &dst, &remote, &ReplaceAll, Delete);
    let report = match result {
        Ok(report) => report,
        Err(err) => err.into_parts().1,
    };
    assert_eq!(
        read(&dst.join("STRASSE.txt")),
        b"BBBB",
        "the fold must not replace the destination-only entry's content: {report:?}"
    );
    assert_eq!(
        dir_names(&dst),
        vec![std::ffi::OsString::from("STRASSE.txt")],
        "the on-disk spelling survives under its own name: {report:?}"
    );
    assert!(
        report
            .conflicts
            .iter()
            .any(|conflict| conflict.path == "Straße.txt"),
        "the fold is reported, not silently absorbed: {report:?}"
    );
    assert!(
        !report.applied.iter().any(|p| p == "Straße.txt"),
        "{report:?}"
    );
}

/// F1 in a SUBDIRECTORY: the fold and the touched-directory check must be keyed
/// on the full manifest path, not a bare file name. `d/other.txt` forces a real
/// install into `d`, so the per-directory listing and untouched-content checks
/// run against `d`.
#[cfg(unix)]
#[test]
fn a_nested_unicode_case_fold_never_overwrites_a_destination_entry() {
    if !filesystem_folds("Straße.txt", "STRASSE.txt") {
        announce_skip(
            "this filesystem does not fold `Straße.txt` onto `STRASSE.txt` (it may \
             fold ASCII and still keep this Unicode pair distinct, like macOS FAT), \
             so the nested Unicode-fold reproduction is untestable here",
        );
        return;
    }
    if !the_filesystem_honours_modes() {
        announce_skip(
            "this filesystem does not report a chmod, so the directory mode in the \
             nested fixture is unrepresentable",
        );
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(dst.join("d")).unwrap();
    set_mode(&dst.join("d"), 0o755);
    write(&dst.join("d").join("STRASSE.txt"), b"BBBB");
    set_mode(&dst.join("d").join("STRASSE.txt"), 0o644);
    let stra_e = crate::digest::sha256_bytes(b"AAAA");
    let strasse = crate::digest::sha256_bytes(b"BBBB");
    let other = crate::digest::sha256_bytes(b"CCCC");
    let manifest = format!(
        "d\td\t1ed\t1\t\t\nd/Straße.txt\tf\t1a4\t1\t{stra_e}\t\nd/STRASSE.txt\tf\t1a4\t1\t{strasse}\t\nd/other.txt\tf\t1a4\t1\t{other}\t\n"
    );
    write(&src.join("d").join("Straße.txt"), b"AAAA");
    write(&src.join("d").join("other.txt"), b"CCCC");
    let remote = RecordingRemote::over(transport(&src), false).with_manifest_output(manifest);

    let report = owned(Direction::Pull, &dst, &remote, &ReplaceAll, Keep).unwrap();
    assert_eq!(
        read(&dst.join("d").join("STRASSE.txt")),
        b"BBBB",
        "the nested victim's content is unchanged: {report:?}"
    );
    assert_eq!(read(&dst.join("d").join("other.txt")), b"CCCC");
    let conflict = conflict_at(&report, "d/Straße.txt");
    assert_eq!(
        conflict.reason,
        ConflictReason::NameNotFaithful,
        "{report:?}"
    );
    assert_eq!(
        conflict.on_disk.as_deref(),
        Some("STRASSE.txt"),
        "the nested conflict names BOTH spellings: {report:?}"
    );
    assert!(
        !report.applied.iter().any(|p| p == "d/Straße.txt"),
        "{report:?}"
    );
}

/// ADDENDUM A: a fold in a PARENT COMPONENT. `ς` folds onto `σ` on APFS while
/// `str::to_lowercase` keeps them distinct, so the parent-directory install was
/// never refused and the run CREATED `σ/child` — a path NO report list named
/// (only the source spelling `ς/child` was named). The per-directory gate on
/// the parent now refuses `ς` before anything is created, and the prohibition
/// derived from that conflict blocks the child.
#[cfg(unix)]
#[test]
fn a_folded_parent_component_never_mutates_an_unreported_path() {
    if !filesystem_folds("ς", "σ") {
        announce_skip(
            "this filesystem does not fold `ς` onto `σ` (it may fold ASCII and \
             still keep this Unicode pair distinct, like macOS FAT), so the \
             parent-component-fold reproduction is untestable here",
        );
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(dst.join("σ")).unwrap();
    write(&dst.join("σ").join("keep"), b"old");
    let child = crate::digest::sha256_bytes(b"new");
    let manifest = format!("ς\td\t1ed\t1\t\t\nς/child\tf\t1a4\t1\t{child}\t\n");
    let remote = RecordingRemote::over(transport(&src), false).with_manifest_output(manifest);

    let result = owned(Direction::Pull, &dst, &remote, &ReplaceAll, Keep);
    let report = match result {
        Ok(report) => report,
        Err(err) => err.into_parts().1,
    };
    // The destination directory and its child are byte-identical: the fold was
    // refused before any mutation.
    assert_eq!(
        read(&dst.join("σ").join("keep")),
        b"old",
        "the existing destination entry is untouched: {report:?}"
    );
    assert_eq!(
        dir_names(&dst.join("σ")),
        vec![std::ffi::OsString::from("keep")],
        "no entry was created under the folded parent: {report:?}"
    );
    assert_eq!(report.transfers, 0, "nothing was mutated: {report:?}");
    // The report NAMES the fold on the parent component.
    let parent = conflict_at(&report, "ς");
    assert_eq!(parent.reason, ConflictReason::NameNotFaithful, "{report:?}");
    assert_eq!(
        parent.on_disk.as_deref(),
        Some("σ"),
        "the parent conflict names BOTH spellings: {report:?}"
    );
    assert!(
        conflict_at(&report, "ς/child").reason == ConflictReason::ParentRefused,
        "the child is blocked by the refused ancestor: {report:?}"
    );
}

/// ADDENDUM B: an ABSENT destination root must not disable the up-front
/// case-pair refusal. The old code returned before probing when the root was
/// missing, so a pull that creates the root moments later installed one member
/// and reported the other as a post-transfer `verify_failure` (`Err`). The
/// refusal now fires without creating the root when the destination cannot be
/// told apart; the kept member still transfers and the other is a clean
/// conflict.
///
/// (The name states the OBSERVABLE property — the kept member transfers and the
/// other is a clean CONFLICT rather than a post-transfer verification failure —
/// not a "before any transfer" ordering the report cannot express, since the
/// kept member is itself transferred by design. The all-refused fixture
/// [`a_fully_refused_case_pair_leaves_the_destination_root_absent`] pins the
/// up-front refusal's policy-independence.)
#[cfg(unix)]
#[test]
fn a_case_colliding_pair_is_a_clean_conflict_not_a_verification_failure() {
    if !filesystem_is_case_insensitive() {
        announce_skip(
            "this filesystem is case-SENSITIVE, so a case-colliding pair IS \
             representable and this refusal reproduction is untestable here",
        );
        return;
    }
    // The crafted manifest encodes a mode (`1a4`), so a mode-ignoring filesystem
    // would report a mode verification failure instead of the clean up-front
    // conflict this reproduction pins.
    if !the_filesystem_honours_modes() {
        announce_skip(
            "this filesystem does not report a chmod, so the crafted manifest's \
             mode cannot be preserved and the case-collision reproduction would \
             fail on mode before reaching its assertion",
        );
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    assert!(!dst.exists());
    let a = crate::digest::sha256_bytes(b"A");
    let b = crate::digest::sha256_bytes(b"B");
    let manifest = format!("Foo\tf\t1a4\t1\t{a}\t\nfoo\tf\t1a4\t1\t{b}\t\n");
    write(&src.join("Foo"), b"A");
    let remote = RecordingRemote::over(transport(&src), false).with_manifest_output(manifest);

    let report = owned(Direction::Pull, &dst, &remote, &ReplaceAll, Keep).unwrap();
    // A clean up-front conflict, not a post-transfer verification failure.
    assert!(
        report.verify_failures.is_empty(),
        "the pair is refused BEFORE any transfer: {report:?}"
    );
    let refused = conflict_at(&report, "foo");
    assert_eq!(
        refused.reason,
        ConflictReason::NameNotFaithful,
        "{report:?}"
    );
    assert_eq!(
        refused.on_disk.as_deref(),
        Some("Foo"),
        "the refused member names the kept spelling: {report:?}"
    );
    assert!(report.applied.iter().any(|p| p == "Foo"), "{report:?}");
    assert_eq!(
        dir_names(&dst),
        vec![std::ffi::OsString::from("Foo")],
        "exactly the kept member exists: {report:?}"
    );
    assert_eq!(read(&dst.join("Foo")), b"A");
}

/// The complement of ADDENDUM B: the conservative refusal must NOT create the
/// destination root when every entry is refused. This is the existing
/// "a fully-refused pull creates nothing" property, exercised through a
/// case-colliding pair (the case that used to need a probe).
#[test]
fn a_fully_refused_case_pair_leaves_the_destination_root_absent() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    assert!(!dst.exists());
    let a = crate::digest::sha256_bytes(b"A");
    let b = crate::digest::sha256_bytes(b"B");
    let manifest = format!("Foo\tf\t1a4\t1\t{a}\t\nfoo\tf\t1a4\t1\t{b}\t\n");
    let remote = RecordingRemote::over(transport(&src), false).with_manifest_output(manifest);
    let refuse = |_: &str, _: EntryKind| EntryPolicy::Refuse;

    let report = owned(Direction::Pull, &dst, &remote, &refuse, Keep).unwrap();
    assert_eq!(report.transfers, 0, "{report:?}");
    assert!(report.applied.is_empty(), "{report:?}");
    assert!(
        !dst.exists(),
        "a fully-refused pull creates NOTHING, not even the root: {report:?}"
    );
    // The up-front case-pair refusal runs INDEPENDENTLY of the per-entry
    // policy: even with EVERY entry refused, the member the destination cannot
    // represent is a `NameNotFaithful` conflict naming the kept spelling, not
    // merely a policy `Refused`. This is what makes
    // `refuse_unrepresentable_case_aliases` load-bearing: with it disabled the
    // `foo` conflict degrades to `Refused` (its fold is never even considered,
    // because nothing is installed for the gate to catch).
    let refused = conflict_at(&report, "foo");
    assert_eq!(
        refused.reason,
        ConflictReason::NameNotFaithful,
        "the unrepresentable member is a name conflict, not only a policy refusal: {report:?}"
    );
    assert_eq!(
        refused.on_disk.as_deref(),
        Some("Foo"),
        "the refusal names the kept spelling: {report:?}"
    );
}

// ---------------------------------------------------------------------------
// Round 20: a source manifest the assembler should have refused (not
// PARENT-CLOSED), and the post-transfer checks that must hold even if one
// reaches the applier.
//
// A crafted far-side manifest `d/x` with no `d` entry made the run install the
// path through an implicitly created parent (named by no report list) or, on an
// aliasing destination, through a folded parent spelling: the report named a
// spelling the destination did not hold and ONE on-disk entry appeared under
// TWO spellings. The applier now REFUSES such a manifest before any mutation,
// and independently verifies EVERY ancestor component against its own parent's
// live listing after a transfer.
// ---------------------------------------------------------------------------

/// JOB 1/3: a NON-PARENT-CLOSED source manifest is refused BEFORE any mutation.
/// `d/x` with no `d` entry would otherwise implicitly create `d` (a path named
/// by no report list on Linux, or a fold onto an existing `D` on macOS) and
/// report `applied=["d/x"]` for a spelling the destination does not hold.
#[test]
fn a_non_parent_closed_source_manifest_is_refused_before_any_mutation() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    // The source bytes exist at `d/x`, so pre-fix the install SUCCEEDS and
    // implicitly creates `d`; the missing manifest entry for `d` is the defect,
    // not a missing source file.
    write(&src.join("d/x"), b"new");
    let hash = crate::digest::sha256_bytes(b"new");
    // The parent `d` is deliberately absent: not a directory entry, not any
    // entry.
    let manifest = format!("d/x\tf\t1a4\t1\t{hash}\t\n");
    let remote = RecordingRemote::over(transport(&src), false).with_manifest_output(manifest);

    let result = owned(Direction::Pull, &dst, &remote, &ReplaceAll, Keep);
    let err = match result {
        Ok(report) => panic!(
            "a non-parent-closed manifest must be refused, not reported as an \
             applied path: {report:?}"
        ),
        Err(err) => err,
    };
    assert_eq!(
        err.report().transfers,
        0,
        "the refusal happens BEFORE any mutation: {err:?}"
    );
    assert!(
        err.report().applied.is_empty(),
        "no path is reported applied: {err:?}"
    );
    assert!(
        dir_names(&dst).is_empty(),
        "the implicitly created parent must not exist: {:?}",
        dir_names(&dst)
    );
    // ONE layer refuses, and it must name the property: the manifest
    // assembler refuses a wire manifest that is not parent-closed (it sees the
    // raw wire). The applier deliberately does NOT repeat the gate — every
    // manifest it can be handed has already passed the assembler — so this
    // reproduction pins the ASSEMBLER's guarantee, not an applier-side check.
    let message = format!("{}", err.error()).to_lowercase();
    assert!(
        message.contains("parent-closed"),
        "the refusal names the property it enforces: {err:?}"
    );
}

/// JOB 1: the round-20 reproduction. On a case-insensitive destination holding
/// `D/x`, the crafted single-line manifest `d/x` used to yield
/// `Ok { applied: ["d/x"], extraneous: ["D","D/x"] }` with
/// `canonicalize_tree(dst) == {D, D/x}`: `applied` named a spelling the
/// destination does not hold and ONE on-disk entry appeared under TWO
/// spellings. It is now refused before any mutation, so the destination is
/// byte-identical and no spelling is fabricated.
#[cfg(unix)]
#[test]
fn a_non_parent_closed_manifest_cannot_invent_a_parent_spelling() {
    if !filesystem_is_case_insensitive() {
        announce_skip(
            "this filesystem is case-SENSITIVE, so `d` cannot fold onto `D` and \
             the parent-spelling reproduction is untestable here",
        );
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/x"), b"new");
    write(&dst.join("D/x"), b"old");
    let hash = crate::digest::sha256_bytes(b"new");
    let manifest = format!("d/x\tf\t1a4\t1\t{hash}\t\n");
    let remote = RecordingRemote::over(transport(&src), false).with_manifest_output(manifest);

    let result = owned(Direction::Pull, &dst, &remote, &ReplaceAll, Keep);
    let err = match result {
        Ok(report) => panic!(
            "the crafted manifest names `d/x` while the destination holds `D/x`; \
             it must be refused rather than report a spelling the destination \
             does not hold: {report:?}"
        ),
        Err(err) => err,
    };
    assert_eq!(err.report().transfers, 0, "{err:?}");
    assert_eq!(
        dir_names(&dst),
        vec![std::ffi::OsString::from("D")],
        "the destination holds exactly its own spelling: {err:?}"
    );
    assert_eq!(
        read(&dst.join("D/x")),
        b"old",
        "the destination entry is untouched: {err:?}"
    );
}

/// JOB 2: the post-transfer verification checks EVERY ancestor COMPONENT, not
/// only the final one. A mirrored writer renames the parent `d` to `D` AFTER
/// `d/x` is installed — a change the pre-install gate cannot see, because the
/// The ancestor walk in [`Applier::verify_names`] is the ONLY check that reads a
/// listing for a directory the per-directory backstop never visits: the run
/// transfers into `a/b`, so `a/b` is touched, but its PARENT `a` is not (nothing
/// is installed directly into `a`). A mirrored writer renames the intermediate
/// ancestor `a/b` -> `a/B` AFTER `a/b/x` is installed, so the child's parent
/// component no longer names the entry the manifest holds. The backstop lists
/// `a/b` (now gone, so it reports the missing CHILD `a/b/x`) and the root (which
/// still holds `a`), but it never lists `a`; only the ancestor walk notices that
/// `a/b` itself is not present under `a`. Pre-fix, `applied=["a/b/x"]` was
/// reported (the final-component check read the listing THROUGH the renamed
/// parent and saw `x`). The ancestor check now refuses to report the child as
/// applied and names the parent's actual spelling.
///
/// The reproduction is a PLAIN rename, not a filesystem fold, so it runs and
/// pins the ancestor walk on a CASE-SENSITIVE filesystem (Linux/ext4) as well as
/// on macOS — unlike the pre-install fold-gate tests, which need the destination
/// itself to alias two spellings.
#[cfg(unix)]
#[test]
fn a_folded_ancestor_after_an_install_is_not_reported_applied() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    // `a` and `a/b` are IDENTICAL on both sides, so neither is transferred:
    // only `a/b/x` is, and `a/b` is the only directory this run installs into.
    // `a` is therefore NOT added to `touched_dirs`, and the per-directory
    // backstop never lists it.
    write(&src.join("a/b/x"), b"new");
    write(&dst.join("a/b/x"), b"old");
    set_mode(&src.join("a"), 0o755);
    set_mode(&dst.join("a"), 0o755);
    set_mode(&src.join("a/b"), 0o755);
    set_mode(&dst.join("a/b"), 0o755);

    let mut remote = RecordingRemote::over(transport(&dst), false);
    remote.after_write = Some((1, AfterWrite::Rename("a/b".to_string(), "a/B".to_string())));

    let result = unowned(Direction::Push, &src, &remote, &ReplaceAll, Keep);
    // The refusal may surface as a conflict on an `Ok` run or as an error; the
    // report is the same either way, and the child is never `applied`.
    let report = match result {
        Ok(report) => report,
        Err(err) => err.into_parts().1,
    };
    assert!(
        !report.applied.iter().any(|p| p == "a/b/x"),
        "a path whose PARENT component is not faithful is never applied: {report:?}"
    );
    let parent = conflict_at(&report, "a/b");
    assert_eq!(parent.reason, ConflictReason::NameNotFaithful, "{report:?}");
    assert_eq!(
        parent.on_disk.as_deref(),
        Some("B"),
        "the conflict names the parent's actual on-disk spelling: {report:?}"
    );
    assert_eq!(
        dir_names(&dst.join("a")),
        vec![std::ffi::OsString::from("B")],
        "the destination holds the renamed parent under its own spelling: {report:?}"
    );
    assert_eq!(read(&dst.join("a/B/x")), b"new");
}

/// DEAD-CHECK `verify_directory_listings`, made load-bearing: a mirrored writer
/// creates an entry NO manifest spelling addresses after an install lands. The
/// per-directory backstop is the ONLY check that looks at names it did not
/// intend, and an unplanned on-disk name is now a hard ERROR (it has no
/// conflict for the caller to act on and would otherwise live only in
/// `verify_failures` on an `Ok` run).
#[test]
fn an_unplanned_destination_entry_is_an_error_not_a_silent_ok() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    // The destination exists (an empty tree), so the far-side manifest walk has
    // a directory to describe; the unplanned entry appears only AFTER the
    // install.
    fs::create_dir_all(&dst).unwrap();
    write(&src.join("d/x"), b"new");
    let mut remote = RecordingRemote::over(transport(&dst), false);
    remote.after_write = Some((1, AfterWrite::CreateFile("d/y".to_string())));

    let result = unowned(Direction::Push, &src, &remote, &ReplaceAll, Keep);
    let err = match result {
        Ok(report) => panic!("an unplanned on-disk entry must not be an `Ok` run: {report:?}"),
        Err(err) => err,
    };
    assert!(
        err.report().verify_failures.iter().any(|p| p == "d/y"),
        "the unplanned entry is named: {err:?}"
    );
    assert_eq!(read(&dst.join("d/y")), b"", "{err:?}");
}

/// The unplanned-entry error NAMES the destination ROOT rather than
/// interpolating its EMPTY manifest spelling. Before the fix the root's label
/// was the empty string, so the message rendered as `the directory  holds ...`
/// (a doubled space and an unnamed directory) for every unplanned name in the
/// destination root — the one directory every run examines.
#[test]
fn an_unplanned_root_entry_names_the_destination_root() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"new");
    fs::create_dir_all(&dst).unwrap();
    let mut remote = RecordingRemote::over(transport(&dst), false);
    remote.after_write = Some((1, AfterWrite::CreateFile("zzz".to_string())));

    let err = match unowned(Direction::Push, &src, &remote, &ReplaceAll, Keep) {
        Ok(report) => panic!("an unplanned root entry must not be an `Ok` run: {report:?}"),
        Err(err) => err,
    };
    // The FIRST failure must be the unplanned-entry one, and the unplanned path
    // is the ROOT's child.
    let message = err.error().to_string();
    assert!(
        message.contains("the destination root holds the unplanned entry zzz"),
        "the destination root must be NAMED, never interpolated as an empty \
         directory name: {message}"
    );
    assert!(
        !message.contains("the directory  holds"),
        "the root label must not render as an unnamed directory: {message}"
    );
}

/// DEAD-CHECK `verify_claimed_untouched`, made load-bearing: a mirrored writer
/// changes the CONTENT of a destination entry the report would call `Skipped`
/// (a no-mutation claim). Only the claimed-untouched check reads those entries,
/// so without it the run reports a changed file as left alone.
#[test]
fn a_claimed_untouched_entry_changed_by_a_writer_is_not_reported_skipped() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/x"), b"new");
    write(&src.join("d/skip"), b"same");
    write(&dst.join("d/skip"), b"same");
    let mut remote = RecordingRemote::over(transport(&dst), false);
    remote.after_write = Some((
        1,
        AfterWrite::Overwrite("d/skip".to_string(), b"CHANGED".to_vec()),
    ));

    let report = unowned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap();
    assert!(
        !report.skipped.iter().any(|p| p == "d/skip"),
        "an entry whose content changed under the run is not a no-mutation \
         claim: {report:?}"
    );
    assert!(
        report.verify_failures.iter().any(|p| p == "d/skip"),
        "the changed entry is named as a verification failure: {report:?}"
    );
}

/// D1(b): a FAILED verification READ is an INFRASTRUCTURE error, never a
/// content-mismatch claim. An entry the run left alone has its bytes re-read to
/// confirm the no-mutation claim; when that read FAILS (here injected for one
/// path), the run must surface the read failure. The pre-fix
/// `.unwrap_or(false)` folded the error into "the entry changed": the run
/// returned `Ok` with the path in `verify_failures` and DROPPED from `skipped`,
/// claiming a content mismatch it never observed.
#[test]
fn a_failed_verification_read_is_an_infrastructure_error_not_a_content_mismatch() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/x"), b"new");
    write(&src.join("d/skip"), b"same");
    write(&dst.join("d/skip"), b"same");
    let mut remote = RecordingRemote::over(transport(&dst), false);
    // Fail ONLY the claimed-untouched re-read of `d/skip`; the transferred
    // `d/x` verification read still succeeds, so the failure lands exactly on
    // `verify_claimed_untouched`.
    remote.fail_read_for = Some("d/skip".to_string());

    let result = unowned(Direction::Push, &src, &remote, &ReplaceAll, Keep);
    let err = match result {
        Ok(report) => panic!(
            "a failed verification read must not return Ok with a content-mismatch claim: {report:?}"
        ),
        Err(err) => err,
    };
    let message = err.error().to_string();
    assert!(
        message.contains("could not READ d/skip"),
        "the error must name the path whose read failed: {message}"
    );
    assert!(
        message.contains("injected read failure"),
        "the error must preserve the read failure's cause: {message}"
    );
    assert!(
        !message.contains("destination hashes"),
        "a read failure must NOT be reported as a content mismatch: {message}"
    );
    // The untouched entry is not advertised as `skipped` on the failure path's
    // report either: its no-mutation claim was never confirmed.
    assert!(
        !err.report().skipped.iter().any(|p| p == "d/skip"),
        "an unconfirmed untouched claim is not `skipped`: {:?}",
        err.report()
    );
}

// ---------------------------------------------------------------------------
// Round 21: content verification for mode-only transfers, KIND verification for
// every report-named path, and the faithful destination listing.
// ---------------------------------------------------------------------------

/// F3 (round 21): a MODE-ONLY `Replace` mutates the destination (the chmod) but
/// used to push no `VerifyItem`, so its CONTENT was never re-read. A writer that
/// changed the bytes in the window between the chmod and verification was
/// reported `applied` — a path whose destination content was wrong. Every
/// `Transferred` file is now content-verified, the mode-only path included.
#[cfg(unix)]
#[test]
fn a_mode_only_transfer_is_content_verified() {
    if !the_filesystem_honours_modes() {
        announce_skip(
            "this filesystem does not report a chmod, so a mode-only change is \
             not representable and this reproduction is untestable here",
        );
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"same");
    set_mode(&src.join("f"), 0o600);
    write(&dst.join("f"), b"same");
    set_mode(&dst.join("f"), 0o644);
    // A genuinely Missing second entry supplies the write the seam hangs on:
    // `f` is mode-only, so the FIRST write is `g`'s, and the writer then changes
    // `f`'s content.
    write(&src.join("g"), b"new");

    let mut remote = RecordingRemote::over(transport(&dst), false);
    remote.after_write = Some((
        1,
        AfterWrite::Overwrite("f".to_string(), b"MUTATED".to_vec()),
    ));

    let result = unowned(Direction::Push, &src, &remote, &ReplaceAll, Keep);
    // A failed post-transfer check makes the RUN an error; the report is still
    // the honest account of what landed.
    let report = match result {
        Ok(report) => report,
        Err(err) => err.into_parts().1,
    };
    assert!(
        !report.applied.iter().any(|p| p == "f"),
        "a mode-only transfer whose content changed under the run is never \
         `applied`: {report:?}"
    );
    assert!(
        report.verify_failures.iter().any(|p| p == "f"),
        "the changed content is named as a verification failure: {report:?}"
    );
    assert!(
        report.applied.iter().any(|p| p == "g"),
        "the unrelated transfer is still applied: {report:?}"
    );
    assert_eq!(read(&dst.join("f")), b"MUTATED");
}

/// F3 (round 21), `AppendTail`: the append rule wrote no bytes (the destination
/// already held the same stream) but applied a differing mode. That mode-only
/// `Transferred` outcome pushed no `VerifyItem` either, so its content was never
/// re-read. It is now verified against the bytes the append rule observed.
#[cfg(unix)]
#[test]
fn an_append_mode_only_transfer_is_content_verified() {
    if !the_filesystem_honours_modes() {
        announce_skip(
            "this filesystem does not report a chmod, so a mode-only change is \
             not representable and this reproduction is untestable here",
        );
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"same");
    set_mode(&src.join("f"), 0o600);
    write(&dst.join("f"), b"same");
    set_mode(&dst.join("f"), 0o644);
    write(&src.join("g"), b"new");

    let mut remote = RecordingRemote::over(transport(&dst), false);
    remote.after_write = Some((
        1,
        AfterWrite::Overwrite("f".to_string(), b"MUTATED".to_vec()),
    ));

    let result = unowned(Direction::Push, &src, &remote, &append_files, Keep);
    let report = match result {
        Ok(report) => report,
        Err(err) => err.into_parts().1,
    };
    assert!(
        !report.applied.iter().any(|p| p == "f"),
        "an append mode-only transfer whose content changed under the run is \
         never `applied`: {report:?}"
    );
    assert!(
        report.verify_failures.iter().any(|p| p == "f"),
        "the changed content is named as a verification failure: {report:?}"
    );
    assert_eq!(read(&dst.join("f")), b"MUTATED");
}

/// F4 (round 21): no check verified a directory's KIND. `verify_claimed_untouched`
/// returned `intact = true` for `EntryKind::Dir`, and the name checks compare
/// names only, so a `Same` directory a writer replaced with a regular file (the
/// name stays present) was reported `skipped`. Every path the report names now
/// has its KIND verified.
#[cfg(unix)]
#[test]
fn a_same_directory_replaced_by_a_file_is_not_reported_skipped() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(src.join("d")).unwrap();
    fs::create_dir_all(dst.join("d")).unwrap();
    set_mode(&src.join("d"), 0o755);
    set_mode(&dst.join("d"), 0o755);
    // `g` is Missing and supplies the write the seam hangs on; `d` is `Same`.
    write(&src.join("g"), b"new");

    let mut remote = RecordingRemote::over(transport(&dst), false);
    remote.after_write = Some((1, AfterWrite::ReplaceDirWithFile("d".to_string())));

    let report = unowned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap();
    assert!(
        !report.skipped.iter().any(|p| p == "d"),
        "a directory replaced by a file is not a no-mutation claim: {report:?}"
    );
    assert!(
        report.verify_failures.iter().any(|p| p == "d"),
        "the KIND change is named as a verification failure: {report:?}"
    );
    assert!(
        fs::symlink_metadata(dst.join("d")).unwrap().is_file(),
        "the reproduction really swapped the kind: {report:?}"
    );
}

/// F1 (round 21): the destination LISTING view was lossy on the `Remote` path,
/// so a raw-`0xFF` name and an intended `U+FFFD` name both rendered as
/// `U+FFFD`; the run then reported `Ok` over a destination it could not address.
/// With a faithful-or-error listing, the raw name is a name NO manifest spelling
/// holds. The transport now refuses to hand out the lossy listing, and the
/// applier must then fail CLOSED: a directory it cannot enumerate faithfully is
/// one against which it cannot verify its own result, so the run is an `Err`
/// carrying the unrepresentable on-disk name — not an `Ok` that converts the
/// listing failure into a per-path `NameNotFaithful` conflict.
///
/// LINUX-ONLY: macOS refuses a non-UTF-8 name, so the reproduction skips there.
#[cfg(unix)]
#[test]
fn an_unplanned_raw_non_utf8_destination_name_is_an_error_not_a_silent_ok() {
    if !filesystem_stores_a_non_utf8_name() {
        // The probe already announced the skip.
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    // The manifest holds the intended `U+FFFD` spelling; transferring it makes
    // the root a touched directory. The writer then adds the raw single-byte
    // `0xFF` name, whose lossy rendering is EXACTLY `U+FFFD` — the collision.
    write(&src.join("\u{FFFD}"), b"planned");
    let mut remote = RecordingRemote::over(transport(&dst), false);
    remote.after_write = Some((1, AfterWrite::RawName(b"\xff".to_vec())));

    let result = unowned(Direction::Push, &src, &remote, &ReplaceAll, Keep);
    let err = match result {
        Ok(report) => panic!(
            "an unplanned raw non-UTF-8 destination name must not be an `Ok` run: \
             {report:?}"
        ),
        Err(err) => err,
    };
    assert!(
        !err.report().verify_failures.is_empty(),
        "the unaddressable entry is named, not absorbed into the planned \
         spelling: {err:?}"
    );
    // The run-level failure carries the underlying cause: the directory could
    // not be enumerated because its listing holds a name that is not valid
    // UTF-8.
    let message = format!("{}", err.error()).to_lowercase();
    assert!(
        message.contains("enumerated"),
        "the failure names the directory that could not be enumerated: {err:?}"
    );
    assert!(
        message.contains("not valid utf-8"),
        "the failure carries the underlying cause (an unrepresentable on-disk \
         name): {err:?}"
    );
}

/// F1 (round 21), DESTRUCTION variant: with `delete_extraneous=true` the run
/// must still fail closed on a destination directory it cannot enumerate, and
/// it must not remove ANY entry from that directory. The root holds the
/// unaddressable raw `0xFF` entry AND an ordinary destination-only entry
/// (`doomed`) the sanctioned removal would otherwise delete; both survive, and
/// the run is an `Err`.
///
/// LINUX-ONLY: macOS refuses a non-UTF-8 name, so the reproduction skips there.
#[cfg(unix)]
#[test]
fn a_non_utf8_destination_directory_is_never_removed_from_and_fails_closed() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    if !filesystem_stores_a_non_utf8_name() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    write(&src.join("\u{FFFD}"), b"planned");
    // A destination-only entry the sanctioned removal would delete if the root
    // could be enumerated. It sits in the SAME directory as the raw name, so
    // every entry of that directory is off-limits to destruction.
    write(&dst.join("doomed"), b"keep");
    let mut remote = RecordingRemote::over(transport(&dst), false);
    remote.after_write = Some((1, AfterWrite::RawName(b"\xff".to_vec())));

    let result = unowned(Direction::Push, &src, &remote, &ReplaceAll, Delete);
    match result {
        Ok(report) => panic!(
            "a destination the run cannot enumerate must fail closed even when \
             `delete_extraneous` is set: {report:?}"
        ),
        Err(err) => {
            assert!(
                err.report().verify_failures.iter().any(|p| p == "\u{FFFD}"),
                "the transferred entry the run could not verify is named: {err:?}"
            );
        }
    }
    // The destruction invariant: the unaddressable entry, the entry the
    // sanctioned removal would have deleted, and the transferred entry are all
    // still present, because NO entry in an unenumerable directory is removed.
    assert_eq!(read(&dst.join(OsStr::from_bytes(b"\xff"))), b"");
    assert_eq!(read(&dst.join("doomed")), b"keep");
    assert_eq!(read(&dst.join("\u{FFFD}")), b"planned");
    let mut expected = vec![
        std::ffi::OsString::from("doomed"),
        std::ffi::OsString::from("\u{FFFD}"),
        OsStr::from_bytes(b"\xff").to_os_string(),
    ];
    expected.sort();
    assert_eq!(
        dir_names(&dst),
        expected,
        "no entry was removed from the unenumerable directory"
    );
}

/// F1 (round 21), DESTRUCTION variant that reaches the REMOVAL pass: the raw
/// `0xFF` name lives inside a destination-only subtree (`d`) the sanctioned
/// `delete_extraneous` pass would recursively remove. `d` is not a directory the
/// run installed into, so the verification pass never lists it; ONLY
/// `remove_extraneous` meets the unenumerable listing. It must fail closed
/// BEFORE any removal, so the whole subtree — the raw name and the ordinary
/// `d/keep` — survives, and the run is an `Err`. Disabling the removal pass's
/// listing failure makes the run recurse into `d` and destroy both (and report
/// `Ok`), so this test pins that path.
///
/// LINUX-ONLY: macOS refuses a non-UTF-8 name, so the reproduction skips here.
#[cfg(unix)]
#[test]
fn delete_extraneous_never_removes_from_a_directory_it_cannot_enumerate() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    if !filesystem_stores_a_non_utf8_name() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    // A root-level write hangs the seam on; the raw name is added under the
    // destination-only subtree afterwards, so the removal pass is what meets it.
    write(&src.join("x"), b"new");
    write(&dst.join("d/keep"), b"keep");
    let mut remote = RecordingRemote::over(transport(&dst), false);
    remote.after_write = Some((
        1,
        AfterWrite::RawNameUnder("d".to_string(), b"\xff".to_vec()),
    ));

    let result = unowned(Direction::Push, &src, &remote, &ReplaceAll, Delete);
    if let Ok(report) = result {
        panic!(
            "a directory the removal pass cannot enumerate must fail closed, not \
             report `Ok` after recursing into it: {report:?}"
        );
    }
    // The destruction invariant: NOTHING under the unenumerable `d` was
    // removed, the raw name included.
    assert_eq!(read(&dst.join("d/keep")), b"keep");
    assert_eq!(read(&dst.join("d").join(OsStr::from_bytes(b"\xff"))), b"");
    assert!(dst.join("d").is_dir(), "the subtree survives whole");
}

/// F4 (round 21), APPLIED entry: a directory this run CREATED is replaced by a
/// regular file by the writer. The name stays present, so only the KIND check on
/// the `Transferred` entry's `VerifyItem` catches it; without that check the run
/// reports the directory `applied`.
#[cfg(unix)]
#[test]
fn a_transferred_directory_replaced_by_a_file_is_not_reported_applied() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    fs::create_dir_all(src.join("d")).unwrap();
    fs::create_dir_all(&dst).unwrap();
    // `g` supplies the write the seam hangs on; `d` is CREATED by the transfer.
    write(&src.join("g"), b"new");

    let mut remote = RecordingRemote::over(transport(&dst), false);
    remote.after_write = Some((1, AfterWrite::ReplaceDirWithFile("d".to_string())));

    let result = unowned(Direction::Push, &src, &remote, &ReplaceAll, Keep);
    let report = match result {
        Ok(report) => report,
        Err(err) => err.into_parts().1,
    };
    assert!(
        !report.applied.iter().any(|p| p == "d"),
        "a created directory replaced by a file is never `applied`: {report:?}"
    );
    assert!(
        report.verify_failures.iter().any(|p| p == "d"),
        "the KIND change is named as a verification failure: {report:?}"
    );
}

/// Whether a `mode 0o000` directory `read_dir` actually FAILS for THIS
/// process. The Finding-A chmod reproduction needs the directory to become
/// unenumerable; root (or `CAP_DAC_READ_SEARCH`) bypasses the mode, so the
/// premise is untestable there and the reproduction skips (loudly).
#[cfg(unix)]
fn a_mode_000_dir_really_refuses_reads() -> bool {
    let dir = fixture_tmpdir(&env()).unwrap();
    let locked = dir.path().join("locked");
    fs::create_dir_all(&locked).unwrap();
    fs::write(locked.join("probe"), b"probe").unwrap();
    set_mode(&locked, 0o000);
    let readable = fs::read_dir(&locked).is_ok();
    set_mode(&locked, 0o755);
    if readable {
        announce_skip(
            "this process can read a mode-0o000 directory (effective uid 0 or \
             CAP_DAC_READ_SEARCH?), so the unreadable-directory premise is \
             untestable here",
        );
        return false;
    }
    true
}

/// The first file named `name` anywhere under `root` (a recursive walk), used
/// to prove a writer-created child survived a claim removal: the claim aside's
/// spelling is unpredictable (pid + counter), so the child is FOUND rather than
/// named.
#[cfg(unix)]
fn find_named(root: &Path, name: &str) -> Option<std::path::PathBuf> {
    for entry in fs::read_dir(root).ok()? {
        let entry = entry.ok()?;
        let file_type = entry.file_type().ok()?;
        if file_type.is_dir() {
            if let Some(found) = find_named(&entry.path(), name) {
                return Some(found);
            }
        } else if entry.file_name() == std::ffi::OsStr::new(name) {
            return Some(entry.path());
        }
    }
    None
}

/// F1 (round 22): an extraneous REMOVAL must never follow a symlink a writer
/// planted at a destination DIRECTORY position. `dst/d/y` is in the destination
/// manifest (extraneous) and `dst/d` was a directory when the manifest was
/// read; a writer replaces `dst/d` with a symlink to an OUTSIDE directory
/// holding `y` before the removal pass. Pre-fix the pass follows the link and
/// DESTROYS the outside `y`.
#[cfg(unix)]
#[test]
fn an_extraneous_removal_never_follows_a_swapped_directory_symlink() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    let outside = dir.path().join("outside");
    write(&src.join("x"), b"payload");
    write(&dst.join("d/y"), b"inside");
    write(&outside.join("y"), b"OUTSIDE-MUST-SURVIVE");

    let remote = RecordingRemote::over(transport(&dst), true)
        .swapping_before_first_op(dst.join("d"), outside.clone());
    let result = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete);
    assert!(
        outside.join("y").exists(),
        "the run DESTROYED a file OUTSIDE the destination root through a \
         symlinked directory component; result: {result:?}"
    );
    assert_eq!(read(&outside.join("y")), b"OUTSIDE-MUST-SURVIVE");
    let report = match result {
        Ok(report) => panic!("the run must not return Ok over a followed symlink: {report:?}"),
        Err(error) => error.into_parts().1,
    };
    assert!(
        !report.applied.contains(&"d/y".to_string()),
        "applied must never name the followed path: {report:?}"
    );
    assert_report_lists_disjoint(&report);
}

/// F2 (round 22): an INSTALL must never follow a symlink a writer planted at a
/// destination DIRECTORY position. `src/d/x` is installed under a `d` the
/// destination manifest described as an empty directory; a writer replaces
/// `dst/d` with a symlink to an empty OUTSIDE directory before the install.
/// Pre-fix the install lands at `OUTSIDE/x` and the run reports `d/x` applied.
#[cfg(unix)]
#[test]
fn an_install_never_follows_a_swapped_directory_symlink() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    let outside = dir.path().join("outside");
    write(&src.join("d/x"), b"payload");
    fs::create_dir_all(dst.join("d")).unwrap();
    fs::create_dir_all(&outside).unwrap();

    let remote = RecordingRemote::over(transport(&dst), true)
        .swapping_before_first_op(dst.join("d"), outside.clone());
    let result = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep);
    assert!(
        !outside.join("x").exists(),
        "the run INSTALLED a file OUTSIDE the destination root through a \
         symlinked directory component; result: {result:?}"
    );
    let report = match result {
        Ok(report) => panic!("the run must not return Ok over a followed symlink: {report:?}"),
        Err(error) => error.into_parts().1,
    };
    assert!(
        !report.applied.contains(&"d/x".to_string()),
        "applied must never name a path outside the destination root: {report:?}"
    );
    assert_report_lists_disjoint(&report);
}

/// NON-RACY F1: the destination manifest DESCRIBES `d` as a directory with an
/// extraneous `d/y`, but the live destination already holds a SYMLINK at `d`.
/// No concurrent writer is needed: a crafted far-side manifest is exactly the
/// manifest the remote verification script emits for a directory, and it must
/// not make an extraneous removal follow the live link.
#[cfg(unix)]
#[test]
fn a_preexisting_directory_symlink_is_refused_for_extraneous_removal() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    let outside = dir.path().join("outside");
    write(&src.join("x"), b"payload");
    fs::create_dir_all(&dst).unwrap();
    write(&outside.join("y"), b"OUTSIDE-MUST-SURVIVE");
    std::os::unix::fs::symlink(&outside, dst.join("d")).unwrap();

    let hash = crate::digest::sha256_bytes(b"y");
    let manifest = format!("d\td\t1ed\t1\t\t\nd/y\tf\t1a4\t1\t{hash}\t\n");
    let remote = RecordingRemote::over(transport(&dst), false).with_manifest_output(manifest);
    let result = unowned(Direction::Push, &src, &remote, &ReplaceAll, Delete);
    assert!(
        outside.join("y").exists(),
        "the run DESTROYED OUTSIDE/y through a pre-existing symlinked directory; \
         result: {result:?}"
    );
    assert_eq!(read(&outside.join("y")), b"OUTSIDE-MUST-SURVIVE");
    match result {
        Ok(report) => panic!(
            "a symlink where the manifest says Dir must not be treated as an \
             intact directory: {report:?}"
        ),
        Err(error) => {
            let report = error.into_parts().1;
            assert!(
                !report.applied.contains(&"d/y".to_string()),
                "applied must not name the followed path: {report:?}"
            );
            assert_report_lists_disjoint(&report);
        }
    }
}

/// NON-RACY F2: the destination manifest DESCRIBES `d` as a directory, but the
/// live destination already holds a SYMLINK there. No concurrent writer. The
/// install under `d` must be refused, not written through the link.
#[cfg(unix)]
#[test]
fn a_preexisting_directory_symlink_is_refused_for_install() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    let outside = dir.path().join("outside");
    write(&src.join("d/x"), b"payload");
    fs::create_dir_all(&dst).unwrap();
    fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, dst.join("d")).unwrap();

    let manifest = "d\td\t1ed\t1\t\t\n";
    let remote =
        RecordingRemote::over(transport(&dst), false).with_manifest_output(manifest.to_string());
    let result = unowned(Direction::Push, &src, &remote, &ReplaceAll, Keep);
    assert!(
        !outside.join("x").exists(),
        "the run INSTALLED OUTSIDE/x through a pre-existing symlinked directory; \
         result: {result:?}"
    );
    match result {
        Ok(report) => panic!(
            "a symlink where the manifest says Dir must not be treated as an \
             intact directory: {report:?}"
        ),
        Err(error) => {
            let report = error.into_parts().1;
            assert!(
                !report.applied.contains(&"d/x".to_string()),
                "applied must never name a path outside the destination root: {report:?}"
            );
            assert_report_lists_disjoint(&report);
        }
    }
}

/// KIND-carrying listing (COVERAGE-ONLY): a LIVE symlink where the manifest
/// says `Dir` is reported as a mismatch, not treated as an intact directory.
/// This pins the kind comparison in `verify_directory_listings`; pre-fix the
/// same swap was already caught by `verify_claimed_untouched`'s OWN kind check,
/// so this test does not fail against the pre-fix code.
#[cfg(unix)]
#[test]
fn a_live_symlink_where_the_manifest_says_dir_is_not_an_intact_directory() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    let outside = dir.path().join("outside");
    fs::create_dir_all(src.join("d")).unwrap();
    fs::create_dir_all(&dst).unwrap();
    fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, dst.join("d")).unwrap();
    // The crafted manifest declares mode 0o755 for `d`; pin the source's mode
    // so `d` is `Same` whatever the process umask is.
    set_mode(&src.join("d"), 0o755);

    let manifest = "d\td\t1ed\t1\t\t\n";
    let remote =
        RecordingRemote::over(transport(&dst), false).with_manifest_output(manifest.to_string());
    let report = unowned(Direction::Push, &src, &remote, &ReplaceAll, Keep)
        .expect("no destination mutation is required");
    assert!(
        !report.skipped.contains(&"d".to_string()),
        "a live symlink where the manifest says Dir is not an intact directory: {report:?}"
    );
    assert!(
        report.verify_failures.contains(&"d".to_string()),
        "the kind mismatch is named: {report:?}"
    );
    assert!(!report.applied.contains(&"d".to_string()));
}

/// PARITY (round 22): the SAME fixture — `d/x` to install, `d` swapped for a
/// symlink to an OUTSIDE directory at the moment of the install — must AGREE on
/// whether the outside path exists for BOTH an fd-confined `Side::Local`
/// destination and a path-based `Side::Remote` destination.
#[cfg(unix)]
#[test]
fn local_and_remote_destinations_agree_a_swapped_symlink_is_not_followed() {
    let dir = fixture_tmpdir(&env()).unwrap();

    // (a) Remote destination (Push): the swap fires before the destination's
    // first trait operation.
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    let outside_remote = dir.path().join("out-remote");
    write(&src.join("d/x"), b"payload");
    fs::create_dir_all(dst.join("d")).unwrap();
    fs::create_dir_all(&outside_remote).unwrap();
    let remote_dest = RecordingRemote::over(transport(&dst), true)
        .swapping_before_first_op(dst.join("d"), outside_remote.clone());
    let _ = owned(Direction::Push, &src, &remote_dest, &ReplaceAll, Keep);
    let remote_created = outside_remote.join("x").exists();

    // (b) Local destination (Pull): the swap fires before the SOURCE's first
    // read, which precedes the fd-confined local write (and follows the local
    // manifest read).
    let src2 = dir.path().join("src2");
    let local = dir.path().join("local");
    let outside_local = dir.path().join("out-local");
    write(&src2.join("d/x"), b"payload");
    fs::create_dir_all(local.join("d")).unwrap();
    fs::create_dir_all(&outside_local).unwrap();
    let remote_src = RecordingRemote::over(transport(&src2), true)
        .swapping_before_first_op(local.join("d"), outside_local.clone());
    let _ = owned(Direction::Pull, &local, &remote_src, &ReplaceAll, Keep);
    let local_created = outside_local.join("x").exists();

    assert_eq!(
        remote_created, local_created,
        "the confined local destination and the path-based remote destination \
         must AGREE on whether the outside path was created \
         (remote_created={remote_created}, local_created={local_created})"
    );
    assert!(
        !remote_created && !local_created,
        "neither destination may install outside the root"
    );
}

/// F-1 REGRESSION (destination-component confinement). On a PATH-BASED
/// destination the preflight is the ONLY confinement, so a directory the run
/// confirmed once must still be probed LIVE on every later operation. Here the
/// first transfer of `a/1` confirms `a`, a writer then replaces `a` with a
/// symlink to an OUTSIDE tree, and the second transfer into `a` must REFUSE.
///
/// Against the pre-fix memo the second transfer hit the cached `a` and skipped
/// the `lstat`, and the path-based `write` followed the symlink: `outside/2` was
/// OVERWRITTEN (and a missing one created). Post-fix the live guard refuses
/// first and nothing is created or overwritten outside the root.
#[cfg(unix)]
#[test]
fn a_path_based_destination_refuses_a_directory_swapped_for_a_symlink_after_a_transfer() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    let outside = dir.path().join("outside");
    // Source `a/1` and `a/2`; the destination holds a REAL `a/` directory with
    // BOTH names already present (`Changed`), so listing `a` caches both names
    // and the first transfer is a WRITE that confirms `a` and fires the swap.
    // `outside/2` already holds bytes that a followed write would overwrite.
    write(&src.join("a/1"), b"one");
    write(&src.join("a/2"), b"two");
    write(&dst.join("a/1"), b"old-one");
    write(&dst.join("a/2"), b"old-two");
    fs::create_dir_all(&outside).unwrap();
    write(&outside.join("2"), b"PRE-EXISTING");

    let remote = PathRemote::over(&dst).after_write(
        1,
        AfterWrite::ReplaceDirWithSymlink("a".to_string(), outside.clone()),
    );
    let error = unowned(Direction::Push, &src, &remote, &ReplaceAll, Keep)
        .expect_err("a swapped directory component must be refused, not followed");

    // THE DECISIVE ASSERTION: NOTHING was created or overwritten outside the
    // root. Pre-fix `outside/2` held the transferred `two`.
    assert_eq!(
        read(&outside.join("2")),
        b"PRE-EXISTING",
        "a pre-existing file outside the root must NOT be overwritten"
    );
    assert_eq!(
        fs::read_dir(&outside).unwrap().count(),
        1,
        "no transfer may create anything outside the destination root"
    );

    let text = error.to_string();
    assert!(
        text.contains("destination path a is a symlink"),
        "the refusal must name the swapped component distinctly: {text}"
    );
    assert!(
        !error.report().applied.contains(&"a/2".to_string()),
        "a refused path is never reported applied: {:?}",
        error.report()
    );
}

/// FINDING A (round 22), chmod variant: a `Skipped` path whose final
/// verification COULD NOT RUN because its parent directory became unreadable
/// must be a verification failure, never advertised `skipped`. The failure was
/// recorded in the listing-failure branch, but `derive_report` ranked the
/// `Skipped` outcome above it.
#[cfg(unix)]
#[test]
fn a_skipped_path_whose_verification_could_not_run_is_not_reported_skipped() {
    if !a_mode_000_dir_really_refuses_reads() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/skip"), b"same");
    write(&dst.join("d/skip"), b"same");
    write(&src.join("d/y"), b"new");
    write(&dst.join("d/y"), b"old");
    set_mode(&src.join("d"), 0o755);
    set_mode(&dst.join("d"), 0o755);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // `d/y` (Changed) is written first; the writer then makes `d` unreadable.
    remote.after_write = Some((1, AfterWrite::Chmod("d".to_string(), 0o000)));
    let result = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep);
    let report = match result {
        Ok(report) => panic!("an unenumerable directory must fail closed: {report:?}"),
        Err(error) => error.into_parts().1,
    };
    assert!(
        !report.skipped.contains(&"d/skip".to_string()),
        "an unverified path is never reported skipped: {report:?}"
    );
    assert!(
        report.verify_failures.contains(&"d/skip".to_string()),
        "the unverified path is named in verify_failures: {report:?}"
    );
    assert_report_lists_disjoint(&report);
}

/// FINDING A (round 22), raw-name variant (LINUX-ONLY): a writer adds a
/// non-UTF-8 name under `d`, so the run cannot enumerate `d` and the `Skipped`
/// `d/skip` verifies NOWHERE. It must be a verification failure, not `skipped`.
#[cfg(unix)]
#[test]
fn a_skipped_path_under_a_raw_named_directory_is_not_reported_skipped() {
    if !filesystem_stores_a_non_utf8_name() {
        return;
    }
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("d/skip"), b"same");
    write(&dst.join("d/skip"), b"same");
    write(&src.join("d/y"), b"new");
    write(&dst.join("d/y"), b"old");
    set_mode(&src.join("d"), 0o755);
    set_mode(&dst.join("d"), 0o755);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.after_write = Some((
        1,
        AfterWrite::RawNameUnder("d".to_string(), b"\xff".to_vec()),
    ));
    let result = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep);
    assert!(
        result.is_err(),
        "a directory the run cannot enumerate must fail closed: {result:?}"
    );
    let report = result.unwrap_err().into_parts().1;
    assert!(
        !report.skipped.contains(&"d/skip".to_string()),
        "an unverified path is never reported skipped: {report:?}"
    );
    assert!(
        report.verify_failures.contains(&"d/skip".to_string()),
        "the unverified path is named in verify_failures: {report:?}"
    );
    assert_report_lists_disjoint(&report);
}

/// FINDING B (round 22): an `OwnClaim` directory removal must re-establish the
/// sanction against the LIVE listing. `dst/a` is an empty directory in the
/// manifest (so it is emptied-and-replaced by the source file) and the claim is
/// taken then; a writer adds `a/extra` before the claim's removal, and pre-fix
/// the removal destroys it silently.
#[cfg(unix)]
#[test]
fn an_own_claim_removal_never_destroys_a_live_unaddressed_child() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("0first"), b"one");
    write(&src.join("a"), b"new");
    fs::create_dir_all(dst.join("a")).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // `0first` (path-ordered first) is written; the writer then adds a child
    // under the directory the source will replace with a file.
    remote.after_write = Some((
        1,
        AfterWrite::Overwrite("a/extra".to_string(), b"KEEP".to_vec()),
    ));
    let result = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep);

    let survivor = find_named(&dst, "extra");
    assert!(
        survivor.is_some(),
        "an entry no manifest spelling addresses must never be destroyed by an \
         OwnClaim removal; result: {result:?}"
    );
    assert_eq!(read(&survivor.unwrap()), b"KEEP");
    assert!(
        result.is_err(),
        "the run must fail closed rather than report a clean success: {result:?}"
    );
}

/// FINDING B (round 22), NESTED variant: the writer-created child is under a
/// NESTED directory inside the claimed tree, so the re-establishment must hold
/// at every recursion depth, not only the claim root.
#[cfg(unix)]
#[test]
fn an_own_claim_removal_never_destroys_a_live_nested_unaddressed_child() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("0first"), b"one");
    write(&src.join("a"), b"new");
    fs::create_dir_all(dst.join("a")).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // The writer creates the NESTED directory AND its child after the scan, so
    // neither is a manifest entry (a manifest-known child would make the
    // directory non-empty and block the replacement entirely).
    remote.after_write = Some((1, AfterWrite::CreateFile("a/b/extra".to_string())));
    let result = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep);

    let survivor = find_named(&dst, "extra");
    assert!(
        survivor.is_some(),
        "a NESTED entry no manifest spelling addresses must never be destroyed \
         by an OwnClaim removal; result: {result:?}"
    );
    assert_eq!(read(&survivor.unwrap()), b"");
    assert!(
        result.is_err(),
        "the run must fail closed rather than report a clean success: {result:?}"
    );
}

/// Platform-independent pin of the NAME-fold predicate ([`alias_in`]) the two
/// fold defenses rest on. The filesystem reproductions of those defenses
/// (`refuse_address_folded_onto_another_name` and the identity-aware removal
/// branch in `remove_extraneous`) only run where the destination actually folds
/// two spellings, so on a case-sensitive destination they pin nothing. The
/// predicate itself is pure, so it is pinned directly here with a synthetic
/// listing, on EVERY platform: `to_lowercase` names the common ASCII case fold
/// (`FOO.TXT`/`foo.txt`) and deliberately does not fabricate a fold it cannot
/// model (`Straße.txt`/`STRASSE.txt`).
#[test]
fn the_case_fold_predicate_names_only_a_fold_it_models() {
    let names = vec![
        (b"foo.txt".to_vec(), EntryKind::File),
        (b"STRASSE.txt".to_vec(), EntryKind::File),
        (b"other.txt".to_vec(), EntryKind::Dir),
    ];
    assert_eq!(
        alias_in(&names, b"FOO.TXT"),
        Some("foo.txt".to_string()),
        "a fold `to_lowercase` models is named"
    );
    assert_eq!(
        alias_in(&names, b"other.txt"),
        Some("other.txt".to_string()),
        "a byte-identical present name matches itself (callers check exact \
         equality first)"
    );
    assert_eq!(
        alias_in(&names, "Straße.txt".as_bytes()),
        None,
        "the predicate never fabricates the `ß`/`ss` fold it does not model"
    );
    assert_eq!(
        alias_in(&names, b"missing.txt"),
        None,
        "an absent name has no alias"
    );
}

// ---------------------------------------------------------------------------
// Round 23: the TOTAL sanction rule (OwnPartial included), rollback accounting,
// and the live-kind gate for the mode-only short circuit.
// ---------------------------------------------------------------------------

/// Materialise a source entry of `kind` at `rel` under `root` (a DIR gets a
/// child, so it is a real directory and its kind change is a real claim).
#[cfg(unix)]
fn build_source_kind(root: &Path, rel: &str, kind: EntryKind) {
    match kind {
        EntryKind::File => write(&root.join(rel), b"SOURCE-FILE"),
        EntryKind::Dir => write(&root.join(rel).join("inner"), b"INNER"),
        EntryKind::Symlink => {
            fs::create_dir_all(root).unwrap();
            let link = root.join(rel);
            if let Some(parent) = link.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            std::os::unix::fs::symlink("source-target", &link).unwrap();
        }
    }
}

/// Materialise a destination entry of `kind` at `rel` under `root`. A DIR is
/// EMPTY so a source FILE/SYMLINK may replace it without extra sanction.
#[cfg(unix)]
fn build_dest_kind(root: &Path, rel: &str, kind: EntryKind) {
    match kind {
        EntryKind::File => write(&root.join(rel), b"DEST-FILE"),
        EntryKind::Dir => {
            fs::create_dir_all(root.join(rel)).unwrap();
        }
        EntryKind::Symlink => {
            fs::create_dir_all(root).unwrap();
            let link = root.join(rel);
            if let Some(parent) = link.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            std::os::unix::fs::symlink("dest-target", &link).unwrap();
        }
    }
}

/// THE CLASS-LEVEL CAMPAIGN (Finding 1). A kind-changing replacement opens a
/// claim window (a source read, a remote round trip, a `make_overwritable`
/// chmod). A concurrent writer materialises `p/wc/gc` inside that window, and
/// the install is then forced to fail so `rollback_claim`/`discard_partial`
/// run. Pre-fix, `Sanction::OwnPartial` returned `true` unconditionally for
/// BOTH `may_delete` and the live-child re-establishment, so `discard_partial`
/// recursively destroyed the writer subtree and the successful rollback rename
/// then erased `p` from `indeterminate` — the report named the lost data
/// NOWHERE. The fix makes the live re-establishment TOTAL at ONE authority
/// ([`Applier::live_entry_manifest_spelling`]): a live entry no manifest
/// spelling addresses is preserved and NAMED under EVERY sanction variant.
///
/// Run for every SOURCE KINd × DESTINATION KIND kind-changing pair and BOTH
/// `delete_extraneous` settings, with an induced operation failure.
#[cfg(unix)]
#[test]
fn a_claim_window_writer_subtree_survives_every_rollback_campaign_case() {
    let kinds = [EntryKind::File, EntryKind::Dir, EntryKind::Symlink];
    let mut cases = 0;
    for src_kind in kinds {
        for dst_kind in kinds {
            if src_kind == dst_kind {
                continue;
            }
            for extraneous in [Keep, Delete] {
                cases += 1;
                let dir = fixture_tmpdir(&env()).unwrap();
                let src = dir.path().join("src");
                let dst = dir.path().join("dst");
                build_source_kind(&src, "p", src_kind);
                build_dest_kind(&dst, "p", dst_kind);

                let mut remote = RecordingRemote::over(transport(&dst), true);
                // AFTER the claim rename, BEFORE the install: the writer
                // materialises a subtree no manifest spelling addresses.
                remote.after_rename = Some((
                    1,
                    AfterWrite::WriteTree("p/wc/gc".to_string(), b"WRITER-DATA".to_vec()),
                ));
                // Force the install to FAIL so the rollback family runs: a
                // `create_dir_all` that creates and then errors (src DIR), or
                // the natural failure of writing a FILE/SYMLINK over the live
                // directory the writer just created.
                if src_kind == EntryKind::Dir {
                    remote.fail_create_dir_all_after_create = true;
                }

                let result = owned(Direction::Push, &src, &remote, &ReplaceAll, extraneous);

                let context =
                    format!("src={src_kind:?} dst={dst_kind:?} extraneous={extraneous:?}");
                let survivor = find_named(&dst, "gc").unwrap_or_else(|| {
                    panic!("the claim-window writer subtree was DESTROYED ({context}): {result:?}")
                });
                assert_eq!(read(&survivor), b"WRITER-DATA", "{context}");
                let report = match &result {
                    Ok(report) => report,
                    Err(error) => error.report(),
                };
                assert!(
                    report_names(report, "p/wc") || report_names(report, "p/wc/gc"),
                    "the surviving writer subtree must be NAMED ({context}): {report:?}"
                );
                assert_residue_present(report, &[&dst]);
                assert_report_lists_disjoint(report);
                assert!(
                    result.is_err(),
                    "a claim-window divergence must fail closed ({context}): {result:?}"
                );
            }
        }
    }
    assert_eq!(cases, 12, "6 kind-changing pairs x 2 delete settings");
}

/// THE ACCOUNTING HALF OF FINDING 1: a rolled-back failure must not erase the
/// fact that a path was touched. Here the rollback SUCCEEDS (the sync discards
/// its own empty partial and restores the original byte-identically), but the
/// failed install must remain named. Pre-fix, `discard_partial`'s removal and
/// `rename_back` each `commit_mutation`d `p` with the same `MutationKind`, so
/// the failed `create_dir_all` attempt was cleared and `p` was named NOWHERE.
#[cfg(unix)]
#[test]
fn a_rolled_back_failure_still_names_the_path_it_touched() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p/f"), b"new");
    write(&dst.join("p"), b"old");
    let before = canonicalize_tree(&dst).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_create_dir_all_after_create = true;
    let err = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();

    assert_eq!(
        canonicalize_tree(&dst).unwrap(),
        before,
        "the rollback succeeded, so the destination is byte-identical: {err:?}"
    );
    assert!(
        err.restore_failures().is_empty(),
        "a successful rollback is not a restore failure: {:?}",
        err.restore_failures()
    );
    assert_report_names(err.report(), "p");
    assert_report_lists_disjoint(err.report());
}

/// THE RELATED `rename_back` HOLE: after `discard_partial` removes this sync's
/// own partial, the rollback rename targets a path the run EXPECTS to be
/// absent. A writer that appears there in the window must NOT be silently
/// displaced by the rename (a plain `renameat` replaces the final entry):
/// pre-fix `rename_back` guarded the target `FinalPolicy::Unresolved` and
/// overwrote the writer's file with the claimed aside. Post-fix the rollback
/// refuses and names both the writer's entry and the stranded aside.
#[cfg(unix)]
#[test]
fn a_rollback_never_displaces_a_writer_entry_at_its_target() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p/f"), b"new");
    write(&dst.join("p"), b"old");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_create_dir_all_after_create = true;
    // After the sync removes its OWN partial directory, a writer creates a file
    // at the rollback target `p` (the aside holds a FILE, so a rename would
    // replace it).
    remote.after_removal = Some((
        1,
        AfterWrite::Overwrite("p".to_string(), b"WRITER-AT-TARGET".to_vec()),
    ));
    let result = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep);

    assert_eq!(
        read(&dst.join("p")),
        b"WRITER-AT-TARGET",
        "the rollback must not displace the writer entry at its target: {result:?}"
    );
    let report = match &result {
        Ok(report) => report,
        Err(error) => error.report(),
    };
    assert!(
        report_names(report, "p"),
        "the writer-created entry is NAMED: {report:?}"
    );
    // The refusal is a MUTATION-TIME failure at `p`, so `p` is `indeterminate`
    // and the partition (indeterminate > residue) names it there rather than as
    // residue. The ordinary-residue KIND is pinned by
    // `a_claim_window_writer_source_addressed_child_is_preserved_under_own_partial`,
    // where the writer's child carries no attempted mutation.
    assert!(
        report.indeterminate.contains(&"p".to_string()),
        "the refused rollback leaves `p` indeterminate: {report:?}"
    );
    assert_residue_present(report, &[&dst]);
    assert_report_lists_disjoint(report);
    assert!(result.is_err(), "the refusal is reported: {result:?}");
}

/// FINDING 2: the mode-only `Replace` short-circuit trusted the manifest
/// SNAPSHOT kind. A writer that replaces a destination FILE with a live
/// DIRECTORY before the first operation made the sync chmod the DIRECTORY to
/// the source FILE's mode (0o600), leaving it non-traversable and NOT restored.
/// The LIVE kind now gates the short-circuit: a non-FILE live kind takes the
/// kind-changing claim route (or refuses), so the source FILE mode is never
/// applied to a directory.
#[cfg(unix)]
#[test]
fn a_live_directory_is_never_chmodded_by_a_mode_only_file_transfer() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"IDENTICAL");
    set_mode(&src.join("p"), 0o600);
    write(&dst.join("p"), b"IDENTICAL");
    set_mode(&dst.join("p"), 0o644);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    // A writer replaces the destination FILE with a live DIRECTORY before the
    // first trait operation.
    remote.mutate_before_first_op = Some(AfterWrite::ReplaceWithDirTree(
        "p".to_string(),
        b"WRITER-DATA".to_vec(),
    ));

    let result = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep);
    let live = fs::symlink_metadata(dst.join("p")).unwrap();
    assert!(
        !live.is_dir(),
        "the source FILE mode must not be applied to a live DIRECTORY: {result:?}"
    );
    assert_eq!(
        mode_of(&dst.join("p")),
        0o600,
        "the path is now the source regular file, so its file mode is correct"
    );
    let survivor = find_named(&dst, "gc").unwrap_or_else(|| {
        panic!("the writer's live subtree must survive (or be named): {result:?}")
    });
    assert_eq!(read(&survivor), b"WRITER-DATA");
    let report = match &result {
        Ok(report) => report,
        Err(error) => error.report(),
    };
    assert_report_names(report, "p");
    assert_residue_present(report, &[&dst]);
}

/// FINDING 3 (COVERAGE-ONLY): the `skipped` contract is SCOPED to a TOUCHED
/// parent. `a/f` is `Same` and nothing under `a` transfers, so `a` is never a
/// touched directory; a writer may change `a/f` after the manifest scan and the
/// run neither mutates it nor re-reads it. The report names it `skipped` (it
/// needed no mutation) WITHOUT a re-confirmation, which is exactly what
/// [`SyncReport::skipped`] now documents. `b/g` DOES transfer, so `b` is
/// touched and its children are re-confirmed.
///
/// COVERAGE-ONLY: the code behaviour is unchanged by the Finding 3 resolution
/// (which scopes the documented guarantee to what the code actually does), so
/// this test passes against the pre-fix code as well; it pins the scoped
/// contract so a future attempt to re-widen the doc fails here.
#[cfg(unix)]
#[test]
fn a_skipped_path_under_an_untouched_directory_is_reported_on_the_manifest_alone() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("a/f"), b"SAME");
    write(&dst.join("a/f"), b"SAME");
    write(&src.join("b/g"), b"NEW");
    write(&dst.join("b/g"), b"OLD");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.mutate_before_first_op = Some(AfterWrite::Overwrite(
        "a/f".to_string(),
        b"WRITER-CHANGED".to_vec(),
    ));
    let report = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap();

    // `a` is NOT a touched directory (nothing under it transfers), so the run
    // makes no re-confirmation claim about `a/f`; it is reported on the
    // manifest snapshot alone.
    assert!(
        report.skipped.iter().any(|path| path == "a/f"),
        "a Same entry under an untouched directory is reported skipped: {report:?}"
    );
    assert!(
        report.verify_failures.is_empty(),
        "the run performed no verification of the untouched directory: {report:?}"
    );
    assert_eq!(
        read(&dst.join("a/f")),
        b"WRITER-CHANGED",
        "the run did not touch `a/f`, so the writer change is live on disk"
    );
    assert_report_lists_disjoint(&report);
}

/// FINDING 1, SOURCE-ADDRESSED CHILD VARIANT of the same class: the writer
/// creates a child the SOURCE manifest DOES address (`p/f`). A rule keyed only
/// on "is the live spelling in the diff" would allow it. But the sync's own
/// partial creation is `create_dir_all`'s EMPTY directory (or one file/symlink);
/// nothing strictly below the claim's real path was written by this sync, so
/// `OwnPartial`'s proof does not REACH it. It is preserved and named.
#[cfg(unix)]
#[test]
fn a_claim_window_writer_source_addressed_child_is_preserved_under_own_partial() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p/f"), b"source-child");
    write(&dst.join("p"), b"old");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.after_rename = Some((
        1,
        AfterWrite::WriteTree("p/f".to_string(), b"WRITER-CHILD".to_vec()),
    ));
    remote.fail_create_dir_all_after_create = true;
    let result = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep);

    let survivor = find_named(&dst, "f").unwrap_or_else(|| {
        panic!("the writer's source-addressed child must survive (or be named): {result:?}")
    });
    assert_eq!(read(&survivor), b"WRITER-CHILD");
    let report = match &result {
        Ok(report) => report,
        Err(error) => error.report(),
    };
    assert_report_names(report, "p/f");
    assert!(
        report.residue.contains(&"p/f".to_string()),
        "the writer's source-addressed child, blocked by the partial-creation proof, \
         is ORDINARY residue (no reserved component): {report:?}"
    );
    assert_residue_present(report, &[&dst]);
    assert_report_lists_disjoint(report);
    assert!(result.is_err(), "the run fails closed: {result:?}");
}

// ---------------------------------------------------------------------------
// Round 24: the LIVE-KIND dispatch rule (Finding 1: a kind observed at an
// earlier moment must never select a mutation against the live object) and the
// confined-LOCAL destination coverage gap that hid it. `pull`'s destination is
// a `Side::Local` that no `Remote` wrapper can intercept, so the reviewer's
// `oracle_stale_claim_kind` scenario had never been exercised there.
// ---------------------------------------------------------------------------

/// Whether the report NAMES the writer subtree planted at `p/wc`: either the
/// LIVE spelling (an unplanned entry under a touched directory, or a residue
/// path under the real name), or a reserved `.sync-aside.` residue root (the
/// claimed live directory the run moved aside and then left in place).
fn report_names_writer_subtree(report: &SyncReport, live_spelling: &str) -> bool {
    report_names(report, live_spelling)
        || report
            .residue
            .iter()
            .any(|path| path.starts_with(ASIDE_PREFIX))
}

/// FINDING 1 on the CONFINED-LOCAL destination (`pull` through `Side::Local`):
/// a live subtree no manifest spelling addresses is destroyed recursively,
/// silently, with a clean `Ok`.
///
/// The destination SNAPSHOT says `p` is a regular FILE. `0first` sorts before
/// `p`; its source READ is the one instrumented call that fires after the
/// destination manifest was read and before `p` is processed, and a writer used
/// it to swap the LIVE `p` for a DIRECTORY holding `p/wc/gc` — an entry no
/// manifest spelling addresses. Pre-fix `transfer_dir`/`transfer_symlink`
/// passed the SNAPSHOT `dest_kind` (`File`) into `claim_aside`, `drop_claim`
/// passed that stale kind to `remove_subtree`, and `remove_subtree`'s
/// `File|Symlink` arm never consulted the authority; on the local destination
/// `LocalSide::remove` re-derived the live kind and called `remove_dir_all`, so
/// the writer's subtree was deleted and the run returned `Ok`. Post-fix the
/// route is chosen from the LIVE kind and the removal reads it live, so the
/// subtree SURVIVES and is NAMED (as an unplanned entry for the directory
/// variant, as a claim-aside residue root for the symlink variant).
#[cfg(unix)]
#[test]
fn a_confined_pull_live_kind_swap_is_preserved_and_named() {
    confined_pull_live_kind_swap_scenario(EntryKind::Dir);
}

/// The SYMLINK-source half of the same Finding-1 scenario. Split out so each
/// variant has its own pre-fix failure proof.
#[cfg(unix)]
#[test]
fn a_confined_pull_live_kind_swap_symlink_source_is_preserved_and_named() {
    confined_pull_live_kind_swap_scenario(EntryKind::Symlink);
}

#[cfg(unix)]
fn confined_pull_live_kind_swap_scenario(src_kind: EntryKind) {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let local = dir.path().join("local");
    let outside = dir.path().join("outside");
    write(&outside.join("sentinel"), b"OUTSIDE");
    let outside_before = canonicalize_tree(&outside).unwrap();

    write(&src.join("0first"), b"FIRST");
    build_source_kind(&src, "p", src_kind);
    // The destination SNAPSHOT: `p` is a regular FILE.
    write(&local.join("p"), b"DEST-FILE");

    let mut remote = RecordingRemote::over(transport(&src), true);
    remote.pull_writer = Some((
        1,
        local.clone(),
        AfterWrite::ReplaceWithDirTreeAt(
            "p".to_string(),
            "wc/gc".to_string(),
            b"WRITER-GC".to_vec(),
        ),
    ));

    let result = owned(Direction::Pull, &local, &remote, &ReplaceAll, Keep);
    let context = format!("src={src_kind:?}");

    let survivor = find_named(&local, "gc").unwrap_or_else(|| {
        panic!("the writer's live subtree was DESTROYED ({context}): {result:?}")
    });
    assert_eq!(read(&survivor), b"WRITER-GC", "{context}");
    assert_eq!(
        canonicalize_tree(&outside).unwrap(),
        outside_before,
        "nothing outside the destination root may change ({context})"
    );
    let report = match &result {
        Ok(report) => report,
        Err(error) => error.report(),
    };
    assert!(
        report_names_writer_subtree(report, "p/wc"),
        "the surviving writer subtree must be NAMED ({context}): {report:?}"
    );
    assert_report_lists_disjoint(report);
    assert!(
        result.is_err(),
        "a claim-window divergence must fail closed ({context}): {result:?}"
    );
}

/// THE EXTENDED CAMPAIGN (Finding 1 coverage): the confined-LOCAL destination
/// is exercised for every kind-changing source/destination pair and both
/// `delete_extraneous` settings, with a live-kind swap AND (where the local
/// path has a source read inside the window) an injected operation failure.
///
/// Every case plants `p/wc/gc` in the live destination after the destination
/// manifest was read, so the run's snapshot kind for `p` is stale. Assertions
/// per case: the writer subtree is PRESERVED with its bytes; NOTHING outside
/// the root changes; the report is a valid partition; the run fails closed. A
/// claimed live directory is additionally asserted to be left as RESIDUE that
/// still exists (an injected read failure rolls the claim back, so that family
/// has no aside to leave as residue).
#[cfg(unix)]
#[test]
fn a_confined_pull_claim_window_campaign() {
    let kinds = [EntryKind::File, EntryKind::Dir, EntryKind::Symlink];
    let mut cases = 0usize;
    let mut residue_cases = 0usize;
    let mut injected_failures = 0usize;
    for src_kind in kinds {
        for dst_kind in kinds {
            if src_kind == dst_kind {
                continue;
            }
            for extraneous in [Keep, Delete] {
                // An injected source-read failure needs a read on the local
                // path inside the window: only a source FILE install has one
                // (target `p`). A source DIR is a mode-only change post-fix and
                // a source SYMLINK carries its target in the manifest, so
                // neither has a read to fail — the failure family is honestly
                // limited to the source-FILE pairs.
                let failure_modes: &[bool] = if src_kind == EntryKind::File {
                    &[false, true]
                } else {
                    &[false]
                };
                for &inject_failure in failure_modes {
                    cases += 1;
                    let dir = fixture_tmpdir(&env()).unwrap();
                    let src = dir.path().join("src");
                    let local = dir.path().join("local");
                    let outside = dir.path().join("outside");
                    write(&outside.join("sentinel"), b"OUTSIDE");
                    let outside_before = canonicalize_tree(&outside).unwrap();

                    write(&src.join("0first"), b"FIRST");
                    build_source_kind(&src, "p", src_kind);
                    build_dest_kind(&local, "p", dst_kind);

                    let mut remote = RecordingRemote::over(transport(&src), true);
                    remote.pull_writer = Some((
                        1,
                        local.clone(),
                        AfterWrite::ReplaceWithDirTreeAt(
                            "p".to_string(),
                            "wc/gc".to_string(),
                            b"WRITER-GC".to_vec(),
                        ),
                    ));
                    if inject_failure {
                        injected_failures += 1;
                        // Read #1 is `0first` (fires the writer); read #2 is the
                        // install source read for `p`, AFTER the claim, so the
                        // failure drives `rollback_claim`.
                        remote.fail_nth_read = Some(2);
                    }

                    let result = owned(Direction::Pull, &local, &remote, &ReplaceAll, extraneous);
                    let context = format!(
                        "src={src_kind:?} dst={dst_kind:?} extraneous={extraneous:?} fail={inject_failure}"
                    );

                    let survivor = find_named(&local, "gc").unwrap_or_else(|| {
                        panic!("the writer's live subtree was DESTROYED ({context}): {result:?}")
                    });
                    assert_eq!(read(&survivor), b"WRITER-GC", "{context}");
                    assert_eq!(
                        canonicalize_tree(&outside).unwrap(),
                        outside_before,
                        "nothing outside the destination root may change ({context})"
                    );
                    let report = match &result {
                        Ok(report) => report,
                        Err(error) => error.report(),
                    };
                    // The live subtree is PRESERVED (above) or NAMED; when the
                    // run took a route that leaves it in place it must NAME it.
                    assert_report_lists_disjoint(report);
                    assert!(
                        result.is_err(),
                        "a writer divergence must fail closed ({context}): {result:?}"
                    );
                    if case_leaves_claim_residue(src_kind, inject_failure) {
                        assert!(
                            !report.residue.is_empty(),
                            "the claimed live directory is left as residue ({context}): {report:?}"
                        );
                        assert_residue_present(report, &[&local]);
                        residue_cases += 1;
                    }
                }
            }
        }
    }
    // 6 kind-changing pairs x 2 delete settings, plus the source-FILE pairs
    // (2) x 2 delete settings with an injected read failure.
    assert_eq!(cases, 6 * 2 + 2 * 2, "campaign case count");
    assert_eq!(injected_failures, 4, "injected operation failures");
    assert_eq!(residue_cases, 12, "cases that leave claim residue");
}

/// Whether the campaign case leaves the LIVE directory as a claim aside: every
/// swap-only case CLAIMS the live directory (the snapshot kind is stale), so
/// the writer child is unaddressed inside the aside and left as residue. An
/// injected read failure makes the source-FILE cases ROLL BACK the claim, so
/// the live directory ends up back at its real path with no aside to leave.
#[cfg(unix)]
fn case_leaves_claim_residue(_src_kind: EntryKind, inject_failure: bool) -> bool {
    !inject_failure
}

/// FINDING 2: `restore` applied the journal's FILE-kind mode to a live
/// DIRECTORY.
///
/// The destination file `p` (mode `0o444`) is widened by `make_overwritable`
/// for an overwrite, which journals kind FILE with the original `0o444`; the
/// write then FAILS and, in the same call, a writer swaps the live `p` for a
/// directory. Pre-fix `restore` read with the JOURNAL's kind
/// (`mode_opt(&rel, File)`) and re-applied with it
/// (`set_mode(&rel, 0o444, File)`); the transport/`LocalSide` chmods the
/// directory to the file's mode and the wrong-kind chmod is SILENT
/// (`restore_failures` empty). Post-fix `restore` reads the LIVE kind and
/// REFUSES (and NAMES) a kind the journal never recorded.
#[cfg(unix)]
#[test]
fn a_restore_never_applies_a_recorded_mode_to_a_live_kind_it_never_recorded() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"NEW-BYTES");
    write(&dst.join("p"), b"OLD-BYTES");
    set_mode(&dst.join("p"), 0o444);

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.fail_writes = true;
    // The write FAILS (returning `Err`), and IN THE SAME CALL the writer swaps
    // the live `p` for a directory holding an unaddressed child.
    remote.mutate_after_failed_write = Some((
        1,
        AfterWrite::ReplaceWithDirTreeAt(
            "p".to_string(),
            "data/gc".to_string(),
            b"WRITER".to_vec(),
        ),
    ));

    let error = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep).unwrap_err();
    let live = fs::symlink_metadata(dst.join("p")).unwrap();
    assert!(
        live.is_dir(),
        "the writer's live directory is preserved: {error:?}"
    );
    assert_ne!(
        mode_of(&dst.join("p")),
        0o444,
        "the recorded FILE mode must not be applied to the live DIRECTORY: {error:?}"
    );
    assert!(
        error
            .restore_failures()
            .iter()
            .any(|failure| failure.contains("refusing to apply a mode")),
        "the wrong-kind restore must be NAMED, never silent: {:?}",
        error.restore_failures()
    );
    assert_eq!(
        read(&dst.join("p/data/gc")),
        b"WRITER",
        "the writer's subtree survives: {error:?}"
    );
    assert_report_lists_disjoint(error.report());
}

/// THE REMOVAL-WINDOW HOLE (second reviewer): `remove_subtree` enumerated a
/// directory's children, decided each child's fate through the live authority,
/// and then removed the DIRECTORY itself with a RECURSIVE primitive (`rm -rf`
/// remotely, `remove_dir_all_fd` locally). A non-reserved entry created AFTER
/// the enumeration but BEFORE that final removal was destroyed WITHOUT ever
/// being listed or named.
///
/// The window is won DETERMINISTICALLY here: the `before_dir_removal` hook runs
/// inside the directory-removal primitive — after every listing the walk
/// performs and immediately before the directory's own removal — and creates
/// `d/late`. With the NON-RECURSIVE rmdir leaf the removal fails `ENOTEMPTY`,
/// the run fails loudly, and `d/late` is preserved AND NAMED as residue. Before
/// the fix the recursive primitive deleted both `d` and the unseen `d/late` and
/// the run returned `Ok`.
#[cfg(unix)]
#[test]
fn a_late_child_in_the_removal_window_is_refused_and_preserved() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    let outside = dir.path().join("outside");
    write(&outside.join("sentinel"), b"OUTSIDE");
    let outside_before = canonicalize_tree(&outside).unwrap();

    write(&src.join("f"), b"same");
    write(&dst.join("f"), b"same");
    write(&dst.join("d/child"), b"authorized");

    let mut remote = RecordingRemote::over(transport(&dst), true);
    remote.before_dir_removal = Some((
        1,
        AfterWrite::WriteTree("d/late".to_string(), b"LATE".to_vec()),
    ));
    let result = owned(Direction::Push, &src, &remote, &ReplaceAll, Delete);

    let late = dst.join("d/late");
    assert!(
        fs::symlink_metadata(&late).is_ok(),
        "the late child was DESTROYED unnamed by the removal: {result:?}"
    );
    assert_eq!(read(&late), b"LATE");
    assert!(
        !dst.join("d/child").exists(),
        "the ENUMERATED (authorized) child was still removed: {result:?}"
    );
    let report = match &result {
        Ok(report) => report,
        Err(error) => error.report(),
    };
    assert!(
        result.is_err(),
        "a non-empty directory removal must fail LOUDLY: {result:?}"
    );
    assert_report_names(report, "d/late");
    assert_residue_present(report, &[&dst]);
    assert_report_lists_disjoint(report);
    assert_eq!(
        canonicalize_tree(&outside).unwrap(),
        outside_before,
        "nothing outside the destination root may change"
    );
}

/// The DEPTH of the destination chain [`deep_tree_removal`] removes, and the
/// STACK the removal thread is given.
///
/// A REGRESSION HERE CANNOT BE TESTED WITH THE DEFAULT 2 MiB STACK AT THE DEPTH
/// THE ABORT ACTUALLY NEEDS. `remove_subtree` is `O(depth^3)` in this codebase:
/// every level re-probes EVERY ancestor through
/// [`Applier::guard_destination`] (a descriptor-relative `lstat` walk per
/// ancestor), so a removal of 96 levels already takes ~6 s and 400 levels
/// ~12 min (measured on this host); 10 000 levels would take WEEKS. The abort
/// threshold (~1 200 levels on the 2 MiB libtest stack, ~2.3 KiB of stack per
/// recursive level in a debug build) is therefore unreachable through a real
/// `sync` in bounded time. Shrinking the thread stack instead makes the SAME
/// property — the recursion consumes one Rust stack frame PER LEVEL — testable
/// at a depth that costs seconds: the recursive form needs ~220 KiB at 96
/// levels (measured: it overflows a 128 KiB stack at 64 levels, 64 KiB at 96),
/// while the iterative form's stack use is CONSTANT (measured: it fits in
/// 16 KiB at 96 levels). `64 KiB` at `96` levels is a 3.4x margin over the
/// recursive requirement and a >4x margin under the iterative one.
#[cfg(unix)]
const DEEP_TREE_DEPTH: usize = 96;
#[cfg(unix)]
const DEEP_TREE_STACK_BYTES: usize = 64 * 1024;

/// The env var that turns the test binary into the CHILD that performs the
/// deep-tree removal.
#[cfg(unix)]
const DEEP_TREE_CHILD: &str = "STOREKIT_DEEP_TREE_CHILD";
/// The env vars carrying the child's source and destination roots.
#[cfg(unix)]
const DEEP_TREE_SRC: &str = "STOREKIT_DEEP_TREE_SRC";
#[cfg(unix)]
const DEEP_TREE_DST: &str = "STOREKIT_DEEP_TREE_DST";

/// A deep DESTINATION tree that a `sync` must remove must produce SUCCESS or a
/// clean `Err`, never a process ABORT.
///
/// `remove_subtree` is reached on a kind-changing replacement: a destination
/// directory is CLAIMED by renaming it aside, the source file is installed, and
/// the aside (holding the whole original subtree) is removed. The destination
/// chain is built BEFORE the manifest (so a shallow manifest is legal and the
/// removal still has to descend every level), and the removal runs in a CHILD
/// PROCESS because the pre-fix failure mode is a `SIGABRT` — a stack overflow
/// would take the whole libtest runner with it.
///
/// PRE-FIX EVIDENCE (the original recursive `remove_subtree`, on this host,
/// macOS, debug): the child exits with `signal: 6, SIGABRT` and prints
/// `thread '<unknown>' has overflowed its stack` / `fatal runtime error: stack
/// overflow, aborting`. POST-FIX at the same depth and stack: exit 0 in ~6 s
/// (the iterative walk's stack use does not grow with depth).
#[cfg(unix)]
#[test]
fn a_deep_destination_tree_is_removed_without_aborting_the_process() {
    if std::env::var_os(DEEP_TREE_CHILD).is_some() {
        // ---- CHILD: perform the removal on a deliberately small stack. ----
        let src = std::path::PathBuf::from(std::env::var_os(DEEP_TREE_SRC).unwrap());
        let dst = std::path::PathBuf::from(std::env::var_os(DEEP_TREE_DST).unwrap());
        let handle = std::thread::Builder::new()
            .stack_size(DEEP_TREE_STACK_BYTES)
            .spawn(move || owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete))
            .expect("spawn the deep-removal thread");
        let joined = handle.join().expect("the removal thread must not panic");
        let report = joined.unwrap_or_else(|error| panic!("the sync must succeed: {error:?}"));
        assert!(report.residue.is_empty(), "{report:?}");
        return;
    }

    // ---- PARENT: build the tree, run the child, and clean up either way. ----
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("p"), b"file");
    fs::create_dir_all(dst.join("p")).unwrap();
    build_deep_chain(&dst.join("p"), DEEP_TREE_DEPTH);

    let exe = std::env::current_exe().expect("the test binary's path");
    // The libtest name of THIS test: `module_path!()` carries the crate prefix
    // (`storekit::...`) while libtest registers the in-crate path, so the
    // name is spelled out.
    let name =
        "sync::apply::tests::a_deep_destination_tree_is_removed_without_aborting_the_process";
    let status = std::process::Command::new(&exe)
        .args(["--exact", name, "--nocapture"])
        .env(DEEP_TREE_CHILD, "1")
        .env(DEEP_TREE_SRC, &src)
        .env(DEEP_TREE_DST, &dst)
        .status();

    // Clean up EVEN ON FAILURE, before asserting: a pre-fix abort leaves the
    // claimed aside (and its chain) behind, and the aside is the new spelling
    // of the chain (`dst/p` is already the installed file). `remove_deep_chain`
    // is the iterative, descriptor-relative walk; it is a no-op on a non-chain.
    if let Ok(entries) = fs::read_dir(&dst) {
        for entry in entries.flatten() {
            remove_deep_chain(&entry.path());
        }
    }

    let status = status.expect("spawn the deep-tree child");
    assert!(
        status.success(),
        "a deep destination tree must be removed without aborting the process: the \
         child exited with {status:?}; the pre-fix recursive walk aborts here with \
         SIGABRT (\u{201c}has overflowed its stack\u{201d})"
    );
    assert!(
        !dst.join("p").is_dir(),
        "the replacement must have completed once the child exited cleanly"
    );
}

// ===========================================================================
// THE DESTINATION OPERATION LOCK
// ===========================================================================
//
// `sync` TAKES the destination's operation lock for the whole run. These tests
// pin, in order: the lock is actually HELD during a run; two REAL processes
// cannot interleave on one destination; the guard is released on an ERROR
// exit; and the flock is released when the holder is KILLED.
//
// Determinism: no assertion depends on timing luck. Where the prose says "a
// probe must fail WHILE the run holds the lock", the probe runs from INSIDE
// the run (a caller-supplied `Policy`, which the applier invokes on its real
// code path) or from the parent while a CHILD signals readiness through a
// file. The only waits are BOUNDED by a hard deadline, so a wedged lock test
// fails the suite instead of hanging it.

/// The hard deadline for every blocking wait in the real-process lock tests.
#[cfg(unix)]
const LOCK_WAIT: Duration = Duration::from_secs(30);

/// Env var that turns the test binary into the CHILD holding the destination
/// lock.
#[cfg(unix)]
const LOCK_CHILD: &str = "STOREKIT_LOCK_CHILD";
#[cfg(unix)]
const LOCK_CHILD_SRC: &str = "STOREKIT_LOCK_CHILD_SRC";
#[cfg(unix)]
const LOCK_CHILD_DST: &str = "STOREKIT_LOCK_CHILD_DST";
#[cfg(unix)]
const LOCK_CHILD_HELD: &str = "STOREKIT_LOCK_CHILD_HELD";
#[cfg(unix)]
const LOCK_CHILD_RELEASE: &str = "STOREKIT_LOCK_CHILD_RELEASE";

/// Wait (BOUNDED) for `path` to appear. Returns whether it did.
#[cfg(unix)]
fn wait_for_file(path: &Path) -> bool {
    let deadline = std::time::Instant::now() + LOCK_WAIT;
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

/// A spawned lock holder that CANNOT outlive its test: on drop it tells the
/// child to finish, and kills and reaps it if it does not within a bound — so
/// a failed assertion can never leave a process holding the lock, or block the
/// suite, forever.
#[cfg(unix)]
struct LockHolder {
    child: Option<std::process::Child>,
    release: PathBuf,
}

#[cfg(unix)]
impl LockHolder {
    fn spawn(src: &Path, dst: &Path, held: &Path, release: &Path) -> LockHolder {
        // The libtest name of the CHILD test: `module_path!()` carries the
        // crate prefix while libtest registers the in-crate path, so the name
        // is spelled out (the deep-tree child does the same).
        let name = "sync::apply::tests::destination_lock_child_holder";
        let child =
            std::process::Command::new(std::env::current_exe().expect("the test binary's path"))
                .args(["--exact", name, "--nocapture"])
                .env(LOCK_CHILD, "hold")
                .env(LOCK_CHILD_SRC, src)
                .env(LOCK_CHILD_DST, dst)
                .env(LOCK_CHILD_HELD, held)
                .env(LOCK_CHILD_RELEASE, release)
                .spawn()
                .expect("spawn the lock-holder child");
        LockHolder {
            child: Some(child),
            release: release.to_path_buf(),
        }
    }

    /// Tell the holder to finish and return its exit status.
    fn finish(mut self) -> std::process::ExitStatus {
        let _ = std::fs::write(&self.release, b"go");
        self.child.take().unwrap().wait().unwrap()
    }

    /// Kill the holder (SIGKILL on Unix) and reap it.
    fn kill(mut self) -> std::process::ExitStatus {
        let mut child = self.child.take().unwrap();
        child.kill().expect("kill the lock holder");
        child.wait().unwrap()
    }
}

#[cfg(unix)]
impl Drop for LockHolder {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = std::fs::write(&self.release, b"go");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => return,
                _ => std::thread::sleep(Duration::from_millis(5)),
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// The CHILD side of the real-process lock tests: hold the destination's lock
/// open until the parent releases or kills us. Readiness is signalled by
/// creating `LOCK_CHILD_HELD` from INSIDE the run (the policy runs only after
/// the lock has been acquired), and the child then blocks in the policy until
/// `LOCK_CHILD_RELEASE` appears — a real synchronising hook, not a sleep. The
/// child has its OWN hard deadline, so a misbehaving parent cannot leave a
/// blocked test binary behind. With the env var unset this test is a no-op.
#[cfg(unix)]
#[test]
fn destination_lock_child_holder() {
    if std::env::var_os(LOCK_CHILD).is_none() {
        return;
    }
    let src = PathBuf::from(std::env::var_os(LOCK_CHILD_SRC).unwrap());
    let dst = PathBuf::from(std::env::var_os(LOCK_CHILD_DST).unwrap());
    let held = PathBuf::from(std::env::var_os(LOCK_CHILD_HELD).unwrap());
    let release = PathBuf::from(std::env::var_os(LOCK_CHILD_RELEASE).unwrap());
    let child_deadline = std::time::Instant::now() + LOCK_WAIT + Duration::from_secs(30);
    let policy = move |_rel: &str, _kind: EntryKind| {
        write(&held, b"held");
        while !release.exists() && std::time::Instant::now() < child_deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        EntryPolicy::Replace
    };
    let report = owned(Direction::Push, &src, &transport(&dst), &policy, Keep).unwrap();
    assert!(report.applied.contains(&"f".to_string()), "{report:?}");
}

/// The lock is ACTUALLY TAKEN for the duration of the run, and released after
/// it.
///
/// The probe runs from a caller-supplied `Policy`, which the applier invokes
/// on its real code path INSIDE `run` — after the guard is bound and while it
/// is still alive — so "the record is held" is observed at a point the
/// implementation cannot reorder without breaking the run. After the run the
/// same record must be immediately acquirable again.
///
/// PRE-FIX PROOF: before this change `sync` took no lock, so the in-run
/// `FileLock::acquire` below would SUCCEED and the `expect_err` panics.
#[test]
fn the_destination_lock_is_held_during_the_run_and_released_after() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("f"), b"payload");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();
    let lock_path =
        destination_lock_path(&dst).expect("a destination root in a parent has a lock record");

    let probe_path = lock_path.clone();
    let probe = move |_rel: &str, _kind: EntryKind| {
        let err = match crate::lock::FileLock::acquire(&probe_path, "in-run-probe") {
            Ok(_) => panic!("the destination lock must be held while the run is in progress"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("held by"),
            "the refusal must name the holder: {err}"
        );
        EntryPolicy::Replace
    };
    let report = owned(Direction::Push, &src, &transport(&dst), &probe, Keep).unwrap();
    assert!(report.applied.contains(&"f".to_string()), "{report:?}");

    // The guard has dropped: the record is free again.
    let after = crate::lock::FileLock::acquire(&lock_path, "after-run")
        .expect("the destination lock must be released when the run returns");
    drop(after);
}

/// An ERROR exit path releases the lock.
///
/// Two failure positions are pinned:
///
/// * a failure BEFORE the lock (a missing SOURCE root, so the strict source
///   manifest read fails) creates NOTHING — no destination root and no lock
///   record. This is the corrected order: the source manifest is read before
///   ownership is established, so a refused run leaves no residue;
/// * a failure AFTER the lock is taken (a destination root that is not a
///   directory, so the destination manifest read fails inside `run`) leaves
///   the record in place and FREE: a subsequent acquisition succeeds
///   IMMEDIATELY instead of reporting "held by".
#[test]
fn an_error_exit_releases_the_destination_lock() {
    let dir = fixture_tmpdir(&env()).unwrap();

    // (a) FAILURE BEFORE THE LOCK: the missing source root fails the strict
    // source manifest read, before ownership is established.
    let missing = dir.path().join("missing-source");
    let dst_before = dir.path().join("dst-before");
    let lock_before = destination_lock_path(&dst_before).unwrap();
    let err = owned(
        Direction::Push,
        &missing,
        &transport(&dst_before),
        &ReplaceAll,
        Keep,
    )
    .expect_err("a missing source root must fail the run");
    assert!(
        matches!(err.error(), Error::Materialization(_)),
        "got {err:?}"
    );
    assert!(
        !dst_before.exists(),
        "a pre-lock refusal must NOT create the destination root"
    );
    assert!(
        !lock_before.exists(),
        "a pre-lock refusal must NOT create the destination lock record"
    );

    // (b) FAILURE AFTER THE LOCK: the destination manifest read refuses a
    // non-directory destination root, inside `run`, with the lock held.
    let src = dir.path().join("src");
    write(&src.join("f"), b"ok");
    let dst_after = dir.path().join("dst-after");
    fs::write(&dst_after, b"not a directory").unwrap();
    let lock_after = destination_lock_path(&dst_after).unwrap();
    let err = owned(
        Direction::Push,
        &src,
        &transport(&dst_after),
        &ReplaceAll,
        Keep,
    )
    .expect_err("a non-directory destination root must fail the run");
    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    assert!(
        lock_after.exists(),
        "the lock record must have been created (and held) before the destination manifest failed"
    );
    let after = crate::lock::FileLock::acquire(&lock_after, "after-error")
        .expect("the destination lock must be released on the error exit");
    drop(after);
}

/// Two REAL processes against one destination never interleave: the second run
/// is refused at acquisition while the first holds the lock, and the first
/// completes correctly.
///
/// The holder is a CHILD PROCESS (the test binary re-entered with `--exact`)
/// whose caller-supplied policy signals readiness and then blocks INSIDE the
/// run, so the parent observes "the child holds the lock" from a file rather
/// than a sleep. The parent's own run is refused by the SAME record.
///
/// PRE-FIX PROOF: before this change the parent's run took no lock, so it
/// would proceed (and `expect_err` panics); the two processes would interleave
/// on the destination.
#[cfg(unix)]
#[test]
fn two_concurrent_syncs_against_one_destination_do_not_interleave() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("f"), b"first");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();
    let held = dir.path().join("held");
    let release = dir.path().join("release");

    let holder = LockHolder::spawn(&src, &dst, &held, &release);
    assert!(
        wait_for_file(&held),
        "the holder never reported holding the lock"
    );

    let err = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep)
        .expect_err("the second run must be refused while the holder holds the lock");
    assert!(
        err.error().to_string().contains("held by"),
        "the refusal must name the holder: {err}"
    );

    let status = holder.finish();
    assert!(status.success(), "the lock holder failed: {status:?}");
    assert_eq!(read(&dst.join("f")), b"first");
}

/// Killing the holder releases the lock: `flock` is released by the kernel on
/// process death, so a subsequent acquisition succeeds within a bounded time.
///
/// The holder is SIGKILLed (`Child::kill`) while it blocks inside the run. The
/// parent then acquires the SAME record in a bounded loop. A mechanism that
/// did not rest on the descriptor's lifetime (a content record, say) would
/// leave the record held forever and this test would fail at the deadline.
///
/// This test is meaningful only from this change on (pre-fix `sync` took no
/// lock, so there was no holder to kill); it is the regression guard for the
/// SIGKILL release property.
#[cfg(unix)]
#[test]
fn a_killed_holder_releases_the_destination_lock() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("f"), b"payload");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();
    let held = dir.path().join("held");
    let release = dir.path().join("release");
    let lock_path = destination_lock_path(&dst).unwrap();

    let holder = LockHolder::spawn(&src, &dst, &held, &release);
    assert!(
        wait_for_file(&held),
        "the holder never reported holding the lock"
    );
    assert!(
        crate::lock::FileLock::acquire(&lock_path, "before-kill").is_err(),
        "the record must be held before the kill"
    );

    let status = holder.kill();
    assert!(
        !status.success(),
        "the holder must have been killed: {status:?}"
    );

    let deadline = std::time::Instant::now() + LOCK_WAIT;
    let mut acquired = None;
    while std::time::Instant::now() < deadline {
        match crate::lock::FileLock::acquire(&lock_path, "after-kill") {
            Ok(guard) => {
                acquired = Some(guard);
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    assert!(
        acquired.is_some(),
        "the destination lock was not released after the holder was SIGKILLed; \
         flock must release on process death"
    );
}

/// THE OWNERSHIP AXIS. The owned path REFUSES a destination whose lock the
/// crate cannot take (here: a destination that declares itself REMOTE),
/// mutates nothing, and names the value that states the weaker guarantee. An
/// agentic caller therefore cannot reach an unowned run by taking ownership;
/// it has to type `DestinationOwnership::Unowned`.
///
/// This also pins the ORDERING the refusal depends on: the refusal is a PURE
/// decision taken BEFORE [`Remote::prepare_identity`], so a refused run leaves
/// no transport residue. A real `SshTransport::prepare_identity` creates the
/// local `ControlMaster` mux directory (0700) and pins the verified host key;
/// the [`RecordingRemote`] double cannot observe those real filesystem
/// effects, so this pins the strongest consequence it CAN observe — that
/// `prepare_identity` was never CALLED (`identity_calls() == 0`). Mutation
/// proof: deleting the early `destination_lock_record` check leaves every
/// other assertion in this test green (the later `lock_destination` still
/// refuses with the same message) but calls `prepare_identity` first, so this
/// assertion is what fails. The residue the double cannot observe — the
/// `ControlMaster` mux directory (0700) and the pinned host key — is now
/// enumerated in the module doc and measured in-crate with a hermetic `TMPDIR`,
/// the real `prepare_identity`, and the fake keyscan seam by
/// `transport::ssh::runner::runner_property_tests::prepare_identity_creates_and_keeps_the_residue_outside_the_root`,
/// so this call-count assertion is no longer the only cover for the ordering
/// gap.
#[test]
fn sync_refuses_a_remote_destination_and_points_at_the_unowned_value() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"payload");
    fs::create_dir_all(&dst).unwrap();
    let before = canonicalize_tree(&dst).unwrap();
    let remote = RecordingRemote::over(transport(&dst), false);
    let error = owned(
        Direction::Push,
        &src,
        &remote,
        &ReplaceAll,
        Extraneous::Keep,
    )
    .expect_err("sync must refuse a destination whose lock the crate cannot take");
    assert_eq!(
        error.report().transfers,
        0,
        "the refusal is before every mutation"
    );
    assert_eq!(
        remote.identity_calls(),
        0,
        "the refusal must precede prepare_identity: preparing the transport \
         creates its mux directory and pins its host key, so a refused run \
         must not prepare it (a real SshTransport's prepare_identity creates \
         the control-socket directory and pins the verified host key; the \
         double observes the call, which is the strongest in-crate proof)"
    );
    let text = error.to_string();
    assert!(
        text.contains("DestinationOwnership::Unowned"),
        "the refusal must name the unowned value: {text}"
    );
    assert_eq!(
        canonicalize_tree(&dst).unwrap(),
        before,
        "the refused run mutated nothing"
    );
}

/// The weak path is REACHABLE and correct: an explicitly unowned run against
/// the same remote destination transfers and verifies normally. The refusal
/// above is a redirect, not a removal of the capability.
#[test]
fn an_unowned_run_reaches_a_remote_destination_and_still_verifies() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    write(&src.join("f"), b"payload");
    write(&src.join("d/g"), b"nested");
    fs::create_dir_all(&dst).unwrap();
    let remote = RecordingRemote::over(transport(&dst), false);
    let report = unowned(
        Direction::Push,
        &src,
        &remote,
        &ReplaceAll,
        Extraneous::Keep,
    )
    .expect("the unowned entry point must run against a remote destination");
    assert!(report.conflicts.is_empty(), "{:?}", report.conflicts);
    assert!(
        report.verify_failures.is_empty(),
        "{:?}",
        report.verify_failures
    );
    assert_eq!(
        canonicalize_tree(&src).unwrap(),
        canonicalize_tree(&dst).unwrap()
    );
}

// ---------------------------------------------------------------------------
// F1: the sync entry points prepare the transport's host identity.
// ---------------------------------------------------------------------------

/// The `Locked` token is BOUND to the run it was taken for: a token acquired
/// for one destination is REFUSED when handed to a run against another, so a
/// caller cannot take the lock on a destination it will not mutate.
#[test]
fn a_destination_ownership_token_is_bound_to_its_run() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("f"), b"payload");
    let locked_dst = dir.path().join("locked-dst");
    let other_dst = dir.path().join("other-dst");
    fs::create_dir_all(&locked_dst).unwrap();
    fs::create_dir_all(&other_dst).unwrap();
    let before = canonicalize_tree(&other_dst).unwrap();

    // Take ownership for `locked_dst`...
    let ownership = DestinationOwnership::lock(Direction::Push, &src, &transport(&locked_dst))
        .expect("acquiring the lock for the real destination");
    // ...and hand it to a run against `other_dst`.
    let err = sync(
        Direction::Push,
        &src,
        &transport(&other_dst),
        &ReplaceAll,
        Keep,
        ownership,
    )
    .expect_err("a token taken for another destination must be refused");
    assert!(
        err.error()
            .to_string()
            .contains("destination ownership was taken for"),
        "the refusal must name the mismatch: {err}"
    );
    assert_eq!(
        canonicalize_tree(&other_dst).unwrap(),
        before,
        "the mismatched run must mutate nothing"
    );
}

/// F1: every sync entry point that reaches the transport runs
/// [`Remote::prepare_identity`] BEFORE its first remote request.
///
/// A real `sshd` is not available to the suite, so this pins the CONTRACT with
/// a [`Remote`] double that records WHEN `prepare_identity` was called
/// relative to the first remote request. It does NOT prove real-SSH behaviour
/// (no control socket is created, no host key is pinned): it proves the run
/// calls the transport's own preparation at the right point. See
/// `a_transport_preparation_failure_leaves_nothing_behind` for the failure
/// contract.
#[test]
fn sync_prepares_the_transport_identity_before_the_first_remote_request() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let local = dir.path().join("local");
    fs::create_dir_all(&local).unwrap();
    let remote_root = dir.path().join("remote");
    fs::create_dir_all(&remote_root).unwrap();

    // A non-local double: `remote_manifest` must go through `exec`, so the
    // FIRST remote request is observable. The far-side command fails, so the
    // run ends there — but the identity must already be prepared.
    let broken_exec = || ExecOutcome {
        exit_code: 1,
        stdout: String::new(),
        stderr: "far-side boom".to_string(),
        timeout_cause: None,
    };

    let mut owned_recorder = RecordingRemote::over(transport(&remote_root), false);
    owned_recorder.exec_failure = Some(broken_exec());
    let err = owned(Direction::Pull, &local, &owned_recorder, &ReplaceAll, Keep)
        .expect_err("the far-side manifest command failed");
    assert!(matches!(err.error(), Error::Transport(_)), "got {err:?}");
    // The entry point prepares the transport identity, and the source
    // manifest primitive now SELF-PREPARES too (the D3 fix), so a PULL records
    // exactly two preparations. What matters is unchanged: EVERY prepare call
    // runs before the FIRST remote request (op index 0).
    assert_eq!(
        owned_recorder.identity_calls(),
        2,
        "the owned path prepares once and the self-preparing source manifest primitive \
         prepares again (idempotent)"
    );
    assert_eq!(
        owned_recorder.identity_op_index(),
        vec![0, 0],
        "EVERY prepare_identity call must run before the FIRST remote request"
    );
    assert!(
        owned_recorder.remote_requests() > 0,
        "the run must have reached the transport"
    );

    // The explicitly-unowned path (the only way to reach a remote
    // destination) prepares too.
    let mut unowned_recorder = RecordingRemote::over(transport(&remote_root), false);
    unowned_recorder.exec_failure = Some(broken_exec());
    let _ = unowned(
        Direction::Pull,
        &local,
        &unowned_recorder,
        &ReplaceAll,
        Keep,
    )
    .expect_err("the far-side manifest command failed");
    assert_eq!(
        unowned_recorder.identity_calls(),
        2,
        "the unowned path prepares once and the self-preparing source manifest primitive \
         prepares again (idempotent)"
    );
    assert_eq!(
        unowned_recorder.identity_op_index(),
        vec![0, 0],
        "EVERY prepare_identity call must run before the FIRST remote request"
    );
    assert!(unowned_recorder.remote_requests() > 0);
}

/// F1: a failure from the transport's identity preparation surfaces as THAT
/// failure and leaves no mutation, no residue, and no held lock.
///
/// Preparation runs before the destination lock record is created, so a
/// destination the entry point WOULD have locked is left with no lock record at
/// all — strictly stronger than "the lock is released". The double is
/// non-local so the failure is observed before any remote request.
#[test]
fn a_transport_preparation_failure_leaves_nothing_behind() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let dst = dir.path().join("dst");
    write(&dst.join("f"), b"payload");
    let before = canonicalize_tree(&dst).unwrap();

    let mut remote = RecordingRemote::over(transport(&dst), false);
    remote.identity_failure = Some("injected identity preparation failure".to_string());
    // The run would fail later anyway; the assertion is that the diagnostic
    // names the PREPARATION failure, not a downstream "identity is not
    // configured" or a far-side failure.
    remote.exec_failure = Some(ExecOutcome {
        exit_code: 1,
        stdout: String::new(),
        stderr: "downstream far-side failure".to_string(),
        timeout_cause: None,
    });

    // A PULL puts the LOCAL tree on the destination side, so the owned entry
    // point would have taken the destination lock had preparation succeeded.
    let err = owned(Direction::Pull, &dst, &remote, &ReplaceAll, Delete)
        .expect_err("the injected identity preparation failure must fail the run");
    let msg = err.error().to_string();
    assert!(
        msg.contains("injected identity preparation failure"),
        "the underlying preparation failure is reported: {msg}"
    );
    assert!(
        msg.contains("host-identity preparation failed"),
        "the diagnostic names the preparation stage: {msg}"
    );
    assert_eq!(remote.ops(), 0, "no mutation was attempted");
    assert_eq!(
        remote.remote_requests(),
        0,
        "the failure is before every remote request"
    );
    assert_eq!(
        canonicalize_tree(&dst).unwrap(),
        before,
        "the destination is untouched"
    );
    let lock = destination_lock_path(&dst).expect("a sibling record location");
    assert!(
        !lock.exists(),
        "a run refused before preparation leaves no lock record at {lock:?}"
    );
}

/// F2: the sibling destination record and the in-root `Layout::lock` are
/// DIFFERENT files and do NOT exclude each other. A caller holding a
/// [`crate::lock::FileLock`] on `<dst>/state/operation.lock` (the
/// `Layout::lock` path) does not stop an owned `sync` from running against
/// `<dst>`, and while a `sync` holds the sibling record the in-root lock is
/// still free. The module docs state this precisely; this test pins it so the
/// old "SAME record" claim cannot come back silently.
#[test]
fn the_sibling_record_does_not_compose_with_the_in_root_layout_lock() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("f"), b"payload");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();

    // `Layout::empty().lock` is the CONVENTIONAL in-root record.
    let in_root = dst.join(Layout::empty().lock.as_path());
    let sibling = destination_lock_path(&dst).expect("a sibling record location");
    assert_ne!(
        sibling, in_root,
        "the sibling record and the in-root Layout::lock are different files"
    );

    // Direction 1: holding the in-root lock does not exclude an owned `sync`.
    let in_root_guard = crate::lock::FileLock::acquire(&in_root, "in-root-holder")
        .expect("take the in-root layout lock");
    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep)
        .expect("the in-root layout lock must not exclude a sync");
    assert!(report.applied.contains(&"f".to_string()), "{report:?}");
    drop(in_root_guard);

    // Direction 2: while the sync holds the sibling record, the in-root lock is
    // still free. A NEW source entry forces the policy probe to run INSIDE the
    // run, at which point the sibling record is held.
    write(&src.join("g"), b"second");
    let probe_path = in_root.clone();
    let probe_fired = std::sync::Arc::new(AtomicBool::new(false));
    let fired = probe_fired.clone();
    let probe = move |_rel: &str, _kind: EntryKind| {
        let guard = crate::lock::FileLock::acquire(&probe_path, "in-root-probe")
            .expect("a sync holding the sibling record must not exclude the in-root lock");
        drop(guard);
        fired.store(true, Ordering::SeqCst);
        EntryPolicy::Replace
    };
    let report = owned(Direction::Push, &src, &transport(&dst), &probe, Keep)
        .expect("the run must succeed with the in-run probe");
    assert!(
        probe_fired.load(Ordering::SeqCst),
        "the in-run probe must have observed the held sibling record"
    );
    assert!(report.applied.contains(&"g".to_string()), "{report:?}");
}

/// F2 CROSS-CHECK: the record `destination_lock_path` derives must ALWAYS be a
/// spelling [`crate::reserved::is_reserved_name`] calls reserved. The two are
/// separate authorities over the same file name — the derivation owns what the
/// record is CALLED, and `reserved` owns whether a parent sync must LEAVE IT
/// ALONE — so this asserts their agreement directly, across relative, nested,
/// and absolute destination roots.
///
/// LOAD-BEARING BY MUTATION: the record used to hardcode `".operation.lock"`
/// while `is_reserved_name` consumed `reserved::OPERATION_LOCK_SUFFIX`. Change
/// ONLY the constant (say to `".operation.lockX"`) and the hardcoded record is
/// no longer reserved: a parent sync destroys a held lock record (the
/// `a_parent_sync_never_destroys_a_held_nested_lock_record` failure) and THIS
/// test fails on the suffix assertion. With the record DERIVED from the
/// constant, mutating the constant moves both spellings together and both tests
/// still pass — which is the invariant this test exists to protect.
#[test]
fn the_destination_lock_record_is_a_reserved_spelling() {
    for dest in [
        "/tmp/foo",
        "/tmp/a/b/nested",
        "/var/lib/store",
        "foo",
        "./foo",
        "a/b",
        "x/y/z/deep",
    ] {
        let record = destination_lock_path(Path::new(dest))
            .unwrap_or_else(|| panic!("{dest:?} must have a record location"));
        let name = record
            .file_name()
            .unwrap_or_else(|| panic!("the record for {dest:?} names a file"))
            .to_str()
            .unwrap_or_else(|| panic!("the record for {dest:?} is valid UTF-8"));
        // The record spelling is DERIVED: `.` + the root's final component +
        // the ONE authority's suffix. A hardcoded suffix cannot satisfy this
        // once the authority moves.
        let base = Path::new(dest)
            .file_name()
            .unwrap_or_else(|| panic!("{dest:?} names a final component"))
            .to_str()
            .unwrap();
        assert_eq!(
            name,
            format!(".{base}{OPERATION_LOCK_SUFFIX}"),
            "the record for {dest:?} must derive from OPERATION_LOCK_SUFFIX"
        );
        assert!(
            crate::reserved::is_reserved_name(name),
            "the reserved-spelling authority must reserve the record it names: \
             {name:?} for {dest:?}"
        );
    }
}

/// THE SOURCE-QUIESCENCE PRECONDITION, enforced rather than trusted. A source
/// writer rewrites an entry that has ALREADY been read and installed, so the
/// transfer and the destination verification both succeed — yet the tree the
/// plan was made against no longer exists. The run must FAIL CLOSED and name
/// the path that moved, instead of returning an `Ok` about a stale plan.
#[test]
fn a_source_that_changes_after_the_plan_fails_closed_and_names_the_path() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    let local = dir.path().join("local");
    write(&src.join("a"), b"AAA");
    write(&src.join("b"), b"BBB");
    // The first source read is `a`; the hook then rewrites `a` on disk, so the
    // bytes installed and verified are still the planned `AAA`, and only the
    // end-of-run re-read can see the violation.
    let mut remote = RecordingRemote::over(transport(&src), true);
    remote.source_writer = Some((
        1,
        src.clone(),
        AfterWrite::Overwrite("a".to_string(), b"CHANGED".to_vec()),
    ));
    let error = owned(
        Direction::Pull,
        &local,
        &remote,
        &ReplaceAll,
        Extraneous::Keep,
    )
    .expect_err("a source that moved under the run must fail closed");
    let text = error.to_string();
    assert!(
        text.contains("SOURCE changed"),
        "the failure must name the source-quiescence violation: {text}"
    );
    // A DISTINCTIVE token, not a bare character: `contains("a")` was satisfied
    // by the "a" in "changed" and "paths", so a message that named NO path
    // (or the wrong one) still passed. The prose before the list is fixed, so
    // the assertion names the list itself.
    assert!(
        text.contains("changed paths: a"),
        "the changed path must be named: {text}"
    );
    // The transfer itself landed the planned bytes: the run failed over the
    // PLAN, not over the write.
    assert_eq!(read(&local.join("a")), b"AAA");
}

// ---------------------------------------------------------------------------
// F-2 / F-3: the lock record's sibling location.
// ---------------------------------------------------------------------------

/// Env var that turns the test binary into the CHILD that runs the owned entry
/// point with a RELATIVE destination root from a chosen working directory.
#[cfg(unix)]
const RELATIVE_ROOT_CHILD: &str = "STOREKIT_RELATIVE_ROOT_CHILD";
#[cfg(unix)]
const RELATIVE_ROOT_WORK: &str = "STOREKIT_RELATIVE_ROOT_WORK";
#[cfg(unix)]
const RELATIVE_ROOT_SRC: &str = "STOREKIT_RELATIVE_ROOT_SRC";
#[cfg(unix)]
const RELATIVE_ROOT_RESULT: &str = "STOREKIT_RELATIVE_ROOT_RESULT";

/// The CHILD side of the F-3 test: `chdir` into the work directory (the child
/// owns its process, so the process-global cwd change cannot race other tests)
/// and run the OWNED `sync` against a single-component RELATIVE destination
/// root. The outcome is written to the result file so the parent reads it, and
/// the child test passes either way. With the env var unset this is a no-op.
#[cfg(unix)]
#[test]
fn destination_lock_relative_root_child() {
    if std::env::var_os(RELATIVE_ROOT_CHILD).is_none() {
        return;
    }
    let work = PathBuf::from(std::env::var_os(RELATIVE_ROOT_WORK).unwrap());
    let src = PathBuf::from(std::env::var_os(RELATIVE_ROOT_SRC).unwrap());
    let result = PathBuf::from(std::env::var_os(RELATIVE_ROOT_RESULT).unwrap());
    std::env::set_current_dir(&work).expect("chdir into the work directory");
    let outcome = match owned(
        Direction::Pull,
        Path::new("local"),
        &transport(&src),
        &ReplaceAll,
        Keep,
    ) {
        Ok(_) => "ok".to_string(),
        Err(error) => format!("err: {error}"),
    };
    write(&result, outcome.as_bytes());
}

/// F-3 REGRESSION: a single-component RELATIVE destination root through the
/// OWNED entry point. `destination_lock_path("local")` derived a record whose
/// `Path::parent` is `""`, so the lock helper ran `mkdir ""` (ENOENT) and the
/// run failed with a message that did not name the real problem. The record
/// must resolve to `./.local.operation.lock` — the current directory, exactly
/// as the rest of the path handling resolves a relative root.
///
/// The child process does the `chdir`; the parent asserts only on the child's
/// result and files, so the cwd change cannot race the rest of the suite.
#[cfg(unix)]
#[test]
fn the_owned_entry_point_accepts_a_single_component_relative_destination_root() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("f"), b"payload");
    let work = dir.path().join("work");
    fs::create_dir_all(&work).unwrap();
    let result = dir.path().join("result");
    let child = std::process::Command::new(std::env::current_exe().expect("test binary path"))
        .args([
            "--exact",
            "sync::apply::tests::destination_lock_relative_root_child",
            "--nocapture",
        ])
        .env(RELATIVE_ROOT_CHILD, "1")
        .env(RELATIVE_ROOT_WORK, &work)
        .env(RELATIVE_ROOT_SRC, &src)
        .env(RELATIVE_ROOT_RESULT, &result)
        .output()
        .expect("spawn the relative-root child");
    assert!(
        child.status.success(),
        "the child failed: {}",
        String::from_utf8_lossy(&child.stderr)
    );
    let outcome =
        String::from_utf8(fs::read(&result).expect("the child writes its result")).unwrap();
    assert_eq!(outcome, "ok", "the relative-root owned run must succeed");
    assert_eq!(read(&work.join("local/f")), b"payload");
    assert!(
        work.join(".local.operation.lock").exists(),
        "the lock record must be the sibling of the relative root"
    );
}

/// F-2 REGRESSION: taking the destination's operation lock must NOT narrow a
/// directory OUTSIDE the destination root to the store-private `0o700`.
///
/// The lock record is a SIBLING of the root, so a destination whose parent
/// chain is missing made the lock helper's
/// [`crate::atomic::ensure_private_dir_durable`] create that chain AND chmod it
/// `0o700`, on every run including a fully-refused one. The owned entry point
/// must instead create the chain at the SAME platform-default mode the run's
/// own ancestor creation uses (the `*_unowned` path), so the lock path
/// introduces no mode the run would not have used itself.
///
/// The mode is compared against BOTH the unowned path's chain and a plain
/// `create_dir_all` under the same process umask, so the assertion is exact
/// regardless of umask. Under a `0o077` umask the platform default IS `0o700`,
/// so the PARITY assertions are the load-bearing ones there and this test is
/// (correctly) not discriminating.
#[cfg(unix)]
#[test]
fn taking_the_destination_lock_does_not_narrow_a_missing_parent_to_store_private() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    write(&remote_root.join("f"), b"new");

    // OWNED: the lock's sibling record needs the missing parent chain.
    let owned_parent = dir.path().join("owned-parent");
    let owned_dest = owned_parent.join("local");
    owned(
        Direction::Pull,
        &owned_dest,
        &transport(&remote_root),
        &ReplaceAll,
        Keep,
    )
    .expect("an owned pull into a missing parent chain must run");
    assert_eq!(read(&owned_dest.join("f")), b"new");

    // UNOWNED: the run's own `create_dir_all` creates the same missing chain.
    let unowned_parent = dir.path().join("unowned-parent");
    let unowned_dest = unowned_parent.join("local");
    unowned(
        Direction::Pull,
        &unowned_dest,
        &transport(&remote_root),
        &ReplaceAll,
        Keep,
    )
    .expect("an unowned pull into a missing parent chain must run");

    // A plain directory created under the same process umask: the platform
    // default.
    let umask_probe = dir.path().join("umask-probe");
    fs::create_dir_all(&umask_probe).unwrap();

    assert_eq!(
        mode_of(&owned_parent),
        mode_of(&umask_probe),
        "the owned lock path must create a missing parent at the platform \
         default, not the store-private 0o700"
    );
    assert_eq!(
        mode_of(&unowned_parent),
        mode_of(&umask_probe),
        "the unowned path is the reference for the platform default"
    );

    // A FULLY-REFUSED owned run: the parent chain is still created (the record
    // is a sibling) at the platform default, but the destination ROOT and its
    // subtree are NOT — the "creates nothing" contract holds for the root.
    let refused_parent = dir.path().join("refused-parent");
    let refused_dest = refused_parent.join("local");
    let refuse = |_: &str, _: EntryKind| EntryPolicy::Refuse;
    let report = owned(
        Direction::Pull,
        &refused_dest,
        &transport(&remote_root),
        &refuse,
        Keep,
    )
    .unwrap();
    assert_eq!(report.transfers, 0, "{report:?}");
    assert!(
        !refused_dest.exists(),
        "a fully-refused owned pull still creates NOTHING, not even the root"
    );
    assert_eq!(
        mode_of(&refused_parent),
        mode_of(&umask_probe),
        "even a refused run must not narrow the lock record's parent to 0o700"
    );
}

/// A-F2 REGRESSION: a run that REMOVES a nested destination-only subtree must
/// not then fail re-listing a directory it correctly removed.
///
/// `remove_extraneous` inserts each removed entry's PARENT into `touched_dirs`,
/// and the post-removal `verify` pass re-lists every touched directory. For a
/// chain that is ENTIRELY extraneous (`d/d/f`, nothing left under `d`), the run
/// removes `d` too, so listing `d/d` finds an ABSENT ANCESTOR and the
/// fd-confined local destination raises `openat d: ENOENT`; the run then
/// returned `Err` naming paths it had removed correctly. The path-based remote
/// destination maps a missing-parent path to `Ok(None)`, which is why the
/// pre-existing PULL+Delete tests (which keep a shared non-extraneous ancestor
/// alive) never hit this.
#[test]
fn removing_an_all_extraneous_nested_chain_does_not_fail_the_removal_verify() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    fs::create_dir_all(&remote_root).unwrap();
    let local = dir.path().join("local");
    write(&local.join("d/d/f"), b"gone");

    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &ReplaceAll,
        Extraneous::Delete,
    )
    .expect("removing an all-extraneous nested chain must succeed");
    assert_eq!(
        report.extraneous,
        vec!["d".to_string(), "d/d".to_string(), "d/d/f".to_string()],
        "{report:?}"
    );
    assert!(
        report.verify_failures.is_empty(),
        "a correctly removed chain has no verification failure: {report:?}"
    );
    assert!(
        !local.join("d").exists(),
        "the extraneous chain must be fully removed: {report:?}"
    );
}

/// Build an [`Applier`] with a FRESH ancestry memo, for asserting exactly
/// which destinations may populate it. Every other field is the empty default
/// the run constructor uses, so `guard_destination` is the only code that can
/// touch `ancestry_dirs`.
fn applier_with_ancestry_memo<'a, 'b>(
    source: &'b Side<'a>,
    dest: &'b Side<'a>,
    policy: &'b dyn Policy,
    diff: &'b TreeDiff,
) -> Applier<'a, 'b> {
    Applier {
        source,
        dest,
        policy,
        extraneous_policy: Keep,
        diff,
        outcomes: BTreeMap::new(),
        conflicts: BTreeMap::new(),
        extraneous: BTreeSet::new(),
        verify: Vec::new(),
        verified: BTreeSet::new(),
        verify_failures: BTreeSet::new(),
        indeterminate: BTreeMap::new(),
        pending_final: BTreeMap::new(),
        journal: ModeJournal::default(),
        removed: BTreeSet::new(),
        claim_failures: Vec::new(),
        unconfirmed_moves: Vec::new(),
        source_reserved: BTreeMap::new(),
        dest_residue: BTreeSet::new(),
        dest_unsupported: Vec::new(),
        aliased_dest: BTreeMap::new(),
        dest_case_insensitive: None,
        touched_dirs: BTreeSet::from([String::new()]),
        listings: std::cell::RefCell::new(BTreeMap::new()),
        ancestry_dirs: std::cell::RefCell::new(BTreeSet::new()),
        transfers: 0,
    }
}

/// The confinement predicate is a CONJUNCTION: the side kind ([`Side::Local`])
/// AND the platform property ([`crate::atomic::COMPONENT_CONFINED`]). This
/// pins both values on the running platform without a cfg: a `Side::Local` is
/// confined exactly where the platform's primitives are, and a path-based
/// `Side::Remote` is NEVER confined (the applier treats a remote destination
/// as path-based even when a `LocalTransport` backs it, because it cannot see
/// the transport's primitives).
#[test]
fn the_confinement_predicate_conjoins_the_side_and_the_platform() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let local = LocalSide::open(dir.path(), true).unwrap();
    let remote = transport(dir.path());
    let local_side = Side::Local(&local);
    let remote_side = Side::Remote(&remote);

    assert!(
        matches!(&local_side, Side::Local(_)),
        "the fixture must exercise the local side"
    );
    assert!(
        matches!(&remote_side, Side::Remote(_)),
        "the fixture must exercise a path-based side"
    );
    assert_eq!(
        local_side.is_confined_local(),
        crate::atomic::COMPONENT_CONFINED,
        "a Side::Local is confined exactly where the platform's primitives are"
    );
    assert!(
        !remote_side.is_confined_local(),
        "a Side::Remote (even one backed by a LocalTransport) is never confined"
    );
}

/// The ancestry memo is a cached CONFINEMENT fact, so only a destination whose
/// own primitives enforce component confinement may reuse it. This pins the
/// CODE PATH (not the comment): with a path-based `Side::Remote` destination
/// `guard_destination` must leave `ancestry_dirs` EMPTY, and with a
/// `Side::Local` destination it populates the memo exactly where the platform
/// primitives are component-confined.
#[test]
fn the_ancestry_memo_is_off_for_a_path_based_destination_on_this_platform() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let root = dir.path();
    fs::create_dir_all(root.join("a/b")).unwrap();
    let local = LocalSide::open(root, true).unwrap();
    let remote = transport(root);
    let local_side = Side::Local(&local);
    let remote_side = Side::Remote(&remote);
    let empty = LocalSide::empty_tree();
    let diff = crate::sync::diff::diff_trees(&empty, &empty);
    let policy = ReplaceAll;
    let rel = rooted("a/b/c").unwrap();

    // PATH-BASED destination: the preflight IS the confinement, so every
    // probe is live and nothing is cached.
    let remote_applier = applier_with_ancestry_memo(&local_side, &remote_side, &policy, &diff);
    remote_applier
        .guard_destination(&rel, AncestorPolicy::MustExist, FinalPolicy::Unresolved)
        .expect("the existing ancestor chain guards cleanly");
    assert!(
        remote_applier.ancestry_dirs.borrow().is_empty(),
        "a path-based destination must probe live and cache nothing"
    );

    // LOCAL destination: the memo is populated exactly when the platform is
    // component-confined. On a path-based port the local destination is ALSO
    // unconfined, so the memo must stay empty there too.
    let local_applier = applier_with_ancestry_memo(&local_side, &local_side, &policy, &diff);
    local_applier
        .guard_destination(&rel, AncestorPolicy::MustExist, FinalPolicy::Unresolved)
        .expect("the existing ancestor chain guards cleanly");
    assert_eq!(
        !local_applier.ancestry_dirs.borrow().is_empty(),
        crate::atomic::COMPONENT_CONFINED,
        "a Side::Local destination memoizes exactly where the primitives are confined"
    );
    if crate::atomic::COMPONENT_CONFINED {
        let memo = local_applier.ancestry_dirs.borrow();
        assert!(
            memo.contains("a") && memo.contains("a/b"),
            "the memo must hold the confirmed ancestors, got {memo:?}"
        );
    }
}

/// F1 REGRESSION: a PUSH to a destination root that does not exist yet must
/// create and use it, exactly as the local `provision_layout` already did.
///
/// Pre-fix `run` read the destination manifest BEFORE anything created the
/// root, and `remote_manifest` refuses to describe an absent root as a tree,
/// so this call failed with `local remote root <root> cannot be described: No
/// such file or directory (os error 2)` (and, over ssh, `not a directory:
/// <root>`), even though `LocalTransport::provision_layout` creates the base.
/// The push path now provisions the destination it is about to write into
/// before reading its manifest, so the SAME consumer call works for a local
/// and a remote destination.
#[test]
fn push_to_a_fresh_destination_root_creates_it() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("ok"), b"payload");
    let dst_root = dir.path().join("fresh-dst");
    assert!(
        !dst_root.exists(),
        "premise: the destination root does not exist"
    );

    let remote = transport(&dst_root);
    let report = owned(Direction::Push, &src, &remote, &ReplaceAll, Keep)
        .expect("a push to a fresh destination must create and use the root");

    assert!(dst_root.is_dir(), "the destination root was created");
    assert_eq!(read(&dst_root.join("ok")), b"payload");
    assert_eq!(report.transfers, 1, "{report:?}");
    assert!(report.conflicts.is_empty(), "{report:?}");
}

/// The same fresh-destination push through the UNOWNED entry point (the one a
/// remote destination requires), so the provisioning is on the common path and
/// not only the lock-taking one.
#[test]
fn push_unowned_to_a_fresh_destination_root_creates_it() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("ok"), b"payload");
    let dst_root = dir.path().join("fresh-dst-unowned");

    let remote = transport(&dst_root);
    let report = unowned(Direction::Push, &src, &remote, &ReplaceAll, Keep)
        .expect("an unowned push to a fresh destination must create the root");

    assert!(dst_root.is_dir(), "the destination root was created");
    assert_eq!(read(&dst_root.join("ok")), b"payload");
    assert_eq!(report.transfers, 1, "{report:?}");
}

/// F1 `Layout::empty()` usability, end to end: a layout with no bootstrap
/// directories and no receiver marker is enough to provision a fresh
/// destination. (`transport` builds exactly `Layout::empty()`.)
#[test]
fn push_to_a_fresh_destination_works_with_an_empty_layout() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("nested/ok"), b"payload");
    let dst_root = dir.path().join("empty-layout-dst");

    let remote = transport(&dst_root);
    owned(Direction::Push, &src, &remote, &ReplaceAll, Keep)
        .expect("Layout::empty() must provision a fresh destination");

    // No SPURIOUS entries: only what the source holds (plus the directory the
    // source itself has).
    let mut names: Vec<String> = fs::read_dir(&dst_root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, vec!["nested".to_string()], "{names:?}");
    assert_eq!(read(&dst_root.join("nested/ok")), b"payload");
}

/// F2 REGRESSION (absolute symlink): a destination-only entry the manifest
/// model refuses must not block the WHOLE run, including its own sanctioned
/// deletion.
///
/// Pre-fix `canonicalize_tree` refused `current -> /opt/app/v1` unconditionally
/// and the destination manifest is built BEFORE the diff, so this run died at
/// destination-manifest time with `materialization error: absolute symlink not
/// allowed: <dst>/current` and never reached the `Extraneous::Delete` the
/// caller asked for. An absolute `current -> /abs/release` symlink is the
/// canonical deploy layout, so this is a realistic tree, not a corner case.
#[cfg(unix)]
#[test]
fn sanctioned_delete_clears_an_absolute_symlink_destination_entry() {
    use std::os::unix::fs::symlink;
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("ok"), b"payload");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();
    symlink("/opt/app/v1", dst.join("current")).unwrap();
    assert!(
        fs::symlink_metadata(dst.join("current")).is_ok(),
        "premise: the absolute symlink is present"
    );
    // PRE-FIX PROOF: the STRICT canonicalizer still refuses this entry with
    // exactly the message the run used to die on at destination-manifest time
    // (`sync` did not tolerate it, so the whole run failed here).
    assert_eq!(
        canonicalize_tree(&dst).unwrap_err().to_string(),
        format!(
            "materialization error: absolute symlink not allowed: {}",
            dst.join("current").display()
        )
    );

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete)
        .expect("a sanctioned deletion of an absolute-symlink destination entry must run");

    assert!(
        fs::symlink_metadata(dst.join("current")).is_err(),
        "the sanctioned deletion removed the absolute symlink: {report:?}"
    );
    assert_eq!(read(&dst.join("ok")), b"payload");
    assert!(report.conflicts.is_empty(), "{report:?}");
    assert!(report.verify_failures.is_empty(), "{report:?}");
}

/// F2 REGRESSION (escaping symlink): the second refusal, same capability.
///
/// Pre-fix: `materialization error: escaping symlink not allowed: <dst>/esc`.
#[cfg(unix)]
#[test]
fn sanctioned_delete_clears_an_escaping_symlink_destination_entry() {
    use std::os::unix::fs::symlink;
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("ok"), b"payload");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();
    symlink("../../../etc/passwd", dst.join("esc")).unwrap();
    // PRE-FIX PROOF: the strict canonicalizer's exact message.
    assert_eq!(
        canonicalize_tree(&dst).unwrap_err().to_string(),
        format!(
            "materialization error: escaping symlink not allowed: {}",
            dst.join("esc").display()
        )
    );

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete)
        .expect("a sanctioned deletion of an escaping-symlink destination entry must run");

    assert!(
        fs::symlink_metadata(dst.join("esc")).is_err(),
        "the sanctioned deletion removed the escaping symlink: {report:?}"
    );
    assert_eq!(read(&dst.join("ok")), b"payload");
    assert!(report.conflicts.is_empty(), "{report:?}");
}

/// F2 REGRESSION (hard link): the third refusal, same capability — and the
/// removal unlinks ONE name without destroying the other.
///
/// Pre-fix: `materialization error: hard links not allowed: <dst>/hard`.
#[cfg(unix)]
#[test]
fn sanctioned_delete_clears_a_hard_link_destination_entry_without_touching_its_twin() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("ok"), b"payload");
    // The SOURCE holds the twin under the same name and content, so the diff
    // classifies the twin `Same` (it must be left alone) while `hard` is
    // destination-only.
    write(&src.join("kept"), b"shared-bytes");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();
    write(&dst.join("hard"), b"shared-bytes");
    fs::hard_link(dst.join("hard"), dst.join("kept")).unwrap();
    assert_eq!(
        {
            use std::os::unix::fs::MetadataExt;
            fs::metadata(dst.join("hard")).unwrap().nlink()
        },
        2,
        "premise: the destination entry is a hard link"
    );
    // PRE-FIX PROOF: the strict canonicalizer's message (the walk may name
    // EITHER link, so the assertion pins the reason and the tree, not which of
    // the two names readdir yielded first).
    let strict = canonicalize_tree(&dst).unwrap_err().to_string();
    assert!(
        strict.starts_with("materialization error: hard links not allowed: ")
            && strict.contains("/dst/"),
        "{strict}"
    );

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete)
        .expect("a sanctioned deletion of a hard-link destination entry must run");

    assert!(
        fs::symlink_metadata(dst.join("hard")).is_err(),
        "the sanctioned deletion removed the destination-only hard link: {report:?}"
    );
    assert_eq!(
        read(&dst.join("kept")),
        b"shared-bytes",
        "the twin the source holds is left intact: {report:?}"
    );
    assert_eq!(read(&dst.join("ok")), b"payload");
    assert!(report.conflicts.is_empty(), "{report:?}");
    // W4: the annotation survives the sanctioned removal (the entry was
    // observed as unsupported even though `Delete` removed it), and `hard` is
    // still named by `extraneous`.
    for name in ["hard", "kept"] {
        let reason = unsupported_reason(&report, name);
        assert!(
            reason.starts_with("hard links not allowed: "),
            "the report must explain why {name} is tolerated: {reason}"
        );
    }
    assert_report_lists_disjoint(&report);
}

/// F2 (LOCAL destination, PULL direction): the same tolerance on the local
/// destination manifest, so the capability does not depend on the direction.
#[cfg(unix)]
#[test]
fn sanctioned_delete_clears_an_absolute_symlink_in_a_local_pull_destination() {
    use std::os::unix::fs::symlink;
    let dir = fixture_tmpdir(&env()).unwrap();
    let remote_root = dir.path().join("remote");
    write(&remote_root.join("ok"), b"payload");
    let local = dir.path().join("local");
    fs::create_dir_all(&local).unwrap();
    symlink("/opt/app/v1", local.join("current")).unwrap();
    // PRE-FIX PROOF: the strict canonicalizer's exact message.
    assert_eq!(
        canonicalize_tree(&local).unwrap_err().to_string(),
        format!(
            "materialization error: absolute symlink not allowed: {}",
            local.join("current").display()
        )
    );

    let report = owned(
        Direction::Pull,
        &local,
        &transport(&remote_root),
        &ReplaceAll,
        Delete,
    )
    .expect("a sanctioned deletion of a local destination's absolute symlink must run");

    assert!(
        fs::symlink_metadata(local.join("current")).is_err(),
        "the sanctioned deletion removed the local absolute symlink: {report:?}"
    );
    assert_eq!(read(&local.join("ok")), b"payload");
    assert!(report.conflicts.is_empty(), "{report:?}");
}

/// F2, `Extraneous::Keep`: `keep` must report the unsupported destination entry
/// instead of dying, so a consumer can at least list what differs.
#[cfg(unix)]
#[test]
fn keep_reports_an_unsupported_destination_entry_without_failing_the_run() {
    use std::os::unix::fs::symlink;
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("ok"), b"payload");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();
    symlink("/opt/app/v1", dst.join("current")).unwrap();

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep)
        .expect("a kept unsupported destination entry must be reported, not fatal");

    assert!(
        fs::symlink_metadata(dst.join("current")).is_ok(),
        "Keep must leave the unsupported entry in place: {report:?}"
    );
    assert!(
        report.extraneous.contains(&"current".to_string()),
        "the unsupported entry is reported extraneous: {report:?}"
    );
    // W4: the OUTCOME alone left the caller unable to learn WHY the entry was
    // tolerated, so the report must also carry the strict rule's reason. The
    // annotation is attached to the path `extraneous` already names.
    assert_eq!(
        unsupported_reason(&report, "current"),
        format!(
            "absolute symlink not allowed: {}",
            dst.join("current").display()
        ),
        "the tolerated reason must be reported verbatim: {report:?}"
    );
    assert_report_lists_disjoint(&report);
}

/// W4 (hard link): a destination hard-link pair whose content matches the
/// source is `skipped` — the run correctly mutates nothing — and before the
/// annotation the caller had NO signal that the two names are aliased. The
/// report must name the skipped twin with the hard-link refusal so a consumer
/// can act (break the link) before mirroring the source faithfully.
#[cfg(unix)]
#[test]
fn the_report_explains_a_tolerated_hard_link_destination_entry() {
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(&src.join("ok"), b"payload");
    // The SOURCE holds `kept` with the shared content, so the destination twin
    // is `Same` and is SKIPPED.
    write(&src.join("kept"), b"shared-bytes");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();
    write(&dst.join("kept"), b"shared-bytes");
    fs::hard_link(dst.join("kept"), dst.join("hard")).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(
        fs::metadata(dst.join("kept")).unwrap().nlink(),
        2,
        "premise: the destination entries are hard links"
    );

    let report = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Keep)
        .expect("a kept unsupported destination entry must be reported, not fatal");

    assert!(
        report.skipped.contains(&"kept".to_string()),
        "the twin the source holds is skipped (nothing mutated): {report:?}"
    );
    assert!(
        report.extraneous.contains(&"hard".to_string()),
        "the destination-only twin is kept and reported extraneous: {report:?}"
    );
    for name in ["kept", "hard"] {
        let reason = unsupported_reason(&report, name);
        assert!(
            reason.starts_with("hard links not allowed: ") && reason.contains("dst"),
            "the report must explain why {name} is tolerated: {reason}"
        );
    }
    assert_report_lists_disjoint(&report);
}

/// F2 SOUNDNESS GATE: an unsupported destination entry may be DELETED under a
/// sanction, but the run must NEVER write a source entry over it. The refusal
/// names the path, the reason, and the remedy, and it fires BEFORE any
/// transfer.
#[cfg(unix)]
#[test]
fn a_source_entry_over_an_unsupported_destination_entry_is_refused_before_any_transfer() {
    use std::os::unix::fs::symlink;
    let dir = fixture_tmpdir(&env()).unwrap();
    let src = dir.path().join("src");
    write(
        &src.join("current"),
        b"a regular file the source wants installed",
    );
    write(&src.join("ok"), b"should not be transferred");
    let dst = dir.path().join("dst");
    fs::create_dir_all(&dst).unwrap();
    symlink("/opt/app/v1", dst.join("current")).unwrap();

    let failure = owned(Direction::Push, &src, &transport(&dst), &ReplaceAll, Delete)
        .expect_err("writing over an unsupported destination entry must be refused");

    let message = failure.to_string();
    assert!(
        message.contains("current"),
        "the refusal names the path: {message}"
    );
    assert!(
        message.contains("absolute symlink not allowed"),
        "the refusal names the reason: {message}"
    );
    assert!(
        message.contains("Remedy"),
        "the refusal names the remedy: {message}"
    );
    assert!(
        fs::symlink_metadata(dst.join("current")).is_ok(),
        "the unsupported entry is untouched: {message}"
    );
    assert!(
        fs::symlink_metadata(dst.join("ok")).is_err(),
        "NOTHING was transferred before the refusal: {message}"
    );
}
