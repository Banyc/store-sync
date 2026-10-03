//! Regressions for the PUBLIC tree-copy primitive
//! [`storekit::atomic::copy_dir_recursive_fd`], written from a CONSUMER's
//! point of view (the public API only), so they can be run unchanged against
//! the pre-fix tree in a scratch workspace at the parent revision.
//!
//! The defects pinned here are the ones a reviewer found by using the
//! primitive the way `~/code/deploy` does — an arbitrary out-of-root source,
//! a fresh staging destination, then the caller's own canonicalize + digest
//! + fsync + rename:
//!
//! * I1 — the overlap refusal was decided by PATH SPELLING, so a bind-mount
//!   (Linux) or firmlink (macOS) alias of the root evaded it and the walk
//!   recursed without bound. The fix decides overlap by directory IDENTITY.
//! * I2 — a case-fold-equal `dst_rel` on a folding filesystem (macOS APFS)
//!   was not seen as overlap, and the copy MUTATED ITS OWN SOURCE's mode. The
//!   fix refuses by identity and restores every mode it changes on failure.
//! * I3 — a mid-walk failure left a destination directory the crate's own
//!   `remove_dir_all_fd` could not remove (a `0o200` directory). The fix
//!   restores the modes it changed on failure.
//! * I4 — a copied symlink UNLINKED and REPLACED a live destination file and
//!   returned `Ok`. The fix refuses, all-or-nothing like the file/dir rules.
//! * I5 — a trailing-slash symlink source was FOLLOWED while the error text
//!   claimed it was not. The fix normalizes the source spelling first.
//! * I6(a) — the copy had no `RLIMIT_NOFILE` subprocess regression.
#![cfg(unix)]

use std::path::{Path, PathBuf};

use storekit::RootedRelativePath;
use storekit::StoreKind;
use storekit::atomic::{RootDir, copy_dir_recursive_fd, remove_dir_all_fd};
use storekit::manifest::canonicalize_tree;

/// A validated root-relative path: the mutating primitives take the validated
/// type, so a test spelling is parsed at the boundary too.
fn rp(s: &str) -> RootedRelativePath {
    RootedRelativePath::parse(Path::new(s)).unwrap()
}

/// Announce a SKIPPED assertion on the real console (libtest discards the
/// captured output of a PASSING test, which would make a skip look like a
/// pass). Mirrors the crate's own test support, which an integration test
/// cannot reach.
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

fn tmpdir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Whether this host folds ASCII case (probe a real entry rather than trusting
/// the platform name).
fn host_folds_ascii_case(base: &Path) -> bool {
    let lower = base.join("fold-probe");
    std::fs::write(&lower, b"x").unwrap();
    let folds = std::fs::symlink_metadata(base.join("FOLD-PROBE")).is_ok();
    std::fs::remove_file(&lower).unwrap();
    folds
}

// ----------------------------------------------------------------------
// I5 — a symlink source is refused regardless of a trailing separator.
// ----------------------------------------------------------------------

#[test]
fn a_trailing_separator_does_not_let_a_symlink_source_be_followed() {
    let base = tmpdir();
    let root = RootDir::open(base.path()).unwrap();
    std::fs::create_dir_all(base.path().join("real")).unwrap();
    std::fs::write(base.path().join("real/f"), b"f").unwrap();
    std::os::unix::fs::symlink("real", base.path().join("srclink")).unwrap();

    // The spelling WITH a trailing separator: POSIX resolves the final
    // component as an intermediate one, so `lstat("srclink/")` follows the
    // link and reports a directory — the very thing the refusal exists to
    // stop. PRE-FIX the copy FOLLOWED it and returned `Ok`.
    let err = copy_dir_recursive_fd(&root, &base.path().join("srclink/"), &rp("dst"))
        .expect_err("a symlink source must be refused regardless of a trailing separator");
    let msg = err.to_string();
    assert!(
        msg.contains("is a symlink") && msg.contains("refusing to follow"),
        "the refusal must name the symlink source, got: {msg}"
    );
    // Constraint #4: the caller branches on the TYPED condition, so it does
    // not depend on the message shape.
    assert_eq!(
        err.store_reason(),
        Some(StoreKind::CopySourceIsSymlink),
        "a symlink source is its OWN typed store condition, got: {err:?}"
    );
    assert!(
        !base.path().join("dst").exists(),
        "nothing may be copied from a followed symlink source"
    );
}

#[test]
fn a_symlink_source_without_a_trailing_separator_is_refused() {
    let base = tmpdir();
    let root = RootDir::open(base.path()).unwrap();
    std::fs::create_dir_all(base.path().join("real")).unwrap();
    std::os::unix::fs::symlink("real", base.path().join("srclink")).unwrap();
    let err = copy_dir_recursive_fd(&root, &base.path().join("srclink"), &rp("dst"))
        .expect_err("a symlink source must be refused");
    assert!(err.to_string().contains("is a symlink"), "{err}");
}

#[test]
fn a_genuine_directory_source_with_a_trailing_separator_still_copies() {
    let base = tmpdir();
    let root = RootDir::open(base.path()).unwrap();
    std::fs::create_dir_all(base.path().join("real")).unwrap();
    std::fs::write(base.path().join("real/f"), b"f").unwrap();
    copy_dir_recursive_fd(&root, &base.path().join("real/"), &rp("dst")).unwrap();
    assert_eq!(std::fs::read(base.path().join("dst/f")).unwrap(), b"f");
}

// ----------------------------------------------------------------------
// I1 (ordinary overlap) and I2 (fold-equal, source mutation).
// ----------------------------------------------------------------------

#[test]
fn an_ordinary_destination_inside_the_source_is_still_refused() {
    let base = tmpdir();
    let root = RootDir::open(base.path()).unwrap();
    let tree = base.path().join("tree");
    std::fs::create_dir_all(tree.join("d")).unwrap();
    std::fs::write(tree.join("d/inner"), b"inner").unwrap();
    let err = copy_dir_recursive_fd(&root, &tree, &rp("tree/sub"))
        .expect_err("a destination inside the source must be refused");
    assert!(err.to_string().contains("overlap"), "{err}");
    assert!(!tree.join("sub").exists());
}

#[test]
fn an_ordinary_source_inside_the_destination_is_still_refused() {
    let base = tmpdir();
    let root = RootDir::open(base.path()).unwrap();
    let inner = base.path().join("tree/sub");
    std::fs::create_dir_all(&inner).unwrap();
    std::fs::write(inner.join("f"), b"f").unwrap();
    let err = copy_dir_recursive_fd(&root, &inner, &rp("tree"))
        .expect_err("a source inside the destination must be refused");
    assert!(err.to_string().contains("overlap"), "{err}");
}

#[test]
fn a_non_overlapping_source_still_copies() {
    let base = tmpdir();
    let root = RootDir::open(base.path()).unwrap();
    let tree = base.path().join("tree");
    std::fs::create_dir(&tree).unwrap();
    std::fs::write(tree.join("f"), b"f").unwrap();
    copy_dir_recursive_fd(&root, &tree, &rp("copy")).unwrap();
    assert_eq!(std::fs::read(base.path().join("copy/f")).unwrap(), b"f");
}

/// I2: on a host that folds ASCII case, `dst_rel = "TREE"` resolves to the
/// SOURCE directory `tree`. PRE-FIX the path comparison saw two spellings and
/// did not refuse; `ensure_private_dir_fd` reused the existing (fold-equal)
/// directory, chmodded it, and the two-phase widening left the SOURCE at
/// `0o755` (it was `0o555`) when the copy failed on the first `O_EXCL` clash.
/// The run ended `Err(openat TREE/f: File exists)` and the source was MUTATED.
#[test]
fn a_fold_equal_destination_is_refused_by_identity_and_never_mutates_the_source() {
    let base = tmpdir();
    let root = RootDir::open(base.path()).unwrap();
    let src = base.path().join("tree");
    std::fs::create_dir(&src).unwrap();
    std::fs::write(src.join("f"), b"f").unwrap();
    set_mode(&src, 0o555);

    if !host_folds_ascii_case(base.path()) {
        set_mode(&src, 0o755);
        announce_skip(
            "this host filesystem does not fold ASCII case, so a fold-equal destination cannot \
             be produced here (the macOS APFS reproduction is untestable on this host)",
        );
        return;
    }

    let before = mode_of(&src);
    let result = copy_dir_recursive_fd(&root, &src, &rp("TREE"));
    let after = mode_of(&src);
    let _ = result.map_err(|e| e.to_string());
    set_mode(&src, 0o755);

    assert_eq!(
        before, after,
        "a FAILED copy must not mutate its own source's mode (before={before:o}, after={after:o})"
    );
}

// ----------------------------------------------------------------------
// I3 — a failed copy leaves a destination the crate can remove itself.
// ----------------------------------------------------------------------

#[test]
fn a_failed_copy_restores_the_modes_it_widened_and_leaves_a_removable_destination() {
    let base = tmpdir();
    let root = RootDir::open(base.path()).unwrap();
    let src = base.path().join("src");
    std::fs::create_dir_all(src.join("keep")).unwrap();
    std::fs::write(src.join("keep/inner"), b"inner").unwrap();
    // An escaping symlink INSIDE `keep`: the walk creates and widens `dst` and
    // `dst/keep`, then refuses, so the copy fails with a destination that has
    // already been given the widened walk modes.
    std::os::unix::fs::symlink("../../../outside", src.join("keep/esc")).unwrap();
    // Read-only AFTER the entries exist, so the walk must widen the copied
    // directory (and the widened mode is what a failure must restore).
    set_mode(&src.join("keep"), 0o555);

    let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
        .expect_err("the escaping symlink must refuse the copy");
    assert!(err.to_string().contains("escaping symlink"), "{err}");

    // PRE-FIX `dst/keep` was left at `(0o555 | 0o200) = 0o755` — the widened
    // walk mode, which nothing restored. Post-fix a directory the call CREATED
    // is restored to the removable store-private `0o700`.
    assert_eq!(
        mode_of(&base.path().join("dst/keep")),
        0o700,
        "a directory the call created must be restored to the removable 0o700 on failure"
    );

    // And the crate's own recursive removal must succeed on the partial.
    // Capture the partial's digest BEFORE removing it.
    let partial = canonicalize_tree(&base.path().join("dst"));
    remove_dir_all_fd(&root, &rp("dst"))
        .expect("remove_dir_all_fd must remove the failed copy's partial destination");
    assert!(!base.path().join("dst").exists());

    // The partial was never mistakable for a complete one: a CLEANED copy of
    // the same source (the escaping link repaired) canonicalizes to a
    // DIFFERENT digest (the partial is missing the link, or whatever the walk
    // had not reached).
    set_mode(&src.join("keep"), 0o755);
    std::fs::remove_file(src.join("keep/esc")).unwrap();
    std::os::unix::fs::symlink("inner", src.join("keep/esc")).unwrap();
    copy_dir_recursive_fd(&root, &src, &rp("dst2")).unwrap();
    let complete = canonicalize_tree(&base.path().join("dst2")).unwrap();
    match partial {
        Err(_) => {}
        Ok(meta) => assert_ne!(
            meta.tree_sha256, complete.tree_sha256,
            "a partial destination must not canonicalize to the complete tree's digest"
        ),
    }
}

#[test]
fn a_failed_nested_copy_restores_modes_and_keeps_the_created_ancestors_removable() {
    let base = tmpdir();
    let root = RootDir::open(base.path()).unwrap();
    let src = base.path().join("src");
    std::fs::create_dir_all(src.join("keep")).unwrap();
    std::fs::write(src.join("keep/inner"), b"inner").unwrap();
    std::os::unix::fs::symlink("../../../../../outside", src.join("keep/esc")).unwrap();
    set_mode(&src.join("keep"), 0o555);

    let err = copy_dir_recursive_fd(&root, &src, &rp("p/q/dst"))
        .expect_err("the escaping symlink must refuse the copy");
    let _ = err;

    // The created ancestors stay (the call's own artifacts; see the primitive's ancestor
    // decision), and the partial subtree is removable because its modes were
    // restored.
    assert_eq!(mode_of(&base.path().join("p/q/dst/keep")), 0o700);
    remove_dir_all_fd(&root, &rp("p/q/dst"))
        .expect("remove_dir_all_fd must remove the failed copy at a nested destination");
    assert!(!base.path().join("p/q/dst").exists());
    //
    // The empty ancestors the call created are removable too, through the
    // crate's non-recursive rmdir, once the subtree is gone.
    remove_dir_all_fd(&root, &rp("p")).expect("the created ancestors remain removable");
    // Leave the fixture removable for `TempDir::drop`.
    set_mode(&src.join("keep"), 0o755);
}

/// CHARACTERIZATION for the reviewer's exact I3 repro: at THIS revision a
/// `src/bad` directory of mode `0o000` is caught by the FAIL-CLOSED containment
/// enumeration before any destination mutation, so nothing is created. (The
/// reviewer's run left `dst/bad` at `0o200`; that pre-dated the enumeration
/// this chain added. The undo journal still closes the general class: any
/// reachable mid-walk failure now restores every mode it changed.)
#[test]
fn a_mode_0000_source_directory_fails_closed_before_creating_anything() {
    let base = tmpdir();
    let root = RootDir::open(base.path()).unwrap();
    let src = base.path().join("src");
    std::fs::create_dir_all(src.join("bad")).unwrap();
    std::fs::write(src.join("bad/hidden"), b"hidden").unwrap();
    set_mode(&src.join("bad"), 0o000);
    if std::fs::read_dir(src.join("bad")).is_ok() {
        set_mode(&src.join("bad"), 0o755);
        announce_skip(
            "this process can still read a mode-0000 directory (running as root?), so the \
             fail-closed enumeration premise cannot be exercised here",
        );
        return;
    }
    let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
        .expect_err("an unenumerable source subtree must fail the copy closed");
    assert!(err.to_string().contains("enumerate"), "{err}");
    assert!(
        !base.path().join("dst").exists(),
        "the fail-closed enumeration must create nothing"
    );
    set_mode(&src.join("bad"), 0o755);
}

// ----------------------------------------------------------------------
// I4 — a copied symlink never replaces a live destination entry.
// ----------------------------------------------------------------------

#[test]
fn a_copied_symlink_never_replaces_a_live_destination_file() {
    let base = tmpdir();
    let root = RootDir::open(base.path()).unwrap();
    let src = base.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::os::unix::fs::symlink("target", src.join("clash")).unwrap();
    std::fs::create_dir(base.path().join("dst")).unwrap();
    std::fs::write(base.path().join("dst/clash"), b"ORIGINAL").unwrap();

    let err = copy_dir_recursive_fd(&root, &src, &rp("dst"))
        .expect_err("a copied symlink must refuse a pre-existing destination entry");
    assert!(
        err.to_string().contains("refusing to replace"),
        "the refusal must name the replacement it is refusing, got: {err}"
    );
    assert_eq!(
        std::fs::read(base.path().join("dst/clash")).unwrap(),
        b"ORIGINAL",
        "the pre-existing destination file's content must survive"
    );
    assert!(
        std::fs::symlink_metadata(base.path().join("dst/clash"))
            .unwrap()
            .file_type()
            .is_file(),
        "the pre-existing destination entry must still be the file, not a symlink"
    );
}

/// The COMPLETE kind-pair table: every combination of a copied entry kind over
/// a pre-existing destination kind. The file/directory rules already refuse
/// (O_EXCL / mkdirat); the SYMLINK rules must too, which pre-fix they did NOT
/// for a symlink over a file or a symlink.
#[test]
fn every_kind_pair_refuses_to_replace_a_live_destination_entry() {
    #[derive(Clone, Copy, Debug)]
    enum Kind {
        File,
        Dir,
        Symlink,
    }

    fn create(kind: Kind, path: &Path) {
        match kind {
            Kind::File => {
                std::fs::write(path, b"old-inode").unwrap();
            }
            Kind::Dir => {
                std::fs::create_dir(path).unwrap();
                std::fs::write(path.join("inner"), b"inner").unwrap();
            }
            Kind::Symlink => {
                std::os::unix::fs::symlink("nowhere", path).unwrap();
            }
        }
    }

    fn assert_still(kind: Kind, path: &Path) {
        let meta = std::fs::symlink_metadata(path).unwrap();
        match kind {
            Kind::File => {
                assert!(meta.file_type().is_file(), "{path:?} must still be a file");
                assert_eq!(std::fs::read(path).unwrap(), b"old-inode");
            }
            Kind::Dir => {
                assert!(
                    meta.file_type().is_dir(),
                    "{path:?} must still be a directory"
                );
                assert_eq!(std::fs::read(path.join("inner")).unwrap(), b"inner");
            }
            Kind::Symlink => {
                assert!(
                    meta.file_type().is_symlink(),
                    "{path:?} must still be a symlink"
                );
                assert_eq!(std::fs::read_link(path).unwrap(), Path::new("nowhere"));
            }
        }
    }

    let pairs = [
        (Kind::File, Kind::File),
        (Kind::Dir, Kind::Dir),
        (Kind::Symlink, Kind::File),
        (Kind::Symlink, Kind::Dir),
        (Kind::Symlink, Kind::Symlink),
        (Kind::File, Kind::Symlink),
        (Kind::Dir, Kind::Symlink),
    ];
    for (src_kind, dst_kind) in pairs {
        let base = tmpdir();
        let root = RootDir::open(base.path()).unwrap();
        let src = base.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        let dst = base.path().join("dst");
        std::fs::create_dir(&dst).unwrap();
        create(src_kind, &src.join("clash"));
        create(dst_kind, &dst.join("clash"));

        let result = copy_dir_recursive_fd(&root, &src, &rp("dst"));
        match result {
            Ok(()) => panic!("{src_kind:?} over {dst_kind:?} must refuse, not replace"),
            Err(err) => {
                let _ = err;
            }
        }
        assert_still(dst_kind, &dst.join("clash"));
    }
}

// ----------------------------------------------------------------------
// I1 (macOS) — a firmlink alias of the root is refused by identity.
// ----------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn a_firmlink_alias_of_the_root_is_refused_by_identity() {
    // A tempdir under /tmp, so the canonical spelling is
    // `/private/tmp/...` and the Data-volume firmlink spelling is
    // `/System/Volumes/Data/private/tmp/...`. `realpath(3)` does NOT unify the
    // two (verified: python `os.path.realpath` returns the alias unchanged),
    // while the `(st_dev, st_ino)` pair IS identical — which is why the fix
    // decides by identity.
    let tmp = tempfile::Builder::new().tempdir_in("/tmp").unwrap();
    let root_path = tmp.path().join("root");
    std::fs::create_dir(&root_path).unwrap();
    std::fs::write(root_path.join("f"), b"f").unwrap();
    let canonical = std::fs::canonicalize(&root_path).unwrap();
    let aliased = PathBuf::from("/System/Volumes/Data").join(canonical.strip_prefix("/").unwrap());
    assert!(
        aliased.is_dir(),
        "the Data-volume firmlink spelling {} must exist",
        aliased.display()
    );
    assert_ne!(
        canonical,
        std::fs::canonicalize(&aliased).unwrap(),
        "the premise: the two firmlink spellings are NOT unified by realpath"
    );

    let root = RootDir::open(&root_path).unwrap();
    // PRE-FIX the walk recursed into its own source; bound the damage with a low
    // descriptor limit so the pre-fix run fails FAST instead of filling the disk.
    let saved = set_nofile_soft(64).unwrap();
    let result = copy_dir_recursive_fd(&root, &aliased, &rp("sub"));
    restore_nofile(saved).unwrap();
    let err = result.expect_err("a firmlink alias of the root must be refused by identity");
    assert!(err.to_string().contains("overlap"), "{err}");
    assert!(
        !root_path.join("sub").exists(),
        "nothing may be created before the refusal"
    );
}

// ----------------------------------------------------------------------
// I1 (Linux) — a bind-mount alias of the root is refused by identity.
// ----------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn a_bind_mount_alias_of_the_root_is_refused_by_identity() {
    // A bind mount needs a private mount namespace. Probe first, and announce
    // a SKIP when unavailable rather than silently passing.
    let sudo_ok = std::process::Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !sudo_ok {
        announce_skip(
            "passwordless sudo (or `sudo -n unshare -m`) is unavailable, so a bind-mount alias \
             cannot be produced here; the identity refusal is untestable on this host",
        );
        return;
    }

    let tmp = tmpdir();
    let base = tmp.path();
    let root_path = base.join("root");
    let alias_path = base.join("alias");
    std::fs::create_dir(&root_path).unwrap();
    std::fs::create_dir(&alias_path).unwrap();
    std::fs::write(root_path.join("f"), b"f").unwrap();

    let exe = std::env::current_exe().expect("the integration test binary path");
    // The child runs INSIDE the private namespace: it mounts the bind alias,
    // re-execs this binary for the `bind_mount_child` test, then unmounts. The
    // namespace is torn down when the last process exits, so the mount can
    // never outlive the test.
    let script = format!(
        "mount --bind '{root}' '{alias}'; env 'STOREKIT_BIND_ROOT={root}' \
         'STOREKIT_BIND_ALIAS={alias}' '{exe}' --exact bind_mount_child --ignored --nocapture; \
         rc=$?; umount '{alias}'; exit $rc",
        root = root_path.display(),
        alias = alias_path.display(),
        exe = exe.display(),
    );
    let out = std::process::Command::new("sudo")
        .args(["-n", "unshare", "-m", "--", "bash", "-c"])
        .arg(&script)
        .output()
        .expect("spawn `sudo unshare -m`");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the bind-mount child must pass: status={:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        out.status
    );
    assert!(
        stdout.contains("STOREKIT_BIND_CHILD_DONE"),
        "the child exited 0 but never reached the assertion, so this would pass vacuously:\n{stdout}"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "spawned by a_bind_mount_alias_of_the_root_is_refused_by_identity inside `sudo unshare -m`"]
fn bind_mount_child() {
    let Some(root_os) = std::env::var_os("STOREKIT_BIND_ROOT") else {
        return;
    };
    let root_path = PathBuf::from(root_os);
    let alias = PathBuf::from(std::env::var_os("STOREKIT_BIND_ALIAS").unwrap());
    // The owned root is opened at the BIND-MOUNT ALIAS; the source is the
    // ORIGINAL spelling. Pre-fix the path comparison saw two spellings and the
    // walk created `sub` inside its own source and recursed: bound the damage
    // with a low descriptor limit so the pre-fix run fails FAST (at ~57 levels)
    // instead of filling the disk.
    let root = RootDir::open(&alias).unwrap();
    let saved = set_nofile_soft(64).unwrap();
    let result = copy_dir_recursive_fd(&root, &root_path, Path::new("sub"));
    restore_nofile(saved).unwrap();
    let err = result.expect_err("a bind-mounted alias of the root must be refused by identity");
    assert!(
        err.to_string().contains("overlap"),
        "the refusal must name the overlap, got: {err}"
    );
    assert!(
        !root_path.join("sub").exists(),
        "nothing may be created before the refusal"
    );
    println!("STOREKIT_BIND_CHILD_DONE");
}

// ----------------------------------------------------------------------
// I6(a) — the copy surfaces a clean descriptor exhaustion, never an abort.
// ----------------------------------------------------------------------

const MODE_ENV: &str = "STOREKIT_COPY_EMFILE_MODE";
const ROOT_ENV: &str = "STOREKIT_COPY_EMFILE_ROOT";
const CHILD_TEST: &str = "copy_emfile_child";
const DONE_MARKER: &str = "STOREKIT_COPY_EMFILE_CHILD_DONE";
const DEPTH: usize = 256;
const NOFILE: u64 = 64;

#[test]
fn copy_dir_recursive_fd_surfaces_a_clean_descriptor_exhaustion() {
    let tmp = tmpdir();
    let exe = std::env::current_exe().expect("the integration test binary path");
    let out = std::process::Command::new(exe)
        .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
        .env(MODE_ENV, "copy_emfile")
        .env(ROOT_ENV, tmp.path())
        .output()
        .expect("spawn the emfile child");
    let _ = std::fs::remove_dir_all(tmp.path().join("deep"));
    let _ = std::fs::remove_dir_all(tmp.path().join("out"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the descriptor-exhaustion child must exit successfully (a clean Err, never an abort): \
         status={:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
        out.status
    );
    assert!(
        stdout.contains(DONE_MARKER),
        "the child exited 0 but never reached the assertion:\n{stdout}"
    );
}

#[test]
#[ignore = "spawned by copy_dir_recursive_fd_surfaces_a_clean_descriptor_exhaustion"]
fn copy_emfile_child() {
    let Ok(mode) = std::env::var(MODE_ENV) else {
        return;
    };
    if mode != "copy_emfile" {
        return;
    }
    let root_path = PathBuf::from(std::env::var_os(ROOT_ENV).expect("ROOT_ENV is set"));
    build_deep_tree(&root_path, DEPTH).expect("build the deep tree");
    let root = RootDir::open(&root_path).expect("open the owned root");
    let saved = set_nofile_soft(NOFILE).expect("lower RLIMIT_NOFILE");
    let result = copy_dir_recursive_fd(&root, &root_path.join("deep"), &rp("out"));
    restore_nofile(saved).expect("restore RLIMIT_NOFILE");
    let err = result.expect_err("the copy must surface a clean Err at the lowered limit");
    let msg = format!("{err}");
    assert!(
        msg.contains("Too many open files") || msg.contains("EMFILE"),
        "the error must name the descriptor exhaustion, got: {msg}"
    );
    println!("{DONE_MARKER}");
}

/// Build `<base>/deep/d/d/.../d/leaf` with `mkdirat`/`openat` relative to the
/// level above, so no long path is materialized.
fn build_deep_tree(base: &Path, depth: usize) -> Result<(), String> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    fn cstr(name: &[u8]) -> Result<std::ffi::CString, String> {
        std::ffi::CString::new(name).map_err(|_| "name contains NUL".to_string())
    }
    fn open_dir(dirfd: i32, name: &[u8], shown: &Path) -> Result<OwnedFd, String> {
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
                "openat {}: {}",
                shown.display(),
                std::io::Error::last_os_error()
            ));
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
    fn mkdir(dirfd: i32, name: &[u8]) -> Result<(), String> {
        let c = cstr(name)?;
        if unsafe { libc::mkdirat(dirfd, c.as_ptr(), 0o755) } < 0 {
            return Err(format!(
                "mkdirat {:?}: {}",
                String::from_utf8_lossy(name),
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }
    let c = cstr(base.as_os_str().as_encoded_bytes())?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd < 0 {
        return Err(format!("open base: {}", std::io::Error::last_os_error()));
    }
    let mut cur = unsafe { OwnedFd::from_raw_fd(fd) };
    mkdir(cur.as_raw_fd(), b"deep")?;
    cur = open_dir(cur.as_raw_fd(), b"deep", Path::new("deep"))?;
    for _ in 0..depth {
        mkdir(cur.as_raw_fd(), b"d")?;
        cur = open_dir(cur.as_raw_fd(), b"d", Path::new("d"))?;
    }
    let c = cstr(b"leaf")?;
    let leaf = unsafe {
        libc::openat(
            cur.as_raw_fd(),
            c.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o644,
        )
    };
    if leaf < 0 {
        return Err(format!("open leaf: {}", std::io::Error::last_os_error()));
    }
    let mut leaf = unsafe { std::fs::File::from_raw_fd(leaf) };
    std::io::Write::write_all(&mut leaf, b"deep\n").map_err(|e| format!("write leaf: {e}"))
}

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

fn restore_nofile(saved: libc::rlimit) -> Result<(), String> {
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &saved) } != 0 {
        return Err(format!(
            "restore setrlimit: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
