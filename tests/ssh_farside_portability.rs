//! Far-side USERLAND portability contract for `SshTransport`: the remote of a
//! deployment may be Linux/GNU **or** macOS/BSD, and the crate documents macOS
//! remotes as supported. A far-side script that is GNU-only therefore changes
//! behaviour silently depending on the remote's userland.
//!
//! THE HARNESS — an `ssh` SHIM ON `PATH` (the same harness
//! `tests/ssh_farside_quoting.rs` uses). There is no real `ssh`/`sshd` in the
//! unit-test environment, so the transport is pointed (through the hermetic
//! [`SysEnv`] snapshot every child receives) at a shim `ssh` that takes the
//! remote command string the transport constructed — the FINAL argument,
//! `bash -c '<script>'` — and runs it in a designated working directory:
//!
//! ```sh
//! last=''; for arg in "$@"; do last=$arg; done
//! cd "$STORE_SYNC_SSH_SHIM_WORK" && exec /bin/sh -c "$last"
//! ```
//!
//! WHAT THE SHIM PROVES. The exact command string `SshTransport` builds is
//! re-parsed by a REAL POSIX shell and run against a REAL filesystem with the
//! host's real userland. On macOS (this repository's CI/development host) that
//! host userland is **BSD** (`mv`, `stat`, `cp`, `ln`, `find`, ... are BSD),
//! so the BSD side of every divergence is genuinely exercised; on Linux it is
//! GNU. A GNU-only far-side command therefore FAILS these tests when they run
//! on macOS and PASSES them when they run on Linux — the exact asymmetry this
//! file exists to close.
//!
//! WHAT THE SHIM DOES NOT PROVE. It does not talk to any network and does not
//! exercise the SSH protocol or a real remote login shell: no handshake, no
//! encryption, no `sshd`, no `ControlMaster`, no OpenSSH option parsing, no
//! remote login-shell startup files, and no remote filesystem semantics — the
//! far side is the SAME host and the SAME local filesystem. Real-`sshd`
//! coverage (one Linux sshd, one macOS sshd) is recorded in the change's test
//! evidence, not in this file.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use store_sync::env::SysEnv;
use store_sync::transport::{CreateNewVerdict, Layout, Remote, RootedRelativePath, SshTransport};

/// The environment variable the shim reads to find its "remote working
/// directory" (the directory a remote login shell would start in).
const SHIM_WORK_VAR: &str = "STORE_SYNC_SSH_SHIM_WORK";

const SHIM_SCRIPT: &str = r#"#!/bin/sh
# Test-only `ssh` shim: it never opens a network connection. It reproduces the
# far side by running the transport's final argument (the remote command
# string `bash -c '<script>'`) in $STORE_SYNC_SSH_SHIM_WORK with stdin/stdout/
# stderr connected exactly as the real operation connects them.
set -u
work=${STORE_SYNC_SSH_SHIM_WORK:?the shim work directory is not configured}
last=''
for arg in "$@"; do last=$arg; done
cd "$work" || exit 125
exec /bin/sh -c "$last"
"#;

/// The token a far-side `perl` file-fsync helper carries, so a test's fake
/// `perl` on `PATH` can recognise (and fault-inject into, or log) exactly the
/// file-fsync call without disturbing the other perl calls in the same script.
pub const FSYNC_FILE_TOKEN: &str = "STORE_SYNC_TEST_FSYNC_FILE";
/// The directory-fsync counterpart of [`FSYNC_FILE_TOKEN`].
pub const FSYNC_DIR_TOKEN: &str = "STORE_SYNC_TEST_FSYNC_DIR";

fn install_shim_ssh(bin: &Path) {
    std::fs::create_dir_all(bin).expect("create shim bin dir");
    let shim = bin.join("ssh");
    std::fs::write(&shim, SHIM_SCRIPT).expect("write shim ssh");
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
        .expect("chmod the shim executable");
}

/// Install a far-side `perl` on `bin` that (a) records the path operand of any
/// fsync-token call in `log` and (b) either faults (exit 9) or delegates to the
/// real perl. It never changes what the rest of the script does, because any
/// invocation WITHOUT a fsync token is delegated verbatim.
fn install_perl_probe(bin: &Path, log: &Path, fault_dir: bool, fault_file: bool) {
    let real_perl = which_perl();
    let script = format!(
        "#!/bin/sh\n\
log={log}\n\
last=''; for a in \"$@\"; do last=$a; done\n\
case \"$*\" in\n\
  *{dir_token}*)\n\
    printf '%s\\n' \"$last\" >> \"$log\"\n\
    if [ {fault_dir} = 1 ]; then echo 'perl fsync dir failed' >&2; exit 9; fi ;;\n\
  *{file_token}*)\n\
    printf '%s\\n' \"$last\" >> \"$log\"\n\
    if [ {fault_file} = 1 ]; then echo 'perl fsync file failed' >&2; exit 9; fi ;;\n\
esac\n\
exec {perl} \"$@\"\n",
        log = shell_quote(&log.to_string_lossy()),
        dir_token = FSYNC_DIR_TOKEN,
        file_token = FSYNC_FILE_TOKEN,
        fault_dir = if fault_dir { 1 } else { 0 },
        fault_file = if fault_file { 1 } else { 0 },
        perl = shell_quote(&real_perl.to_string_lossy()),
    );
    let p = bin.join("perl");
    std::fs::write(&p, script).expect("write the fake perl probe");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))
        .expect("chmod the fake perl probe");
}

fn which_perl() -> PathBuf {
    // The probe must delegate to the REAL perl. Resolve it before the shim bin
    // dir is prepended to PATH (this runs from the test process's own PATH,
    // where `perl` is the system one).
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let cand = Path::new(dir).join("perl");
        if cand.is_file() {
            return cand;
        }
    }
    panic!("no `perl` on PATH; the far-side scripts require perl");
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// One hermetic fixture: a shim bin dir, a "remote" working directory, the
/// destination root inside it, and an optional perl probe.
struct Harness {
    tmp: tempfile::TempDir,
    work: PathBuf,
    root: PathBuf,
    log: PathBuf,
}

impl Harness {
    fn new(root_rel: &str) -> Harness {
        let tmp = tempfile::Builder::new()
            .prefix("storesync-sshport-")
            .tempdir()
            .expect("create harness tempdir");
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).expect("create the shim work dir");
        install_shim_ssh(&tmp.path().join("bin"));
        let root = work.join(root_rel);
        std::fs::create_dir_all(&root).expect("create the destination root");
        let log = tmp.path().join("fsync.log");
        Harness {
            tmp,
            work,
            root,
            log,
        }
    }

    /// Install a far-side perl probe that logs fsync operands (and optionally
    /// faults one of the fsync kinds).
    fn probe(&self, fault_dir: bool, fault_file: bool) {
        install_perl_probe(
            &self.tmp.path().join("bin"),
            &self.log,
            fault_dir,
            fault_file,
        );
    }

    fn env(&self) -> SysEnv {
        let bin = self.tmp.path().join("bin");
        let mut vars: BTreeMap<OsString, OsString> = BTreeMap::new();
        vars.insert(
            OsString::from("PATH"),
            OsString::from(format!(
                "{}:{}",
                bin.display(),
                std::env::var("PATH").unwrap_or_default()
            )),
        );
        vars.insert(
            OsString::from(SHIM_WORK_VAR),
            self.work.as_os_str().to_os_string(),
        );
        SysEnv::from_map(vars)
    }

    fn transport(&self) -> SshTransport {
        let env = self.env();
        SshTransport::new(
            "deploy",
            "shim.invalid",
            2222,
            &self.root,
            Layout::empty(),
            Some(Path::new("/dev/null")),
            None,
            &self.tmp.path().join("knownhosts"),
            &env,
            false,
        )
        .expect("construct the shimmed ssh transport")
    }

    fn logged(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(|l| l.to_string())
            .collect()
    }
}

fn rooted(p: &str) -> RootedRelativePath {
    RootedRelativePath::parse(Path::new(p)).expect("parse the rooted relative path")
}

fn symlink(target: &str, link: impl AsRef<Path>) {
    std::os::unix::fs::symlink(target, link.as_ref()).expect("create symlink");
}

// ---------------------------------------------------------------------------
// F1 — the far-side rename primitive.
//
// Pre-fix `rename_cmd` produced `mv -T` (GNU-only). On a BSD/macOS remote
// `mv` rejects `-T` as an illegal option and exits 64, so EVERY kind-changing
// replacement failed. Every POSITIVE test in this section therefore fails on
// macOS pre-fix with `mv: illegal option -- T`, and passes on Linux; the
// REFUSAL test is the one negative case a GNU host also satisfies pre-fix.
// ---------------------------------------------------------------------------

/// THE REPORTED BUG, reduced: replace the top-level `current` symlink that
/// points INTO a directory. A bare `mv src dst` treats the symlink-to-dir
/// destination as the directory itself and moves `src` INSIDE it; pre-fix
/// `-T` prevented that on GNU — and made the whole command illegal on BSD.
#[test]
fn rename_replaces_a_top_level_symlink_to_a_directory() {
    let h = Harness::new("dst");
    std::fs::create_dir_all(h.root.join("objects/app-v1")).unwrap();
    symlink("objects/app-v1", h.root.join("current"));
    symlink("objects/app-v2", h.root.join(".current.tmp.op-x"));

    let t = h.transport();
    t.rename(&rooted(".current.tmp.op-x"), &rooted("current"))
        .expect("replacing a symlink-to-directory must succeed on every userland");

    assert_eq!(
        std::fs::read_link(h.root.join("current")).expect("read the replaced link"),
        Path::new("objects/app-v2"),
        "the `current` link must be REPLACED, not moved INTO objects/app-v1"
    );
    assert!(
        !h.root.join("objects/app-v1/.current.tmp.op-x").exists(),
        "the source must never be moved INTO the destination directory"
    );
}

/// Symlink retarget: the destination is a live symlink to a different target;
/// the source symlink must replace it in place.
#[test]
fn rename_retargets_a_symlink() {
    let h = Harness::new("dst");
    std::fs::write(h.root.join("old-target"), b"old").unwrap();
    std::fs::write(h.root.join("new-target"), b"new").unwrap();
    symlink("old-target", h.root.join("link"));
    symlink("new-target", h.root.join(".link.tmp"));

    h.transport()
        .rename(&rooted(".link.tmp"), &rooted("link"))
        .expect("retargeting a symlink must succeed on every userland");

    assert_eq!(
        std::fs::read_link(h.root.join("link")).unwrap(),
        Path::new("new-target")
    );
}

/// A SELF-LOOP symlink (`link -> link`) is a legal entry the manifest walk
/// sees; it must be replaceable.
#[test]
fn rename_replaces_a_self_loop_symlink() {
    let h = Harness::new("dst");
    symlink("loop", h.root.join("loop"));
    symlink("objects/v2", h.root.join(".loop.tmp"));

    h.transport()
        .rename(&rooted(".loop.tmp"), &rooted("loop"))
        .expect("replacing a self-loop symlink must succeed on every userland");

    assert_eq!(
        std::fs::read_link(h.root.join("loop")).unwrap(),
        Path::new("objects/v2")
    );
}

/// File over symlink: a regular file atomically replaces an existing symlink.
#[test]
fn rename_replaces_a_symlink_with_a_regular_file() {
    let h = Harness::new("dst");
    symlink("somewhere-else", h.root.join("entry"));
    std::fs::write(h.root.join(".entry.tmp"), b"file-payload").unwrap();

    h.transport()
        .rename(&rooted(".entry.tmp"), &rooted("entry"))
        .expect("a file must replace a symlink on every userland");

    let meta = std::fs::symlink_metadata(h.root.join("entry")).unwrap();
    assert!(meta.file_type().is_file(), "the destination must be a file");
    assert_eq!(
        std::fs::read(h.root.join("entry")).unwrap(),
        b"file-payload"
    );
}

/// File over directory, with the applier's DELETE first (a file cannot
/// `rename(2)` onto a directory — the primitive must refuse that, see the
/// refusal test below — so the applier removes the directory then renames).
#[test]
fn rename_replaces_a_deleted_directory_with_a_regular_file() {
    let h = Harness::new("dst");
    std::fs::create_dir_all(h.root.join("entry/nested")).unwrap();
    std::fs::write(h.root.join(".entry.tmp"), b"fresh").unwrap();
    std::fs::remove_dir_all(h.root.join("entry")).unwrap();

    h.transport()
        .rename(&rooted(".entry.tmp"), &rooted("entry"))
        .expect("a file must install after the directory is deleted");

    assert!(
        std::fs::symlink_metadata(h.root.join("entry"))
            .unwrap()
            .file_type()
            .is_file()
    );
}

/// Directory over non-directory: the applier CLAIMS the existing non-directory
/// aside with a rename, then renames the directory into place.
#[test]
fn rename_replaces_a_claimed_nondir_with_a_directory() {
    let h = Harness::new("dst");
    std::fs::write(h.root.join("entry"), b"old-file").unwrap();
    // The claim target must NOT pre-exist: the claim rename CREATES it.
    std::fs::create_dir_all(h.root.join("entry.d")).unwrap();
    std::fs::write(h.root.join("entry.d/inside"), b"x").unwrap();

    let t = h.transport();
    t.rename(&rooted("entry"), &rooted(".entry.claim"))
        .expect("claiming the existing non-directory aside must succeed");
    t.rename(&rooted("entry.d"), &rooted("entry"))
        .expect("installing the directory must succeed after the claim");

    assert!(
        std::fs::symlink_metadata(h.root.join("entry"))
            .unwrap()
            .file_type()
            .is_dir()
    );
    assert!(h.root.join("entry/inside").is_file());
    assert!(
        std::fs::symlink_metadata(h.root.join(".entry.claim"))
            .unwrap()
            .file_type()
            .is_file()
    );
}

/// The GUARD `-T` existed to provide, and which a portable primitive must keep
/// providing: a file must NOT be moved INTO a directory target. The rename must
/// fail loudly (nonzero) and leave both the file and the directory intact.
#[test]
fn rename_refuses_a_file_onto_a_directory_target() {
    let h = Harness::new("dst");
    std::fs::create_dir_all(h.root.join("target")).unwrap();
    std::fs::write(h.root.join("source"), b"must-not-move").unwrap();

    let t = h.transport();
    let res = t.rename(&rooted("source"), &rooted("target"));
    assert!(
        res.is_err(),
        "renaming a file onto a directory must be refused, got {res:?}"
    );
    assert!(
        h.root.join("source").is_file(),
        "the refused source must stay in place"
    );
    assert!(
        h.root.join("target").is_dir(),
        "the refused target must stay a directory"
    );
    assert!(
        !h.root.join("target/source").exists(),
        "the source must NEVER be moved into the directory target"
    );
}

/// The operands are single-quoted and passed after `--`: a destination whose
/// parent path (here the ROOT) contains a space and a glob metacharacter must
/// round-trip literally, not split or expand.
#[test]
fn rename_with_metacharacters_in_the_path_round_trips() {
    let h = Harness::new("dst root*with [meta] and 'quote'");
    std::fs::create_dir_all(h.root.join("objects/v1")).unwrap();
    symlink("objects/v1", h.root.join("current"));
    symlink("objects/v2", h.root.join(".current.tmp"));

    h.transport()
        .rename(&rooted(".current.tmp"), &rooted("current"))
        .expect("a metacharacter-bearing path must round-trip");

    assert_eq!(
        std::fs::read_link(h.root.join("current")).unwrap(),
        Path::new("objects/v2"),
        "the rename must address the literal path"
    );
    // No stray object may appear beside the destination root.
    let mut work: Vec<String> = std::fs::read_dir(&h.work)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    work.sort();
    assert_eq!(work, vec!["dst root*with [meta] and 'quote'".to_string()]);
}

// ---------------------------------------------------------------------------
// F2 — `RemoteEntry.mode`.
//
// Pre-fix the list script ran `stat -c '%f'`; BSD `stat` rejects `-c`, the mode
// column is empty, and the parser silently defaulted it to 0. The test below
// therefore fails on macOS pre-fix (mode 0) and passes on Linux.
// ---------------------------------------------------------------------------

/// `Remote::list` must report the REAL mode on a BSD userland too.
#[test]
fn list_reports_the_real_mode_on_bsd_userland() {
    let h = Harness::new("dst");
    let tree = h.root.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("script.sh"), b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(
        tree.join("script.sh"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::fs::write(tree.join("private"), b"secret").unwrap();
    std::fs::set_permissions(tree.join("private"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::set_permissions(tree.join("sub"), std::fs::Permissions::from_mode(0o750)).unwrap();

    let entries = h
        .transport()
        .list(&rooted("tree"))
        .expect("list must succeed");
    let by_name = |n: &str| {
        entries
            .iter()
            .find(|e| e.name == n)
            .unwrap_or_else(|| panic!("entry {n} missing from {entries:?}"))
            .clone()
    };
    assert_eq!(
        by_name("script.sh").mode,
        0o755,
        "the executable mode must survive the listing on a BSD userland"
    );
    assert_eq!(
        by_name("private").mode,
        0o600,
        "the private mode must survive the listing on a BSD userland"
    );
    assert_eq!(
        by_name("sub").mode,
        0o750,
        "the directory mode must survive the listing on a BSD userland"
    );
}

/// The wire frame is UNCHANGED by the portability fix: NUL-terminated records
/// of `type<TAB>mode<TAB>name` with the name LAST, so a name containing a TAB
/// or a NEWLINE round-trips verbatim — and now carries its real mode too.
#[test]
fn list_frames_tab_and_newline_names_with_real_modes() {
    let h = Harness::new("dst");
    let tree = h.root.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a\tb"), b"tab").unwrap();
    std::fs::set_permissions(tree.join("a\tb"), std::fs::Permissions::from_mode(0o640)).unwrap();
    std::fs::write(tree.join("line\nbreak"), b"newline").unwrap();

    let entries = h
        .transport()
        .list(&rooted("tree"))
        .expect("list must succeed");
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert!(names.contains(&"a\tb"), "tab name must survive: {names:?}");
    assert!(
        names.contains(&"line\nbreak"),
        "newline name must survive: {names:?}"
    );
    let tab = entries.iter().find(|e| e.name == "a\tb").unwrap();
    assert_eq!(tab.mode, 0o640, "the tab-named entry keeps its real mode");
}

// ---------------------------------------------------------------------------
// F3 — durability.
//
// Pre-fix `fsync_tree`/`fsync_parent`/`write_new_cmd` used `sync <operand>`,
// which GNU coreutils >= 8.24 treats as "fsync this path" but BSD/macOS treats
// as a NO-OP (`sync /nonexistent` exits 0). The probe tests below record the
// fsync calls the far-side script actually makes, so pre-fix the log is EMPTY
// on every platform (the operand-less `sync` command is not perl at all).
// ---------------------------------------------------------------------------

/// `fsync_parent` must fsync the PARENT directory (the entry's dirname), via
/// the portable perl primitive.
#[test]
fn fsync_parent_fsyncs_the_parent_directory() {
    let h = Harness::new("dst");
    h.probe(false, false);
    std::fs::create_dir_all(h.root.join("state")).unwrap();
    std::fs::write(h.root.join("state/record"), b"x").unwrap();

    h.transport()
        .fsync_parent(&rooted("state/record"))
        .expect("fsync_parent must succeed");

    let log = h.logged();
    assert_eq!(
        log,
        vec![h.root.join("state").to_string_lossy().into_owned()],
        "the PARENT directory must be the fsynced path"
    );
}

/// `fsync_tree` must fsync every file AND directory in the tree (deepest
/// first), via the portable perl primitive.
#[test]
fn fsync_tree_fsyncs_every_file_and_directory() {
    let h = Harness::new("dst");
    h.probe(false, false);
    let tree = h.root.join("tree");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("a"), b"a").unwrap();
    std::fs::write(tree.join("sub/b"), b"b").unwrap();

    h.transport()
        .fsync_tree(&rooted("tree"))
        .expect("fsync_tree must succeed");

    let mut got = h.logged();
    got.sort();
    let mut want = vec![
        tree.to_string_lossy().into_owned(),
        tree.join("a").to_string_lossy().into_owned(),
        tree.join("sub").to_string_lossy().into_owned(),
        tree.join("sub/b").to_string_lossy().into_owned(),
    ];
    want.sort();
    assert_eq!(got, want, "every file and directory must be fsynced");
}

/// A failure of the far-side directory fsync must PROPAGATE: the probe's fake
/// perl exits 9, and `fsync_parent` must surface that as an error, never a
/// swallowed success.
#[test]
fn fsync_parent_failure_propagates() {
    let h = Harness::new("dst");
    h.probe(true, false);
    std::fs::create_dir_all(h.root.join("state")).unwrap();

    let res = h.transport().fsync_parent(&rooted("state/record"));
    assert!(
        res.is_err(),
        "a failed directory fsync must be a propagated error, got {res:?}"
    );
}

/// F3, the TRANSPORT-side AlreadyPresent retry: when `try_write_new` finds a
/// byte-and-mode-identical record already installed it must still make the
/// parent DIRECTORY durable, through the SAME portable perl primitive the
/// script uses. The retry used to run a bare `sync <parent>`, which the perl
/// probe never sees (and which is a silent no-op on BSD/macOS).
///
/// Pre-fix the log is EMPTY, so this test FAILED on every platform.
#[test]
fn try_write_new_already_present_fsyncs_the_parent_portably() {
    let h = Harness::new("dst");
    h.probe(false, false);
    std::fs::create_dir_all(h.root.join("state")).unwrap();
    std::fs::write(h.root.join("state/op.json"), b"identical").unwrap();
    std::fs::set_permissions(
        h.root.join("state/op.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    let verdict = h
        .transport()
        .try_write_new(&rooted("state/op.json"), b"identical")
        .expect("the identical retry must converge, not error");
    assert!(
        matches!(verdict, CreateNewVerdict::AlreadyPresent),
        "an identical installed record must converge to AlreadyPresent, got {verdict:?}"
    );
    let parent = h.root.join("state").to_string_lossy().into_owned();
    let log = h.logged();
    assert!(
        log.contains(&parent),
        "the AlreadyPresent retry must fsync the parent directory {parent:?} via the portable \
         perl primitive; fsync log was {log:?}"
    );
}
