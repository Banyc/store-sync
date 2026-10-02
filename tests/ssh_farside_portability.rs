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
use store_sync::transport::{
    CreateNewVerdict, Layout, LocalTransport, Remote, RemoteEntry, RootedRelativePath, SshTransport,
};

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

/// Install `body` as an executable at `path` by writing it from a SHORT-LIVED
/// HELPER PROCESS, never from the test process itself.
///
/// Why this is not a direct `std::fs::write`: libtest runs the tests of one
/// binary on many threads of ONE process, and every `std::process::Command`
/// spawn forks a child that COPIES the caller's descriptor table. A direct
/// `write` opens `path` for writing, so a sibling test's concurrent fork
/// inherits that write fd; a FAILED `execve` does not close `O_CLOEXEC`
/// descriptors (a `PATH` search issues several), so the inherited fd can
/// outlive this test's own write. The kernel then refuses to run `path` with
/// `ETXTBSY` ("Text file busy") because the inode's `i_writecount` is still
/// positive, even though this test closed its own fd.
///
/// Writing from a helper keeps the executable's write fd out of the test
/// process's descriptor table entirely, so no sibling fork can ever inherit
/// it; the helper also stages the bytes under a private name and renames them
/// into place, so `path` never exists half-written.
fn write_executable(path: &Path, body: &[u8]) {
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

fn install_shim_ssh(bin: &Path) {
    std::fs::create_dir_all(bin).expect("create shim bin dir");
    write_executable(&bin.join("ssh"), SHIM_SCRIPT.as_bytes());
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
    write_executable(&bin.join("perl"), script.as_bytes());
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
    // RAW `st_mode`, type bits INCLUDED: the value `LocalTransport::list`
    // reports from `symlink_metadata`, not the old perm-only `& 0o7777` mask.
    assert_eq!(
        by_name("script.sh").mode,
        0o100755,
        "the RAW executable mode must survive the listing on a BSD userland"
    );
    assert_eq!(
        by_name("private").mode,
        0o100600,
        "the RAW private mode must survive the listing on a BSD userland"
    );
    assert_eq!(
        by_name("sub").mode,
        0o040750,
        "the RAW directory mode must survive the listing on a BSD userland"
    );
    assert_eq!(
        by_name("script.sh").size,
        b"#!/bin/sh\n".len() as u64,
        "the REAL size must survive the listing, not a literal 0"
    );
}

/// The wire frame is NUL-terminated records of
/// `type<TAB>mode<TAB>size<TAB>name` with the name LAST, so a name containing a
/// TAB or a NEWLINE round-trips verbatim — and the entry carries its RAW mode
/// and REAL size too, matching the local view.
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
    assert_eq!(tab.mode, 0o100640, "the tab-named entry keeps its RAW mode");
    assert_eq!(tab.size, b"tab".len() as u64, "and its real size");
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

/// DEFECT 1, THE HOLE: `fsync_tree` used `find -depth -exec perl … {} ;`, and
/// `find` IGNORES the invoked command's exit status for `;`, so a tree whose
/// EVERY far-side fsync failed still made `find` exit 0 and `fsync_tree` return
/// `Ok(())`. The probe's fake perl exits 9 on the directory-fsync hook; the
/// walk must surface that as an `Err`, never a swallowed success.
///
/// Pre-fix this test FAILED with `Ok(())` (the reviewer proved it over a GNU
/// sshd on 2222 and a BSD sshd on 2223). `fsync_parent` already propagated
/// (`fsync_parent_failure_propagates`), so this is the one hole.
#[test]
fn fsync_tree_failure_propagates() {
    let h = Harness::new("dst");
    h.probe(true, false);
    let tree = h.root.join("tree");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("a"), b"a").unwrap();
    std::fs::write(tree.join("sub/b"), b"b").unwrap();

    let res = h.transport().fsync_tree(&rooted("tree"));
    assert!(
        res.is_err(),
        "a failed far-side fsync ANYWHERE in the tree must be a propagated error, got {res:?}"
    );
    // The failure is not merely logged: the walked entries are still visible,
    // so the test cannot pass by never invoking the primitive.
    assert!(
        !h.logged().is_empty(),
        "the walk must actually invoke the fsync primitive"
    );
}

/// DEFECT 5: the old fsync primitive opened with `"<"`, which BLOCKS FOREVER
/// on a FIFO (a read open waits for a writer). `fsync_tree` must terminate —
/// and, matching the LOCAL walk (which skips non-regular entries), succeed by
/// never opening the fifo.
#[test]
fn fsync_tree_over_a_fifo_terminates() {
    let h = Harness::new("dst");
    let tree = h.root.join("tree");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("file"), b"x").unwrap();
    mkfifo(&tree.join("pipe"));

    let (tx, rx) = std::sync::mpsc::channel();
    let transport = h.transport();
    std::thread::spawn(move || {
        let res = transport.fsync_tree(&rooted("tree"));
        let _ = tx.send(res.map_err(|e| e.to_string()));
    });
    let outcome = rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("fsync_tree must terminate on a tree containing a FIFO, never block forever");
    outcome.expect("fsync_tree skips the non-regular FIFO and succeeds");
}

/// DEFECT 3: an ABSENT directory must list EMPTY, agreeing with
/// `LocalTransport::list` (which deliberately treats `NotFound` as empty so an
/// unprovisioned remote root is inspectable). The rewrite's bare
/// `opendir … or die` made the SSH view error while the pre-fix glob (and the
/// local view) returned empty.
#[test]
fn list_absent_directory_agrees_with_local_empty() {
    let h = Harness::new("dst");
    let remote = h
        .transport()
        .list(&rooted("never-created"))
        .expect("the SSH listing of an absent directory must be an empty Ok, not an error");
    assert!(remote.is_empty(), "an absent directory lists nothing");
    let local = list_local(&h, "never-created");
    assert!(
        local.is_empty(),
        "the local listing of an absent directory lists nothing"
    );
}

/// DEFECT 2 + 3: a present-but-unreadable directory must fail the listing on
/// BOTH views. A `chmod 400` directory has the READ bit (so `opendir`
/// succeeds) but no SEARCH bit (so every `lstat` fails EACCES): pre-fix the
/// remote script's `next unless @s` dropped every entry and returned an empty
/// `Ok` for a NON-EMPTY directory, while the local view returned `Permission
/// denied`. A `chmod 111` directory fails `opendir` itself. This pins
/// remote/local AGREEMENT in both directions.
#[test]
fn list_unreadable_directory_agrees_with_local_error() {
    for (name, mode) in [("read-no-search", 0o400u32), ("search-no-read", 0o111u32)] {
        let h = Harness::new("dst");
        let d = h.root.join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("entry"), b"payload").unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).unwrap();

        let remote = h.transport().list(&rooted(name));
        let local = LocalTransport::new(&h.env(), h.root.clone(), Layout::empty())
            .unwrap()
            .list(&rooted(name));

        // Restore the mode so the fixture can be removed.
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(
            remote.is_err(),
            "the SSH listing of a chmod {mode:o} directory must fail, never silently drop its \
             entries; got {remote:?}"
        );
        assert!(
            local.is_err(),
            "the local listing of the SAME chmod {mode:o} directory must fail too; got {local:?}"
        );
        assert!(
            std::fs::read_dir(&d).unwrap().next().is_some(),
            "premise: the directory is NON-EMPTY, so the remote empty listing would be a lie"
        );
    }
}

/// DEFECT 4, THE CROSS-VIEW PIN: the SSH listing and the LOCAL listing of the
/// SAME tree must agree FIELD BY FIELD (`name`, `is_dir`, `is_symlink`,
/// `size`, `mode`). Pre-fix the SSH view masked `mode` with `& 0o7777` and
/// hardcoded `size: 0`, so for `exec.sh` it reported `755:0` where local
/// reported `100755:10`; the two views of one directory could never agree.
/// Positives preserved: a symlink reports its OWN mode/size (never the
/// target's), a dangling symlink is listed, and tab/newline names round-trip.
#[test]
fn list_remote_and_local_agree_field_by_field_on_the_same_tree() {
    let h = Harness::new("dst");
    let tree = h.root.join("tree");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join(".hidden"), b"h").unwrap();
    std::fs::set_permissions(tree.join(".hidden"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(tree.join("exec.sh"), b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(tree.join("exec.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(tree.join("sub/data"), b"payload").unwrap();
    std::fs::write(tree.join("a\tb"), b"tab-name").unwrap();
    std::fs::write(tree.join("line\nbreak"), b"nl-name").unwrap();
    symlink("nowhere", tree.join("dangling"));
    symlink("exec.sh", tree.join("link"));

    let mut remote = h.transport().list(&rooted("tree")).expect("remote list");
    let mut local = list_local(&h, "tree");
    remote.sort_by(|a, b| a.name.cmp(&b.name));
    local.sort_by(|a, b| a.name.cmp(&b.name));

    let field = |e: &RemoteEntry| {
        format!(
            "{}|{}|{}|{}|{:o}",
            e.name, e.is_dir, e.is_symlink, e.size, e.mode
        )
    };
    let remote_fields: Vec<String> = remote.iter().map(field).collect();
    let local_fields: Vec<String> = local.iter().map(field).collect();
    assert_eq!(
        remote_fields, local_fields,
        "the SSH and local listings of the SAME tree must agree field by field"
    );
    // The values the reviewer's `b1_list_tree` vs `b1_LISTLOCAL` comparison
    // pinned: raw modes (type bits included) and real sizes.
    let get = |name: &str| remote.iter().find(|e| e.name == name).unwrap();
    assert_eq!(get(".hidden").mode, 0o100600);
    assert_eq!(get(".hidden").size, 1);
    assert_eq!(get("exec.sh").mode, 0o100755);
    assert_eq!(get("exec.sh").size, 10);
    let dangling = get("dangling");
    assert!(dangling.is_symlink, "a dangling symlink must be listed");
    assert_eq!(
        dangling.mode & 0o170000,
        0o120000,
        "a symlink reports its OWN mode (the symlink type bits), never the target's regular-file \
         type"
    );
    assert_eq!(
        dangling.size,
        "nowhere".len() as u64,
        "a symlink reports its OWN size (target length), never the target's"
    );
}

/// Build a [`LocalTransport`] rooted at the SAME directory as `h`'s SSH
/// transport, so the two listings can be compared field by field.
fn list_local(h: &Harness, rel: &str) -> Vec<RemoteEntry> {
    LocalTransport::new(&h.env(), h.root.clone(), Layout::empty())
        .expect("build the local transport over the same root")
        .list(&rooted(rel))
        .expect("the local listing must succeed")
}

/// Create a FIFO with the POSIX `mkfifo` utility (portable on GNU and BSD).
fn mkfifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("run mkfifo");
    assert!(status.success(), "mkfifo {path:?} must succeed");
}
