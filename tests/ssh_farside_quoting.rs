//! Far-side shell-quoting contract for `SshTransport`.
//!
//! THE HARNESS — an `ssh` SHIM ON `PATH`. There is no real `ssh`/`sshd` on the
//! machines these tests run on, so the transport is pointed (through the
//! hermetic [`SysEnv`] snapshot every child receives) at a shim `ssh` that
//! takes the remote command string the transport constructed — the FINAL
//! argument, `bash -c '<script>'` — and runs it in a designated working
//! directory:
//!
//! ```sh
//! last=''; for arg in "$@"; do last=$arg; done
//! cd "$STORE_SYNC_SSH_SHIM_WORK" && exec /bin/sh -c "$last"
//! ```
//!
//! WHAT THE SHIM PROVES. The exact command string `SshTransport` builds is
//! re-parsed by a REAL POSIX shell (`/bin/sh -c` parses the `bash -c '...'`
//! invocation; the inner `bash -c` then parses the far-side script), in a real
//! working directory, against a real filesystem. Word splitting, pathname
//! expansion, option parsing, quoting, and the stdin payload all behave as
//! they would far side, and an object created relative to the working
//! directory is a genuine object OUTSIDE the destination root. The macOS run
//! exercises a BSD userland (`stat`, `ln`, `mkdir`, ...); the Linux run
//! exercises GNU coreutils.
//!
//! WHAT THE SHIM DOES NOT PROVE. It does not talk to any network and does not
//! exercise the SSH protocol or a real remote login shell: no connection
//! handshake, no encryption, no `sshd`, no `ConnectionMultiplexing`/`ControlMaster`,
//! no OpenSSH option parsing (`--`/`-p`/`-o`), no remote login-shell startup
//! files, and no remote filesystem semantics (NFS/overlayfs/...) — the far
//! side is the SAME host and the SAME local filesystem. A defect that depends
//! on any of those is out of scope here and is NOT covered by these tests.
//!
//! The tests drive [`Remote::write`] and [`Remote::symlink`] directly. The
//! sync applier slice that normally calls them is not ported into this crate
//! yet (`src/sync.rs` is a stub), so the "run is `Ok` / `applied` is right"
//! assertions are expressed as `Remote::write` returning `Ok`, the literal
//! destination path round-tripping its exact bytes and mode, and the
//! destination root holding exactly the planned entries.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use store_sync::env::SysEnv;
use store_sync::transport::{Layout, Remote, RootedRelativePath, SshTransport};

/// The environment variable the shim reads to find its "remote working
/// directory" (the directory a remote login shell would start in).
const SHIM_WORK_VAR: &str = "STORE_SYNC_SSH_SHIM_WORK";

const SHIM_SCRIPT: &str = r#"#!/bin/sh
# Test-only `ssh` shim: it never opens a network connection. It reproduces the
# far side by running the transport's final argument (the remote command
# string `bash -c '<script>'`) in $STORE_SYNC_SSH_SHIM_WORK with stdin/stdout/
# stderr connected exactly as the real operation connects them. See the test
# module doc for what this does and does not prove about real `ssh`.
set -u
work=${STORE_SYNC_SSH_SHIM_WORK:?the shim work directory is not configured}
last=''
for arg in "$@"; do last=$arg; done
cd "$work" || exit 125
exec /bin/sh -c "$last"
"#;

/// Install `body` as an executable at `path` by writing it from a SHORT-LIVED
/// HELPER PROCESS, never from the test process itself.
///
/// A direct `std::fs::write` runs in the test process, and libtest runs this
/// binary's tests on many threads of ONE process: every `std::process::Command`
/// spawn forks a child that copies the caller's descriptor table, so a sibling
/// test's fork can inherit the shim's still-open write fd. A failed `execve`
/// does not close `O_CLOEXEC` descriptors, so the inherited fd can outlive this
/// test's own write and make a later `execve` of the shim fail with `ETXTBSY`.
/// Writing from a helper keeps that fd out of the test process entirely, and
/// the helper renames the staged bytes into place so `path` is never
/// half-written.
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

fn install_shim(bin: &Path) {
    std::fs::create_dir_all(bin).expect("create shim bin dir");
    write_executable(&bin.join("ssh"), SHIM_SCRIPT.as_bytes());
    // A far-side program whose NAME starts with `-`, used to pin that
    // `Remote::exec` passes its program as an operand rather than an option.
    write_executable(
        &bin.join("-prog"),
        b"#!/bin/sh\nprintf 'DASH-PROG-RAN %s\\n' \"$*\"\n",
    );
}

/// One hermetic fixture: a shim bin dir, a "remote" working directory, and the
/// destination root inside it.
struct Harness {
    tmp: tempfile::TempDir,
    work: PathBuf,
    root: PathBuf,
    root_rel: String,
}

impl Harness {
    fn new(root_rel: &str) -> Harness {
        let tmp = tempfile::Builder::new()
            .prefix("storesync-sshshim-")
            .tempdir()
            .expect("create harness tempdir");
        let work = tmp.path().join("work");
        std::fs::create_dir_all(&work).expect("create the shim work dir");
        install_shim(&tmp.path().join("bin"));
        let root = work.join(root_rel);
        Harness {
            tmp,
            work,
            root,
            root_rel: root_rel.to_string(),
        }
    }

    /// The hermetic child environment: `PATH` starts with the shim bin dir
    /// (then the real `PATH`, so the far-side commands still resolve), and the
    /// shim work dir is configured. Every child the transport spawns receives
    /// EXACTLY this snapshot.
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

    /// The entries directly inside the shim work dir, sorted. Anything besides
    /// the destination root is an object created OUTSIDE the root.
    fn work_entries(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.work)
            .expect("read the shim work dir")
            .map(|e| {
                e.expect("work dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    /// Every entry under the destination root, recursively, as slash-joined
    /// relative names (symlinks are not followed).
    fn root_paths(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.root.exists() {
            return out;
        }
        for entry in walkdir::WalkDir::new(&self.root).min_depth(1) {
            let entry = entry.expect("walk the destination root");
            let rel = entry
                .path()
                .strip_prefix(&self.root)
                .expect("walked entry is under the root");
            out.push(rel.to_string_lossy().into_owned());
        }
        out.sort();
        out
    }
}

/// The literal entries a single upload is allowed to create under the
/// destination root: every ancestor directory of `rel`, `rel` itself, and the
/// caller-declared decoy entries.
fn expected_paths(rel: &str, decoys: &[&str]) -> Vec<String> {
    let p = Path::new(rel);
    let comps: Vec<_> = p.components().collect();
    let mut acc = PathBuf::new();
    let mut out: Vec<String> = Vec::new();
    for c in &comps[..comps.len().saturating_sub(1)] {
        acc.push(c.as_os_str());
        out.push(acc.to_string_lossy().into_owned());
    }
    out.push(rel.to_string());
    for d in decoys {
        out.push((*d).to_string());
    }
    out.sort();
    out
}

/// Run one upload through the real [`Remote::write`] against the shim, then
/// assert the confinement contract: `Ok`, the literal path round-trips its
/// exact bytes and requested mode, nothing exists outside the root, and the
/// root holds exactly the planned names.
fn assert_literal_upload(root_rel: &str, rel: &str, decoys: &[&str], data: &[u8]) {
    let h = Harness::new(root_rel);
    for d in decoys {
        std::fs::create_dir_all(h.root.join(d)).expect("create the declared decoy");
    }
    let t = h.transport();
    let r = RootedRelativePath::parse(Path::new(rel)).expect("parse the rooted relative path");
    let res = t.write(&r, data, 0o644);
    assert!(
        res.is_ok(),
        "write of {rel:?} must be Ok, got {res:?}; the remote work dir held {:?} and the \
         destination root held {:?} (anything in the work dir besides the root is an object \
         created OUTSIDE the destination root)",
        h.work_entries(),
        h.root_paths(),
    );
    assert_eq!(
        std::fs::read(h.root.join(rel)).expect("read the uploaded literal path"),
        data,
        "the literal name {rel:?} must round-trip the exact bytes"
    );
    let meta = std::fs::metadata(h.root.join(rel)).expect("stat the uploaded file");
    assert_eq!(
        meta.mode() & 0o7777,
        0o644,
        "the upload must apply the requested mode (not the umask) for {rel:?}"
    );
    assert_eq!(
        h.work_entries(),
        vec![h.root_rel.clone()],
        "no filesystem object may be created outside the destination root for {rel:?}"
    );
    assert_eq!(
        h.root_paths(),
        expected_paths(rel, decoys),
        "the destination root must hold exactly the literal path (plus declared decoys) for {rel:?}"
    );
}

/// THE REPRODUCTION: a SPACE in a parent component. Pre-fix, the unquoted
/// `$(dirname '<p>')` split at the space: `mkdir -p` created `<root>/aa` (a
/// stray inside the root) and `bb` relative to the remote working directory
/// (an object OUTSIDE the root), and the upload failed because the real
/// parent `aa bb` was never created.
#[test]
fn upload_with_space_in_parent_component_is_confined() {
    assert_literal_upload("dst", "aa bb/c", &[], b"payload space parent");
}

/// A SPACE in the destination ROOT itself. Pre-fix the split happened on the
/// root's parent, creating sibling objects under the working directory.
#[test]
fn upload_with_space_in_destination_root_is_confined() {
    assert_literal_upload("dst root", "c", &[], b"payload space root");
}

/// A NEWLINE in the destination ROOT. This is the case merely QUOTING the
/// command substitution cannot fix: `$(dirname ...)` STRIPS the trailing
/// newline of its output, so `dst\n` is silently truncated to `dst` before
/// `mkdir` ever sees it.
#[test]
fn upload_with_newline_in_destination_root_is_confined() {
    assert_literal_upload("dst\nroot", "c", &[], b"payload newline root");
}

/// A TAB in a parent component: the default `IFS` splits the unquoted
/// substitution result on it exactly as on a space.
#[test]
fn upload_with_tab_in_parent_component_is_confined() {
    assert_literal_upload("dst", "aa\tbb/c", &[], b"payload tab parent");
}

/// A NEWLINE in a parent component: split by `IFS`, and on a component-final
/// newline the substitution output is also truncated.
#[test]
fn upload_with_newline_in_parent_component_is_confined() {
    assert_literal_upload("dst", "aa\nbb/c", &[], b"payload newline parent");
}

/// A GLOB `*` in a parent component. A decoy sibling `aaXbb` makes the
/// unquoted pathname expansion deterministic: pre-fix `aa*bb` expanded to the
/// decoy, so the literal `aa*bb` parent was never created.
#[test]
fn upload_with_star_in_parent_component_does_not_glob() {
    assert_literal_upload("dst", "aa*bb/c", &["aaXbb"], b"payload star parent");
}

/// A `?` in a parent component, with the same decoy.
#[test]
fn upload_with_question_in_parent_component_does_not_glob() {
    assert_literal_upload("dst", "aa?bb/c", &["aaXbb"], b"payload question parent");
}

/// A `[` class in a parent component, with a decoy that the class matches.
#[test]
fn upload_with_bracket_in_parent_component_does_not_glob() {
    assert_literal_upload("dst", "aa[xy]bb/c", &["aaxbb"], b"payload bracket parent");
}

/// A LEADING `-` in a parent component: the destination path is absolute, so
/// this round-trips both pre-fix and post-fix; the test pins that the `--`
/// hardening did not break it and that the split/expansion fix did not start
/// treating it as an option.
#[test]
fn upload_with_leading_dash_in_parent_component_is_confined() {
    assert_literal_upload("dst", "-aa/c", &[], b"payload dash parent");
}

/// A SINGLE QUOTE in a parent component. `shell_quote` already renders it as
/// `'\''`, and command-substitution output is never re-parsed for quotes, so
/// this round-trips both pre-fix and post-fix; the test pins that the fix
/// preserved the existing single-quote escaping.
#[test]
fn upload_with_single_quote_in_parent_component_is_confined() {
    assert_literal_upload("dst", "aa'bb/c", &[], b"payload quote parent");
}

/// The LEAF-name half of the metacharacter matrix: a literal name carrying a
/// tab, newline, glob metacharacter, leading `-`, single quote, or a space
/// must round-trip into the destination with its exact bytes.
#[test]
fn upload_leaf_names_with_metacharacters_round_trip() {
    let names = [
        "a\tb",
        "line\nbreak",
        "star*name",
        "quest?name",
        "brack[et]",
        "-lead",
        "quote'name",
        "sp ace",
    ];
    for (i, name) in names.iter().enumerate() {
        let rel = format!("dir/{name}");
        let data = format!("payload leaf {i} :: {name:?}").into_bytes();
        assert_literal_upload("dst", &rel, &[], &data);
    }
}

/// A symlink LINK TARGET that starts with `-` is an operand, not an option:
/// pre-fix `ln -sfn '-dash-target' <link>` was parsed by `ln` as the option
/// cluster `-d` (`ln: illegal option -- d`) and the link was never created.
#[test]
fn symlink_target_with_leading_dash_is_not_an_option() {
    let h = Harness::new("dst");
    let t = h.transport();
    let rel = RootedRelativePath::parse(Path::new("link")).expect("parse link path");
    t.symlink(Path::new("-dash-target"), &rel)
        .expect("a link target that starts with '-' must not be read as an option");
    assert_eq!(
        std::fs::read_link(h.root.join("link")).expect("read the created link"),
        Path::new("-dash-target"),
        "the link target must round-trip verbatim"
    );
    assert_eq!(
        h.work_entries(),
        vec!["dst".to_string()],
        "no object may be created outside the destination root"
    );
}

/// A `Remote::exec` PROGRAM NAME that starts with `-` is an operand, not an
/// option: pre-fix `exec '-prog'` was parsed by the shell's `exec` builtin as
/// the option cluster `-p` (`exec: -p: invalid option`) and the program never
/// ran.
#[test]
fn exec_program_with_leading_dash_is_not_an_option() {
    let h = Harness::new("dst");
    let t = h.transport();
    let out = t
        .exec(
            &["-prog".to_string(), "hello world".to_string()],
            Duration::from_secs(30),
        )
        .expect("exec must return an outcome");
    assert_eq!(out.exit_code, 0, "exec stderr: {}", out.stderr);
    assert!(
        out.stdout.contains("DASH-PROG-RAN hello world"),
        "the leading-dash program must run with its argv intact; stdout: {:?}",
        out.stdout
    );
}

/// Control for the symlink hardening: ordinary metacharacter-bearing targets
/// still round-trip verbatim and never create anything outside the root.
#[test]
fn symlink_targets_with_metacharacters_round_trip() {
    for (i, target) in ["a b", "a\tb", "a*b", "a?b", "[a]", "a'b"]
        .iter()
        .enumerate()
    {
        let h = Harness::new("dst");
        let t = h.transport();
        let name = format!("link{i}");
        let rel = RootedRelativePath::parse(Path::new(&name)).expect("parse link path");
        t.symlink(Path::new(target), &rel)
            .unwrap_or_else(|e| panic!("symlink to {target:?} must succeed, got {e:?}"));
        assert_eq!(
            std::fs::read_link(h.root.join(&name)).expect("read the created link"),
            Path::new(target),
            "the link target {target:?} must round-trip verbatim"
        );
        assert_eq!(
            h.work_entries(),
            vec!["dst".to_string()],
            "no object may be created outside the destination root for target {target:?}"
        );
    }
}
