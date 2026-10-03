//! REAL-SSHD evidence for the far-side operation lock
//! (`DestinationOwnership::lock_remote` / [`storekit::transport::FarSideLockSession`]).
//!
//! # Why a real `sshd`, and not the `PATH`-shim harness
//!
//! `tests/ssh_farside_quoting.rs` and `tests/ssh_farside_portability.rs` point
//! the transport at an `ssh` SHIM on `PATH` that runs the constructed command
//! string locally. That shim removes exactly the mechanism this feature
//! depends on: there is no SSH connection, no long-lived remote process, and no
//! connection whose death could release a far-side `flock`. A shim-based test
//! therefore cannot say anything about what this feature does. This file stands
//! up a REAL, self-contained `sshd` instead:
//!
//! * its OWN host key and its OWN client key (`ssh-keygen`, ed25519);
//! * its OWN `AuthorizedKeysFile` and its OWN `known_hosts` (via `ssh-keyscan`);
//! * a NON-DEFAULT, dynamically chosen port on `127.0.0.1`, run as the current
//!   (non-root) user under the test's `tempfile::TempDir`;
//! * nothing in `/etc/ssh`, nothing in the real `~/.ssh`, never port 22.
//!
//! The harness's `Drop` shuts the listener down and asks every OpenSSH
//! `ControlMaster` under the test's own `TMPDIR` to exit, so the test leaves no
//! processes behind. The temp dir (host key, client key, keys, config, log) is
//! removed with the `TempDir`.
//!
//! These tests are `#[cfg(unix)]`, like the crate's other ssh tests. They are
//! gated behind `STOREKIT_FULL_TESTS` ONLY in the sense that they need `sshd`,
//! `ssh`, `ssh-keygen`, `ssh-keyscan`, and `perl` on `PATH`; if `sshd` is
//! genuinely absent the harness reports that clearly rather than silently
//! passing.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use storekit::env::SysEnv;
use storekit::error::Error;
use storekit::sync::{
    DestinationOwnership, Direction, Extraneous, ReplaceAll, SyncResult, destination_lock_path,
    sync,
};
use storekit::transport::{Layout, SshTransport};

/// Locate the real `sshd`. Both supported platforms install it at
/// `/usr/sbin/sshd`; fall back to a PATH lookup.
fn find_sshd() -> PathBuf {
    let candidate = PathBuf::from("/usr/sbin/sshd");
    if candidate.is_file() {
        return candidate;
    }
    for dir in std::env::var("PATH").unwrap_or_default().split(':') {
        let p = Path::new(dir).join("sshd");
        if p.is_file() {
            return p;
        }
    }
    panic!(
        "these tests require a real `sshd` (looked in /usr/sbin/sshd and on PATH); \
         install openssh-server or run them on a host that has it"
    );
}

/// A self-contained, non-privileged `sshd` plus the client-side identity the
/// crate's `SshTransport` uses to reach it.
struct TestSshd {
    dir: tempfile::TempDir,
    child: Child,
    port: u16,
    user: String,
    client_key: PathBuf,
    known_hosts: PathBuf,
    /// The per-test `TMPDIR` handed to every child the transport spawns, so the
    /// `ControlMaster` mux sockets live under this harness and can be shut down
    /// on drop.
    tmpdir: PathBuf,
}

impl TestSshd {
    fn start() -> TestSshd {
        // A SHORT scratch root under /tmp: the crate's `ControlMaster` socket
        // path is bounded by `sockaddr_un.sun_path`, and the macOS default
        // `$TMPDIR` (`/var/folders/...`) leaves too little room. `/tmp` is the
        // scratch prefix this file is allowed to use.
        let dir = tempfile::Builder::new()
            .prefix("sk-sshd-")
            .tempdir_in("/tmp")
            .expect("create the sshd harness tempdir under /tmp");
        let root = dir.path();
        let host_key = root.join("host_ed25519");
        let client_key = root.join("client_ed25519");
        for (key, comment) in [
            (&host_key, "storekit-host"),
            (&client_key, "storekit-client"),
        ] {
            let status = Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
                .arg(key)
                .status()
                .expect("run ssh-keygen");
            assert!(status.success(), "ssh-keygen failed for {key:?}");
        }
        let authorized = root.join("authorized_keys");
        std::fs::copy(root.join("client_ed25519.pub"), &authorized)
            .expect("install authorized_keys");
        set_mode(&authorized, 0o600);
        set_mode(&host_key, 0o600);

        let tmpdir = root.join("tmp");
        std::fs::create_dir_all(&tmpdir).expect("create the harness TMPDIR");

        let user = whoami();
        let (child, port) = start_listener(root, &host_key, &authorized);
        let known_hosts = scan_known_hosts(root, port);
        TestSshd {
            dir,
            child,
            port,
            user,
            client_key,
            known_hosts,
            tmpdir,
        }
    }

    /// The hermetic child environment: the process env with `TMPDIR` redirected
    /// under the harness, so the crate's mux directory is per-test.
    fn env(&self) -> SysEnv {
        let mut vars: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
        vars.insert("TMPDIR".into(), self.tmpdir.as_os_str().to_os_string());
        SysEnv::from_map(vars)
    }

    /// A transport rooted at `root` (a far-side path) that reaches this sshd.
    fn transport(&self, root: &Path) -> SshTransport {
        SshTransport::new(
            &self.user,
            "127.0.0.1",
            self.port,
            root,
            Layout::empty(),
            Some(&self.known_hosts),
            None,
            &self.dir.path().join("knownhosts-cache"),
            &self.env(),
            false,
        )
        .expect("construct the real-sshd transport")
        .with_identity_file(&self.client_key)
    }
}

impl Drop for TestSshd {
    fn drop(&mut self) {
        // Ask every ControlMaster under THIS test's mux dir to exit, so the
        // harness leaves no `ssh ... [mux]` process behind. The lock sessions
        // are already dropped by the test (their `Drop` kills the client); this
        // covers the persistent masters the run's other operations created.
        let mux_dir = self.tmpdir.join("dmux");
        if let Ok(entries) = std::fs::read_dir(&mux_dir) {
            for entry in entries.flatten() {
                let socket = entry.path();
                if socket
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("mux-"))
                {
                    let _ = Command::new("ssh")
                        .arg("-o")
                        .arg(format!("ControlPath={}", socket.display()))
                        .args(["-p", &self.port.to_string()])
                        .args(["-O", "exit"])
                        .arg(format!("{}@127.0.0.1", self.user))
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "root".to_string())
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    listener.local_addr().expect("local addr").port()
}

/// Start `sshd -D` on a fresh port, wait until it accepts, and return the
/// listener child and the port.
fn start_listener(root: &Path, host_key: &Path, authorized: &Path) -> (Child, u16) {
    let sshd = find_sshd();
    let mut last_error = String::new();
    for _ in 0..10 {
        let port = free_port();
        let config = root.join(format!("sshd_config.{port}"));
        let log = root.join(format!("sshd.log.{port}"));
        let pid = root.join("sshd.pid");
        let text = format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {host}\n\
             PidFile {pid}\n\
             AuthorizedKeysFile {auth}\n\
             StrictModes no\n\
             UsePAM no\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             PubkeyAuthentication yes\n\
             PermitRootLogin no\n\
             LogLevel ERROR\n",
            host = host_key.display(),
            pid = pid.display(),
            auth = authorized.display(),
        );
        std::fs::write(&config, text).expect("write sshd_config");
        // sshd refuses a group/world-writable config, and a permissive umask
        // (e.g. the `umask 0002` gate) makes `fs::write` group-writable.
        set_mode(&config, 0o600);
        let mut child = Command::new(&sshd)
            .arg("-f")
            .arg(&config)
            .arg("-E")
            .arg(&log)
            .arg("-p")
            .arg(port.to_string())
            .arg("-D")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sshd");
        if wait_for_port(port, Duration::from_secs(10)) {
            return (child, port);
        }
        let _ = child.kill();
        let _ = child.wait();
        last_error = std::fs::read_to_string(&log).unwrap_or_default();
    }
    panic!("could not start a real sshd on any tried port; last log: {last_error}");
}

fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

fn scan_known_hosts(root: &Path, port: u16) -> PathBuf {
    for _ in 0..50 {
        let out = Command::new("ssh-keyscan")
            .args(["-p", &port.to_string(), "-t", "ed25519", "127.0.0.1"])
            .output();
        if let Ok(out) = out
            && out.status.success()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            if text.contains("ssh-ed25519") {
                let path = root.join("known_hosts");
                std::fs::write(&path, text.as_bytes()).expect("write known_hosts");
                set_mode(&path, 0o600);
                return path;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("ssh-keyscan never returned the ed25519 host key");
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

struct Fixture {
    harness: TestSshd,
    src: PathBuf,
    far_root: PathBuf,
}

impl Fixture {
    fn new() -> Fixture {
        let harness = TestSshd::start();
        let base = harness.dir.path().join("fixture");
        std::fs::create_dir_all(&base).expect("create fixture base");
        let src = base.join("src");
        std::fs::create_dir_all(&src).expect("create source");
        std::fs::write(src.join("file"), b"payload").expect("seed source");
        let far_root = base.join("dst");
        Fixture {
            harness,
            src,
            far_root,
        }
    }

    fn record(&self) -> PathBuf {
        destination_lock_path(&self.far_root).expect("the far root has a sibling record")
    }

    /// Acquire the far-side lock for a PUSH of `self.src` into `self.far_root`.
    fn acquire(&self) -> DestinationOwnership {
        let t = self.harness.transport(&self.far_root);
        DestinationOwnership::lock_remote(Direction::Push, &self.src, &t)
            .expect("acquire the far-side lock")
    }

    fn try_acquire(&self) -> Result<DestinationOwnership, Error> {
        let t = self.harness.transport(&self.far_root);
        DestinationOwnership::lock_remote(Direction::Push, &self.src, &t)
    }

    fn sync_owned(&self, ownership: DestinationOwnership) -> SyncResult {
        let t = self.harness.transport(&self.far_root);
        sync(
            Direction::Push,
            &self.src,
            &t,
            &ReplaceAll,
            Extraneous::Keep,
            ownership,
        )
    }
}

/// Acquire the far-side lock, retrying ONLY on the typed contention outcome
/// until `timeout`. A kill releases the far-side flock asynchronously (the
/// holder process must notice the closed channel), so a test that has just
/// killed a session polls rather than assuming the release already happened.
fn acquire_after_release(fixture: &Fixture, timeout: Duration) -> DestinationOwnership {
    let deadline = Instant::now() + timeout;
    loop {
        match fixture.try_acquire() {
            Ok(o) => return o,
            Err(Error::LockContended(_)) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("unexpected acquisition failure: {e:?}"),
        }
    }
}

/// Every process whose argv STARTS with `program` and carries `fragment`.
/// The fragment is this test's unique record path, so only processes THIS test
/// started can match; `program` selects the local `ssh` client (whose argv
/// starts `ssh `) or, because the sshd is on the same host, the far-side `perl`
/// holder (whose argv starts `perl `).
fn pids_matching(program: &str, fragment: &str) -> Vec<i32> {
    let out = Command::new("ps")
        .args(["-ww", "-eo", "pid=,command="])
        .output()
        .expect("run ps");
    let text = String::from_utf8_lossy(&out.stdout);
    let me = std::process::id() as i32;
    let mut pids = Vec::new();
    for line in text.lines() {
        let line = line.trim_start();
        let mut parts = line.splitn(2, char::is_whitespace);
        let Some(pid) = parts.next() else { continue };
        let Some(cmd) = parts.next() else { continue };
        if !cmd.starts_with(program) || !cmd.contains(fragment) {
            continue;
        }
        let Ok(pid) = pid.trim().parse::<i32>() else {
            continue;
        };
        if pid != me {
            pids.push(pid);
        }
    }
    pids
}

/// SIGKILL every pid named by [`pids_matching`], returning those signalled.
fn kill_matching(program: &str, fragment: &str) -> Vec<i32> {
    let pids = pids_matching(program, fragment);
    for pid in &pids {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    pids
}

// ---------------------------------------------------------------------------
// 1. Exclusion is real (a test per direction of the hand-off)
// ---------------------------------------------------------------------------

/// A holds the far-side record; B is REFUSED with the typed contended outcome
/// and its far side is untouched; A finishes; B then succeeds and runs to
/// completion.
#[test]
fn far_side_lock_excludes_a_second_owned_run() {
    let f = Fixture::new();
    let record = f.record();

    let a = f.acquire();
    assert!(
        record.exists(),
        "A's acquisition creates the far-side sibling record {record:?}"
    );
    assert!(
        !f.far_root.exists(),
        "taking the far-side lock must not create the destination root"
    );

    // B contends: the typed outcome, no wait.
    let err = f
        .try_acquire()
        .err()
        .expect("a second run must be refused while A holds the record");
    assert!(
        matches!(err, Error::LockContended(_)),
        "B must get the typed contention outcome, got {err:?}"
    );
    assert!(
        !f.far_root.exists(),
        "B's refused acquisition must leave the far side untouched"
    );

    // A finishes (drops the token, releasing the far-side record); B succeeds.
    drop(a);
    let b = acquire_after_release(&f, Duration::from_secs(20));
    let report = f
        .sync_owned(b)
        .expect("B must acquire the released record and complete the push");
    assert!(
        report.applied.iter().any(|p| p == "file"),
        "B's push applies the file: {:?}",
        report.applied
    );
    assert_eq!(
        std::fs::read(f.far_root.join("file")).expect("read the pushed file"),
        b"payload"
    );
}

/// The SAME exclusion with the roles swapped: B holds first, A is refused,
/// B finishes, A succeeds. Exclusion is symmetric, not an artifact of which
/// run acquires first.
#[test]
fn far_side_lock_exclusion_is_symmetric() {
    let f = Fixture::new();
    let b = f.acquire();
    let err = f
        .try_acquire()
        .err()
        .expect("a second run must be refused while the first holds the record");
    assert!(matches!(err, Error::LockContended(_)), "got {err:?}");
    drop(b);
    let a = acquire_after_release(&f, Duration::from_secs(20));
    f.sync_owned(a).expect("A must complete after B releases");
}

// ---------------------------------------------------------------------------
// 2. Acquisition is non-blocking
// ---------------------------------------------------------------------------

/// Acquisition against a HELD record returns PROMPTLY with the contended
/// outcome. The wait is bounded so a regression that waits can never hang the
/// suite.
#[test]
fn far_side_lock_acquisition_is_non_blocking() {
    let f = Fixture::new();
    let holder = f.acquire();

    let started = Instant::now();
    let err = f.try_acquire().err().expect("must contend, not wait");
    let elapsed = started.elapsed();
    assert!(matches!(err, Error::LockContended(_)), "got {err:?}");
    assert!(
        elapsed < Duration::from_secs(5),
        "acquisition against a held record must return promptly (typed contention, never a \
         wait), but took {elapsed:?}"
    );
    drop(holder);
}

// ---------------------------------------------------------------------------
// 3. Release on every path (a failed run releases)
// ---------------------------------------------------------------------------

/// A run that FAILS after the lock is taken (the far-side destination root is
/// a regular file, so `provision_layout`'s `mkdir -p` fails) releases the
/// record: a subsequent acquisition succeeds.
#[test]
fn far_side_lock_is_released_after_a_failed_run() {
    let f = Fixture::new();
    // The destination root is a FILE on the far side: `mkdir -p <root>` fails.
    std::fs::write(&f.far_root, b"i am a file").expect("create a file at the destination root");

    let ownership = f.acquire();
    let result = f.sync_owned(ownership);
    let error = result.expect_err("the run must fail when the destination root is a file");
    let text = error.to_string();
    assert!(
        text.contains("provision") || text.contains("layout") || text.contains("mkdir"),
        "the failure must name the provisioning stage: {text}"
    );

    // The failed run dropped its token, so the record must be released.
    let again = acquire_after_release(&f, Duration::from_secs(20));
    drop(again);
    assert_eq!(
        std::fs::read(&f.far_root).expect("the root file is untouched"),
        b"i am a file"
    );
}

// ---------------------------------------------------------------------------
// 4. Connection loss releases the record and is REPORTED
// ---------------------------------------------------------------------------

/// Killing the connection (the lock session's local `ssh` client) releases the
/// far-side record, and a run handed the dead session reports a typed
/// connection-loss failure instead of a clean success.
#[test]
fn connection_loss_releases_the_far_side_lock_and_is_reported() {
    let f = Fixture::new();
    let record = f.record();
    let ownership = f.acquire();
    assert!(
        record.exists(),
        "the record exists while the session is alive"
    );

    // Kill the HOLDER (the far-side `perl`), so the local ssh client observes
    // the session ending and has something to report. Both processes carry the
    // test's unique record path in argv, so only our own are matched.
    let fragment = record.to_string_lossy().to_string();
    assert!(
        !pids_matching("ssh ", &fragment).is_empty(),
        "premise: the lock session's local ssh client is running"
    );
    let killed = kill_matching("perl ", &fragment);
    assert!(
        !killed.is_empty(),
        "the far-side lock holder (argv carries {record:?}) must be found and killed"
    );
    // The local client exits once the far side does. Wait for it, so the
    // liveness check below observes a dead session rather than racing the exit
    // (a killed client is asynchronous).
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline && !pids_matching("ssh ", &fragment).is_empty() {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        pids_matching("ssh ", &fragment).is_empty(),
        "the lock session's ssh client must exit after the far-side holder is killed"
    );

    // The run is handed the now-dead session. Even if its operations happen to
    // succeed, `sync` must report the lost lock, never a clean success.
    let result = f.sync_owned(ownership);
    let error = result.expect_err("a run whose lock session died must not report success");
    assert_eq!(
        error.error().transport_reason(),
        Some(storekit::TransportKind::BeforeCommand),
        "the loss must be a typed transport failure: {error:?}"
    );
    let text = error.to_string();
    assert!(
        text.contains("far-side operation-lock session"),
        "the report must name the lost lock session: {text}"
    );
    assert!(
        text.contains("cannot outlive its client"),
        "the report must state the not-a-lease consequence: {text}"
    );

    // The record is released: a later run acquires it (polling the async release).
    let again = acquire_after_release(&f, Duration::from_secs(20));
    drop(again);
}

// ---------------------------------------------------------------------------
// 5. A transport that does not implement far-side locking fails closed
// ---------------------------------------------------------------------------

/// The `Remote::lock_far_side` DEFAULT refuses, so a transport that does not
/// override it cannot be used to run an unowned remote destination silently.
/// `LocalTransport` is such a transport: `lock_remote` refuses it (a local
/// destination is refused even earlier, by the local-destination check, so this
/// asserts the refusal is a `Preflight` naming the right remedy).
#[test]
fn lock_remote_refuses_a_local_destination() {
    let dir = tempfile::tempdir().expect("tempdir");
    let src = dir.path().join("src");
    let dst = dir.path().join("dst");
    std::fs::create_dir_all(&src).expect("src");
    std::fs::write(src.join("f"), b"x").expect("seed");
    let t = storekit::transport::LocalTransport::new(
        &SysEnv::from_process(),
        dst.clone(),
        Layout::empty(),
    )
    .expect("local transport");
    let err = DestinationOwnership::lock_remote(Direction::Push, &src, &t)
        .err()
        .expect("a local destination must be refused by lock_remote");
    assert!(
        matches!(err, Error::Preflight(_)),
        "the refusal must be a typed preflight: {err:?}"
    );
    assert!(
        err.to_string().contains("DestinationOwnership::lock"),
        "the refusal must point at the local constructor: {err}"
    );
}
