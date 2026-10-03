//! The production SSH transport group: the [`SshTransport`] over `ssh`/`scp`,
//! host-identity verification and pinning ([`hostkey`]), and the ONE bounded
//! subprocess runner every ssh operation goes through ([`runner`]) — hard
//! deadline, kill, and deterministic reap.
//!
//! Transport setup is split into two phases: [`Remote::prepare_identity`]
//! (verify/pin the host key) runs before ANY remote request — including a dry
//! run's status inspection — while [`Remote::provision_layout`] (create the
//! deployment-directory layout) runs only behind the push engine's
//! non-dry-run gate.
//!
//! # Submodules
//!
//! * [`hostkey`] — host-identity verification and pinning.
//! * [`runner`] — the bounded subprocess runner.

mod hostkey;
mod runner;

use crate::env::SysEnv;
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{
    ContentEquivalence, CreateNewVerdict, FsBytes, IMMUTABLE_RECORD_MODE, Layout, OpenedEntry,
    OpenedExisting, Remote, RemoteEntry, RemoteMeta, RemoveIfVerdict, RootedRelativePath,
    TimeoutCause, has_normal_component_below_root, provision_receiver_id, verified_to_verdict,
    verify_existing,
};
use hostkey::{pin_known_hosts, simple_hash};
use runner::{
    OpKind, RunError, SSH_CONNECT_TIMEOUT_SECS, SSH_TRANSFER_MIN_RATE_BYTES_PER_SEC, SshRunner,
    leftover_pipe_note,
};

/// The framed ssh-lstat absence protocol (see [`SshTransport::metadata_opt`]):
/// ONE remote exec runs a small perl `lstat` helper that prints a single
/// TAB-separated frame on stdout — the FRAME is the signal (exit 0 for every
/// outcome, because an exit code carries no errno):
///
/// * `P\t<size>\t<rawmode_hex>` — the entry EXISTS (`lstat` succeeded);
///   `<size>` is decimal and `<rawmode>` is hex, the `lstat`-equivalent
///   format, so the [`RemoteMeta`] parse is unchanged.
/// * `A\t<errno>` — `lstat` FAILED with a CONFIRMED-ABSENCE errno: ENOENT
///   or ENOTDIR (the ONLY errnos that mean "no such entry").
/// * `E\t<errno>` — `lstat` FAILED with any OTHER errno (EACCES, EIO,
///   ELOOP, ...).
///
/// `metadata_opt` maps ONLY the `A` frame with errno ENOENT/ENOTDIR to
/// `Ok(None)`; every other outcome — EACCES/EIO frames, malformed frames, a
/// signal-killed command, a nonzero exit, a transport failure — is an error.
/// The frames carry the actual errno, which a shell boolean (`[ ! -e ]`)
/// cannot: a permission failure is an ERROR, never absence. The errno
/// numbers are identical on Linux and macOS (POSIX): ENOENT = 2,
/// ENOTDIR = 20.
const LSTAT_ERRNO_ENOENT: i32 = 2;
const LSTAT_ERRNO_ENOTDIR: i32 = 20;

/// The reserved exit code the remote `try_write_new` script (`write_new_cmd`)
/// exits with when the no-clobber publish (perl `link(2)`) hit an EXISTING
/// destination — the conflict/verdict decision point. It is the ONLY nonzero
/// exit the transport
/// maps to a verdict; every other nonzero exit (a failed pre-install step OR
/// the final parent-directory sync) is a propagated error. `17` cannot collide
/// with the pre-install steps' own failures (each exits nonzero, but the
/// transport distinguishes the verdict by code, never by `exists`-sniffing),
/// and it is deliberately distinct from [`SSH_TWRITE_PREINSTALL_EXIT`].
/// `17` is also EEXIST (POSIX, identical on Linux and macOS) — the raw
/// `link(2)` errno the script maps directly to this code.
pub const SSH_TWRITE_CONFLICT_EXIT: i32 = 17;

/// The exit code the remote `write_new_cmd` script uses for a PRE-INSTALL
/// failure — any failure BEFORE the no-clobber publish: the parent `mkdir`,
/// the `mktemp` allocation, the payload write, the final `chmod`, the file
/// fsync, or a non-EEXIST `link(2)` failure. Such a failure means the
/// operation never reached the publish
/// decision point, so it is a propagated Error, NEVER a verdict — the
/// transport refuses to guess the destination's state. Deliberately distinct
/// from [`SSH_TWRITE_CONFLICT_EXIT`] so the script can tell "the install never
/// happened" from "the destination already existed".
pub const SSH_TWRITE_PREINSTALL_EXIT: i32 = 1;

/// How long the SSH sidecar flock waits before giving up — mirrors
/// `crate::transport::SIDECAR_WAIT_TIMEOUT` (2s) with a 5ms retry interval
/// (`crate::transport::SIDECAR_RETRY_INTERVAL`). The Perl sidecars use a
/// monotonic deadline (`clock_gettime(CLOCK_MONOTONIC)`) so the wait is bounded
/// even if the system clock jumps.
const SIDECAR_FLOCK_DEADLINE_SECS: f64 = 2.0;
const SIDECAR_FLOCK_INTERVAL_SECS: f64 = 0.005;

/// The portable far-side FSYNC primitive: a `perl` one-liner that opens
/// `$ARGV[0]` and calls `IO::Handle::sync` (i.e. `fsync(2)`) on the opened
/// handle. Perl already ships with every reasonable Linux/macOS remote and the
/// crate REQUIRES it for the framed `lstat` helper, `verify_open`, and the
/// sidecars, so this is the ONE durability primitive with identical GNU and
/// BSD semantics.
///
/// `sync <path>` is NOT portable: GNU coreutils >= 8.24 fsyncs the named path,
/// but BSD/macOS `sync` accepts NO operand and silently no-ops —
/// `sync /nonexistent/xyz` exits 0 — so a durability protocol built on
/// `sync <path>` is a protocol that does NOTHING on macOS, a remote this crate
/// documents as supported. `die` makes a failed open/fsync LOUD (nonzero exit)
/// instead of a swallowed success, and the path arrives after `--` as a
/// positional argument, so a leading `-` is an operand, never an option.
///
/// The open is `sysopen` with `O_RDONLY | O_NONBLOCK`, NOT `open "<"`: the
/// latter BLOCKS indefinitely on a FIFO (a read open of a fifo with no writer
/// waits for one), so a single non-regular entry in a tree could hang a deploy
/// forever. `O_NONBLOCK` returns immediately, and an opened entry that is
/// neither a regular file nor a directory is then REFUSED (`die`) rather than
/// fsynced — `fsync(2)` is not meaningful for a fifo/socket/device, and
/// refusing loudly keeps the primitive terminating and fail-closed.
///
/// The two trailing COMMENT tokens are the stable hooks a test's fake `perl`
/// on `PATH` matches to fault-inject or record the file fsync and the
/// directory fsync independently; being comments they change nothing about the
/// executed script.
const PERL_FSYNC_FILE: &str = "use Fcntl qw(O_RDONLY O_NONBLOCK); use IO::Handle; my $p = $ARGV[0]; sysopen(my $fh, $p, O_RDONLY | O_NONBLOCK) or die \"fsync-open $p: $!\"; my @s = stat($fh) or die \"fsync-stat $p: $!\"; my $t = $s[2] & 0170000; die \"fsync-refuse $p: not a regular file or directory\" unless $t == 0100000 || $t == 0040000; $fh->sync or die \"fsync $p: $!\"; close $fh; # STORE_SYNC_TEST_FSYNC_FILE";
const PERL_FSYNC_DIR: &str = "use Fcntl qw(O_RDONLY O_NONBLOCK); use IO::Handle; my $p = $ARGV[0]; sysopen(my $fh, $p, O_RDONLY | O_NONBLOCK) or die \"fsync-open $p: $!\"; my @s = stat($fh) or die \"fsync-stat $p: $!\"; my $t = $s[2] & 0170000; die \"fsync-refuse $p: not a regular file or directory\" unless $t == 0100000 || $t == 0040000; $fh->sync or die \"fsync $p: $!\"; close $fh; # STORE_SYNC_TEST_FSYNC_DIR";

/// ONE shared Perl prelude for the sidecar `flock` — the SSH mirror of
/// `crate::transport::wait_for_sidecar_flock`'s policy: `EWOULDBLOCK`/`EAGAIN`
/// → wait `interval.min(remaining)`; `EINTR` → retry immediately; any other
/// errno → `die "sidecar flock failed: $!"`; contended past the deadline →
/// `die "sidecar contended"`. The prelude reads `$fh` already opened by the
/// caller and keeps the flock held through file fsync and parent-directory sync
/// (the same perl process does the fsyncs while still holding the descriptor).
///
/// TEST-ONLY contention signal: when `DEPLOY_TEST_CONTENDED_FD` is set (a
/// numeric fd a TEST hands the child — the env var must only ever be
/// configured by tests), the prelude writes one `CONTENDED` line to that fd
/// EXACTLY ONCE — right after the FIRST confirmed `EWOULDBLOCK`, before any
/// deadline accounting — then deletes the env key, so later iterations
/// (also EWOULDBLOCKs on a retained lock) stay silent. No timing/sleep is
/// added to the signal path. With the env unset (production) the block is
/// skipped entirely and the emitted behavior is byte-identical to a prelude
/// without the signal.
fn sidecar_flock_prelude(deadline_secs: f64, interval_secs: f64) -> String {
    format!(
        "use Fcntl qw(:flock);\n\
use Errno qw(EINTR EAGAIN EWOULDBLOCK);\n\
use Time::HiRes qw(clock_gettime usleep CLOCK_MONOTONIC);\n\
my $deadline = clock_gettime(CLOCK_MONOTONIC) + {deadline:?};\n\
while (!flock($fh, LOCK_EX | LOCK_NB)) {{{{\n\
    my $errno = 0 + $!;\n\
    next if $errno == EINTR;\n\
    die \"sidecar flock failed: $!\" unless $errno == EAGAIN || $errno == EWOULDBLOCK;\n\
    if (defined $ENV{{\"DEPLOY_TEST_CONTENDED_FD\"}}) {{\n\
        open(my $ready, \">&=\" . $ENV{{\"DEPLOY_TEST_CONTENDED_FD\"}})\n\
            or die \"open contention signal fd: $!\";\n\
        print {{$ready}} \"CONTENDED\\n\";\n\
        delete $ENV{{\"DEPLOY_TEST_CONTENDED_FD\"}};\n\
    }}\n\
    my $remaining = $deadline - clock_gettime(CLOCK_MONOTONIC);\n\
    die \"sidecar contended\" if $remaining <= 0;\n\
    usleep(int(1_000_000 * ($remaining < {interval:?} ? $remaining : {interval:?})));\n\
}}}}",
        deadline = deadline_secs,
        interval = interval_secs
    )
}

/// A transport that drives a real remote host over SSH.
pub struct SshTransport {
    /// `user@address` passed to `ssh` as the connection target.
    target: String,
    /// The caller-supplied deployment layout: the bootstrap directories
    /// `provision_layout` creates, the operation-lock path whose mutations
    /// are sidecar-serialized, and the optional receiver-id marker.
    layout: Layout,
    /// Bare host/address (no `user@` prefix) passed to `ssh-keyscan`, which
    /// expects a hostname/address, not a `user@host` connection string.
    address: String,
    /// Configured SSH port (passed to both `ssh -p` and `ssh-keyscan -p`).
    port: u16,
    root: PathBuf,
    /// Dedicated known-hosts file used with `StrictHostKeyChecking=yes`.
    known_hosts: Option<PathBuf>,
    /// Pre-verified host-key fingerprint (e.g. `SHA256:...`) used to pin the
    /// host key the first time we contact it.
    host_key_fingerprint: Option<String>,
    /// Managed known-hosts file holding the pinned key (used when only a
    /// fingerprint was configured). Set only by [`SshTransport::prepare_identity`],
    /// never at construction, so building the transport has no side effects.
    pinned_known_hosts: std::sync::Mutex<Option<PathBuf>>,
    /// The RESOLVED pin-cache directory for the managed known-hosts file
    /// (the snapshot's `DEPLOY_SSH_KNOWNHOSTS_DIR`, else
    /// `<temp_dir>/deploy-ssh-knownhosts`) — resolved ONCE at the
    /// construction boundary, never read from the process env.
    known_hosts_cache_dir: PathBuf,
    /// The directory holding the SSH connection-multiplexing (ControlMaster)
    /// sockets, one per `user@host:port` — a short path under the system
    /// temp dir (`<temp_dir>/dmux`, created 0700 in
    /// [`SshTransport::prepare_identity`] before any ssh op) because Unix
    /// domain socket paths are length-limited (~104 bytes) and the
    /// known-hosts cache path is too long to host them. Every ssh subprocess
    /// this transport spawns reuses ONE persistent master connection per
    /// remote, so the per-operation SSH handshake (banner, key exchange,
    /// auth, session — several round trips at the link's RTT) is paid once
    /// per push instead of once per operation; the master daemonizes into
    /// its own process group, so the runner's foreground-only containment is
    /// unaffected.
    mux_socket_dir: PathBuf,
    /// The environment snapshot (owned): the pin path's `ssh-keygen`
    /// fingerprint-verification child receives its variables.
    env: SysEnv,
    /// THE bounded subprocess runner every ssh operation goes through
    /// ([`SshRunner`]): hard deadline, kill, and deterministic reap, so no
    /// operation can run unbounded after connection establishment.
    runner: SshRunner,
    /// Per-file upload tracing (`--verbose`): when set, each `upload_bytes`
    /// emits `[trace] upload.start` / `[trace] upload.done` lines to stderr
    /// naming the remote path, the payload size, and the elapsed time, so a
    /// stalled push can be attributed to the exact file being transferred.
    verbose: bool,
    /// The USER's private key for authentication, passed to `ssh` as
    /// `-o IdentitiesOnly=yes -i <path>`. `None` means no key option is added:
    /// ssh then authenticates with the AMBIENT configuration (the running
    /// user's `~/.ssh`, the `SSH_AUTH_SOCK` agent, and `~/.ssh/config`). See
    /// [`SshTransport::with_identity_file`].
    identity_file: Option<PathBuf>,
    /// Caller-supplied extra `ssh -o <value>` options, appended AFTER the
    /// crate's own options. Because OpenSSH uses the FIRST obtained value for
    /// a repeated keyword, a caller cannot override the crate's own host-key
    /// or authentication policy with a conflicting option; a non-conflicting
    /// option (a `ProxyJump`, a `CertificateFile`, a `HostKeyAlgorithms`) is
    /// passed through verbatim. See [`SshTransport::with_ssh_option`].
    ssh_options: Vec<String>,
}

impl SshTransport {
    /// Build a transport for `user@address` (connecting on `port`), whose
    /// application root is the absolute `deploy_dir` path on that host — a
    /// path with at least one normal component below the root (the
    /// filesystem root itself is refused, mirroring the
    /// layout rule: a transport rooted
    /// at `/` would make the deployment cleanup operate on the system
    /// root).
    ///
    /// Host identity must be configured with EXACTLY ONE source: pass a
    /// `known_hosts` file OR a `host_key_fingerprint`. If neither is provided
    /// the transport refuses to connect (no trust-on-first-use); if both are
    /// provided the choice is ambiguous (the ssh arguments would silently
    /// prefer `known_hosts`), so the construction is rejected.
    ///
    /// `known_hosts_cache_dir` is the RESOLVED pin-cache directory for the
    /// managed known-hosts file (from the environment snapshot at the
    /// boundary), and `env` is that snapshot: every child this transport
    /// spawns (ssh, ssh-keyscan, ssh-keygen) receives its variables.
    ///
    /// # Host identity vs the USER's authentication identity
    ///
    /// This constructor's identity material is HOST identity ONLY — which
    /// server key to trust and pin. It does NOT carry the USER's private key:
    /// no `-i`/`IdentityFile`/`IdentitiesOnly` option is added, so ssh
    /// authenticates with the AMBIENT configuration — the running user's
    /// `~/.ssh` default identities, the `SSH_AUTH_SOCK` agent, and
    /// `~/.ssh/config` — exactly as a bare `ssh user@host` would. A tool that
    /// owns its own private key should not rely on that ambient state: pass it
    /// with [`SshTransport::with_identity_file`] (`.with_identity_file(path)`),
    /// which adds `-o IdentitiesOnly=yes -i <path>`. Extra non-conflicting ssh
    /// options are available through [`SshTransport::with_ssh_option`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        user: &str,
        address: &str,
        port: u16,
        deploy_dir: &Path,
        layout: Layout,
        known_hosts: Option<&Path>,
        host_key_fingerprint: Option<&str>,
        known_hosts_cache_dir: &Path,
        env: &SysEnv,
        verbose: bool,
    ) -> Result<Self> {
        if user.is_empty() || address.is_empty() {
            return Err(Error::transport(
                "ssh transport requires a non-empty user and address",
            ));
        }
        if deploy_dir.is_relative() {
            return Err(Error::transport("ssh deploy_dir must be an absolute path"));
        }
        if !has_normal_component_below_root(deploy_dir) {
            return Err(Error::transport(
                "ssh deploy_dir must have at least one normal path component below the root (the filesystem root is not a valid deploy_dir)",
            ));
        }
        // Defensive rejection of ambiguous or unusable identity states, even
        // when the config validation was bypassed (e.g. a direct caller):
        // exactly one of known_hosts / host_key_fingerprint may be set.
        match (known_hosts, host_key_fingerprint) {
            (Some(_), Some(_)) => {
                return Err(Error::transport(
                    "ssh host identity is ambiguous: exactly one of known_hosts or \
                     host_key_fingerprint must be configured (both are set)",
                ));
            }
            (None, None) => {
                return Err(Error::transport(
                    "ssh host identity is not configured: exactly one of `known_hosts` or \
                     `host_key_fingerprint` must be provided (trust-on-first-use is disabled)",
                ));
            }
            _ => {}
        }
        let t = SshTransport {
            target: format!("{user}@{address}"),
            layout,
            address: address.to_string(),
            port,
            root: deploy_dir.to_path_buf(),
            known_hosts: known_hosts.map(|p| p.to_path_buf()),
            host_key_fingerprint: host_key_fingerprint.map(|s| s.to_string()),
            pinned_known_hosts: std::sync::Mutex::new(None),
            known_hosts_cache_dir: known_hosts_cache_dir.to_path_buf(),
            mux_socket_dir: env.temp_dir().join("dmux"),
            env: env.clone(),
            runner: SshRunner::new(env),
            verbose,
            identity_file: None,
            ssh_options: Vec::new(),
        };
        // NOTE: construction is side-effect-free. When a fingerprint was
        // supplied without an explicit known-hosts file, the host key is
        // verified and pinned by `prepare_identity` (before the first remote
        // request), not here — a dry run must never touch the network or disk.
        Ok(t)
    }

    /// Test-only constructor: same validation as [`SshTransport::new`], but with
    /// an injected runner (fake seam + tiny deadlines), so the property test can
    /// drive the deadline/kill/reap contract through the real entry points
    /// without any real subprocess.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_runner(
        user: &str,
        address: &str,
        port: u16,
        deploy_dir: &Path,
        known_hosts: Option<&Path>,
        host_key_fingerprint: Option<&str>,
        known_hosts_cache_dir: &Path,
        env: &SysEnv,
        runner: SshRunner,
    ) -> Result<Self> {
        let mut t = Self::new(
            user,
            address,
            port,
            deploy_dir,
            Layout::empty(),
            known_hosts,
            host_key_fingerprint,
            known_hosts_cache_dir,
            env,
            false,
        )?;
        t.runner = runner;
        Ok(t)
    }

    /// The `provision_layout` command: `mkdir -p <root> <bootstrap_dirs...>`.
    ///
    /// The ROOT is the FIRST operand so the transport can create a fresh
    /// destination (see [`Remote::provision_layout`]); the bootstrap
    /// directories follow it. Every path is single-quoted by `argv_cmd` so it
    /// reaches `mkdir` verbatim.
    fn provision_layout_cmd(root: &Path, layout: &Layout) -> String {
        let mut argv: Vec<String> = vec!["mkdir".into(), "-p".into()];
        argv.push(root.to_string_lossy().into_owned());
        argv.extend(
            layout
                .bootstrap_dirs
                .iter()
                .map(|d| root.join(d).to_string_lossy().into_owned()),
        );
        Self::argv_cmd(&argv)
    }

    /// Supply the USER's private key used to authenticate to the remote,
    /// appended to the ssh arguments as `-o IdentitiesOnly=yes -i <path>`.
    ///
    /// `IdentitiesOnly=yes` makes ssh use exactly this key and skip the ambient
    /// agent/`~/.ssh` identities, so a tool that owns its own key does not need
    /// to install it into the user's agent or `~/.ssh`. The path is passed to
    /// ssh verbatim and must be readable by the ssh process (construction stays
    /// side-effect-free; a missing or unreadable key fails at the first remote
    /// request, not here). Without this method the transport relies on the
    /// ambient ssh configuration — see [`SshTransport::new`]'s "Host identity
    /// vs the USER's authentication identity".
    pub fn with_identity_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.identity_file = Some(path.into());
        self
    }

    /// Append a caller-supplied `ssh` option, passed as `-o <value>` (e.g.
    /// `with_ssh_option("ProxyJump", "bastion")`). Options are appended AFTER
    /// the crate's own, so OpenSSH's first-obtained-value rule keeps the
    /// crate's host-key and authentication policy authoritative; a
    /// non-conflicting option is passed through verbatim. The value is passed
    /// to ssh as one argument, never through a shell.
    pub fn with_ssh_option(mut self, key: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        self.ssh_options
            .push(format!("{}={}", key.as_ref(), value.as_ref()));
        self
    }

    /// Build the fixed `ssh` arguments (options + target). Errors if no host
    /// identity has been configured, so the caller cannot accidentally fall back
    /// to trust-on-first-use.
    fn ssh_args(&self) -> Result<Vec<String>> {
        let mut args: Vec<String> = vec![
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            "PreferredAuthentications=publickey".into(),
            "-o".into(),
            format!("ConnectTimeout={SSH_CONNECT_TIMEOUT_SECS}"),
            "-o".into(),
            "Compression=yes".into(),
            // SSH connection multiplexing: every operation of a push reuses
            // ONE persistent master connection per user@host:port, so the
            // multi-round-trip handshake (banner, key exchange, auth,
            // session) is paid once per push instead of once per operation.
            // The socket name is a short FNV hash of user@host:port (Unix
            // domain socket paths are length-limited); the master daemonizes
            // into its own process group, so the runner's foreground-only
            // containment is unaffected; a stale socket (dead master) is
            // detected and replaced by ssh itself.
            "-o".into(),
            "ControlMaster=auto".into(),
            "-o".into(),
            format!(
                "ControlPath={}/mux-{}",
                self.mux_socket_dir.display(),
                simple_hash(&format!("{}:{}", self.target, self.port))
            ),
            "-o".into(),
            "ControlPersist=120".into(),
            "-p".into(),
            self.port.to_string(),
        ];
        // Read the pinned path through the lock; it is set only by
        // `prepare_identity`.
        let pinned = self.pinned_known_hosts.lock().ok().and_then(|g| g.clone());
        match (&self.known_hosts, &pinned) {
            (Some(kh), _) => {
                args.push("-o".into());
                args.push(format!("UserKnownHostsFile={}", kh.display()));
                args.push("-o".into());
                args.push("StrictHostKeyChecking=yes".into());
            }
            (None, Some(pinned)) => {
                args.push("-o".into());
                args.push(format!("UserKnownHostsFile={}", pinned.display()));
                args.push("-o".into());
                args.push("StrictHostKeyChecking=yes".into());
            }
            (None, None) => {
                return Err(Error::transport(
                    "ssh host identity is not configured: provide `known_hosts` or \
                     `host_key_fingerprint` (trust-on-first-use is disabled)",
                ));
            }
        }
        // The USER's authentication identity, when the caller supplied one. The
        // ambient configuration (agent, `~/.ssh`) is used when it is absent.
        // Placed AFTER the crate's own options so the first-obtained-value rule
        // keeps the crate's host-key policy authoritative.
        if let Some(identity) = &self.identity_file {
            args.push("-o".into());
            args.push("IdentitiesOnly=yes".into());
            args.push("-i".into());
            args.push(identity.to_string_lossy().into_owned());
        }
        for option in &self.ssh_options {
            args.push("-o".into());
            args.push(option.clone());
        }
        args.push(self.target.clone());
        Ok(args)
    }

    /// Verify the remote host key against the configured fingerprint and pin
    /// it in a managed known-hosts file (see [`pin_known_hosts`]).
    /// Fails closed if the key cannot be fetched or does not match. Takes
    /// `&self`: the pinned path is stored through the interior-mutability
    /// lock; the verification/cache logic itself lives in `pin_known_hosts`.
    pub(crate) fn pin_known_hosts(&self) -> Result<()> {
        let fingerprint = self
            .host_key_fingerprint
            .clone()
            .ok_or_else(|| Error::transport("host_key_fingerprint required for pinning"))?;
        let pinned = pin_known_hosts(
            &fingerprint,
            &self.target,
            &self.address,
            self.port,
            &self.known_hosts_cache_dir,
            &self.env,
            &self.runner,
        )?;
        if let Ok(mut g) = self.pinned_known_hosts.lock() {
            *g = Some(pinned);
        }
        Ok(())
    }

    /// Run a single remote shell command (already fully quoted) and return its
    /// stdout/stderr/status. The command is passed as one `ssh` argument after
    /// `--`, so OpenSSH cannot interpret any part of our data as options or as
    /// the connection target. Runs through the shared bounded runner: once
    /// connected, a remote command that hangs is killed after
    /// `SSH_COMMAND_TIMEOUT_SECS`, and the call returns within that deadline
    /// PLUS the additive termination/drain tail (~2.2 s; see
    /// [`SshRunner::run`]) — bounded, but not at the deadline exactly.
    pub(crate) fn run_remote(&self, command: &str) -> Result<std::process::Output> {
        self.run_remote_op(OpKind::Remote, command)
    }

    pub(crate) fn run_remote_ok(&self, command: &str) -> Result<()> {
        let out = self.run_remote_op(OpKind::RemoteOk, command)?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh command failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }

    /// Shared implementation of the single-command ssh operations: build the
    /// `ssh <args> -- <command>` vector and run it through the runner under the
    /// command deadline. `run_remote` and `run_remote_ok` differ only in the
    /// recorded operation kind and in whether they check the exit status.
    fn run_remote_op(&self, op: OpKind, command: &str) -> Result<std::process::Output> {
        let argv = self.ssh_command_argv(command)?;
        self.runner.run(op, &argv, None, None).map_err(|e| match e {
            RunError::Spawn(m) => Error::transport(format!("ssh {command}: {m}")),
            RunError::StdinWrite(m) => Error::transport(format!("ssh {command}: {m}")),
            RunError::Wait(m) => Error::transport(format!("ssh {command}: {m}")),
            RunError::Background(m) => Error::transport(format!("ssh {command}: {m}")),
            RunError::Timeout {
                after,
                leftover_pipes,
            } => Error::transport(format!(
                "ssh command timed out after {after:?}{}: {command}",
                leftover_pipe_note(&leftover_pipes)
            )),
        })
    }

    /// Build the `ssh <args> -- <command>` argv, forcing the remote command to
    /// run under `bash` regardless of the deployment account's login shell.
    /// The remote scripts (globs, the `[ -e ] || [ -L ] || continue`
    /// existence guard, ...) are
    /// written for POSIX sh/bash semantics; a login shell like zsh aborts on
    /// an unmatched glob (`no matches found`) instead of passing the pattern
    /// through, which breaks e.g. the first `list` of an empty object store.
    /// Wrapping the command in `bash -c '<quoted>'` means the outer login
    /// shell only parses the trivial `bash -c '...'` invocation (single-
    /// quoted, no globs to expand), and the inner script runs under bash.
    fn ssh_command_argv(&self, command: &str) -> Result<Vec<String>> {
        let mut argv = vec!["ssh".to_string()];
        argv.extend(self.ssh_args()?);
        argv.push("--".into());
        argv.push(format!("bash -c {}", shell_quote(command)));
        Ok(argv)
    }

    /// Build the remote command for an atomic path replacement.
    ///
    /// The primitive is perl's `rename(2)` — the ONE operation with POSIX
    /// rename semantics, using the same interpreter the framed `lstat` helper
    /// and `verify_open` already require on the far side. It has exactly the
    /// three properties the transport depends on, on EVERY userland:
    ///
    /// * it is ATOMIC and it atomically REPLACES an existing non-directory
    ///   target (a regular file, a live or DANGLING symlink, a self-loop
    ///   symlink), which is the per-slot commit point;
    /// * it NEVER moves the source INTO a directory target — the failure mode
    ///   of a bare `mv src dst` when `dst` is a symlink to a directory
    ///   (`mv` dereferences the destination and moves `src` inside it,
    ///   silently polluting the store); and
    /// * it REFUSES, loudly (nonzero, `die` on stderr), when the target is a
    ///   directory and the source is not (`EISDIR`/`ENOTDIR`), so a
    ///   kind-changing replacement that the applier did not stage is an error
    ///   rather than a surprise.
    ///
    /// GNU `mv -T` provided the first two points on GNU only. It is an
    /// ILLEGAL option on BSD/macOS (`mv: illegal option -- T`, exit 64), so on
    /// a supported macOS/BSD remote EVERY kind-changing replacement — the
    /// symlink-to-directory `current` swap, a symlink retarget, dir-over-nondir
    /// — failed with a transport error. `rename(2)` is portable and has no
    /// option parsing at all: both operands are shell-quoted and passed after
    /// `--`, so a leading `-` is an operand, never an option.
    fn rename_cmd(root: &Path, from: &Path, to: &Path) -> String {
        let f = root.join(from).to_string_lossy().into_owned();
        let t = root.join(to).to_string_lossy().into_owned();
        let parent = Path::new(&t)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        format!(
            "mkdir -p {parent} && perl -e 'rename($ARGV[0], $ARGV[1]) or die \"rename $ARGV[0] -> $ARGV[1]: $!\";' -- {f} {t}",
            parent = shell_quote(&parent),
            f = shell_quote(&f),
            t = shell_quote(&t),
        )
    }

    /// Build the remote command that fsyncs `root.join(rel)` and every entry
    /// BELOW it, children before parents, so a staged bundle is durable before
    /// the atomic install rename. The primitive is the portable perl
    /// ([`PERL_FSYNC_DIR`]) because `sync <path>` is GNU-only and a silent
    /// no-op on BSD/macOS.
    ///
    /// The walk mirrors `LocalTransport::fsync_tree`'s classification exactly:
    /// `-type d` and `-type f` (like `symlink_metadata`, `-type` does NOT
    /// follow a symlink) select the regular files and directories; symlinks
    /// and every other entry are SKIPPED — their durability is their
    /// directory entry, which the parent-directory fsync covers. A dangling
    /// symlink is therefore not a failure, and a fifo is never opened.
    ///
    /// `-exec … {} +`, NOT `-exec … {} ;`, is what makes a failed fsync an
    /// error: `find` IGNORES the invoked command's exit status for `;` (proved
    /// on GNU and BSD: a tree whose every fsync exited 9 still made `find` exit
    /// 0), while for `+` POSIX `find` exits nonzero if ANY invocation does.
    /// The `sh -c` wrapper stops at the first failed entry (`|| exit 1`), so
    /// the single nonzero invocation survives as `find`'s nonzero exit and
    /// [`Remote::fsync_tree`] surfaces an `Err` instead of a durability claim
    /// nothing backed.
    fn fsync_tree_cmd(root: &Path, rel: &Path) -> String {
        let p = root.join(rel).to_string_lossy().into_owned();
        let fsync = shell_quote(PERL_FSYNC_DIR);
        let wrapper = format!("for f do perl -e {fsync} -- \"$f\" || exit 1; done");
        Self::argv_cmd(&[
            "find".into(),
            p,
            "-depth".into(),
            "(".into(),
            "-type".into(),
            "d".into(),
            "-o".into(),
            "-type".into(),
            "f".into(),
            ")".into(),
            "-exec".into(),
            "sh".into(),
            "-c".into(),
            wrapper,
            "sh".into(),
            "{}".into(),
            "+".into(),
        ])
    }

    /// Build the remote command that fsyncs the PARENT directory of
    /// `root.join(rel)` — the directory whose entry the mutation just changed.
    /// See [`PERL_FSYNC_DIR`] for why `sync <dir>` cannot be used.
    fn fsync_parent_cmd(root: &Path, rel: &Path) -> String {
        let p = root.join(rel).to_string_lossy().into_owned();
        let parent = Path::new(&p)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        format!(
            "perl -e '{PERL_FSYNC_DIR}' -- {parent}",
            parent = shell_quote(&parent)
        )
    }

    /// Build a remote shell command string from an `argv`, quoting every
    /// argument so the remote shell re-tokenizes it back into exactly `argv`.
    fn argv_cmd(argv: &[String]) -> String {
        argv.iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Upload raw bytes to a remote path (creating parent dirs). Runs through
    /// the shared bounded runner: the stdin payload is written as part of the
    /// bounded wait, so an upload to a remote that stops reading (hung remote
    /// mid-`cat`) times out after `SSH_COMMAND_TIMEOUT_SECS` instead of
    /// blocking the push indefinitely.
    ///
    /// When the transport was built with `verbose` (the CLI's `--verbose`),
    /// each upload emits `[trace] upload.start` / `[trace] upload.done` lines
    /// to stderr naming the remote path, the payload size, and the elapsed
    /// time — so a stalled or slow push can be attributed to the exact file
    /// being transferred.
    pub(crate) fn upload_bytes(&self, rel: &Path, data: &[u8], mode: u32) -> Result<()> {
        let remote_path = self.root.join(rel);
        let remote_path_str = remote_path.to_string_lossy().into_owned();
        // The parent is computed HERE and single-quoted, never via an unquoted
        // `$(dirname ...)`: command-substitution output is subject to word
        // splitting and pathname expansion, so a destination whose parent
        // contains a space, a tab, a newline, or a glob metacharacter would
        // create stray entries and — for a split word — an object relative to
        // the remote working directory, OUTSIDE the destination root. A
        // command substitution also strips a trailing newline from `dirname`'s
        // output, silently truncating a parent that ends in one. `--` keeps a
        // component that starts with `-` from being read as an option.
        let parent = Path::new(&remote_path_str)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        // The payload is written to a UNIQUE temp file in the destination's
        // own directory, the FINAL MODE is applied to the temp, the temp is
        // fsynced, the temp is RENAMED into place (atomically, and without
        // following a final-component symlink), and then the PARENT DIRECTORY
        // is fsynced. This is the far-side realization of the same
        // compare-free atomic replace the local path uses: a failure at ANY
        // step before the rename leaves the PREVIOUS content visible and
        // removes the temp, so a failed upload can no longer destroy or
        // truncate the entry it was replacing. The rename is perl's raw
        // `rename(2)` (ships with every reasonable remote; GNU and BSD agree)
        // so it OVERWRITES the final entry atomically — a destination that is
        // a DIRECTORY makes it fail loudly rather than being linked into or
        // descended. The fsyncs are the portable perl primitives
        // ([`PERL_FSYNC_FILE`] / [`PERL_FSYNC_DIR`]): `sync <path>` is
        // GNU-only and a silent no-op on BSD/macOS.
        //
        // Every operand is a single quoted word ([`shell_quote`]); the parent
        // is computed here (never by a remote `dirname`), and `--` keeps a
        // leading-dash component from being read as an option. The payload is
        // NEVER embedded in the command string — it arrives on STDIN and the
        // remote `cat` redirects it into the temp — so arbitrary bytes
        // round-trip exactly.
        let basename = Path::new(&remote_path_str)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "object".to_string());
        let tmp_template = format!("{}/.{}.tmp.XXXXXX", parent.trim_end_matches('/'), basename,);
        // The final mode is applied to the TEMP before the rename (the same
        // ordering `write_new_cmd` uses), so the published inode carries the
        // caller's mode, never the remote umask. A `mode` of 0 keeps the
        // historical "no chmod" meaning; the mktemp temp is private (0o600).
        let chmod_step = if mode != 0 {
            format!("chmod {:o} \"$tmp\" && ", mode & 0o7777)
        } else {
            String::new()
        };
        let script = format!(
            "mkdir -p -- {parent} && tmp=$(mktemp {tpl}) && cat > \"$tmp\" && {chmod}perl -e '{fsync_file}' -- \"$tmp\"; pre=$?; if [ \"$pre\" -ne 0 ]; then rm -f \"$tmp\"; exit 1; fi; perl -e 'exit 0 if rename($ARGV[0], $ARGV[1]); exit 1' \"$tmp\" {p}; rc=$?; if [ \"$rc\" -ne 0 ]; then rm -f \"$tmp\"; exit 1; fi; perl -e '{fsync_dir}' -- {parent}",
            parent = shell_quote(&parent),
            tpl = shell_quote(&tmp_template),
            chmod = chmod_step,
            p = shell_quote(&remote_path_str),
            fsync_file = PERL_FSYNC_FILE,
            fsync_dir = PERL_FSYNC_DIR,
        );
        let argv = self.ssh_command_argv(&script)?;
        // Size-aware deadline: a large upload over a slow link must not be
        // killed by the fixed command timeout mid-transfer (a truncated
        // object would fail its post-upload integrity re-hash). The bound
        // scales with the payload at a conservative minimum rate (the
        // snapshot's `DEPLOY_SSH_MIN_RATE_BYTES_PER_SEC` override, else the
        // 64KB/s default).
        let bytes = data.len() as u64;
        let min_rate = upload_min_rate_bytes_per_sec(&self.env);
        let command_deadline = self.runner.command_deadline();
        let transfer_timeout = upload_deadline(bytes, min_rate, command_deadline);
        if self.verbose {
            eprintln!("[trace] upload.start: {remote_path_str} ({bytes} bytes)");
        }
        let started = std::time::Instant::now();
        let out = self
            .runner
            .run(OpKind::Upload, &argv, Some(data), Some(transfer_timeout))
            .map_err(|e| match e {
                RunError::Spawn(m) => Error::transport(format!("ssh upload spawn: {m}")),
                RunError::StdinWrite(m) => Error::transport(format!("ssh upload stdin write: {m}")),
                RunError::Wait(m) => Error::transport(format!("ssh upload wait: {m}")),
                RunError::Background(m) => Error::transport(format!("ssh upload: {m}")),
                RunError::Timeout {
                    after,
                    leftover_pipes,
                } => {
                    // DIAGNOSIS, not a dead end: name the file and size, and
                    // point at the fix (slow link vs hung remote).
                    upload_timeout_error(
                        after,
                        &leftover_pipes,
                        bytes,
                        &remote_path_str,
                        transfer_timeout,
                        command_deadline,
                        min_rate,
                    )
                }
            })?;
        if self.verbose {
            eprintln!(
                "[trace] upload.done: {remote_path_str} +{:.1}s",
                started.elapsed().as_secs_f32()
            );
        }
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh upload failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        // The mode was applied to the temp BEFORE the rename by the remote
        // script, so no separate chmod round trip (and no window where the
        // published entry carries the temp's private mode) is needed.
        Ok(())
    }

    fn download_bytes(&self, rel: &Path) -> Result<Vec<u8>> {
        let remote_path = self.root.join(rel);
        let remote_path_str = remote_path.to_string_lossy().into_owned();
        // Read the file contents with `cat`; the path is quoted so a path that
        // happens to contain shell metacharacters (or an executable-bit path) is
        // never executed.
        let out = self.run_remote(&format!("cat {}", shell_quote(&remote_path_str)))?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh download failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(out.stdout)
    }
}

/// The size-aware upload deadline: `max(runner command deadline, bytes /
/// min_rate)` — a large upload over a slow link is never killed mid-transfer,
/// while a hung upload (a remote that stops reading stdin) is still bounded.
/// The BASE deadline is the runner's [`SshRunner::command_deadline`], never
/// a hardcoded constant: the test seam injects a tiny command deadline and
/// MUST see it applied to uploads too (the fake Hang child waits for THIS
/// bound, not a production constant).
fn upload_deadline(data_len: u64, min_rate: u64, command_deadline: Duration) -> Duration {
    command_deadline.max(Duration::from_secs(data_len / min_rate))
}

/// Build the DIAGNOSTIC error for an upload that hit its deadline. A size-
/// scaled deadline (`deadline > command_deadline`) means the link is slower
/// than the assumed minimum rate — the message says so and points at the
/// `DEPLOY_SSH_MIN_RATE_BYTES_PER_SEC` override with a concrete suggested
/// value (half the current rate), so a slow link is recoverable without
/// reading the source. A bare command deadline means the remote stopped
/// reading stdin (a hung remote or wedged filesystem) — a different failure
/// that a rate override cannot fix. Both branches name the remote file and
/// its byte size so a stalling file is attributable.
fn upload_timeout_error(
    after: Duration,
    leftover_pipes: &Option<String>,
    bytes: u64,
    remote_path: &str,
    deadline: Duration,
    command_deadline: Duration,
    min_rate: u64,
) -> Error {
    let leftover = leftover_pipe_note(leftover_pipes);
    if deadline > command_deadline {
        let suggested = (min_rate / 2).max(1024);
        Error::transport(format!(
            "ssh upload timed out after {after:?}{leftover}: {bytes} bytes to '{remote_path}' did not \
             finish within the size-scaled deadline (bytes / min_rate = {bytes} / {min_rate} B/s; the \
             default minimum is {SSH_TRANSFER_MIN_RATE_BYTES_PER_SEC} B/s, overridable via \
             DEPLOY_SSH_MIN_RATE_BYTES_PER_SEC). The link is slower than the assumed minimum — \
             retry with DEPLOY_SSH_MIN_RATE_BYTES_PER_SEC={suggested} (half the current rate) or \
             lower so the deadline scales to the real link speed"
        ))
    } else {
        Error::transport(format!(
            "ssh upload timed out after {after:?}{leftover}: {bytes} bytes to '{remote_path}' did not \
             finish within the base command deadline ({command_deadline:?}) — the remote likely \
             stopped reading stdin (a hung remote or wedged filesystem)"
        ))
    }
}

/// Resolve the upload min-rate from the environment snapshot:
/// `DEPLOY_SSH_MIN_RATE_BYTES_PER_SEC` (a positive integer) overrides the
/// default [`SSH_TRANSFER_MIN_RATE_BYTES_PER_SEC`]; an unset, empty,
/// non-numeric, or non-positive value falls back to the default. Resolved
/// ONCE per upload from the snapshot — never from the live process env.
fn upload_min_rate_bytes_per_sec(env: &SysEnv) -> u64 {
    env.get("DEPLOY_SSH_MIN_RATE_BYTES_PER_SEC")
        .and_then(|v| v.into_string().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|r| *r > 0)
        .unwrap_or(SSH_TRANSFER_MIN_RATE_BYTES_PER_SEC)
}

/// Single-quote a string for safe inclusion in a remote shell token. A `'` is
/// escaped as `'\''` (close-quote, escaped quote, reopen-quote).
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Build the perl script for atomic compare-and-delete under the sidecar:
/// open the sidecar, flock exclusively with bounded retry, then read the
/// lock file, compare to `expected`, unlink if match, otherwise leave it.
/// Prints a single verdict frame: `R` (removed), `M` (mismatch), or `A`
/// (absent). Continuously visible for mismatch — the file is never made
/// absent.
fn remove_file_if_sidecar_cmd(
    root: &Path,
    sidecar_rel: &RootedRelativePath,
    lock_rel: &RootedRelativePath,
    expected: &str,
) -> String {
    let sidecar = root.join(sidecar_rel).to_string_lossy().into_owned();
    let lock = root.join(lock_rel).to_string_lossy().into_owned();
    let sidecar_parent = std::path::Path::new(&sidecar)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string());
    let sidecar_q = shell_quote(&sidecar);
    let sidecar_parent_q = shell_quote(&sidecar_parent);
    let lock_q = shell_quote(&lock);
    let expected_q = shell_quote(expected);
    let prelude = sidecar_flock_prelude(SIDECAR_FLOCK_DEADLINE_SECS, SIDECAR_FLOCK_INTERVAL_SECS);
    format!(
        "mkdir -p {sidecar_parent} && touch {sidecar} && chmod 644 {sidecar} && perl -e '
use Fcntl qw(:flock);
open my $fh, \"+<\", $ARGV[0] or die \"open sidecar: $!\";
{prelude}
my $lock=$ARGV[1]; my $exp=$ARGV[2];
if (! -e $lock && ! -l $lock) {{ print \"A\"; exit 0; }}
open my $lf, \"<\", $lock or do {{ print \"M\"; exit 0; }};
my $content=do {{ local $/; <$lf> }}; close $lf;
if ($content eq $exp) {{ unlink $lock or die \"unlink: $!\"; print \"R\"; }} else {{ print \"M\"; }}
' -- {sidecar} {lock} {exp}",
        sidecar_parent = sidecar_parent_q,
        sidecar = sidecar_q,
        lock = lock_q,
        exp = expected_q,
        prelude = prelude,
    )
}

/// Build the perl script for atomic recover under the sidecar: open the
/// sidecar, flock exclusively with bounded retry, then read the lock file,
/// compare to `observed`, unlink if match, then install `new_data` via a
/// temp+rename with durability (chmod 644, fsync file, fsync parent). Prints
/// a single verdict frame: `OK`, `MISMATCH`, or `ABSENT` (or dies on
/// contended/transport failure).
fn recover_sidecar_cmd(
    root: &Path,
    sidecar_rel: &RootedRelativePath,
    lock_rel: &RootedRelativePath,
    observed: &str,
    new_data: &str,
) -> String {
    let sidecar = root.join(sidecar_rel).to_string_lossy().into_owned();
    let lock = root.join(lock_rel).to_string_lossy().into_owned();
    let parent = std::path::Path::new(&lock)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string());
    let sidecar_q = shell_quote(&sidecar);
    let lock_q = shell_quote(&lock);
    let parent_q = shell_quote(&parent);
    let observed_q = shell_quote(observed);
    let new_q = shell_quote(new_data);
    let sidecar_parent = std::path::Path::new(&sidecar)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| ".".to_string());
    let sidecar_parent_q = shell_quote(&sidecar_parent);
    let prelude = sidecar_flock_prelude(SIDECAR_FLOCK_DEADLINE_SECS, SIDECAR_FLOCK_INTERVAL_SECS);
    format!(
        "mkdir -p {parent} && mkdir -p {sidecar_parent} && touch {sidecar} && chmod 644 {sidecar} && perl -e '
use Fcntl qw(:flock);
open my $fh, \"+<\", $ARGV[0] or die \"open sidecar: $!\";
{prelude}
my $lock=$ARGV[1]; my $obs=$ARGV[2]; my $new=$ARGV[3];
if (! -e $lock && ! -l $lock) {{ print \"ABSENT\\n\"; exit 0; }}
open my $lf, \"<\", $lock or do {{ print \"MISMATCH\\n\"; exit 0; }};
my $content=do {{ local $/; <$lf> }}; close $lf;
if ($content ne $obs) {{ print \"MISMATCH\\n\"; exit 0; }}
unlink $lock or die \"unlink: $!\";
my $dir=$lock; $dir=~s{{/[^/]+$}}{{}}; $dir=\".\" if $dir eq \"\";
my $tmp=\"$dir/.operation.lock.tmp.$$\";
open my $tf, \">\", $tmp or die \"create tmp: $!\";
print $tf $new; close $tf;
chmod 0644, $tmp;
open my $tff, \"+<\", $tmp or die;
$tff->sync or die \"fsync tmp: $!\"; close $tff;
rename $tmp, $lock or die \"rename: $!\";
open my $dfh, \"<\", $dir or die;
$dfh->sync or die \"fsync dir: $!\";
print \"OK\\n\";
' -- {sidecar} {lock} {obs} {new}",
        parent = parent_q,
        sidecar_parent = sidecar_parent_q,
        sidecar = sidecar_q,
        lock = lock_q,
        obs = observed_q,
        new = new_q,
        prelude = prelude,
    )
}

impl SshTransport {
    /// Build the remote shell command implementing the durability protocol
    /// for an immutable record at `root.join(rel)` — the remote realization
    /// of the ONE canonical create-new primitive (`durable_create_new` in
    /// the parent module), with the IDENTICAL seven-step sequence:
    ///
    /// 1. Allocate the temporary file REMOTELY with `mktemp` (exclusive
    ///    create, O_EXCL), so the name cannot collide with another
    ///    controller's temp no matter its pid or host: no two invocations
    ///    are ever handed the same name, and a stale temp left behind by a
    ///    crashed controller is never selected — and therefore never
    ///    truncated. The name is dot-prefixed and lives INSIDE the
    ///    destination's parent directory, so a concurrent reader never sees
    ///    a partial record and listing-based observers skip the temp name.
    /// 2. Write the payload — the RAW BYTES arrive on the command's STDIN
    ///    (the transport pipes them to the ssh child; the remote `cat`
    ///    redirects them into the temp with `cat > "$tmp"`). The payload is
    ///    NEVER embedded in the command string — no shell escaping, no
    ///    quoting — so ARBITRARY bytes (NULs, non-UTF8, control chars,
    ///    quotes, shell metacharacters, long payloads) round-trip exactly:
    ///    this is the byte-preservation contract of [`Remote::try_write_new`].
    /// 3. Apply the FINAL MODE with `chmod` BEFORE the file fsync — the
    ///    published inode carries the caller's mode, never the remote umask.
    /// 4. A perl `fsync(2)` of the temp file — the file is durable. (See
    ///    [`PERL_FSYNC_FILE`]: `sync "$tmp"` is GNU-only and a NO-OP on
    ///    BSD/macOS, so it cannot carry a durability guarantee.)
    /// 5. Install atomically WITHOUT replacement via perl's raw `link(2)`
    ///    (the same interpreter the framed `lstat` helper relies on) — it
    ///    FAILS if the destination exists in ANY form (a regular file, a
    ///    directory, a symlink — never linked-inside or dereferenced the way
    ///    a shell `ln` would), so no loser can clobber a winner. The loser's
    ///    failure is reported through the reserved `SSH_TWRITE_CONFLICT_EXIT`
    ///    exit code, NEVER by replacing the winner.
    /// 6. Remove only the temporary file THIS invocation created (the
    ///    cleanup runs on the conflict path too — the `rc` capture keeps it
    ///    outside the `&&` chain).
    /// 7. A perl `fsync(2)` of the PARENT directory — the rename that publishes
    ///    the record is durable, and its failure PROPAGATES (a failed fsync is a
    ///    failed install, never a silent success).
    ///    PROPAGATES (the old script swallowed it with `2>/dev/null`): a
    ///    failed sync is a failed install, never a silent success.
    ///
    /// The parent directory is created first (the remote layout is not
    /// provisioned by SSH the way LocalTransport does it), so a fresh remote
    /// root still allows the first lock acquisition. The PRE-INSTALL chain
    /// (`mkdir` .. `sync "$tmp"`) is `&&`-connected and its exit status is
    /// captured separately: if ANY pre-install step fails, the command exits
    /// [`SSH_TWRITE_PREINSTALL_EXIT`] WITHOUT installing anything (fail
    /// closed) — a pre-install failure is a propagated ERROR, never the
    /// conflict verdict, because the operation never reached the publish
    /// decision point. The publish is perl `link(2)` — RAW link semantics,
    /// so a destination that exists in ANY form (a regular file, a DIRECTORY
    /// — which a shell `ln` would silently link INSIDE — or a symlink) is
    /// EEXIST, never dereferenced and never linked-into; EEXIST (17, the
    /// same value as [`SSH_TWRITE_CONFLICT_EXIT`]) exits the reserved
    /// conflict code directly, any other link failure is the pre-install
    /// exit. Only a nonzero publish exit whose destination is then PRESENT
    /// (`[ -e ]`/`[ -L ]`) is the confirmed-EEXIST verdict
    /// [`SSH_TWRITE_CONFLICT_EXIT`] (the winner is never replaced; the
    /// transport verifies it and decides AlreadyPresent vs Conflict); a
    /// nonzero publish exit with the destination ABSENT is a real publish
    /// failure, again the pre-install exit (an error). The final `sync
    /// <parent>` runs ONLY on the install-success path, and its exit status
    /// is the command's exit status — a real `fsync(2)` (perl `IO::Handle::sync`),
    /// never a best-effort swallow. (The
    /// AlreadyPresent retry's parent sync runs in the TRANSPORT — see
    /// [`SshTransport::try_write_new`] — mirroring the local primitive's
    /// "parent fsync on Created AND AlreadyPresent, never on Conflict".)
    //
    // Portability notes: `mktemp TEMPLATE` accepts a template argument on
    // both GNU and BSD/macOS, provided `XXXXXX` ends the final component
    // (kept here). Durability is the perl `fsync(2)` primitive
    // ([`PERL_FSYNC_FILE`] / [`PERL_FSYNC_DIR`]) because `sync <path>` is
    // GNU-only and a silent no-op on BSD/macOS. The payload write is a
    // bare `cat > "$tmp"`: `cat` is POSIX, reads stdin to EOF, and the
    // redirect opens the temp — no quoting of data anywhere.
    fn write_new_cmd(root: &Path, rel: &Path, mode: u32) -> String {
        let remote_path = root.join(rel);
        let remote_path_str = remote_path.to_string_lossy().into_owned();
        let parent = Path::new(&remote_path_str)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        // Durability protocol — the seven-step sequence is documented on
        // this function; the comment here only notes the pieces that are
        // invisible in the final string: the pre-install chain fails closed
        // with the PRE-INSTALL exit (distinct from the conflict verdict), the
        // publish is perl `link(2)` (raw link semantics — a destination that
        // exists in ANY form is EEXIST and exits the reserved conflict code
        // directly, never linked-inside or dereferenced the way a shell `ln`
        // would), the confirmed-EEXIST fallback decision is made by checking
        // the destination's PRESENCE after a failed publish (never by
        // swallowing every publish failure as a verdict), the `rc` capture
        // keeps the temp cleanup outside the chain so it runs on the
        // conflict path too, and the
        // parent-dir sync runs ONLY after a successful install and its
        // failure is the command's exit status.
        let basename = Path::new(&remote_path_str)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "record".to_string());
        // The temp lives INSIDE the destination's parent directory and is
        // dot-prefixed, exactly like LocalTransport's durable_create_new. A
        // sibling name (`{parent}.{basename}.tmp...`) would escape the
        // managed remote root whenever the destination's parent IS the
        // deployment root. The `XXXXXX` suffix is the mktemp template; it
        // must survive shell quoting verbatim (single quotes are fine) so GNU
        // and BSD mktemp both accept it.
        let tmp_template = format!("{}/.{}.tmp.XXXXXX", parent.trim_end_matches('/'), basename,);
        let mode_str = format!("{:o}", mode & 0o7777);
        // The publish step: perl's raw `link(2)` (perl ships with every
        // reasonable remote — the same interpreter the framed `lstat` helper
        // already relies on). A shell `ln` would silently place the link
        // INSIDE an existing directory destination (or follow a symlink);
        // `link(2)` fails with EEXIST whenever the destination name exists in
        // ANY form — a regular file, a directory, a symlink — so the
        // immutable-record destination can never be silently created over a
        // non-file entry. EEXIST is 17 on both Linux and macOS (POSIX),
        // identical to the reserved [`SSH_TWRITE_CONFLICT_EXIT`]; any other
        // link failure is the pre-install exit (a real publish error).
        format!(
            "mkdir -p {p} && tmp=$(mktemp {tpl}) && cat > \"$tmp\" && chmod {mode} \"$tmp\" && perl -e '{fsync_file}' -- \"$tmp\"; pre=$?; if [ \"$pre\" -ne 0 ]; then rm -f \"$tmp\"; exit {preinst}; fi; perl -e 'exit 0 if link($ARGV[0], $ARGV[1]); exit(($! + 0) == 17 ? {conflict} : {preinst})' \"$tmp\" {d}; rc=$?; rm -f \"$tmp\"; if [ \"$rc\" -eq 0 ]; then perl -e '{fsync_dir}' -- {parent}; exit $?; fi; if [ -e {d} ] || [ -L {d} ]; then exit {conflict}; fi; exit {preinst}",
            p = shell_quote(&parent),
            tpl = shell_quote(&tmp_template),
            mode = mode_str,
            d = shell_quote(&remote_path_str),
            conflict = SSH_TWRITE_CONFLICT_EXIT,
            preinst = SSH_TWRITE_PREINSTALL_EXIT,
            parent = shell_quote(&parent),
            fsync_file = PERL_FSYNC_FILE,
            fsync_dir = PERL_FSYNC_DIR,
        )
    }

    /// Build the perl-native command for the operation-lock `try_write_new`:
    /// the ENTIRE seven-step durable create is performed inside the SAME Perl
    /// process that owns the sidecar `flock`. The sidecar is created durably
    /// (`mkdir -p`, `touch`, `chmod 644`) and never removed; the perl helper
    /// acquires an exclusive `LOCK_EX|LOCK_NB` with a 2-second monotonic deadline
    /// and 5ms retry interval (mirroring `SIDECAR_WAIT_TIMEOUT` /
    /// `SIDECAR_RETRY_INTERVAL`): `EWOULDBLOCK`/`EAGAIN` waits
    /// `interval.min(remaining)`, `EINTR` retries immediately, any other errno
    /// fails with `sidecar flock failed`, contended past the deadline dies with
    /// `sidecar contended`. The lock is held via the open file description until
    /// the perl process exits — no `exec` is ever performed, so the descriptor is
    /// never closed with `FD_CLOEXEC` before the mutation, and the flock stays
    /// held through file fsync and parent-directory sync. Perl is used because it
    /// ships on every Linux/macOS remote and provides portable `flock`.
    ///
    /// The parent-directory fsync (step 7) is performed INSIDE the Perl process
    /// before exit by opening the directory and calling `IO::Handle->sync` on
    /// the descriptor, so the flock is still held (the `sync` is durability,
    /// not mutual exclusion, but keeping it inside avoids releasing the lock
    /// before the directory entry is durable).
    fn try_write_new_sidecar_cmd(&self, rel: &Path, mode: u32) -> String {
        let sidecar = self
            .root
            .join(&self.layout.lock_sidecar)
            .to_string_lossy()
            .into_owned();
        let lock = self.root.join(rel).to_string_lossy().into_owned();
        let parent = std::path::Path::new(&lock)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        let sidecar_q = shell_quote(&sidecar);
        let parent_q = shell_quote(&parent);
        let lock_q = shell_quote(&lock);
        let mode_str = format!("{:o}", mode & 0o7777);
        let mode_q = shell_quote(&mode_str);
        let prelude =
            sidecar_flock_prelude(SIDECAR_FLOCK_DEADLINE_SECS, SIDECAR_FLOCK_INTERVAL_SECS);
        format!(
            "mkdir -p {parent} && touch {sidecar} && chmod 644 {sidecar} && perl -e 'use Fcntl qw(:flock O_WRONLY O_CREAT O_EXCL); use IO::Handle; open my $fh, \"+<\", $ARGV[0] or die \"open sidecar $ARGV[0]: $!\"; {prelude} binmode STDIN; my $data = do {{ local $/; <STDIN> }}; my $lock=$ARGV[1]; my $mode=$ARGV[2]; my $dir=$lock; $dir=~s{{/[^/]+$}}{{}}; $dir=\".\" if $dir eq \"\"; my $base=$lock; $base=~s{{.*/}}{{}}; my $tmp; my $tfh; for (1..32) {{ my $uniq=\"$$.\".time.\".\".int(rand(1000000)); $tmp=\"$dir/.$base.tmp.$uniq\"; if (sysopen($tfh, $tmp, O_WRONLY|O_CREAT|O_EXCL)) {{ last; }} $tmp=undef; if (($!+0)!=17) {{ exit {preinst}; }} }} if (!defined $tmp || !defined $tfh) {{ exit {preinst}; }} binmode $tfh; print $tfh $data or do {{ close $tfh; unlink $tmp; exit {preinst}; }}; close $tfh or do {{ unlink $tmp; exit {preinst}; }}; chmod oct($mode), $tmp or do {{ unlink $tmp; exit {preinst}; }}; open my $sfh, \"+<\", $tmp or do {{ unlink $tmp; exit {preinst}; }}; $sfh->sync or do {{ unlink $tmp; exit {preinst}; }}; close $sfh; if (link($tmp, $lock)) {{ unlink $tmp; open my $dfh, \"<\", $dir or exit {preinst}; $dfh->sync or exit {preinst}; close $dfh; exit 0; }} else {{ my $e=$!+0; unlink $tmp; if ($e==17) {{ exit {conflict}; }} else {{ exit {preinst}; }} }}' -- {sidecar} {lock} {mode}",
            parent = parent_q,
            sidecar = sidecar_q,
            lock = lock_q,
            mode = mode_q,
            conflict = SSH_TWRITE_CONFLICT_EXIT,
            preinst = SSH_TWRITE_PREINSTALL_EXIT,
            prelude = prelude,
        )
    }

    /// Build the remote `list` script for `rel`. It is ONE perl one-liner —
    /// perl is already REQUIRED on the far side by the framed `lstat` helper,
    /// `verify_open`, and the sidecars — that `opendir`s the directory,
    /// `lstat`s each entry, and prints the frame. The mode comes from
    /// `lstat`'s `st_mode` (`$s[2] & 0xffff`, the same raw-mode value the
    /// `lstat` protocol uses), NOT from `stat -c '%f'`: BSD/macOS `stat`
    /// rejects `-c`, so the old script produced an EMPTY mode on a supported
    /// macOS remote and the parser silently defaulted every entry to mode 0.
    ///
    /// The FRAME is one NUL-terminated record per entry,
    /// `type<TAB>mode<TAB>size<TAB>name`. NUL is the only byte a POSIX file
    /// name cannot contain, so it is the only unambiguous delimiter: a tab- or
    /// newline-delimited frame silently truncates a name containing that byte,
    /// and `sync`'s listing check is BYTE-EXACT — two distinct on-disk names
    /// must never collapse into one compared spelling. The name is the
    /// `readdir` entry printed VERBATIM (no `basename`/parameter expansion, so
    /// neither a trailing newline nor an embedded TAB/LF is ever stripped) and
    /// is the LAST field, so the Rust parser can `splitn(4, '\t')` and keep
    /// every remaining byte as the name. The two numeric fields are the ones
    /// the LOCAL listing reports, so the two views of one tree compare equal:
    /// the RAW `st_mode` (type bits INCLUDED, not masked to `0o7777`) and the
    /// REAL `st_size` (for a symlink, the length of its target — `lstat` never
    /// follows it). The previous mask + literal `size: 0` made the SSH view
    /// report `600:0` where the local view reported `100600:1`, so a
    /// field-by-field comparison of the two views could never agree.
    ///
    /// The classification is `lstat`-based (not `-e`/`-d`, which FOLLOW a
    /// symlink), so a DANGLING symlink is INCLUDED — an entry the far-side
    /// manifest walk (also `lstat`) includes. The two views of one directory
    /// must agree: the old omission made `sync` report a legitimately installed
    /// dangling link as a `NameNotFaithful` conflict, refuse to replace an
    /// existing one, and (with `delete_extraneous`) hide a reserved dangling
    /// child from the residue gate so the sanctioned recursive removal
    /// destroyed the caller's copy. `.`/`..` are skipped explicitly.
    ///
    /// The errno of an `opendir`/`lstat` failure is handled the way
    /// `LocalTransport::list` handles it, so the two views agree on FAILURE
    /// too:
    ///
    /// * `opendir` ENOENT ⇒ empty output, exit 0. `LocalTransport::list`
    ///   deliberately treats a `NotFound` directory as an empty listing (an
    ///   unprovisioned remote root is not an error), and the pre-rewrite glob
    ///   also produced empty output; the rewrite's bare `die` made the SSH view
    ///   diverge for an absent directory.
    /// * any OTHER `opendir` failure (EACCES, ENOTDIR, ...) ⇒ `die` loudly.
    /// * ANY `lstat` failure ⇒ `die` loudly. An entry that cannot be stat'd
    ///   must fail the listing, never vanish: the old `next unless @s` silently
    ///   dropped every entry of a `chmod 400` directory (opendir succeeds on
    ///   the read bit, each `lstat` then fails EACCES), so the SSH view
    ///   returned an empty list for a NON-EMPTY directory while the local view
    ///   returned `Permission denied`.
    ///
    /// Names are printed as RAW BYTES (`binmode STDOUT`); a non-UTF-8 name is
    /// refused by the Rust decoder, never lossily decoded.
    fn list_script(&self, rel: &Path) -> String {
        let p = shell_quote(&self.root.join(rel).to_string_lossy());
        format!(
            "perl -e 'binmode STDOUT; my $dir = $ARGV[0]; \
opendir(my $dh, $dir) or do {{ exit 0 if (($! + 0) == 2); die \"list: opendir $dir: $!\"; }}; \
for my $n (readdir($dh)) {{ next if $n eq \".\" || $n eq \"..\"; \
my @s = lstat(\"$dir/$n\"); die \"list: lstat $dir/$n: $!\" unless @s; \
my $mt = $s[2] & 0170000; my $t = ($mt == 0120000) ? \"l\" : (($mt == 0040000) ? \"d\" : \"f\"); \
printf \"%s\\t%x\\t%s\\t%s\\0\", $t, $s[2] & 0xffff, $s[7], $n; }}' -- {p}"
        )
    }

    /// Build the remote shell command implementing the atomic compare-and-
    /// delete (the ssh mirror of `LocalTransport::remove_file_if`): CLAIM the
    /// entry with `mv` to a mktemp-allocated same-directory name (the lock is
    /// always a regular file, so plain `mv` — portable GNU and BSD — moves it
    /// without the perl `rename(2)` the symlink-to-directory `current` swap
    /// needs; only ONE contender can win the claim; a failed mv with the
    /// destination still present is a Mismatch verdict, with the destination
    /// absent an Absent verdict), VERIFY with `cmp`, then either DELETE the
    /// claim (match → frame `R`) or RESTORE it no-replace with `ln` (mismatch →
    /// frame `M`; a concurrent install makes `ln` fail — the winner is never
    /// replaced and the claim is discarded). The single stdout frame is
    /// parsed strictly; a malformed frame is an error, never a silent
    /// verdict.
    fn remove_file_if_cmd(root: &Path, rel: &Path, expected: &str) -> String {
        let remote_path_str = root.join(rel).to_string_lossy().into_owned();
        let parent = Path::new(&remote_path_str)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        let basename = Path::new(&remote_path_str)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "record".to_string());
        // The claim temp lives INSIDE the destination's parent directory and
        // is dot-prefixed, exactly like write_new_cmd's temp.
        let tmp_template = format!(
            "{}/.{}.claim.XXXXXX",
            parent.trim_end_matches('/'),
            basename
        );
        let expected_str = expected.to_string();
        format!(
            "mkdir -p {p} && tmp=$(mktemp {tpl}) && rm -f \"$tmp\" && if mv {d} \"$tmp\" 2>/dev/null; then if printf '%s' {exp} | cmp -s \"$tmp\" -; then rm -f \"$tmp\"; printf 'R'; else ln \"$tmp\" {d} 2>/dev/null; rm -f \"$tmp\"; printf 'M'; fi; else if [ -e {d} ] || [ -L {d} ]; then printf 'M'; else printf 'A'; fi; fi",
            p = shell_quote(&parent),
            tpl = shell_quote(&tmp_template),
            d = shell_quote(&remote_path_str),
            exp = shell_quote(&expected_str),
        )
    }

    /// Build the remote framed `lstat` helper for `rel`: ONE remote exec
    /// whose single stdout frame reports the OUTCOME WITH THE ERRNO (see the
    /// [`LSTAT_ERRNO_ENOENT`] protocol doc on this module). The helper is a
    /// `perl -e` one-liner (perl ships with every reasonable Linux/macOS
    /// remote — the same interpreter the test fixtures already use) that
    /// performs a REAL `lstat` and prints `P`/`A`/`E` frames, exiting 0 for
    /// all three outcomes — the FRAME is the signal, an exit code carries no
    /// errno. The path is passed as a positional argument after `--` (already
    /// single-quoted), so the shell and perl both see it verbatim.
    fn lstat_script(&self, rel: &Path) -> String {
        let p = shell_quote(&self.root.join(rel).to_string_lossy());
        format!(
            "perl -e 'my @s = lstat($ARGV[0]); if (@s) {{ printf \"P\\t%s\\t%x\\n\", $s[7], $s[2] & 0xffff; exit 0; }} my $e = $! + 0; print(($e == 2 || $e == 20) ? \"A\\t$e\\n\" : \"E\\t$e\\n\");' -- {p}"
        )
    }

    /// Build the remote DESCRIPTOR-BOUND verification helper for `rel`: ONE
    /// remote exec whose SINGLE stdout payload performs the open→fstat→read
    /// sequence on ONE opened inode — `sysopen` with `O_NOFOLLOW` (a symlink
    /// → ELOOP, NEVER followed — even one pointing at a matching regular
    /// file; `O_NONBLOCK` so a fifo/device open cannot block the helper),
    /// `stat` on the SAME handle (fstat), and `sysread` THROUGH the same
    /// handle — closing the client-side TOCTOU the old
    /// lstat-then-separate-read left open (there is NO client round-trip
    /// between the steps: one frame carries the fd-derived mode AND content,
    /// or the errno). The remote-side race between the helper's OWN steps is
    /// out of scope — the guarantee is that metadata and content come from
    /// the SAME opened inode. Frame (stdout bytes):
    ///
    /// * `O\t<rawmode_hex>\n<content>` — a REGULAR file: the raw mode from
    ///   the opened fd's fstat, then the content read through the SAME fd
    ///   (raw bytes, possibly empty);
    /// * `N\t<rawmode_hex>` — opened + fstat'd but NOT a regular file (the
    ///   mode bits classify dir/symlink/other);
    /// * `E\t<errno>` — the open/fstat/read failed (ELOOP → symlink,
    ///   ENOENT/ENOTDIR → absent, EISDIR → directory, EACCES/... →
    ///   unreadable; the errno numbers are POSIX, identical on Linux and
    ///   macOS).
    ///
    /// The path is a positional argument after `--` (single-quoted); the
    /// perl is multi-line inside the single-quoted `-e` argument (shell
    /// single quotes span newlines).
    fn verify_open_script(&self, rel: &Path) -> String {
        let p = shell_quote(&self.root.join(rel).to_string_lossy());
        format!(
            "perl -e 'use Fcntl qw(O_RDONLY O_NOFOLLOW O_NONBLOCK);\n\
             my $p = $ARGV[0];\n\
             if (!sysopen(FH, $p, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)) {{ printf \"E\\t%d\\n\", $! + 0; exit 0; }}\n\
             my @s = stat(FH);\n\
             if (!@s) {{ printf \"E\\t%d\\n\", $! + 0; exit 0; }}\n\
             my $type = $s[2] & 0170000;\n\
             if ($type == 0100000) {{\n\
               my $content = \"\";\n\
               while (1) {{\n\
                 my $n = sysread(FH, my $buf, 65536);\n\
                 if (!defined $n) {{ printf \"E\\t%d\\n\", $! + 0; exit 0; }}\n\
                 last if $n == 0;\n\
                 $content .= $buf;\n\
               }}\n\
               printf \"O\\t%x\\n%s\", $s[2] & 0xffff, $content;\n\
               exit 0;\n\
             }}\n\
             printf \"N\\t%x\\n\", $s[2] & 0xffff;\n\
             ' -- {p}"
        )
    }

    /// Classify a raw mode (the raw `st_mode` value the `lstat`/`verify_open`
    /// helpers print, whose `S_IFMT` bits and permission bits are POSIX on
    /// GNU and BSD alike) into a [`RemoteMeta`] — the shared classification of
    /// the framed lstat protocol AND the descriptor-bound verify-open protocol.
    ///
    /// `mode` is the RAW `st_mode`, type bits INCLUDED: the same value
    /// `LocalTransport::metadata` reports through `meta_to_remote` (which uses
    /// `metadata_mode`), so the two views of one entry compare equal. Every
    /// consumer of the field masks it with `& 0o7777` itself (see
    /// `verify_existing`), so the raw value changes no decision; the old
    /// `& 0o7777` here made the field silently different from the local view.
    fn meta_from_raw_mode(raw: u32) -> RemoteMeta {
        let is_symlink = (raw & 0o170000) == 0o120000;
        let is_dir = (raw & 0o170000) == 0o040000;
        RemoteMeta {
            is_dir,
            is_symlink,
            is_file: !is_symlink && !is_dir,
            // The verify-open frame carries no size; content is compared
            // byte-exactly, so the field is unused there. The framed-lstat
            // parser (`parse_lstat_frame`) overwrites it with the REAL size
            // from the frame, so `metadata()` agrees with the local view.
            size: 0,
            mode: raw,
        }
    }

    /// The [`NotRegularFileKind`] of a [`RemoteMeta`] (directory / symlink /
    /// other) — the verify-open parser's type classification.
    fn kind_of(meta: &RemoteMeta) -> crate::transport::NotRegularFileKind {
        use crate::transport::NotRegularFileKind;
        if meta.is_dir {
            NotRegularFileKind::Directory
        } else if meta.is_symlink {
            NotRegularFileKind::Symlink
        } else {
            NotRegularFileKind::Other
        }
    }

    /// Parse the SINGLE-frame stdout produced by
    /// [`SshTransport::verify_open_script`] into the descriptor-bound
    /// [`OpenedExisting`] the shared verification maps: `O` (a regular file
    /// opened with `O_NOFOLLOW` and fstat'd+read through the SAME
    /// descriptor — mode from the raw mode bits, content the raw bytes after
    /// the header line), `N` (opened+fstat'd non-regular entry — dir/symlink/
    /// other by the mode bits), or `E` (open/fstat/read failed —
    /// ENOENT/ENOTDIR → NotFound, ELOOP → NotRegularFile{Symlink} (the
    /// `O_NOFOLLOW` open, never followed), EISDIR → NotRegularFile{Directory},
    /// every other errno → Unreadable). Anything malformed — garbage, wrong
    /// prefix, extra fields, missing newline — is an error, never a silent
    /// default.
    fn parse_verify_open_frame(stdout: &[u8]) -> Result<OpenedExisting> {
        let malformed = |detail: &str| {
            Error::transport(format!(
                "ssh verify-open: malformed frame: {detail} (stdout {:?})",
                String::from_utf8_lossy(stdout)
            ))
        };
        let nl = stdout
            .iter()
            .position(|&b| b == b'\n')
            .ok_or_else(|| malformed("no newline"))?;
        let header =
            std::str::from_utf8(&stdout[..nl]).map_err(|_| malformed("non-utf8 header"))?;
        let content = stdout[nl + 1..].to_vec();
        let mut it = header.split('\t');
        match it.next() {
            // A REGULAR file: fd-derived mode + fd-derived content.
            Some("O") => {
                let raw = it
                    .next()
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
                    .ok_or_else(|| malformed(header))?;
                if it.next().is_some() {
                    return Err(malformed(header));
                }
                let meta = Self::meta_from_raw_mode(raw);
                if !meta.is_file {
                    // Defense in depth: the helper only emits O for a regular
                    // file; a non-regular mode is still classified.
                    return Ok(OpenedExisting::NotRegular {
                        kind: Self::kind_of(&meta),
                    });
                }
                Ok(OpenedExisting::Entry(OpenedEntry { meta, content }))
            }
            // Opened + fstat'd, NOT a regular file: the mode bits classify.
            Some("N") => {
                let raw = it
                    .next()
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
                    .ok_or_else(|| malformed(header))?;
                if it.next().is_some() {
                    return Err(malformed(header));
                }
                let meta = Self::meta_from_raw_mode(raw);
                Ok(OpenedExisting::NotRegular {
                    kind: Self::kind_of(&meta),
                })
            }
            // The open/fstat/read failed: the errno maps to the typed reason.
            Some("E") => {
                let errno = it
                    .next()
                    .and_then(|s| s.parse::<i32>().ok())
                    .ok_or_else(|| malformed(header))?;
                if it.next().is_some() {
                    return Err(malformed(header));
                }
                // POSIX errnos: ENOENT=2, ENOTDIR=20, EISDIR=21 on both
                // Linux and macOS; ELOOP differs (40 on Linux, 62 on macOS)
                // — both mean the O_NOFOLLOW open hit a symlink (EACCES=13 /
                // EPERM=1 / EIO=... → Unreadable).
                Ok(match errno {
                    LSTAT_ERRNO_ENOENT | LSTAT_ERRNO_ENOTDIR => OpenedExisting::NotFound,
                    40 | 62 => OpenedExisting::NotRegular {
                        kind: crate::transport::NotRegularFileKind::Symlink,
                    },
                    21 => OpenedExisting::NotRegular {
                        kind: crate::transport::NotRegularFileKind::Directory,
                    },
                    other => OpenedExisting::Unreadable(format!(
                        "ssh verify-open failed (errno {other})"
                    )),
                })
            }
            _ => Err(malformed(header)),
        }
    }

    /// Parse the ONE-LINE framed record produced by [`SshTransport::lstat_script`]
    /// (see the module doc): a `P` frame parses strictly into a [`RemoteMeta`]
    /// (exactly two TAB-separated payload fields — decimal size, hex raw
    /// mode), an `A` frame with errno ENOENT/ENOTDIR is the ONLY `Ok(None)`
    /// (confirmed absence), an `A` frame with any other errno and every `E`
    /// frame are errors (a permission/IO failure is NEVER absence), and
    /// anything malformed — garbage, missing fields, wrong prefix, extra
    /// fields, extra lines — is an error, never a silent default.
    fn parse_lstat_frame(stdout: &str) -> Result<Option<RemoteMeta>> {
        let lines: Vec<&str> = stdout.lines().collect();
        let [line] = lines.as_slice() else {
            return Err(Error::transport(format!(
                "ssh lstat: malformed frame: expected exactly one line, got {lines:?}"
            )));
        };
        let mut it = line.split('\t');
        match it.next() {
            // Present: strictly parse `size` (decimal) + `rawmode` (hex).
            Some("P") => {
                let size = it
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .ok_or_else(|| {
                        Error::transport(format!("ssh lstat: malformed present frame: {line:?}"))
                    })?;
                let raw = it
                    .next()
                    .and_then(|s| u32::from_str_radix(s, 16).ok())
                    .ok_or_else(|| {
                        Error::transport(format!("ssh lstat: malformed present frame: {line:?}"))
                    })?;
                if it.next().is_some() {
                    return Err(Error::transport(format!(
                        "ssh lstat: malformed present frame: {line:?}"
                    )));
                }
                let mut meta = Self::meta_from_raw_mode(raw);
                meta.size = size;
                Ok(Some(meta))
            }
            // Absent: ONLY ENOENT/ENOTDIR are confirmed absence; an `A` frame
            // carrying any other errno is a helper bug/mismatch -> error.
            Some("A") => {
                let errno = it.next().and_then(Self::parse_lstat_errno).ok_or_else(|| {
                    Error::transport(format!("ssh lstat: malformed absent frame: {line:?}"))
                })?;
                if it.next().is_some() {
                    return Err(Error::transport(format!(
                        "ssh lstat: malformed absent frame: {line:?}"
                    )));
                }
                match errno {
                    LSTAT_ERRNO_ENOENT | LSTAT_ERRNO_ENOTDIR => Ok(None),
                    other => Err(Error::transport(format!(
                        "ssh lstat: absent frame with non-absence errno {other}: {line:?}"
                    ))),
                }
            }
            // Error: ANY errno here is an error — EACCES/EIO/... are never
            // absence.
            Some("E") => {
                let errno = it.next().and_then(Self::parse_lstat_errno).ok_or_else(|| {
                    Error::transport(format!("ssh lstat: malformed error frame: {line:?}"))
                })?;
                if it.next().is_some() {
                    return Err(Error::transport(format!(
                        "ssh lstat: malformed error frame: {line:?}"
                    )));
                }
                Err(Error::transport(format!(
                    "ssh lstat failed (errno {errno}): {line:?}"
                )))
            }
            _ => Err(Error::transport(format!(
                "ssh lstat: malformed frame: {line:?}"
            ))),
        }
    }

    /// Parse an `<errno>` frame field: a decimal errno NUMBER (cross-platform
    /// — ENOENT=2 and ENOTDIR=20 are identical on Linux and macOS), or the
    /// POSIX name (`ENOENT`/`ENOTDIR`). Anything else is malformed.
    fn parse_lstat_errno(s: &str) -> Option<i32> {
        if let Ok(n) = s.parse::<i32>() {
            return Some(n);
        }
        match s {
            "ENOENT" => Some(LSTAT_ERRNO_ENOENT),
            "ENOTDIR" => Some(LSTAT_ERRNO_ENOTDIR),
            _ => None,
        }
    }

    /// Decode the RAW stdout of [`SshTransport::list_script`] into entries.
    ///
    /// The frame is NUL-terminated records of `type<TAB>mode<TAB>size<TAB>name`
    /// (see [`SshTransport::list_script`]); the name is the FINAL field and may
    /// contain a tab, a newline, or a carriage return, so each record is split
    /// on TAB at most three times and the remainder is the name verbatim. The
    /// payload must be valid UTF-8: a name that is NOT is REFUSED (fail-closed)
    /// rather than decoded with `from_utf8_lossy`, because two distinct
    /// non-UTF-8 names both decode to U+FFFD and would then be
    /// indistinguishable to the byte-exact listing comparison. The error names
    /// the offending record so the destination entry is identifiable.
    fn decode_list_output(stdout: &[u8]) -> Result<Vec<RemoteEntry>> {
        let text = match std::str::from_utf8(stdout) {
            Ok(text) => text,
            Err(e) => {
                let at = e.valid_up_to();
                let start = stdout[..at]
                    .iter()
                    .rposition(|&b| b == 0)
                    .map(|i| i + 1)
                    .unwrap_or(0);
                let end = stdout[at..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|i| at + i)
                    .unwrap_or(stdout.len());
                return Err(Error::transport(format!(
                    "ssh list: an entry name is not valid UTF-8, so the listing cannot be compared byte-exactly (a lossy decode would make distinct names both U+FFFD); refusing. Offending record (lossily rendered for the message): {:?}",
                    String::from_utf8_lossy(&stdout[start..end])
                )));
            }
        };
        Self::parse_list_output(text)
    }

    /// Parse the NUL-framed records produced by [`SshTransport::list_script`].
    /// `.` and `..` are never emitted by the script, but are skipped here
    /// defensively. The parse is STRICT on every field: a structurally
    /// malformed record (fewer than four TAB fields) is refused, a mode field
    /// that is not hex is an ERROR rather than a silent 0, and a size field
    /// that is not decimal is an error rather than a silent 0. The old
    /// `unwrap_or(0)` default was exactly how a BSD/macOS `stat -c` failure
    /// turned every entry's mode into 0 without a single error — a public field
    /// that was silently wrong on a supported platform. The producer is now
    /// portable, so an unparseable mode means a mangled frame, never a
    /// userland we do not support.
    ///
    /// The `mode` is carried RAW — the full `st_mode`, type bits INCLUDED —
    /// and the `size` is the real `st_size`, so an entry parsed here is
    /// field-by-field identical to the entry `LocalTransport::list` builds from
    /// `symlink_metadata`. The old `& 0o7777` mask and literal `size: 0` were a
    /// silent divergence between the two views of one tree. The `type` field is
    /// the script's own classification and must AGREE with the mode's type bits
    /// (both come from the same `lstat`), so a frame cannot carry a type that
    /// contradicts its mode.
    fn parse_list_output(text: &str) -> Result<Vec<RemoteEntry>> {
        let mut entries = Vec::new();
        for record in text.split('\0') {
            if record.is_empty() {
                continue;
            }
            let malformed = || {
                Error::transport(format!(
                    "ssh list: malformed listing record (expected type<TAB>mode<TAB>size<TAB>name): {record:?}"
                ))
            };
            let mut it = record.splitn(4, '\t');
            let t = it.next().ok_or_else(malformed)?;
            let raw = it.next().ok_or_else(malformed)?;
            let raw_size = it.next().ok_or_else(malformed)?;
            let name = it.next().ok_or_else(malformed)?;
            if name.is_empty() || name == "." || name == ".." {
                continue;
            }
            let mode = u32::from_str_radix(raw, 16).map_err(|_| {
                Error::transport(format!(
                    "ssh list: malformed mode field (expected hex, got {raw:?}) in record {record:?}"
                ))
            })?;
            let size = raw_size.parse::<u64>().map_err(|_| {
                Error::transport(format!(
                    "ssh list: malformed size field (expected decimal, got {raw_size:?}) in record {record:?}"
                ))
            })?;
            // The raw mode is authoritative for the type (it is the same source
            // `LocalTransport::list` classifies from); the `type` field must
            // agree, or the record is refused rather than trusted.
            let derived_t = match mode & 0o170000 {
                0o040000 => "d",
                0o120000 => "l",
                _ => "f",
            };
            if t != derived_t {
                return Err(Error::transport(format!(
                    "ssh list: type field {t:?} contradicts the raw mode {raw:?} in record {record:?}"
                )));
            }
            entries.push(RemoteEntry {
                name: name.to_string(),
                is_dir: t == "d",
                is_symlink: t == "l",
                size,
                mode,
            });
        }
        Ok(entries)
    }

    /// Decode the stdout of `readlink` into the symlink target.
    ///
    /// `readlink` prints the RAW target followed by EXACTLY ONE newline. Strip
    /// exactly that one byte and NOTHING else: a target may legitimately begin
    /// and/or end with whitespace (including a newline of its own — then the
    /// output ends in two newlines and exactly one is removed), and a `.trim()`
    /// would delete those bytes, making the SSH read a DIFFERENT value than the
    /// raw local `read_link` for the same link. That divergence is both a false
    /// post-transfer verification failure and a blind spot: a concurrent
    /// `"x"` -> `"x "` change keeps the same trimmed value, so the target hash
    /// still matches. A target that is not valid UTF-8 is refused: the manifest
    /// already refuses a non-UTF-8 target, so a lossy read here could only
    /// misreport one.
    fn parse_readlink_output(stdout: &[u8], rel: &Path) -> Result<PathBuf> {
        let target = stdout.strip_suffix(b"\n").unwrap_or(stdout);
        let target = std::str::from_utf8(target).map_err(|_| {
            Error::transport(format!(
                "ssh readlink {}: the symlink target is not valid UTF-8; the manifest refuses a non-UTF-8 target, so the read is refused rather than decoded lossily",
                rel.display()
            ))
        })?;
        Ok(PathBuf::from(target))
    }
}

impl Remote for SshTransport {
    fn root(&self) -> &Path {
        &self.root
    }

    fn is_local(&self) -> bool {
        false
    }

    fn prepare_identity(&self) -> Result<()> {
        // Create the local ControlMaster socket directory (0700) before any
        // ssh op: the multiplexing sockets live here, keyed by
        // `user@host:port`. Local-only, like the known-hosts pin below — a
        // dry run's status inspection still connects over ssh and therefore
        // needs the mux dir to exist.
        std::fs::create_dir_all(&self.mux_socket_dir).map_err(|e| {
            Error::transport(format!(
                "create ssh mux dir {}: {e}",
                self.mux_socket_dir.display()
            ))
        })?;
        crate::platform::chmod(&self.mux_socket_dir, 0o700).map_err(|e| {
            Error::transport(format!(
                "chmod ssh mux dir {}: {e}",
                self.mux_socket_dir.display()
            ))
        })?;
        // If a fingerprint was supplied without an explicit known-hosts file,
        // verify the host key and pin it in a managed file BEFORE any remote
        // request — including a dry run's status inspection, which still
        // connects over ssh and therefore needs the pinned key.
        if self.known_hosts.is_none() && self.host_key_fingerprint.is_some() {
            self.pin_known_hosts()?;
        }
        Ok(())
    }

    fn provision_layout(&self) -> Result<()> {
        // Create the ROOT ITSELF, then the caller-supplied bootstrap
        // directories, in ONE `mkdir -p`. Every path is single-quoted by
        // `argv_cmd`/`shell_quote` so it reaches `mkdir` verbatim. This runs
        // only after the push engine's non-dry-run gate.
        //
        // The ROOT is an operand on purpose, mirroring
        // `LocalTransport::provision_layout`'s `create_dir_all(self.base)`.
        // The pre-fix argv omitted it, so with `Layout::empty()` (no bootstrap
        // directories) the command was `mkdir -p` with NO OPERAND and the
        // remote `mkdir` failed with its usage error (`missing operand` on
        // GNU, `usage: mkdir [-pv] [-m mode] directory_name ...` on macOS);
        // and even when bootstrap directories were supplied, the root itself
        // was still left absent, so the first destination manifest read failed
        // with `not a directory: <root>`. A fresh destination is now usable
        // through the same call on either transport.
        let cmd = Self::provision_layout_cmd(&self.root, &self.layout);
        self.run_remote_ok(&cmd).map_err(|error| {
            error.with_context(format!(
                "creating the destination layout failed (stage: `mkdir -p {}`), so the \
                 destination root and the caller's bootstrap directories were not created; \
                 remedy: ensure the destination's parent directory exists and is writable by \
                 the remote account",
                self.root.display()
            ))
        })?;
        // The IMMUTABLE receiver-id marker: the PHYSICAL identity of this
        // deploy_dir, created ONCE at provisioning and never changed (a
        // re-provisioning adopts the existing marker).
        if let Some(marker) = &self.layout.receiver_marker {
            provision_receiver_id(self, marker)?;
        }
        Ok(())
    }

    fn read(&self, rel: &RootedRelativePath) -> Result<Vec<u8>> {
        self.download_bytes(rel.as_path())
    }

    fn write(&self, rel: &RootedRelativePath, data: &[u8], mode: u32) -> Result<()> {
        self.upload_bytes(rel.as_path(), data, mode)
    }

    fn create_dir(&self, rel: &RootedRelativePath) -> Result<()> {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        self.run_remote_ok(&Self::argv_cmd(&["mkdir".into(), p]))
    }

    fn create_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        self.run_remote_ok(&Self::argv_cmd(&["mkdir".into(), "-p".into(), p]))
    }

    fn set_mode(&self, rel: &RootedRelativePath, mode: u32) -> Result<()> {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        self.run_remote_ok(&Self::argv_cmd(&[
            "chmod".into(),
            format!("{:o}", mode & 0o7777),
            p,
        ]))
    }

    fn list(&self, rel: &RootedRelativePath) -> Result<Vec<RemoteEntry>> {
        let out = self.run_remote(&self.list_script(rel.as_path()))?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh list failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Self::decode_list_output(&out.stdout)
    }

    fn rename(&self, from: &RootedRelativePath, to: &RootedRelativePath) -> Result<()> {
        self.run_remote_ok(&SshTransport::rename_cmd(
            &self.root,
            from.as_path(),
            to.as_path(),
        ))
    }

    fn fsync_tree(&self, rel: &RootedRelativePath) -> Result<()> {
        // `find -depth` visits entries DEEPEST-FIRST (children before
        // parents), so each entry is fsynced before its parent — the whole
        // staged bundle is durable before the atomic install rename. The fsync
        // itself is the portable perl primitive (see [`PERL_FSYNC_DIR`]);
        // `sync <path>` is GNU-only and a NO-OP on BSD/macOS, so the old
        // command silently made this method a no-op on a supported remote.
        let cmd = Self::fsync_tree_cmd(&self.root, rel.as_path());
        self.run_remote_ok(&cmd)
    }

    fn fsync_parent(&self, rel: &RootedRelativePath) -> Result<()> {
        // FAIL-CLOSED: the parent-directory fsync is the portable perl
        // primitive (see [`PERL_FSYNC_DIR`]) and a failed fsync is a propagated
        // error (the mutation's durability is unconfirmed). `sync <dir>` would
        // have been a silent no-op here on BSD/macOS.
        let cmd = Self::fsync_parent_cmd(&self.root, rel.as_path());
        self.run_remote_ok(&cmd)
    }

    fn symlink(&self, target: &Path, link: &RootedRelativePath) -> Result<()> {
        // The target is embedded in a shell command, so a non-UTF-8 target
        // could only be written LOSSILY — creating a link whose target differs
        // from the caller's intent, which the post-transfer `read_link`
        // verification would then compare against a corrupted value. The
        // manifest already refuses a non-UTF-8 target; fail closed here too.
        let t = target.to_str().ok_or_else(|| {
            Error::transport(format!(
                "ssh symlink: the link target is not valid UTF-8 and cannot be written to the remote verbatim: {target:?}"
            ))
        })?;
        let l = self.root.join(link).to_string_lossy().into_owned();
        let parent = Path::new(&l)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());
        // `--` before the link target: `target` is a plain relative link
        // target and may legitimately start with `-`; without it the `ln`
        // option parser reads it as an option cluster and refuses the link.
        let cmd = format!(
            "mkdir -p -- {parent} && ln -sfn -- {t} {l}",
            parent = shell_quote(&parent),
            t = shell_quote(t),
            l = shell_quote(&l),
        );
        self.run_remote_ok(&cmd)
    }

    fn read_link(&self, rel: &RootedRelativePath) -> Result<PathBuf> {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        let out = self.run_remote(&Self::argv_cmd(&["readlink".into(), p]))?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh readlink failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Self::parse_readlink_output(&out.stdout, &self.root.join(rel))
    }

    fn remove_file(&self, rel: &RootedRelativePath) -> Result<()> {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        // Ignore "not found".
        let out = self.run_remote(&Self::argv_cmd(&["rm".into(), "-f".into(), p]))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if !stderr.contains("No such file") && !stderr.contains("No such") {
                return Err(Error::transport(format!("ssh rm failed: {stderr}")));
            }
        }
        Ok(())
    }

    fn remove_file_if(&self, rel: &RootedRelativePath, expected: &[u8]) -> Result<RemoveIfVerdict> {
        // The remote compare runs a shell command carrying `expected` as an
        // argv token: a non-UTF-8 `expected` could only be embedded LOSSILY,
        // so the compare would be against a different byte string than the
        // caller's. Fail closed instead of comparing a lossy rendering.
        let expected = std::str::from_utf8(expected).map_err(|_| {
            Error::transport(
                "ssh remove_file_if: the expected content is not valid UTF-8 and cannot be compared byte-exactly over the remote shell; refusing rather than comparing a lossy rendering",
            )
        })?;
        let cmd = if rel.as_path() == self.layout.lock.as_path() {
            remove_file_if_sidecar_cmd(
                &self.root,
                &self.layout.lock_sidecar,
                &self.layout.lock,
                expected,
            )
        } else {
            Self::remove_file_if_cmd(&self.root, rel.as_path(), expected)
        };
        let out = self.run_remote(&cmd)?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh remove_file_if failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        match String::from_utf8_lossy(&out.stdout).trim() {
            "R" => Ok(RemoveIfVerdict::Removed),
            "M" => Ok(RemoveIfVerdict::Mismatch),
            "A" => Ok(RemoveIfVerdict::Absent),
            other => Err(Error::transport(format!(
                "ssh remove_file_if: malformed verdict frame {other:?}"
            ))),
        }
    }

    fn remove_dir_all(&self, rel: &RootedRelativePath) -> Result<()> {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        self.run_remote_ok(&Self::argv_cmd(&["rm".into(), "-rf".into(), p]))
    }

    fn copy_tree(&self, src: &RootedRelativePath, dest: &RootedRelativePath) -> Result<()> {
        if let Some(parent) = dest.parent() {
            self.create_dir_all(&parent)?;
        }
        let s = self.root.join(src).to_string_lossy().into_owned();
        let d = self.root.join(dest).to_string_lossy().into_owned();
        // Same-filesystem `cp -a` on the remote: no bytes cross the link.
        // `-a` preserves modes (including the setuid/setgid/sticky bits),
        // symlink targets, and timestamps, and on both GNU and current
        // macOS/BSD userlands it also preserves extended attributes and
        // POSIX ACLs (GNU `-a` is `-dR --preserve=all`; BSD/macOS `-a` is
        // `-R -P -p`). Both userlands copy a read-only source directory by
        // creating the destination directory writable and chmodding it at
        // the end.
        //
        // It does NOT preserve OWNERSHIP for a NON-ROOT caller. `cp -a`
        // tries to reproduce the source uid/gid, but a non-root caller may
        // only set ownership within its own permissions: the uid becomes the
        // COPIER's (a chown to a different uid fails, and `cp` IGNORES the
        // failure and still exits 0), and the gid is reproduced only when the
        // copier is a member of that group — otherwise it too becomes the
        // copier's. The loss is silent. A caller that needs the source owner
        // reproduced must run the copy privileged, or apply `chown` out of
        // band.
        //
        // Relative to the DEFAULT walk, this override is therefore HIGHER
        // fidelity: xattrs, ACLs, and timestamps survive here but not in the
        // walk, while ownership is the copier's in both (the walk sets both
        // uid and gid to the copier's; `cp -a` always sets the uid and the
        // gid when it cannot reproduce it). See the crate's fidelity scope in
        // `crate::manifest`. The destination must not already exist (the
        // caller removes a stale staging dir first).
        self.run_remote_ok(&Self::argv_cmd(&["cp".into(), "-a".into(), s, d]))
    }

    fn exists(&self, rel: &RootedRelativePath) -> bool {
        let p = self.root.join(rel).to_string_lossy().into_owned();
        let out = self.run_remote(&Self::argv_cmd(&["test".into(), "-e".into(), p]));
        matches!(out, Ok(o) if o.status.success())
    }

    fn metadata(&self, rel: &RootedRelativePath) -> Result<RemoteMeta> {
        self.metadata_opt(rel)?.ok_or_else(|| {
            Error::NotFound(format!(
                "ssh stat {}: no such entry",
                self.root.join(rel).to_string_lossy()
            ))
        })
    }

    fn metadata_opt(&self, rel: &RootedRelativePath) -> Result<Option<RemoteMeta>> {
        // ONE remote exec: the framed perl `lstat` helper reports the OUTCOME
        // WITH THE ERRNO (a `P`/`A`/`E` frame on stdout, exit 0 for every
        // outcome). The frame is the signal — no shell booleans, no reserved
        // exit code — so a permission failure (EACCES) can never be mistaken
        // for absence. A transport failure, a signal-killed command, or any
        // nonzero exit is an error; the single stdout frame is parsed
        // strictly (malformed output is never a silent default).
        let out = self.run_remote(&self.lstat_script(rel.as_path()))?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh lstat failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Self::parse_lstat_frame(std::str::from_utf8(&out.stdout).map_err(|_| {
            Error::transport(format!(
                "ssh lstat: frame is not valid UTF-8: {:?}",
                String::from_utf8_lossy(&out.stdout)
            ))
        })?)
    }

    fn exec(&self, argv: &[String], timeout: Duration) -> Result<crate::transport::ExecOutcome> {
        if argv.is_empty() {
            return Err(Error::transport("empty command"));
        }
        // Preserve argv boundaries: quote every argument and run them via `exec`
        // so the program receives exactly `argv` and the remote shell cannot
        // reinterpret spaces/metacharacters inside an argument.
        // `--` before the program: `argv[0]` is caller-supplied and a program
        // name that starts with `-` must not be parsed as an `exec` option.
        let command = format!("exec -- {}", Self::argv_cmd(argv));
        let full = self.ssh_command_argv(&command)?;
        // Runs through THE shared runner with the caller-supplied timeout: on
        // deadline the child is killed and reaped (deterministically) before the
        // Timeout outcome is returned, so `exec` can never hang the push either.
        match self.runner.run(OpKind::Exec, &full, None, Some(timeout)) {
            Ok(out) => Ok(crate::transport::ExecOutcome {
                exit_code: out.status.code().unwrap_or(-1),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                // A normally-exited command: any `-1` here is a signal-killed
                // child (`status.code()` is `None`), NOT a deadline. The cause
                // is left `None` so that case is never blamed on the deadline.
                timeout_cause: None,
            }),
            Err(RunError::Spawn(m)) => Err(Error::transport(m)),
            Err(RunError::StdinWrite(m)) => Err(Error::transport(m)),
            Err(RunError::Wait(m)) => Err(Error::transport(m)),
            // The command RAN and EXITED; a process that outlived it held its
            // pipes open past the post-exit drain bound (which is independent
            // of the caller's deadline). This is carried as an OUTCOME (not a
            // bare transport error) so the manifest classifier can tell it
            // from "the command was killed at the deadline" — the ambiguity
            // the bounded drain introduced. `exit_code == -1` is the SENTINEL
            // meaning "the collected exit status is not reported", never "the
            // command did not run" and never "a deadline was outlasted".
            Err(RunError::Background(m)) => Ok(crate::transport::ExecOutcome {
                exit_code: -1,
                stdout: String::new(),
                stderr: m,
                timeout_cause: Some(TimeoutCause::OutputDrainGaveUp),
            }),
            Err(RunError::Timeout {
                after,
                leftover_pipes,
            }) => Ok(crate::transport::ExecOutcome {
                // Outcome classification is preserved EXACTLY: the timeout
                // still reports exit_code == -1; the typed cause records that
                // the deadline killed a RUNNING command (the leftover-pipe
                // note is a secondary message, never the carrier of the fact).
                exit_code: -1,
                stdout: String::new(),
                stderr: format!(
                    "timed out after {after:?}{}",
                    leftover_pipe_note(&leftover_pipes)
                ),
                timeout_cause: Some(TimeoutCause::CommandStillRunning),
            }),
        }
    }

    fn filesystem_bytes(&self) -> Result<FsBytes> {
        let p = self.root.to_string_lossy().into_owned();
        let out = self.run_remote(&Self::argv_cmd(&["df".into(), "-kP".into(), p]))?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh df failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let line = text
            .lines()
            .nth(1)
            .ok_or_else(|| Error::transport("unexpected ssh df output".to_string()))?;
        let cols: Vec<&str> = line.split_whitespace().collect();
        // blocks is the 2nd column and avail the 4th (1-indexed) on both
        // macOS and Linux; both are in 1024-byte units.
        let total_kb = cols
            .get(1)
            .and_then(|c| c.parse::<u64>().ok())
            .ok_or_else(|| Error::transport("could not parse ssh df blocks".to_string()))?;
        let avail_kb = cols
            .get(3)
            .and_then(|c| c.parse::<u64>().ok())
            .ok_or_else(|| Error::transport("could not parse ssh df avail".to_string()))?;
        Ok(FsBytes {
            total: total_kb * 1024,
            available: avail_kb * 1024,
        })
    }

    fn try_write_new(&self, rel: &RootedRelativePath, data: &[u8]) -> Result<CreateNewVerdict> {
        self.try_write_new_with(rel, data, ContentEquivalence::Exact)
    }

    fn try_write_new_with(
        &self,
        rel: &RootedRelativePath,
        data: &[u8],
        equivalence: ContentEquivalence,
    ) -> Result<CreateNewVerdict> {
        let cmd = if rel.as_path() == self.layout.lock.as_path() {
            self.try_write_new_sidecar_cmd(rel.as_path(), IMMUTABLE_RECORD_MODE)
        } else {
            Self::write_new_cmd(&self.root, rel.as_path(), IMMUTABLE_RECORD_MODE)
        };
        let argv = self.ssh_command_argv(&cmd)?;
        // The payload travels through the runner's STDIN — never through the
        // command string (see `write_new_cmd`): the raw `data` bytes are
        // piped to the remote `cat > "$tmp"` exactly, so arbitrary `Vec<u8>`
        // (NULs, non-UTF8, quotes, shell metacharacters, long payloads)
        // round-trips byte-for-byte through the ssh transport — the same
        // byte-preserving contract the LOCAL transport delivers via
        // `durable_create_new`. The runner pipes the payload as part of the
        // bounded wait, so a remote that stops reading stdin is killed at the
        // command deadline like any other stalled operation.
        let out = self
            .runner
            .run(OpKind::Upload, &argv, Some(data), None)
            .map_err(|e| match e {
                RunError::Spawn(m) => Error::transport(format!("ssh try_write_new spawn: {m}")),
                RunError::StdinWrite(m) => {
                    Error::transport(format!("ssh try_write_new stdin write: {m}"))
                }
                RunError::Wait(m) => Error::transport(format!("ssh try_write_new wait: {m}")),
                RunError::Background(m) => Error::transport(format!("ssh try_write_new: {m}")),
                RunError::Timeout {
                    after,
                    leftover_pipes,
                } => Error::transport(format!(
                    "ssh try_write_new timed out after {after:?}{}",
                    leftover_pipe_note(&leftover_pipes)
                )),
            })?;
        if out.status.success() {
            // All seven steps completed: the record is installed with the
            // final mode and a parent-directory-sync'd durable entry.
            return Ok(CreateNewVerdict::Created);
        }
        // A pre-install failure (the temp allocation, the payload write, the
        // final chmod, or the file fsync) or the final parent-dir sync failure
        // exits with a code other than the reserved conflict code: the
        // operation never reached (or never finished) the publish decision
        // point, so this is a propagated ERROR — never a verdict. The
        // transport never guesses the destination's state from a failed
        // pre-install.
        if out.status.code() != Some(SSH_TWRITE_CONFLICT_EXIT) {
            return Err(Error::transport(format!(
                "ssh try_write_new failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        // CONFIRMED EEXIST: the no-clobber publish (perl `link(2)`) found
        // the destination already present — the verdict decision point. The
        // winner is NEVER replaced.
        // VERIFY the existing entry through THE ONE CENTRALIZED
        // DESCRIPTOR-BOUND verification
        // ([`crate::transport::verify_existing`]): ONE remote helper
        // operation ([`SshTransport::verify_open_script`]) performs the
        // open-with-O_NOFOLLOW → fstat-the-same-fd → read-through-the-same-fd
        // sequence and emits ONE frame carrying the fd-derived mode + content
        // (or the errno) — there is NO client round-trip between the metadata
        // check and the read (the old lstat-then-separate-read left a
        // client-side TOCTOU window open; a symlink is never followed — the
        // `O_NOFOLLOW` open fails it with ELOOP). A regular file with the
        // EXACT required mode and the caller's accepted content equivalence →
        // AlreadyPresent (and the PARENT DIRECTORY is synced here, so the
        // convergent retry returns with a durable entry — the same
        // parent-sync guarantee a fresh Created install gets); every other
        // outcome → Conflict carrying the TYPED reason (a different-content
        // winner, a mode mismatch, a directory/symlink/other entry, an
        // unreadable entry — never an undifferentiated conflict).
        let verified = verify_existing(
            || {
                let out = self.run_remote(&self.verify_open_script(rel.as_path()))?;
                if !out.status.success() {
                    return Err(Error::transport(format!(
                        "ssh verify-open failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    )));
                }
                Self::parse_verify_open_frame(&out.stdout)
            },
            data,
            IMMUTABLE_RECORD_MODE,
            equivalence,
        )?;
        let verdict = verified_to_verdict(verified);
        if let CreateNewVerdict::AlreadyPresent = &verdict {
            // The convergent retry must return with a DURABLE entry, exactly as
            // a fresh Created install does: fsync the parent directory with the
            // SAME portable perl primitive the script uses ([`PERL_FSYNC_DIR`]).
            // A bare `sync <dir>` here would be a silent no-op on BSD/macOS.
            self.run_remote_ok(&SshTransport::fsync_parent_cmd(&self.root, rel.as_path()))?;
            return Ok(CreateNewVerdict::AlreadyPresent);
        }
        Ok(verdict)
    }

    fn atomic_recover(
        &self,
        rel: &RootedRelativePath,
        observed: &[u8],
        new_data: &[u8],
    ) -> Result<Option<()>> {
        // Only the operation lock's recover is sidecar-serialized; other paths are not supported.
        if rel.as_path() != self.layout.lock.as_path() {
            return Ok(None);
        }
        // `observed` and `new_data` cross into the remote perl command as argv
        // tokens: a non-UTF-8 value could only be embedded LOSSILY, so the
        // compare-and-replace would act on a different byte string than the
        // caller's. Fail closed rather than embedding a lossy rendering.
        let observed = std::str::from_utf8(observed).map_err(|_| {
            Error::transport(
                "ssh atomic_recover: the observed record is not valid UTF-8 and cannot be compared byte-exactly over the remote shell; refusing rather than comparing a lossy rendering",
            )
        })?;
        let new_data = std::str::from_utf8(new_data).map_err(|_| {
            Error::transport(
                "ssh atomic_recover: the replacement record is not valid UTF-8 and cannot be written byte-exactly over the remote shell; refusing rather than writing a lossy rendering",
            )
        })?;
        let cmd = recover_sidecar_cmd(
            &self.root,
            &self.layout.lock_sidecar,
            &self.layout.lock,
            observed,
            new_data,
        );
        let out = self.run_remote(&cmd)?;
        if !out.status.success() {
            return Err(Error::transport(format!(
                "ssh atomic_recover failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        match String::from_utf8_lossy(&out.stdout).trim() {
            "OK" => Ok(Some(())),
            "MISMATCH" => Err(Error::transport(
                "recovery refused: the lock no longer carries the observed record — a successor is never removed; re-read and re-confirm",
            )),
            "ABSENT" => Err(Error::transport(
                "no lock to recover: the slot is already free (the observed record is gone) — no recovery needed",
            )),
            other => Err(Error::transport(format!(
                "ssh atomic_recover: malformed verdict {other:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests_ssh {
    use super::*;
    use crate::transport::ssh::runner::SSH_COMMAND_TIMEOUT_SECS;
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::RngSeed;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    /// The unit tests construct transports with a dummy cache dir + a process
    /// snapshot: they never pin (a known_hosts file is always configured), so
    /// neither the cache path nor the snapshot's contents matter.
    fn test_env() -> SysEnv {
        SysEnv::from_process()
    }

    fn transport() -> SshTransport {
        // Use a (dummy) known_hosts file so `new` does not attempt a live
        // ssh-keyscan pin; the unit tests below only exercise command
        // construction and list parsing, not real key pinning.
        SshTransport::new(
            "deploy",
            "db.example.com",
            2222,
            Path::new("/srv/app"),
            Layout::empty(),
            Some(Path::new("/dev/null")),
            None,
            Path::new("/tmp/deploy-ssh-knownhosts-unit"),
            &test_env(),
            false,
        )
        .unwrap()
    }

    // Host identity must be EXACTLY ONE source: both set is ambiguous, neither
    // set is trust-on-first-use (disabled). Construction fails closed on both.
    #[test]
    fn new_rejects_root_deploy_dir() {
        // The filesystem root is refused at construction (defense in depth,
        // mirroring the AbsoluteDeployDir parse rule): a transport rooted
        // at `/` would make the deployment cleanup operate on the system
        // root.
        let err = SshTransport::new(
            "deploy",
            "db.example.com",
            2222,
            Path::new("/"),
            Layout::empty(),
            Some(Path::new("/dev/null")),
            None,
            Path::new("/tmp/deploy-ssh-knownhosts-unit"),
            &test_env(),
            false,
        )
        .err()
        .expect("the filesystem root must be refused as a deploy_dir");
        assert!(
            err.to_string()
                .contains("at least one normal path component"),
            "error must name the rule, got: {err}"
        );
    }

    #[test]
    fn new_rejects_both_identity_sources() {
        let err = SshTransport::new(
            "deploy",
            "db.example.com",
            2222,
            Path::new("/srv/app"),
            Layout::empty(),
            Some(Path::new("/etc/ssh/known_hosts")),
            Some("SHA256:abc"),
            Path::new("/tmp/deploy-ssh-knownhosts-unit"),
            &test_env(),
            false,
        )
        .err()
        .expect("both identity sources must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("exactly one of known_hosts or host_key_fingerprint")
                && msg.contains("both are set"),
            "error must explain the ambiguity, got: {msg}"
        );
    }

    #[test]
    fn new_rejects_missing_identity() {
        let err = SshTransport::new(
            "deploy",
            "db.example.com",
            2222,
            Path::new("/srv/app"),
            Layout::empty(),
            None,
            None,
            Path::new("/tmp/deploy-ssh-knownhosts-unit"),
            &test_env(),
            false,
        )
        .err()
        .expect("missing identity must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("exactly one of `known_hosts` or `host_key_fingerprint`")
                && msg.contains("trust-on-first-use is disabled"),
            "error must refuse trust-on-first-use, got: {msg}"
        );
    }

    #[test]
    fn ssh_args_carries_port() {
        let t = transport();
        let args = t.ssh_args().unwrap();
        let p = args.iter().position(|a| a == "-p").unwrap();
        assert_eq!(args[p + 1], "2222");
        // The ssh connection target keeps the user@host form.
        assert!(args.iter().any(|a| a == "deploy@db.example.com"));
    }

    // The fixed ssh arguments must bound the connection phase: a dead or
    // unreachable host aborts after `SSH_CONNECT_TIMEOUT_SECS` instead of
    // hanging the transport indefinitely.
    #[test]
    fn ssh_args_carries_connect_timeout() {
        let t = transport();
        let args = t.ssh_args().unwrap();
        assert!(
            args.windows(2).any(|w| {
                w[0] == "-o" && w[1] == format!("ConnectTimeout={SSH_CONNECT_TIMEOUT_SECS}")
            }),
            "ssh args must carry -o ConnectTimeout={}, got: {args:?}",
            SSH_CONNECT_TIMEOUT_SECS
        );
    }

    /// The size-aware upload deadline must scale with the payload at the
    /// minimum transfer rate: a small payload keeps the command deadline, a
    /// large payload extends it proportionally (a slow-but-healthy link is
    /// never killed mid-transfer), and the bound still grows past the base
    /// window the moment the payload needs more than it. The RUNNER's command
    /// deadline is the floor — a test seam's tiny injected deadline applies to
    /// uploads too.
    #[test]
    fn upload_deadline_scales_with_payload_size() {
        let base = Duration::from_secs(SSH_COMMAND_TIMEOUT_SECS);
        // Small payloads (and empty ones) keep the command deadline.
        assert_eq!(upload_deadline(0, 64 * 1024, base), base);
        assert_eq!(upload_deadline(64 * 1024, 64 * 1024, base), base);
        // A payload that needs more than the base window at the minimum rate
        // extends the deadline proportionally (24MB at 64KB/s).
        let mb24 = 24 * 1024 * 1024;
        assert_eq!(
            upload_deadline(mb24, 64 * 1024, base),
            Duration::from_secs(mb24 / SSH_TRANSFER_MIN_RATE_BYTES_PER_SEC)
        );
        // The boundary: a payload needing more than the base window at the
        // minimum rate extends the deadline past the command deadline
        // (integer division: the deadline grows only past a full rate-unit).
        let boundary = SSH_COMMAND_TIMEOUT_SECS * SSH_TRANSFER_MIN_RATE_BYTES_PER_SEC;
        assert_eq!(upload_deadline(boundary, 64 * 1024, base), base);
        assert!(
            upload_deadline(
                boundary + SSH_TRANSFER_MIN_RATE_BYTES_PER_SEC,
                64 * 1024,
                base
            ) > base
        );
        // A lower configured min-rate extends the deadline proportionally
        // (the slow-link override: 24MB at 32KB/s is twice the 64KB/s bound).
        assert_eq!(
            upload_deadline(mb24, 32 * 1024, base),
            Duration::from_secs(mb24 / (32 * 1024))
        );
        // The RUNNER's command deadline is the floor for an upload whose
        // payload needs less than it (the seam's tiny injected deadline
        // applies to uploads — the fake Hang child waits for THIS bound,
        // never a production constant); a payload that needs MORE than the
        // floor still scales past it.
        let tiny = Duration::from_millis(25);
        assert_eq!(upload_deadline(0, 64 * 1024, tiny), tiny);
        assert_eq!(upload_deadline(7, 64 * 1024, tiny), tiny);
        assert!(
            upload_deadline(mb24, 64 * 1024, tiny) > tiny,
            "a payload needing more than the floor scales past it"
        );
    }

    /// A size-scaled upload timeout names the file, the size, the deadline
    /// math, and the `DEPLOY_SSH_MIN_RATE_BYTES_PER_SEC` fix with a concrete
    /// suggestion — an agent hitting a slow link can recover without reading
    /// the source.
    #[test]
    fn upload_timeout_error_names_file_and_rate_fix() {
        let base = Duration::from_secs(SSH_COMMAND_TIMEOUT_SECS);
        let err = upload_timeout_error(
            Duration::from_secs(372),
            &None,
            24 * 1024 * 1024,
            "/srv/app/app/bin/linux/armv7/proxy",
            Duration::from_secs(372),
            base,
            64 * 1024,
        );
        let msg = err.to_string();
        // The file and byte size are attributable.
        assert!(msg.contains("/srv/app/app/bin/linux/armv7/proxy"));
        assert!(msg.contains("25165824 bytes"));
        // The deadline math and the override are named.
        assert!(msg.contains("DEPLOY_SSH_MIN_RATE_BYTES_PER_SEC"));
        assert!(msg.contains("DEPLOY_SSH_MIN_RATE_BYTES_PER_SEC=32768"));
        // It is identified as a size-scaled (slow-link) timeout, not a hang.
        assert!(msg.contains("size-scaled"));
    }

    /// A bare command-deadline timeout is diagnosed as a hung remote (the
    /// remote stopped reading stdin), NOT as a slow link — a rate override
    /// cannot fix a hang, so the message must not send the user there.
    #[test]
    fn upload_timeout_error_distinguishes_hung_remote() {
        let base = Duration::from_secs(SSH_COMMAND_TIMEOUT_SECS);
        let err = upload_timeout_error(
            base,
            &None,
            512,
            "/srv/app/app/config.toml",
            base,
            base,
            64 * 1024,
        );
        let msg = err.to_string();
        assert!(msg.contains("base command deadline"));
        assert!(msg.contains("stopped reading stdin"));
        // The slow-link fix must NOT be suggested for a hang.
        assert!(!msg.contains("DEPLOY_SSH_MIN_RATE_BYTES_PER_SEC="));
    }

    /// The framed-lstat `RemoteMeta` must carry the RAW `st_mode` (type bits
    /// INCLUDED) and the REAL size, so it matches `LocalTransport::metadata`
    /// (`meta_to_remote`). The old `& 0o7777` mask made the field silently
    /// different from the local view; every consumer masks it itself, so the
    /// raw value is safe. Frame: `P\t<size>\t<rawmode_hex>`.
    #[test]
    fn lstat_frame_carries_the_raw_mode_and_the_real_size() {
        let file = SshTransport::parse_lstat_frame("P\t7\t81a4\n")
            .unwrap()
            .expect("a P frame is an existing entry");
        assert_eq!(file.mode, 0o100644, "the RAW file mode is carried");
        assert_eq!(file.size, 7, "the REAL size is carried");
        assert!(file.is_file && !file.is_dir && !file.is_symlink);

        let link = SshTransport::parse_lstat_frame("P\t3\ta1ed\n")
            .unwrap()
            .expect("a P frame is an existing entry");
        assert_eq!(link.mode, 0o120755, "the RAW symlink mode is carried");
        assert_eq!(link.size, 3, "a symlink carries its own size");
        assert!(link.is_symlink && !link.is_file && !link.is_dir);
    }

    // Finding 3: `.` and `..` are excluded, and real modes are preserved.
    #[test]
    fn list_excludes_dot_entries_and_keeps_modes() {
        // The wire frame is NUL-terminated records of
        // `type<TAB>mode<TAB>size<TAB>name`; 0x81ed = 100755 (executable),
        // 0x81a4 = 100644, 0xa1ed = 120755 (symlink), 0x41ed = 040755 (dir).
        let out = "f\t81ed\t3\tapp\0d\t41ed\t64\t.\0d\t41ed\t64\t..\0l\ta1ed\t6\thidden\0f\t81a4\t6\treadme\0";
        let entries = SshTransport::parse_list_output(out).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(!names.contains(&"."), ". must be excluded");
        assert!(!names.contains(&".."), ".. must be excluded");
        assert!(names.contains(&"app"));
        assert!(names.contains(&"hidden"));
        assert!(names.contains(&"readme"));

        let app = entries.iter().find(|e| e.name == "app").unwrap();
        assert!(!app.is_dir && !app.is_symlink);
        assert_eq!(app.mode, 0o100755, "the RAW executable mode is preserved");
        assert_eq!(app.size, 3, "the real size is preserved");
        let readme = entries.iter().find(|e| e.name == "readme").unwrap();
        assert_eq!(readme.mode, 0o100644, "the RAW file mode is preserved");
        assert_eq!(readme.size, 6, "the real size is preserved");
        let hidden = entries.iter().find(|e| e.name == "hidden").unwrap();
        assert!(hidden.is_symlink, "symlink type preserved");
        assert_eq!(hidden.mode, 0o120755, "the RAW symlink mode is preserved");
        assert_eq!(hidden.size, 6, "a symlink reports its OWN size");
    }

    /// F2: the LITERAL `list_script` must report the REAL mode on a BSD
    /// userland. Pre-fix it ran `stat -c '%f'`, which BSD/macOS `stat` rejects;
    /// the mode column came out empty and the parser silently defaulted every
    /// entry to 0, so this test FAILED on macOS with `left: 0` for each entry.
    /// The script is now one perl `lstat` one-liner (perl is already required
    /// far side), and the mode is `st_mode & 0xffff` in hex — POSIX on GNU and
    /// BSD alike. It also pins that hidden entries are covered and `.`/`..` are
    /// never emitted, which the previous shape-only test asserted by string
    /// matching.
    #[test]
    fn list_script_reports_the_real_mode_on_bsd_userland() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("exec.sh"), b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(
            tree.join("exec.sh"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        std::fs::write(tree.join(".hidden"), b"h").unwrap();
        std::fs::set_permissions(
            tree.join(".hidden"),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        std::fs::create_dir_all(tree.join("sub")).unwrap();
        std::fs::set_permissions(
            tree.join("sub"),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();

        let entries = run_list_script(&transport_at(dir.path()), Path::new("tree"));
        let get = |n: &str| {
            entries
                .iter()
                .find(|e| e.name == n)
                .unwrap_or_else(|| panic!("entry {n} missing from {entries:?}"))
        };
        assert_eq!(
            get("exec.sh").mode,
            0o100755,
            "the RAW executable mode must be real on a BSD userland, never silently 0"
        );
        assert_eq!(get(".hidden").mode, 0o100600, "the hidden file's raw mode");
        assert_eq!(get("sub").mode, 0o040700, "the directory's raw mode");
        assert_eq!(
            get("exec.sh").size,
            b"#!/bin/sh\n".len() as u64,
            "the real size must be carried, never a literal 0"
        );
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&".hidden"), "hidden entries are covered");
        assert!(!names.contains(&"."), ". must never be emitted");
        assert!(!names.contains(&".."), ".. must never be emitted");
    }

    /// A transport rooted at a caller-supplied directory, so the LITERAL
    /// `list_script` can be executed under `/bin/sh` against a temp tree
    /// instead of the fixed `/srv/app` the other (command-construction) tests
    /// use.
    fn transport_at(root: &Path) -> SshTransport {
        SshTransport::new(
            "deploy",
            "db.example.com",
            2222,
            root,
            Layout::empty(),
            Some(Path::new("/dev/null")),
            None,
            Path::new("/tmp/deploy-ssh-knownhosts-unit"),
            &test_env(),
            false,
        )
        .unwrap()
    }

    /// Run the LITERAL `list_script` for `rel` under `/bin/sh` and return the
    /// parsed entries. The mode is now obtained through the portable perl
    /// `lstat` path (NOT GNU-only `stat -c`), so these tests assert on the mode
    /// too; the old "callers must never assert on the mode" caveat is gone
    /// because the underlying defect is fixed.
    fn run_list_script(t: &SshTransport, rel: &Path) -> Vec<RemoteEntry> {
        let script = t.list_script(rel);
        let out = run_sh_stdin(&script, &[]);
        assert!(
            out.status.success(),
            "list script must exit 0 under sh: {} {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        SshTransport::decode_list_output(&out.stdout).unwrap()
    }

    /// Run the LITERAL `list_script` for `rel` and return the RAW outcome, so a
    /// test can assert on a FAILING listing (an unreadable directory) without
    /// the success assertion [`run_list_script`] makes.
    fn run_list_script_raw(t: &SshTransport, rel: &Path) -> std::process::Output {
        run_sh_stdin(&t.list_script(rel), &[])
    }

    /// DEFECT 3: an ABSENT directory must list EMPTY, matching
    /// `LocalTransport::list`'s deliberate `NotFound` ⇒ empty rule. Pre-fix
    /// `opendir … or die` exited 2 for a missing directory.
    #[test]
    fn list_script_absent_directory_is_empty() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let entries = run_list_script(&transport_at(dir.path()), Path::new("never-created"));
        assert!(
            entries.is_empty(),
            "an absent directory must list empty, got {entries:?}"
        );
    }

    /// DEFECT 2 + 3: a `chmod 400` directory has the READ bit (so `opendir`
    /// succeeds) but no SEARCH bit, so every `lstat` fails EACCES. The old
    /// `next unless @s` silently dropped every entry, printing ZERO bytes and
    /// exiting 0 for a NON-EMPTY directory — `Ok(vec![])` where the local view
    /// returned `Permission denied`. The listing must now FAIL. A `chmod 111`
    /// directory has no read bit, so `opendir` itself must fail loudly.
    #[test]
    fn list_script_unreadable_directory_is_an_error_not_an_empty_listing() {
        for (mode, needle) in [(0o400u32, "lstat"), (0o111u32, "opendir")] {
            let dir =
                crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
            let locked = dir.path().join("locked");
            std::fs::create_dir_all(&locked).unwrap();
            std::fs::write(locked.join("entry"), b"payload").unwrap();
            std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(mode))
                .unwrap();

            let out = run_list_script_raw(&transport_at(dir.path()), Path::new("locked"));
            std::fs::set_permissions(&locked, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .unwrap();

            assert!(
                !out.status.success(),
                "a chmod {mode:o} directory must fail the listing, not return an empty Ok \
                 (stdout {:?})",
                String::from_utf8_lossy(&out.stdout)
            );
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains(needle),
                "the failure must name `{needle}`; stderr was {stderr:?}"
            );
            assert!(
                out.stdout.is_empty(),
                "a failed listing must emit NOTHING, got {:?}",
                String::from_utf8_lossy(&out.stdout)
            );
        }
    }

    /// DEFECT 5: the fsync primitives must TERMINATE on a FIFO. The old
    /// `open my $fh, "<", $ARGV[0]` blocks forever on a fifo with no writer
    /// (proved on GNU and BSD with `timeout 3` → rc 124); `sysopen` with
    /// `O_NONBLOCK` returns immediately and the non-regular entry is refused.
    /// Both primitives share the pattern, so both are pinned.
    #[test]
    fn fsync_primitives_refuse_a_fifo_without_blocking() {
        for (prim, name) in [(PERL_FSYNC_DIR, "dir"), (PERL_FSYNC_FILE, "file")] {
            let dir =
                crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
            let fifo = dir.path().join(format!("pipe-{name}"));
            mkfifo(&fifo);
            let cmd = format!(
                "perl -e {prim} -- {p}",
                prim = shell_quote(prim),
                p = shell_quote(&fifo.to_string_lossy())
            );
            let out = run_sh_with_timeout(&cmd, 15)
                .unwrap_or_else(|| panic!("the {name} fsync primitive must NOT block on a FIFO"));
            assert!(
                !out.status.success(),
                "a FIFO must be REFUSED, not fsynced (primitive {name})"
            );
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("fsync-refuse"),
                "the refusal must be loud (primitive {name}): {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    /// DEFECT 1 (the hole): the `fsync_tree` command must exit NONZERO when a
    /// far-side fsync fails. Pre-fix `find … -exec … {} ;` ignored the invoked
    /// command's exit status, so a fake perl that failed EVERY call still made
    /// the whole command exit 0. This runs the LITERAL command under `/bin/sh`
    /// with such a fake on `PATH`.
    #[test]
    fn fsync_tree_cmd_propagates_a_failed_fsync() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(tree.join("sub")).unwrap();
        std::fs::write(tree.join("a"), b"a").unwrap();
        std::fs::write(tree.join("sub/b"), b"b").unwrap();
        let fakebin = dir.path().join("fakebin");
        install_fake_perl(&fakebin, FSYNC_DIR_HOOK, 9);

        let cmd = SshTransport::fsync_tree_cmd(dir.path(), Path::new("tree"));
        let out = run_sh_stdin(
            &format!(
                "PATH={fake}:$PATH; {cmd}",
                fake = shell_quote(&fakebin.to_string_lossy())
            ),
            &[],
        );
        assert!(
            !out.status.success(),
            "a failed far-side fsync ANYWHERE in the tree must make the command exit nonzero \
             (pre-fix find exited 0); stdout {:?} stderr {:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// DEFECT 5, at the TREE level: `find -type d -o -type f` (like the local
    /// walk's `symlink_metadata`) never selects a FIFO, so the tree walk
    /// terminates AND succeeds — no entry ever opens it.
    #[test]
    fn fsync_tree_cmd_skips_a_fifo_and_terminates() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("file"), b"x").unwrap();
        mkfifo(&tree.join("pipe"));

        let cmd = SshTransport::fsync_tree_cmd(dir.path(), Path::new("tree"));
        let out = run_sh_with_timeout(&cmd, 20)
            .expect("the tree fsync must terminate on a tree containing a FIFO");
        assert!(
            out.status.success(),
            "the FIFO is skipped (matching the local walk): {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A DANGLING symlink must be LISTED. The old guard `[ -e "$e" ] ||
    /// continue` FOLLOWS the symlink, so such an entry vanished from `list`
    /// while the far-side manifest walk (which uses `lstat`) still included it
    /// — the two views of one directory disagreed. `sync` then reported a
    /// legitimately installed dangling link as a `NameNotFaithful` conflict,
    /// refused to replace an existing one, and (with `delete_extraneous`) could
    /// no longer see a reserved dangling child, so the sanctioned recursive
    /// removal destroyed the caller's only copy. This runs the LITERAL script
    /// under `/bin/sh`; pre-fix the dangling entry is absent, so the assertion
    /// FAILS.
    #[test]
    fn list_script_lists_a_dangling_symlink() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("live"), b"x").unwrap();
        std::os::unix::fs::symlink("nowhere", tree.join("dangling")).unwrap();

        let entries = run_list_script(&transport_at(dir.path()), Path::new("tree"));
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"dangling"),
            "a dangling symlink must be listed (POSIX `-e` follows the link); got {names:?}"
        );
        assert!(
            names.contains(&"live"),
            "a live file must still be listed; got {names:?}"
        );
        let dangling = entries.iter().find(|e| e.name == "dangling").unwrap();
        assert!(
            dangling.is_symlink,
            "the dangling entry must be classified as a symlink, got {dangling:?}"
        );
        assert!(!dangling.is_dir);
    }

    /// Non-regression: the `-e`/`-L` guard still filters the UNMATCHED globs.
    /// When a directory is empty every pattern expands to its own literal text
    /// (`<dir>/*`, `<dir>/.[!.]*`, `<dir>/..?*`), which is not an entry; a bare
    /// `|| continue` cannot be dropped, or those literals would be listed as
    /// bogus names. This pins that the dangling-symlink fix did not open that
    /// hole.
    #[test]
    fn list_script_filters_unmatched_globs_in_an_empty_directory() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let tree = dir.path().join("empty");
        std::fs::create_dir_all(&tree).unwrap();
        let entries = run_list_script(&transport_at(dir.path()), Path::new("empty"));
        assert!(
            entries.is_empty(),
            "an empty directory must list nothing, got {:?}",
            entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>()
        );
    }

    /// DEFECT 1 (Remote half, script): the wire frame must carry a name
    /// containing a TAB or a NEWLINE verbatim. Pre-fix the frame was
    /// tab/LF-delimited, so `a\tb` parsed as `a` (the tab split the fields)
    /// and `line1\nline2` split into TWO bogus entries — the listing view used
    /// by the byte-exact comparison silently disagreed with the directory.
    /// The frame is now NUL-terminated (`type<TAB>mode<TAB>size<TAB>name`), and
    /// NUL is the one byte a POSIX name cannot contain. Runs on any POSIX host (these
    /// names are legal on APFS too).
    #[test]
    fn list_script_carries_a_tab_and_a_newline_in_a_name() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("a\tb"), b"x").unwrap();
        std::fs::write(tree.join("line1\nline2"), b"x").unwrap();
        std::fs::write(tree.join("x "), b"x").unwrap();
        std::fs::write(tree.join(" x"), b"x").unwrap();

        let mut names: Vec<String> = run_list_script(&transport_at(dir.path()), Path::new("tree"))
            .into_iter()
            .map(|e| e.name)
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                " x".to_string(),
                "a\tb".to_string(),
                "line1\nline2".to_string(),
                "x ".to_string(),
            ]
        );
    }

    /// DEFECT 1 (Remote half, script): a name ending in a newline is legal and
    /// must survive the frame. Pre-fix the script derived the name with
    /// `$(basename ...)`, and command substitution strips EVERY trailing
    /// newline, so `n\n` became `n` — a byte-exact comparison would then match
    /// the wrong entry (or miss the intended one entirely).
    #[test]
    fn list_script_carries_a_trailing_newline_in_a_name() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("n\n"), b"x").unwrap();
        std::fs::write(tree.join("plain"), b"x").unwrap();

        let mut names: Vec<String> = run_list_script(&transport_at(dir.path()), Path::new("tree"))
            .into_iter()
            .map(|e| e.name)
            .collect();
        names.sort();
        assert_eq!(names, vec!["n\n".to_string(), "plain".to_string()]);
    }

    /// DEFECT 1 (Remote half, decoder): the listing payload is decoded from
    /// RAW bytes and a non-UTF-8 name is REFUSED. Pre-fix
    /// `String::from_utf8_lossy(&out.stdout)` mapped every such name to U+FFFD,
    /// so two DISTINCT on-disk names became one compared spelling. This is the
    /// byte-level reproduction of the U+FFFD conflation and needs no
    /// filesystem that can actually hold such a name.
    #[test]
    fn decode_list_output_refuses_two_distinct_non_utf8_names() {
        // 0xff and 0xfe are both invalid standalone UTF-8, so `from_utf8_lossy`
        // renders both as U+FFFD — indistinguishable.
        let raw = b"f\t81a4\t1\t\xff\0f\t81a4\t1\t\xfe\0";
        let err = SshTransport::decode_list_output(raw)
            .expect_err("a non-UTF-8 name must refuse the listing, never decode to U+FFFD");
        let msg = err.to_string();
        assert!(
            msg.contains("not valid UTF-8"),
            "the error must name the reason, got: {msg}"
        );
    }

    /// The decoder keeps a tab and a newline INSIDE a name (they are data,
    /// not delimiters) and refuses a structurally malformed record rather than
    /// defaulting it.
    #[test]
    fn parse_list_output_keeps_tabs_and_newlines_in_names() {
        let text = "f\t81a4\t1\ta\tb\0f\t81a4\t1\tline1\nline2\0f\t81a4\t1\tx \0";
        let entries = SshTransport::parse_list_output(text).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a\tb", "line1\nline2", "x "]);

        // A record with fewer than four TAB fields is malformed, not an
        // empty-named entry.
        assert!(
            SshTransport::parse_list_output("f\t81a4").is_err(),
            "a short record must be refused"
        );
    }

    /// DEFECT 2: `readlink` prints the RAW target plus ONE newline. The frame
    /// must strip exactly that one byte — the pre-fix `.trim()` also deleted a
    /// leading/trailing whitespace byte that is PART OF THE TARGET, so the SSH
    /// read differed from the raw local `read_link` and a concurrent `"x"` ->
    /// `"x "` change kept the same target hash.
    #[test]
    fn parse_readlink_output_strips_exactly_one_newline() {
        let rel = Path::new("link");
        for target in ["plain", "x ", " x", " x ", "a b", "a\tb", "n\n"] {
            let mut framed = target.as_bytes().to_vec();
            framed.push(b'\n');
            assert_eq!(
                SshTransport::parse_readlink_output(&framed, rel).unwrap(),
                PathBuf::from(target),
                "target {target:?} must round-trip through the readlink frame"
            );
        }
        // Exactly ONE newline is the framing byte: a target that itself ends in
        // a newline arrives as two, and one must survive.
        assert_eq!(
            SshTransport::parse_readlink_output(b"x\n\n", rel).unwrap(),
            PathBuf::from("x\n"),
        );
        // Nothing else is trimmed: a payload without a framing newline is the
        // target verbatim.
        assert_eq!(
            SshTransport::parse_readlink_output(b"x ", rel).unwrap(),
            PathBuf::from("x "),
        );
    }

    /// Pre-fix `String::from_utf8_lossy` turned a non-UTF-8 target into U+FFFD;
    /// the manifest refuses a non-UTF-8 target, so the read must fail closed
    /// rather than misreport one.
    #[test]
    fn parse_readlink_output_refuses_a_non_utf8_target() {
        let err = SshTransport::parse_readlink_output(b"\xff\n", Path::new("link"))
            .expect_err("a non-UTF-8 target must be an error, never a lossy read");
        assert!(err.to_string().contains("not valid UTF-8"), "got: {err}");
    }

    /// The two read mechanisms must AGREE on the exact bytes of a target: the
    /// LOCAL path is raw (`std::fs::read_link`, the mechanism
    /// `LocalTransport::read_link` uses), and the SSH frame must return the
    /// same bytes for the same link. Pre-fix `.trim()` returned `"x"` for a
    /// local `"x "`, so an SSH destination/source failed post-transfer
    /// verification on a legitimate link.
    #[test]
    fn local_and_ssh_readlink_agree_on_whitespace_targets() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        for (i, target) in ["plain", "x ", " x", " x ", "a b"].iter().enumerate() {
            let name = format!("link{i}");
            std::os::unix::fs::symlink(target, tree.join(&name)).unwrap();
            let local = std::fs::read_link(tree.join(&name)).unwrap();
            let mut framed = local.to_str().unwrap().as_bytes().to_vec();
            framed.push(b'\n');
            let ssh = SshTransport::parse_readlink_output(&framed, Path::new(&name)).unwrap();
            assert_eq!(
                ssh, local,
                "the SSH read must equal the raw local read for target {target:?}"
            );
        }
    }

    /// The two views of one directory must AGREE on a dangling symlink:
    /// `Remote::list` (the address-fidelity and residue view) and the far-side
    /// manifest walk (which uses `lstat` and therefore includes it). This is
    /// the cross-view pin for the defect: pre-fix `list` omitted the entry
    /// while the manifest kept it, so the assertion on `list` FAILS.
    #[test]
    fn list_and_manifest_agree_on_a_dangling_symlink() {
        if !perl_available() {
            eprintln!("skipping: perl is not on PATH, so the manifest walk cannot run");
            return;
        }
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let tree = dir.path().join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("live"), b"x").unwrap();
        std::os::unix::fs::symlink("nowhere", tree.join("dangling")).unwrap();

        // The manifest walk's view (perl `lstat`): includes the dangling link.
        let out = std::process::Command::new("perl")
            .args(["-e", crate::manifest::remote_tree_verify_script()])
            .arg(&tree)
            .output()
            .expect("perl must run");
        assert!(
            out.status.success(),
            "manifest walk failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let manifest = crate::manifest::canonicalize_remote_entries(
            &String::from_utf8_lossy(&out.stdout),
            &tree,
        )
        .unwrap();
        assert!(
            manifest.entries.iter().any(|e| e.path == "dangling"),
            "the manifest walk must include the dangling symlink: {:?}",
            manifest
                .entries
                .iter()
                .map(|e| e.path.clone())
                .collect::<Vec<_>>()
        );

        // The list view must agree.
        let entries = run_list_script(&transport_at(dir.path()), Path::new("tree"));
        assert!(
            entries.iter().any(|e| e.name == "dangling" && e.is_symlink),
            "`list` must include the dangling symlink as a symlink; got {:?}",
            entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>()
        );
    }

    /// Whether `perl` is on `PATH` (the far-side manifest walk needs it).
    fn perl_available() -> bool {
        std::process::Command::new("perl")
            .args(["-e", "exit 0"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// THE DATA-LOSS PRECONDITION: with `delete_extraneous`, a claimed
    /// (renamed-aside) directory is recursively removed unless the residue
    /// gate sees a RESERVED entry inside it. The gate reads the SAME `list`
    /// view. A RESERVED DANGLING symlink left in the claimed directory must be
    /// VISIBLE (and typed as a symlink, so the gate treats it as residue, not
    /// as a removable file); pre-fix the walk saw an ordinary directory, ran
    /// the recursive `rm -rf`, and destroyed the caller's only copy with
    /// `residue` empty. This asserts the precondition the gate consumes and
    /// FAILS pre-fix (the reserved child is absent from the listing).
    #[test]
    fn list_reports_a_reserved_dangling_symlink_for_the_residue_gate() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let claimed = dir.path().join("claimed");
        std::fs::create_dir_all(&claimed).unwrap();
        std::fs::write(claimed.join("ordinary"), b"x").unwrap();
        // The reserved entry is a DANGLING symlink: its target was removed (the
        // object it points at is gone), which is exactly why the naive
        // existence test dropped it.
        std::os::unix::fs::symlink("../../objects/gone", claimed.join(".reserved")).unwrap();
        assert!(
            !claimed.join(".reserved").exists()
                && std::fs::symlink_metadata(claimed.join(".reserved"))
                    .unwrap()
                    .file_type()
                    .is_symlink(),
            "premise: the reserved entry is a dangling symlink"
        );

        let entries = run_list_script(&transport_at(dir.path()), Path::new("claimed"));
        let reserved = entries
            .iter()
            .find(|e| e.name == ".reserved")
            .unwrap_or_else(|| {
                panic!(
                    "the residue gate cannot see the reserved dangling child; it would remove the \
                 claimed subtree recursively and destroy it. listing: {:?}",
                    entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>()
                )
            });
        assert!(
            reserved.is_symlink,
            "the reserved child must be typed as a symlink so the gate treats it as residue"
        );
        assert!(
            entries.iter().any(|e| e.name == "ordinary"),
            "the ordinary sibling is still listed"
        );
    }

    // Finding 4: try_write_new creates the parent directory before the
    // noclobber install, so a fresh remote root can host the first lock.
    #[test]
    fn try_write_new_creates_parent_dir() {
        let t = transport();
        let cmd = SshTransport::write_new_cmd(
            t.root(),
            Path::new("state/operation.lock"),
            IMMUTABLE_RECORD_MODE,
        );
        assert!(
            cmd.starts_with("mkdir -p '/srv/app/state'"),
            "parent directory is created first, got: {cmd}"
        );
        // ... and the remote allocation happens only after the parent exists.
        let mkdir_end = cmd.find("&&").unwrap();
        assert!(
            cmd[mkdir_end..].contains("mktemp"),
            "mktemp allocation must follow mkdir -p, got: {cmd}"
        );
    }

    /// F1, BEHAVIOUR: `provision_layout` must create the destination ROOT, not
    /// only the caller's bootstrap directories.
    ///
    /// Pre-fix the argv listed ONLY `layout.bootstrap_dirs`, so with
    /// `Layout::empty()` the command was `mkdir -p` with NO OPERAND and the
    /// remote `mkdir` failed with its usage error (`mkdir: missing operand` on
    /// GNU, `usage: mkdir [-pv] [-m mode] directory_name ...` on macOS); with
    /// bootstrap directories present the ROOT was still left absent, so the
    /// first destination manifest read failed with `not a directory: <root>`.
    /// `LocalTransport::provision_layout` already created its base, so the
    /// same consumer call worked locally and failed only on the remote path.
    /// This pins the ROOT as the FIRST operand.
    #[test]
    fn provision_layout_creates_the_destination_root() {
        let t = transport();
        let cmd = SshTransport::provision_layout_cmd(t.root(), &Layout::empty());
        assert_eq!(
            cmd, "'mkdir' '-p' '/srv/app'",
            "an empty layout must still create the destination root"
        );

        let mut layout = Layout::empty();
        layout.bootstrap_dirs = vec![
            RootedRelativePath::parse(Path::new("state")).unwrap(),
            RootedRelativePath::parse(Path::new("releases")).unwrap(),
        ];
        let cmd = SshTransport::provision_layout_cmd(t.root(), &layout);
        assert_eq!(
            cmd, "'mkdir' '-p' '/srv/app' '/srv/app/state' '/srv/app/releases'",
            "the root is the first operand, then every bootstrap directory"
        );
    }

    /// The USER identity channel: `with_identity_file` adds `-i <path>` and
    /// `IdentitiesOnly=yes`; without it no key option is added (ssh uses the
    /// ambient `~/.ssh`/agent configuration, which the constructor documents).
    /// A caller-supplied `-o` option is appended AFTER the crate's own, so the
    /// first-obtained-value rule keeps the crate's host-key policy
    /// authoritative.
    #[test]
    fn with_identity_file_adds_the_user_key_and_identities_only() {
        let path = Path::new("/home/deploy/.config/app/deploy_ed25519");
        let t = transport().with_identity_file(path);
        let args = t.ssh_args().unwrap();
        let i = args.iter().position(|a| a == "-i").expect("an -i option");
        assert_eq!(args[i + 1], path.to_string_lossy().into_owned());
        assert!(
            args.iter().any(|a| a == "IdentitiesOnly=yes"),
            "IdentitiesOnly=yes forces the supplied key: {args:?}"
        );

        // Without it, no key option is added: the ambient configuration is the
        // documented default.
        let plain = transport().ssh_args().unwrap();
        assert!(!plain.iter().any(|a| a == "-i"), "{plain:?}");
        assert!(
            !plain.iter().any(|a| a == "IdentitiesOnly=yes"),
            "{plain:?}"
        );

        // A caller option is appended after the crate's own options.
        let args = transport()
            .with_ssh_option("ProxyJump", "bastion")
            .ssh_args()
            .unwrap();
        let strict_pos = args
            .iter()
            .position(|a| a == "StrictHostKeyChecking=yes")
            .expect("the crate's host-key policy is present");
        let caller_pos = args
            .iter()
            .position(|a| a == "ProxyJump=bastion")
            .expect("the caller option is present");
        assert!(
            strict_pos < caller_pos,
            "crate options precede caller options: {args:?}"
        );
    }

    /// F1, BEHAVIOUR: the LITERAL `rename_cmd` runs under `sh` against a real
    /// root, and a symlink-to-directory destination is REPLACED IN PLACE. This
    /// replaces the old `rename_uses_no_target_directory_flag`, which asserted
    /// `cmd.contains("mv -T")` — a shape assertion that could not tell whether
    /// the command RUNS.
    ///
    /// Pre-fix `rename_cmd` emitted `mv -T`; on this host (macOS/BSD userland)
    /// `mv` rejects it and the command exits 64, so this test FAILED with
    /// `mv: illegal option -- T` + usage. On Linux/GNU it passed, which is
    /// exactly the silent platform divergence this pins.
    #[test]
    fn rename_replaces_a_symlink_to_a_directory() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let root = dir.path().join("remote");
        std::fs::create_dir_all(root.join("objects/app-v1")).unwrap();
        std::fs::create_dir_all(root.join("objects/app-v2")).unwrap();
        std::os::unix::fs::symlink("objects/app-v1", root.join("current")).unwrap();
        std::os::unix::fs::symlink("objects/app-v2", root.join(".current.tmp.op-x")).unwrap();

        let cmd =
            SshTransport::rename_cmd(&root, Path::new(".current.tmp.op-x"), Path::new("current"));
        let out = run_sh_stdin(&cmd, &[]);
        assert!(
            out.status.success(),
            "rename must succeed on every userland; stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            std::fs::read_link(root.join("current")).unwrap(),
            Path::new("objects/app-v2"),
            "the `current` link must be REPLACED, not moved INTO objects/app-v1"
        );
        assert!(
            !root.join("objects/app-v1/.current.tmp.op-x").exists(),
            "the source must NEVER be moved INTO the destination directory"
        );
    }

    /// F1, GUARD: the property `-T` existed to provide — a regular file must
    /// not be moved INTO a directory target — must survive the portable
    /// primitive. The `rename(2)` refusal (`EISDIR`/`ENOTDIR`) is loud (nonzero)
    /// and leaves both operands untouched. This pins the guard; it passes
    /// pre-fix too (pre-fix `mv -T` also refused, just for the wrong reason on
    /// BSD), but without it a "fix" that dropped the guard would regress
    /// silently.
    #[test]
    fn rename_refuses_a_file_onto_a_directory_target() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let root = dir.path().join("remote");
        std::fs::create_dir_all(root.join("target")).unwrap();
        std::fs::write(root.join("source"), b"must-not-move").unwrap();

        let cmd = SshTransport::rename_cmd(&root, Path::new("source"), Path::new("target"));
        let out = run_sh_stdin(&cmd, &[]);
        assert!(
            !out.status.success(),
            "a file onto a directory must be refused, got status {:?}",
            out.status.code()
        );
        assert!(
            root.join("source").is_file(),
            "the source must stay in place"
        );
        assert!(
            root.join("target").is_dir(),
            "the target must stay a directory"
        );
        assert!(
            !root.join("target/source").exists(),
            "the source must NEVER be moved INTO the directory target"
        );
    }

    /// The remote compare-and-delete script (`remove_file_if_cmd`), executed
    /// locally with `sh -c`: it CLAIMS the entry with `mv`, deletes it on a
    /// byte match (frame `R`), RESTORES it no-replace on mismatch (frame `M`
    /// — the winner survives byte-for-byte), and reports genuine absence
    /// (frame `A`).
    #[test]
    fn remove_file_if_script_frames() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let root = dir.path().join("remote");
        let rel = Path::new("state/operation.lock");
        // The mutation-lock record: operation_id + unique acquisition id (no
        // time anywhere in the protocol — create-once ownership with no
        // lease/expiry).
        let payload = "{\"operation_id\":\"a\",\"acquisition_id\":\"acq-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b6\"}";

        // Genuinely absent: the Absent frame.
        let cmd = SshTransport::remove_file_if_cmd(&root, rel, payload);
        let out = run_sh_stdin(&cmd, &[]);
        assert!(out.status.success(), "script must exit 0: {out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "A");

        // Install the record, then remove on a byte match: the Removed frame
        // and the entry is gone.
        std::fs::create_dir_all(root.join("state")).unwrap();
        std::fs::write(root.join(rel), payload).unwrap();
        let out = run_sh_stdin(&cmd, &[]);
        assert!(out.status.success(), "script must exit 0: {out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "R");
        assert!(
            !root.join(rel).exists(),
            "the matched entry must be removed"
        );

        // Reinstall, then compare against a DIFFERENT expected record: the
        // Mismatch frame and the entry is restored byte-for-byte.
        std::fs::write(root.join(rel), payload).unwrap();
        let cmd2 = SshTransport::remove_file_if_cmd(
            &root,
            rel,
            "{\"operation_id\":\"b\",\"acquisition_id\":\"acq-0192a3b4-c5d6-7e7f-8a9b-0c1d2e3f4a5b7\"}",
        );
        let out = run_sh_stdin(&cmd2, &[]);
        assert!(out.status.success(), "script must exit 0: {out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "M");
        assert_eq!(
            std::fs::read(root.join(rel)).unwrap(),
            payload.as_bytes(),
            "the mismatch must restore the winner byte-for-byte"
        );
    }

    // The unique temp file for the durability protocol must live INSIDE the
    // destination's parent directory and be dot-prefixed (mirroring
    // LocalTransport), never a sibling of the parent: a sibling name would
    // escape the managed remote root whenever the destination's parent IS the
    // deployment root. The name is allocated remotely by `mktemp`, so the
    // XXXXXX template suffix must survive quoting verbatim.
    #[test]
    fn try_write_new_temp_is_dot_prefixed_inside_destination_parent() {
        let t = transport();
        let cmd = SshTransport::write_new_cmd(
            t.root(),
            Path::new("state/operation.lock"),
            IMMUTABLE_RECORD_MODE,
        );
        assert!(
            cmd.contains("mktemp '/srv/app/state/.operation.lock.tmp.XXXXXX'"),
            "temp must be inside the destination parent, dot-prefixed, and mktemp-allocated, got: {cmd}"
        );
        assert!(
            !cmd.contains("/srv/app.state.operation.lock"),
            "temp must not be a dot-sibling of the destination parent, got: {cmd}"
        );
        assert!(
            !cmd.contains("/srv/app/.state.operation.lock"),
            "temp must not leak above the destination parent, got: {cmd}"
        );
        assert!(
            cmd.contains(".tmp.XXXXXX"),
            "mktemp template must carry XXXXXX at the end of the last component, got: {cmd}"
        );
    }

    // Regression: when the destination sits directly in the deployment root,
    // the old sibling naming (`{root}.{basename}.tmp...`) placed the temp OUTSIDE
    // the managed root entirely.
    #[test]
    fn try_write_new_temp_stays_inside_root_for_root_level_dest() {
        let t = transport();
        let cmd = SshTransport::write_new_cmd(t.root(), Path::new("files"), IMMUTABLE_RECORD_MODE);
        assert!(
            cmd.contains("mktemp '/srv/app/.files.tmp.XXXXXX'"),
            "temp for a root-level destination must stay inside the root, got: {cmd}"
        );
        assert!(
            !cmd.contains("/srv.files.tmp."),
            "temp must not escape the managed root, got: {cmd}"
        );
    }

    #[test]
    fn try_write_new_sidecar_is_perl_native_and_holds_flock() {
        let tr = transport();
        let cmd =
            tr.try_write_new_sidecar_cmd(Path::new("state/operation.lock"), IMMUTABLE_RECORD_MODE);
        assert!(
            !cmd.contains("exec"),
            "the sidecar flock must survive to process exit: the perl must not exec"
        );
        assert!(
            cmd.contains("<STDIN"),
            "the perl-native acquire must read the payload from STDIN, got: {cmd}"
        );
        assert!(
            cmd.contains("link("),
            "the perl-native acquire must install via link(2), got: {cmd}"
        );
        assert!(
            cmd.contains("flock($fh"),
            "the perl-native acquire must hold the flock loop, got: {cmd}"
        );
        // Verify the command is the sidecar-wrapped perl, not the ordinary shell write_new.
        assert!(
            cmd.contains("operation.lock.mutex"),
            "the sidecar command must reference the mutex file, got: {cmd}"
        );
        assert!(
            cmd.contains("operation.lock"),
            "the sidecar command must reference the lock file, got: {cmd}"
        );
        // Ensure the exit-code protocol parity is preserved (conflict and preinstall).
        assert!(
            cmd.contains(&SSH_TWRITE_CONFLICT_EXIT.to_string()),
            "the sidecar command must encode the conflict exit code, got: {cmd}"
        );
        assert!(
            cmd.contains(&SSH_TWRITE_PREINSTALL_EXIT.to_string()),
            "the sidecar command must encode the preinstall exit code, got: {cmd}"
        );
        // Ordinary (non-lock) writes keep the shell implementation — they must not go through the sidecar perl.
        let ordinary = SshTransport::write_new_cmd(
            tr.root(),
            Path::new("state/other.json"),
            IMMUTABLE_RECORD_MODE,
        );
        assert!(
            !ordinary.contains("operation.lock.mutex"),
            "ordinary writes must not be sidecar-wrapped"
        );
        assert!(
            ordinary.contains("mktemp"),
            "ordinary writes retain mktemp-based shell implementation, got: {ordinary}"
        );
        // New deadline policy: shared prelude uses monotonic deadline, EINTR retry,
        // and distinguishes contention from other errno.
        assert!(
            cmd.contains("while (!flock($fh"),
            "sidecar flock must use deadline while loop, got: {cmd}"
        );
        assert!(
            cmd.contains("clock_gettime(CLOCK_MONOTONIC)"),
            "sidecar flock must use monotonic clock, got: {cmd}"
        );
        assert!(
            cmd.contains("usleep"),
            "sidecar flock must use usleep with bounded interval, got: {cmd}"
        );
        assert!(
            cmd.contains("EINTR"),
            "sidecar flock must handle EINTR, got: {cmd}"
        );
    }

    #[test]
    fn sidecar_flock_prelude_contains_expected_branches() {
        let prelude =
            sidecar_flock_prelude(SIDECAR_FLOCK_DEADLINE_SECS, SIDECAR_FLOCK_INTERVAL_SECS);
        assert!(prelude.contains("use Fcntl qw(:flock)"), "missing Fcntl");
        assert!(
            prelude.contains("use Errno qw(EINTR EAGAIN EWOULDBLOCK)"),
            "missing Errno"
        );
        assert!(
            prelude.contains("use Time::HiRes qw(clock_gettime usleep CLOCK_MONOTONIC)"),
            "missing Time::HiRes"
        );
        assert!(
            prelude.contains("clock_gettime(CLOCK_MONOTONIC)"),
            "missing deadline"
        );
        assert!(
            prelude.contains("while (!flock($fh, LOCK_EX | LOCK_NB))"),
            "missing while flock"
        );
        assert!(
            prelude.contains("next if $errno == EINTR"),
            "missing EINTR retry"
        );
        assert!(
            prelude.contains("sidecar flock failed"),
            "missing non-contention die"
        );
        assert!(
            prelude.contains("EAGAIN") && prelude.contains("EWOULDBLOCK"),
            "missing contention check"
        );
        assert!(
            prelude.contains("sidecar contended"),
            "missing contended die"
        );
        assert!(prelude.contains("usleep"), "missing usleep");
        // test-only contention signal: env-gated (inert in production), fires
        // exactly once after the first confirmed EWOULDBLOCK
        assert!(
            prelude.contains("DEPLOY_TEST_CONTENDED_FD"),
            "missing test-only contention signal gate"
        );
        assert!(
            prelude.contains("CONTENDED"),
            "missing test-only contention signal"
        );
        // production constants
        assert!(
            prelude.contains("2"),
            "deadline 2.0 missing, got: {prelude}"
        );
        assert!(
            prelude.contains("0.005"),
            "interval 0.005 missing, got: {prelude}"
        );
        // parameterized variant
        let short = sidecar_flock_prelude(0.05, 0.005);
        assert!(
            short.contains("0.05"),
            "short deadline not embedded, got: {short}"
        );
    }

    #[test]
    fn sidecar_flock_prelude_all_builders_share_deadline_policy() {
        let remove = remove_file_if_sidecar_cmd(
            Path::new("/srv/app"),
            &RootedRelativePath::parse(Path::new("state/operation.lock.mutex")).unwrap(),
            &RootedRelativePath::parse(Path::new("state/operation.lock")).unwrap(),
            "exp",
        );
        let recover = recover_sidecar_cmd(
            Path::new("/srv/app"),
            &RootedRelativePath::parse(Path::new("state/operation.lock.mutex")).unwrap(),
            &RootedRelativePath::parse(Path::new("state/operation.lock")).unwrap(),
            "obs",
            "new",
        );
        let tr = transport();
        let create =
            tr.try_write_new_sidecar_cmd(Path::new("state/operation.lock"), IMMUTABLE_RECORD_MODE);
        for (name, cmd) in [
            ("remove", remove),
            ("recover", recover),
            ("create-new", create),
        ] {
            assert!(
                cmd.contains("while (!flock($fh"),
                "{name} missing while loop"
            );
            assert!(
                cmd.contains("clock_gettime(CLOCK_MONOTONIC)"),
                "{name} missing monotonic clock"
            );
            assert!(cmd.contains("EINTR"), "{name} missing EINTR");
            assert!(
                cmd.contains("EAGAIN") && cmd.contains("EWOULDBLOCK"),
                "{name} missing EAGAIN/EWOULDBLOCK"
            );
            assert!(
                cmd.contains("sidecar flock failed"),
                "{name} missing flock failed"
            );
            assert!(
                cmd.contains("sidecar contended"),
                "{name} missing contended"
            );
            assert!(cmd.contains("usleep"), "{name} missing usleep");
            // the old bounded-retry loop is gone (flock part); the create-new tmp-name
            // allocation loop is a different O_EXCL concern and is intentionally kept.
            // So we don't assert absence of "for (1..32)" globally.
        }
        // The tmp-name O_EXCL allocation loop in create-new is still present.
        let tr2 = transport();
        let create2 =
            tr2.try_write_new_sidecar_cmd(Path::new("state/operation.lock"), IMMUTABLE_RECORD_MODE);
        assert!(
            create2.contains("sysopen($tfh"),
            "create-new must retain tmp sysopen loop"
        );
        assert!(
            create2.contains("O_EXCL"),
            "create-new must retain O_EXCL tmp allocation"
        );
    }

    // ------------------------------------------------------------------
    // Synchronized flock-contention tests: process scheduling is exercised
    // with DETERMINISTIC synchronization — a real OS pipe handshake — never
    // elapsed-time guesses. The old `sidecar_flock_prelude_runtime_with_
    // short_deadline` proptest slept a holder thread and compared wall
    // clocks against a 50 ms deadline, which flaked under parallel load.
    // The input space here is three discrete concurrency states, so these
    // are plain deterministic `#[test]`s: the sidecar reports its FIRST
    // confirmed EWOULDBLOCK through the prelude's env-gated
    // `DEPLOY_TEST_CONTENDED_FD` signal, the parent is signal-driven off
    // that pipe, and every assertion checks a STATE TRANSITION (deadline
    // error vs success) — never an elapsed-millisecond comparison. The pure
    // prelude-generation proptests stay.
    // ------------------------------------------------------------------

    /// The flock contention window the synchronized tests exercise (passed as
    /// the prelude's deadline AND the sidecar's own contention window): 500 ms.
    /// The tests assert only the state transitions, never elapsed
    /// milliseconds, so this needn't match the 2 s production constant; the
    /// outer harness cap below is meaningfully longer.
    const SIDECAR_FLOCK_TEST_DEADLINE: Duration = Duration::from_millis(500);

    /// The outer cap on every parent-side bounded wait (contention signal,
    /// child exit): meaningfully longer than [`SIDECAR_FLOCK_TEST_DEADLINE`],
    /// so the outcome is decided by the sidecar's OWN deadline — a harness
    /// timeout would be a test failure, never the thing under test. 5 s also
    /// leaves room for a wedged child to be killed and reaped.
    const SIDECAR_FLOCK_TEST_OUTER_TIMEOUT: Duration = Duration::from_secs(5);

    /// The typed sidecar exit contract, classified from the child's
    /// stdout/stderr per the real sidecar protocol (`OK` / `sidecar contended`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum SidecarErrorCode {
        /// Exit 0 with `OK` on stdout: the sidecar acquired the flock.
        Success,
        /// Nonzero exit with `sidecar contended` on stderr: the deadline
        /// elapsed while the flock stayed contended.
        LockDeadlineExceeded,
    }

    /// Harness-side failure; every variant names the state transition that
    /// did not happen (the tests assert transitions, never timings).
    #[derive(Debug)]
    // The variant payloads exist for `{:?}` diagnostics in assertion
    // messages; equality is by variant, so the fields are never destructured.
    #[allow(dead_code)]
    enum TestError {
        /// The outer cap elapsed before the child reported its contention
        /// signal.
        ContentionSignalTimeout,
        /// The child exited without ever writing the contention signal
        /// (EOF on the pipe, no data).
        ChildExitedWithoutSignal,
        /// The child wrote something else where `CONTENDED` was expected.
        WrongContentionSignal(String),
        /// The outer cap elapsed while the child still ran; the harness
        /// killed and reaped it.
        ChildExitTimeout,
        /// The uncontended path produced an outcome other than `Success`.
        UnexpectedSidecarCode(SidecarErrorCode),
        /// The child exited with an outcome the contract does not cover
        /// (nonzero without `sidecar contended`, or success without `OK`).
        UnexpectedChildExit {
            status: std::process::ExitStatus,
            stderr: String,
        },
        Io(std::io::Error),
    }

    /// Equality by variant only: the tests compare an outcome against
    /// `Ok(SidecarErrorCode::…)`, never the payloads of two errors, and
    /// `std::io::Error` no longer carries a `PartialEq` impl on this
    /// toolchain. `std::mem::discriminant` keeps the comparison meaningful
    /// exactly where it is used.
    impl PartialEq for TestError {
        fn eq(&self, other: &Self) -> bool {
            std::mem::discriminant(self) == std::mem::discriminant(other)
        }
    }

    impl From<std::io::Error> for TestError {
        fn from(err: std::io::Error) -> Self {
            TestError::Io(err)
        }
    }

    type TestOutcome = std::result::Result<SidecarErrorCode, TestError>;

    /// A Rust-side exclusive flock holder: opens the lock path read-write
    /// (creating it like the real sidecar's mutex file) and takes `LOCK_EX`;
    /// the `Drop` releases the lock deterministically — including on a test
    /// panic — instead of a `sleep`-timed release.
    struct HolderGuard {
        file: std::fs::File,
    }

    /// Acquire the flock on `path` exclusively, creating the file if needed.
    fn acquire_exclusive_lock(path: &Path) -> HolderGuard {
        use std::os::unix::io::AsRawFd;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false) // the mutex file's (empty) content is untouched
            .open(path)
            .unwrap_or_else(|e| panic!("open lock path {path:?} for the holder: {e}"));
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        assert_eq!(
            rc,
            0,
            "flock LOCK_EX on {path:?} failed: {}",
            std::io::Error::last_os_error()
        );
        HolderGuard { file }
    }

    impl Drop for HolderGuard {
        fn drop(&mut self) {
            use std::os::unix::io::AsRawFd;
            // Unlock is best-effort (the fd closes right after anyway).
            let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }

    /// An instrumented sidecar child plus the read end of the contention
    /// pipe its perl holds (via `DEPLOY_TEST_CONTENDED_FD`, a raw `pipe(2)`
    /// write end inherited without `FD_CLOEXEC`).
    struct InstrumentedSidecar {
        child: std::process::Child,
        contention_rx: std::fs::File,
    }

    /// The full `perl -e` script the synchronized tests run: the shared
    /// prelude (test deadline, production interval) preceded by the caller
    /// side's `$fh` open and followed by the `OK` success line — the shape
    /// of every real sidecar command.
    fn sidecar_flock_script(deadline: Duration) -> String {
        let prelude = sidecar_flock_prelude(deadline.as_secs_f64(), SIDECAR_FLOCK_INTERVAL_SECS);
        format!(
            "open my $fh, \"+<\", $ARGV[0] or die \"open sidecar: $!\"; {prelude} print \"OK\\n\";"
        )
    }

    /// Spawn the instrumented sidecar: `perl -e <prelude-script> -- <path>`
    /// with `DEPLOY_TEST_CONTENDED_FD` set to a fresh pipe's write end. The
    /// raw `pipe(2)` fd carries no `FD_CLOEXEC`, so it survives the exec into
    /// perl. The parent closes its write-end copy immediately after the
    /// spawn, so the read end sees EOF the moment the child exits; the child
    /// writes `CONTENDED` to that fd exactly once (the prelude deletes the
    /// env key after the first signal).
    fn spawn_instrumented_sidecar(path: &Path, deadline: Duration) -> InstrumentedSidecar {
        use std::os::unix::io::FromRawFd;
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(
            rc,
            0,
            "pipe() for the contention handshake failed: {}",
            std::io::Error::last_os_error()
        );
        let (read_fd, write_fd) = (fds[0], fds[1]);
        let child = std::process::Command::new("perl")
            .arg("-e")
            .arg(sidecar_flock_script(deadline))
            .arg("--")
            .arg(path)
            .env("DEPLOY_TEST_CONTENDED_FD", write_fd.to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn();
        let child = match child {
            Ok(child) => child,
            Err(err) => {
                // Do not leak the pipe on a spawn failure.
                unsafe {
                    libc::close(read_fd);
                    libc::close(write_fd);
                }
                panic!("spawn instrumented sidecar: {err}");
            }
        };
        unsafe { libc::close(write_fd) };
        let contention_rx = unsafe { std::fs::File::from_raw_fd(read_fd) };
        InstrumentedSidecar {
            child,
            contention_rx,
        }
    }

    impl InstrumentedSidecar {
        /// Block until the child reports its first CONFIRMED contention (the
        /// prelude's env-gated signal, fired exactly once after the first
        /// `EWOULDBLOCK`), or until `outer` elapses. `poll(2)` on the pipe
        /// read end makes the wait signal-driven: the parent sleeps in the
        /// kernel until the child writes — never on a timer.
        fn read_confirmed_contention(&self, outer: Duration) -> std::result::Result<(), TestError> {
            use std::io::{BufRead, BufReader};
            use std::os::unix::io::AsRawFd;
            let timeout_ms = i32::try_from(outer.as_millis()).unwrap_or(i32::MAX);
            let mut pfd = libc::pollfd {
                fd: self.contention_rx.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, timeout_ms) };
            if rc == 0 {
                return Err(TestError::ContentionSignalTimeout);
            }
            if rc < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            if (pfd.revents & libc::POLLIN) == 0 {
                // HUP/ERR with no data: the child exited without ever
                // confirming contention.
                return Err(TestError::ChildExitedWithoutSignal);
            }
            let mut line = String::new();
            // dup the read end so the read consumes only the local clone.
            let mut rx = BufReader::new(self.contention_rx.try_clone()?);
            rx.read_line(&mut line)?;
            if line.trim() != "CONTENDED" {
                return Err(TestError::WrongContentionSignal(line));
            }
            Ok(())
        }

        /// Wait for the child with a hard `outer` cap, then classify its exit
        /// against the sidecar contract (see [`bounded_wait_for_child`]).
        fn wait_with_outer_timeout(&mut self, outer: Duration) -> TestOutcome {
            bounded_wait_for_child(&mut self.child, outer)
        }
    }

    /// Bounded, signal-driven wait for a sidecar child: the child closes its
    /// stdout on exit, so `poll(2)` on the stdout pipe fires exactly when the
    /// process is gone — on macOS a closed pipe write end is reported as
    /// `POLLIN|POLLHUP` (never as a bare `POLLHUP` with `events: 0`, which
    /// does not wake at all); a still-open write end with no data never
    /// wakes the parent. `wait()` then reaps immediately and the (now-EOF)
    /// streams are drained. No timer-based polling, no unbounded `wait()`.
    fn bounded_wait_for_child(child: &mut std::process::Child, outer: Duration) -> TestOutcome {
        use std::os::unix::io::AsRawFd;
        let stdout_fd = child
            .stdout
            .as_ref()
            .expect("sidecar stdout must be piped")
            .as_raw_fd();
        let timeout_ms = i32::try_from(outer.as_millis()).unwrap_or(i32::MAX);
        let mut pfd = libc::pollfd {
            fd: stdout_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, timeout_ms) };
        if rc == 0 {
            // Wedged child: kill and reap so the suite leaks nothing.
            let _ = child.kill();
            let _ = child.wait();
            return Err(TestError::ChildExitTimeout);
        }
        if rc < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let status = child.wait().map_err(TestError::Io)?;
        let (stdout, stderr) = drain_output(child);
        classify_sidecar_exit(status, stdout, stderr)
    }

    /// Drain the child's (now-EOF) stdout/stderr: the child has exited, so
    /// both pipes are already closed by the kernel — no locking dance needed,
    /// and the per-sidecar output is a few bytes, far below pipe capacity.
    fn drain_output(child: &mut std::process::Child) -> (String, String) {
        use std::io::Read;
        let mut stdout = String::new();
        if let Some(mut so) = child.stdout.take() {
            let _ = so.read_to_string(&mut stdout);
        }
        let mut stderr = String::new();
        if let Some(mut se) = child.stderr.take() {
            let _ = se.read_to_string(&mut stderr);
        }
        (stdout, stderr)
    }

    /// Classify the child's exit against the sidecar protocol.
    fn classify_sidecar_exit(
        status: std::process::ExitStatus,
        stdout: String,
        stderr: String,
    ) -> TestOutcome {
        if status.success() && stdout.trim() == "OK" {
            return Ok(SidecarErrorCode::Success);
        }
        if !status.success() && stderr.contains("sidecar contended") {
            return Ok(SidecarErrorCode::LockDeadlineExceeded);
        }
        Err(TestError::UnexpectedChildExit { status, stderr })
    }

    /// The uncontended path (test 1): the PRODUCTION prelude — the
    /// `DEPLOY_TEST_CONTENDED_FD` env is explicitly removed, so the signal
    /// block is inert — against a fresh lock path, which is immediately
    /// acquirable.
    fn run_sidecar_with_deadline(
        path: &Path,
        deadline: Duration,
    ) -> std::result::Result<(), TestError> {
        let mut child = std::process::Command::new("perl")
            .arg("-e")
            .arg(sidecar_flock_script(deadline))
            .arg("--")
            .arg(path)
            .env_remove("DEPLOY_TEST_CONTENDED_FD")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(TestError::Io)?;
        match bounded_wait_for_child(&mut child, SIDECAR_FLOCK_TEST_OUTER_TIMEOUT) {
            Ok(SidecarErrorCode::Success) => Ok(()),
            Ok(other) => Err(TestError::UnexpectedSidecarCode(other)),
            Err(err) => Err(err),
        }
    }

    /// Test 1 (uncontended): a fresh lock path with NO holder — the sidecar
    /// acquires immediately and reports OK.
    #[test]
    fn sidecar_flock_uncontended_acquisition_succeeds() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let lock_path = dir.path().join("sidecar.flock");
        std::fs::write(&lock_path, b"").unwrap();
        let result = run_sidecar_with_deadline(&lock_path, SIDECAR_FLOCK_TEST_DEADLINE);
        assert!(
            result.is_ok(),
            "an uncontended fresh lock must be acquired immediately, got: {result:?}"
        );
    }

    /// Test 2 (confirmed contention, holder RETAINED): the sidecar must
    /// report its production deadline error (`sidecar contended`). The holder
    /// is released only during cleanup, AFTER the assertion — so the
    /// assertion runs against a still-held lock; the guard also drops on a
    /// panic.
    #[test]
    fn sidecar_flock_contention_times_out_while_retained() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let lock_path = dir.path().join("sidecar.flock");
        let holder = acquire_exclusive_lock(&lock_path);
        let mut sidecar = spawn_instrumented_sidecar(&lock_path, SIDECAR_FLOCK_TEST_DEADLINE);
        sidecar
            .read_confirmed_contention(SIDECAR_FLOCK_TEST_OUTER_TIMEOUT)
            .expect("child must report confirmed contention");
        let outcome = sidecar.wait_with_outer_timeout(SIDECAR_FLOCK_TEST_OUTER_TIMEOUT);
        assert_eq!(
            outcome,
            Ok(SidecarErrorCode::LockDeadlineExceeded),
            "a retained lock must drive the sidecar to its deadline error"
        );
        drop(holder);
    }

    /// Test 3 (confirmed contention, holder RELEASED): the sidecar must
    /// acquire the freed lock and report OK.
    #[test]
    fn sidecar_flock_contention_succeeds_after_release() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let lock_path = dir.path().join("sidecar.flock");
        let holder = acquire_exclusive_lock(&lock_path);
        let mut sidecar = spawn_instrumented_sidecar(&lock_path, SIDECAR_FLOCK_TEST_DEADLINE);
        sidecar
            .read_confirmed_contention(SIDECAR_FLOCK_TEST_OUTER_TIMEOUT)
            .expect("child must report confirmed contention");
        drop(holder); // release happens BEFORE the wait
        let outcome = sidecar.wait_with_outer_timeout(SIDECAR_FLOCK_TEST_OUTER_TIMEOUT);
        assert_eq!(
            outcome,
            Ok(SidecarErrorCode::Success),
            "the released lock must let the sidecar acquire and report OK"
        );
    }

    /// Execute `sh -c "$command"` with `stdin` piped to the shell — the
    /// payload the remote script's `cat > "$tmp"` consumes, exactly as the
    /// transport pipes it through the ssh child (never embedded in the
    /// command string).
    fn run_sh_stdin(command: &str, stdin: &[u8]) -> std::process::Output {
        use std::io::Write;
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sh -c");
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(stdin)
            .expect("write payload");
        child.wait_with_output().expect("wait sh -c")
    }

    /// Run `sh -c "$command"` but return `None` if it has not exited within
    /// `secs` (the child is killed and reaped). A blocking primitive under test
    /// then FAILS the test instead of hanging the suite forever.
    fn run_sh_with_timeout(command: &str, secs: u64) -> Option<std::process::Output> {
        use std::io::Read;
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn sh -c");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        loop {
            match child.try_wait().expect("try_wait") {
                Some(status) => {
                    let mut stdout = Vec::new();
                    let mut stderr = Vec::new();
                    if let Some(mut s) = child.stdout.take() {
                        s.read_to_end(&mut stdout).ok();
                    }
                    if let Some(mut e) = child.stderr.take() {
                        e.read_to_end(&mut stderr).ok();
                    }
                    return Some(std::process::Output {
                        status,
                        stdout,
                        stderr,
                    });
                }
                None => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return None;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(25));
                }
            }
        }
    }

    /// Create a FIFO with the POSIX `mkfifo` utility (portable on GNU and BSD).
    fn mkfifo(path: &Path) {
        let status = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo {path:?} must succeed");
    }

    /// Resolve the REAL `perl` from the test process's own `PATH`, before a
    /// fake one is prepended.
    fn real_perl() -> std::path::PathBuf {
        for dir in std::env::var("PATH").unwrap_or_default().split(':') {
            let cand = Path::new(dir).join("perl");
            if cand.is_file() {
                return cand;
            }
        }
        panic!("no `perl` on PATH; the far-side scripts require perl");
    }

    /// The literal hook tokens embedded as comments in [`PERL_FSYNC_FILE`] and
    /// [`PERL_FSYNC_DIR`]. A fake `perl` matches these to fault-inject or
    /// record exactly one fsync kind without disturbing the script's other perl
    /// calls (notably the perl `link(2)` publish).
    const FSYNC_FILE_HOOK: &str = "STORE_SYNC_TEST_FSYNC_FILE";
    const FSYNC_DIR_HOOK: &str = "STORE_SYNC_TEST_FSYNC_DIR";

    /// The body of a fake `perl` that exits `code` when its `-e` program
    /// contains `needle` and otherwise delegates VERBATIM to the real perl.
    fn fake_perl_body(needle: &str, code: i32) -> String {
        let real = real_perl();
        format!(
            "#!/bin/sh\ncase \"$*\" in\n  *{needle}*) echo 'fake perl: faulted {needle}' >&2; exit {code} ;;\n  *) exec {real} \"$@\" ;;\nesac\n",
            needle = needle,
            code = code,
            real = shell_quote(&real.to_string_lossy()),
        )
    }

    /// Install a fake `perl` on `bin` that faults on `needle` (see
    /// [`fake_perl_body`]).
    fn install_fake_perl(bin: &Path, needle: &str, code: i32) {
        std::fs::create_dir_all(bin).unwrap();
        let p = bin.join("perl");
        crate::test_support::write_executable(&p, fake_perl_body(needle, code).as_bytes());
    }

    // The old temp name derived from the LOCAL pid + a per-process counter, so
    // two controllers on different hosts could share a pid and collide on the
    // same remote temp name; `printf ... > tmp` then truncated the collided
    // path, and the no-clobber publish could install the WRONG payload. With
    // remote `mktemp` allocation, concurrent controllers can never be handed
    // the same name: exactly one install wins, every loser reports failure,
    // and no reader ever observes torn/mixed content.
    #[test]
    fn try_write_new_concurrent_controllers_never_collide() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // SLOW-test gate: spawns many concurrent shells and exceeds the fast
        // suite's budget; run it under the full suites.
        if !crate::test_support::slow_tests_enabled() {
            eprintln!("skipped: slow test — set STORE_SYNC_FULL_TESTS=1 to run");
            return;
        }

        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let root = dir.path().to_path_buf();
        let rel = Path::new("state/op.json");
        let dest = root.join(rel);
        let payloads: Vec<String> = (0..8)
            .map(|i| format!("payload-{i}:{}", "x".repeat(64 + i * 7)))
            .collect();

        std::thread::scope(|s| {
            let done = Arc::new(AtomicBool::new(false));

            // Writers: every controller runs the exact generated command for
            // the same destination with a different payload.
            let mut writers = Vec::new();
            for payload in &payloads {
                let cmd = SshTransport::write_new_cmd(&root, rel, IMMUTABLE_RECORD_MODE);
                let payload = payload.clone();
                writers.push(s.spawn(move || run_sh_stdin(&cmd, payload.as_bytes())));
            }

            // Readers: while the writers race, any observation of the
            // destination must be a complete payload — never torn, empty, or
            // mixed. Dot-prefixed temp names are what listing-based observers
            // skip, exactly as in LocalTransport::try_write_new.
            let done2 = done.clone();
            let parent = dest.parent().unwrap().to_path_buf();
            let payloads2 = payloads.clone();
            let dest3 = dest.clone();
            s.spawn(move || {
                while !done2.load(Ordering::SeqCst) {
                    let Ok(entries) = std::fs::read_dir(&parent) else {
                        continue;
                    };
                    for e in entries.flatten() {
                        let name = e.file_name().to_string_lossy().into_owned();
                        if name != "op.json" {
                            assert!(
                                name.starts_with('.'),
                                "observer must only ever see the final name or dot-prefixed temps, got {name}"
                            );
                            continue;
                        }
                        let data = std::fs::read(&dest3).unwrap_or_default();
                        assert!(
                            payloads2.iter().any(|p| p.as_bytes() == data),
                            "reader observed a torn/mixed/partial record: {:?}",
                            String::from_utf8_lossy(&data)
                        );
                    }
                }
            });

            let results: Vec<std::process::Output> =
                writers.into_iter().map(|h| h.join().unwrap()).collect();
            done.store(true, Ordering::SeqCst);

            // Exactly one controller installs; every other reports failure.
            let wins = results.iter().filter(|r| r.status.success()).count();
            assert_eq!(
                wins, 1,
                "exactly one concurrent controller must win the no-clobber install"
            );
            let data = std::fs::read(&dest).unwrap();
            assert!(
                payloads.iter().any(|p| p.as_bytes() == data),
                "installed content must be one complete payload, got {:?}",
                String::from_utf8_lossy(&data)
            );
        });
    }

    // Recovery: a controller crashed AFTER `ln` but BEFORE `rm -f "$tmp"`,
    // leaving the destination installed plus a stale hard-linked temp (nlink
    // 2) in the same name space. A fresh invocation must allocate a DIFFERENT
    // temp name, never touch the stale temp or the installed destination, and
    // remove only its own temp.
    #[test]
    fn try_write_new_recovers_from_stale_hardlinked_temp() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let root = dir.path().to_path_buf();
        let rel = Path::new("state/op.json");
        let dest = root.join(rel);
        let parent = dest.parent().unwrap();

        // First invocation: installs the record and cleans up its own temp.
        let cmd1 = SshTransport::write_new_cmd(&root, rel, IMMUTABLE_RECORD_MODE);
        let out1 = run_sh_stdin(&cmd1, b"gen-1");
        assert!(
            out1.status.success(),
            "first install failed: {}",
            String::from_utf8_lossy(&out1.stderr)
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"gen-1");
        let temps = || {
            std::fs::read_dir(parent)
                .unwrap()
                .flatten()
                .filter(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    n != "op.json"
                })
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        };
        assert!(temps().is_empty(), "first invocation left temps behind");

        // Crash AFTER `ln` but BEFORE `rm -f "$tmp"`: the stale temp is a
        // second hard link to the installed inode (nlink 2), sitting in the
        // same name space a future mktemp draws from.
        let stale = parent.join(".op.json.tmp.crashed");
        std::fs::hard_link(&dest, &stale).unwrap();
        let stale_meta = std::fs::metadata(&stale).unwrap();
        assert_eq!(
            stale_meta.nlink(),
            2,
            "stale temp must hard-link the installed inode"
        );

        // Fresh invocation with a different payload: must fail (already
        // exists), leave dest and stale untouched, and clean up its own temp.
        let cmd2 = SshTransport::write_new_cmd(&root, rel, IMMUTABLE_RECORD_MODE);
        let out2 = run_sh_stdin(&cmd2, b"gen-2");
        assert_eq!(
            out2.status.code(),
            Some(SSH_TWRITE_CONFLICT_EXIT),
            "reinstall after a winner must exit the reserved conflict code"
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"gen-1",
            "installed destination must stay intact"
        );
        let stale_after = std::fs::metadata(&stale).unwrap();
        assert_eq!(
            stale_after.nlink(),
            2,
            "stale temp must not have been truncated or removed"
        );
        assert_eq!(
            std::fs::read(&stale).unwrap(),
            b"gen-1",
            "stale temp content must be untouched"
        );
        let left = temps();
        assert_eq!(
            left,
            vec![stale.file_name().unwrap().to_string_lossy().into_owned()],
            "only the stale temp may remain; the fresh invocation's own temp must be removed"
        );
    }

    /// F3, ORDER: the remote script implements the canonical seven-step
    /// sequence — the FINAL MODE is chmod'd onto the temp BEFORE the portable
    /// FILE fsync, which is before the no-clobber install, and the
    /// PARENT-DIRECTORY fsync (also the portable perl primitive) runs after the
    /// install and is never swallowed (`2>/dev/null` is gone).
    ///
    /// Pre-fix the script used `sync "$tmp"` / `sync <dir>`; the fix uses the
    /// perl `fsync(2)` the [`PERL_FSYNC_FILE`]/[`PERL_FSYNC_DIR`] hooks are
    /// named for. This test therefore FAILED pre-fix at
    /// "the file fsync step must be present".
    #[test]
    fn try_write_new_cmd_final_chmod_and_portable_fsyncs() {
        let t = transport();
        let cmd = SshTransport::write_new_cmd(t.root(), Path::new("state/operation.lock"), 0o640);
        // Step 3 (final chmod) BEFORE step 4 (file fsync) BEFORE step 5
        // (no-replace install) BEFORE step 7 (parent-dir fsync): the published
        // inode carries the caller's mode, never the remote umask, and the
        // durability steps are the PORTABLE perl `fsync(2)`, never the
        // GNU-only `sync <operand>` that is a silent no-op on BSD/macOS.
        let chmod_pos = cmd
            .find("chmod 640 \"$tmp\"")
            .expect("the final chmod step must be present");
        let file_fsync_pos = cmd
            .find(PERL_FSYNC_FILE)
            .expect("the portable FILE fsync step must be present");
        let publish_pos = cmd
            .find("link($ARGV[0], $ARGV[1])")
            .expect("the no-replace install must be present");
        let dir_fsync_pos = cmd
            .find(PERL_FSYNC_DIR)
            .expect("the portable PARENT-DIRECTORY fsync step must be present");
        assert!(
            chmod_pos < file_fsync_pos
                && file_fsync_pos < publish_pos
                && publish_pos < dir_fsync_pos,
            "step order must be chmod -> file fsync -> install -> parent fsync, got: {cmd}"
        );
        // The GNU-only operand-taking `sync` is GONE, and the parent fsync is
        // never swallowed.
        assert!(
            !cmd.contains("sync \"$tmp\""),
            "the GNU-only `sync <file>` must be gone, got: {cmd}"
        );
        assert!(
            !cmd.contains("sync '/srv/app/state'"),
            "the GNU-only `sync <dir>` must be gone, got: {cmd}"
        );
        assert!(
            !cmd.contains("2>/dev/null"),
            "the parent fsync failure must never be swallowed, got: {cmd}"
        );
    }

    /// The final chmod step is EXECUTED before the install: under a
    /// restrictive umask the published record still carries the intended
    /// mode, never the umask-derived one.
    #[test]
    fn try_write_new_installs_final_mode_not_umask() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let root = dir.path().to_path_buf();
        let rel = Path::new("state/op.json");
        let cmd = SshTransport::write_new_cmd(&root, rel, 0o644);
        // `mktemp` under umask 077 creates the temp 0600; without the chmod
        // step the installed record would keep 0600. The final chmod must
        // make it 0644 before the install. The payload is piped on stdin,
        // exactly as the transport delivers it.
        let out = run_sh_stdin(&format!("umask 077; {cmd}"), b"payload-data");
        assert!(
            out.status.success(),
            "install failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let meta = std::fs::metadata(root.join(rel)).unwrap();
        assert_eq!(
            meta.mode() & 0o7777,
            0o644,
            "the published record must carry the intended final mode, not the umask"
        );
        assert_eq!(std::fs::read(root.join(rel)).unwrap(), b"payload-data");
    }

    /// F3, PROPAGATION: a FAILED parent-directory fsync is a propagated error,
    /// never a swallowed success. The fake perl exits 9 on the
    /// [`PERL_FSYNC_DIR`] hook; the FILE fsync and the perl `link(2)` publish
    /// still run (the fake delegates them to the real perl), so the record is
    /// fully installed and the command's exit status is EXACTLY the failed
    /// durability step.
    ///
    /// Pre-fix there was no perl dir-fsync hook: the parent durability step was
    /// the operand-taking `sync <dir>`, which the fake perl never saw, so the
    /// command exited 0 and this test FAILED with `Some(0)` instead of `Some(9)`.
    #[test]
    fn try_write_new_dir_fsync_failure_propagates() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let root = dir.path().to_path_buf();
        let rel = Path::new("state/op.json");
        let cmd = SshTransport::write_new_cmd(&root, rel, IMMUTABLE_RECORD_MODE);
        let fakebin = dir.path().join("fakebin");
        install_fake_perl(&fakebin, FSYNC_DIR_HOOK, 9);
        let out = run_sh_stdin(
            &format!(
                "PATH={fake}:$PATH; {cmd}",
                fake = shell_quote(&fakebin.to_string_lossy())
            ),
            b"payload-data",
        );
        assert_eq!(
            out.status.code(),
            Some(9),
            "the parent-directory fsync failure must propagate (never swallowed)"
        );
        // The install itself succeeded (the perl link ran) — the propagated
        // failure is EXACTLY the final durability step, and the record is
        // complete.
        assert_eq!(
            std::fs::read(root.join(rel)).unwrap(),
            b"payload-data",
            "the record must be fully installed before the parent-directory fsync"
        );
    }

    /// F3, FAIL-CLOSED: a failure of the FILE fsync (step 4) aborts BEFORE the
    /// publish — the command exits [`SSH_TWRITE_PREINSTALL_EXIT`] and NOTHING is
    /// installed, because the record's bytes were never made durable.
    ///
    /// Pre-fix there was no perl file-fsync hook: the GNU-only `sync "$tmp"`
    /// succeeded (or silently no-opped), the publish ran, and this test FAILED
    /// with `Some(0)` instead of `Some(1)`.
    #[test]
    fn try_write_new_file_fsync_failure_aborts_before_publish() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let root = dir.path().to_path_buf();
        let rel = Path::new("state/op.json");
        let cmd = SshTransport::write_new_cmd(&root, rel, IMMUTABLE_RECORD_MODE);
        let fakebin = dir.path().join("fakebin");
        install_fake_perl(&fakebin, FSYNC_FILE_HOOK, 9);
        let out = run_sh_stdin(
            &format!(
                "PATH={fake}:$PATH; {cmd}",
                fake = shell_quote(&fakebin.to_string_lossy())
            ),
            b"payload-data",
        );
        assert_eq!(
            out.status.code(),
            Some(SSH_TWRITE_PREINSTALL_EXIT),
            "a failed file fsync is a pre-install failure, never a verdict"
        );
        assert!(
            !root.join(rel).exists(),
            "nothing may be published when the file fsync failed"
        );
    }

    /// The fault-injection hooks the tests key on are actually carried by the
    /// fsync snippets, and the two snippets are DISTINCT (a fake perl must be
    /// able to fault the file fsync without touching the directory fsync and
    /// vice versa).
    #[test]
    fn perl_fsync_snippets_carry_their_distinct_hooks() {
        assert!(
            PERL_FSYNC_FILE.contains(FSYNC_FILE_HOOK),
            "PERL_FSYNC_FILE must carry {FSYNC_FILE_HOOK}"
        );
        assert!(
            PERL_FSYNC_DIR.contains(FSYNC_DIR_HOOK),
            "PERL_FSYNC_DIR must carry {FSYNC_DIR_HOOK}"
        );
        assert!(
            !PERL_FSYNC_FILE.contains(FSYNC_DIR_HOOK) && !PERL_FSYNC_DIR.contains(FSYNC_FILE_HOOK),
            "the two fsync snippets must be distinguishable by their hooks"
        );
    }

    /// The no-clobber conflict is reported through the reserved exit code and
    /// NEVER replaces the winner: a second invocation with different content
    /// exits `SSH_TWRITE_CONFLICT_EXIT` and the winner's bytes stay intact.
    #[test]
    fn try_write_new_conflict_exits_reserved_code_and_never_replaces() {
        let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let root = dir.path().to_path_buf();
        let rel = Path::new("state/op.json");
        let cmd1 = SshTransport::write_new_cmd(&root, rel, IMMUTABLE_RECORD_MODE);
        let out1 = run_sh_stdin(&cmd1, b"gen-1");
        assert!(
            out1.status.success(),
            "first install failed: {}",
            String::from_utf8_lossy(&out1.stderr)
        );
        let cmd2 = SshTransport::write_new_cmd(&root, rel, IMMUTABLE_RECORD_MODE);
        let out2 = run_sh_stdin(&cmd2, b"gen-2");
        assert_eq!(
            out2.status.code(),
            Some(SSH_TWRITE_CONFLICT_EXIT),
            "a loser must exit the reserved conflict code"
        );
        assert_eq!(
            std::fs::read(root.join(rel)).unwrap(),
            b"gen-1",
            "the conflict must NEVER replace the winner"
        );
    }

    /// The stage-failure dimension of the ssh protocol: a failure at EVERY
    /// script-failable stage must exit with a code that is NEITHER 0 NOR the
    /// reserved conflict verdict — a pre-install failure or a real publish/
    /// sync failure is a propagated ERROR, never a verdict (the verdict is
    /// ONLY a CONFIRMED EEXIST at the no-clobber publish). `Unlink` is not
    /// script-failable (`rm -f` is best-effort cleanup by design); that crash
    /// point is covered by the local primitive's `FailAt(Unlink)` case and by
    /// `try_write_new_recovers_from_stale_hardlinked_temp`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SshStageFailure {
        /// `mktemp` fails — the temp allocation (step 1).
        CreateTemp,
        /// The payload write fails — a fake `mktemp` hands back an unwritable
        /// path so the `cat > "$tmp"` redirect fails to open (step 2; the
        /// redirect is a shell-level error, so a PATH fake cannot shadow it —
        /// `cat` never runs).
        Write,
        /// `chmod` fails (step 3).
        Chmod,
        /// The FILE fsync fails (step 4) — the portable perl `fsync(2)`, faulted
        /// by a fake `perl` that exits 1 on the [`FSYNC_FILE_HOOK`] token.
        FileFsync,
        /// `ln` fails for a reason OTHER than EEXIST (step 5) — with the
        /// destination ABSENT, so the script must NOT call it a verdict. The
        /// publish is perl `link(2)`, so the stage is faulted by a fake
        /// `perl` that exits 1.
        Publish,
        /// The PARENT-DIRECTORY fsync fails (step 7) — the file fsync passes, the
        /// parent-dir fsync is the propagated failure. Faulted by a fake `perl`
        /// that exits 9 on the [`FSYNC_DIR_HOOK`] token.
        ParentFsync,
    }

    fn ssh_stage_failure() -> impl Strategy<Value = SshStageFailure> {
        prop_oneof![
            Just(SshStageFailure::CreateTemp),
            Just(SshStageFailure::Write),
            Just(SshStageFailure::Chmod),
            Just(SshStageFailure::FileFsync),
            Just(SshStageFailure::Publish),
            Just(SshStageFailure::ParentFsync),
        ]
    }

    proptest! {
        // Bounded cases, fixed seed 0x5EED_5EED (house style), no persistence.
        #![proptest_config(ProptestConfig {
            cases: crate::test_support::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn write_new_cmd_stage_failures_propagate(stage in ssh_stage_failure()) {
            let dir = crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
            let root = dir.path().to_path_buf();
            let rel = Path::new("state/op.json");
            let dest = root.join(rel);
            let cmd = SshTransport::write_new_cmd(&root, rel, IMMUTABLE_RECORD_MODE);
            let fakebin = dir.path().join("fakebin");
            std::fs::create_dir_all(&fakebin).unwrap();

            let (name, body) = match stage {
                SshStageFailure::CreateTemp => ("mktemp", "#!/bin/sh\nexit 1\n".to_string()),
                SshStageFailure::Write => (
                    "mktemp",
                    "#!/bin/sh\nprintf '%s\\n' '/definitely/unwritable/.op.json.tmp.XXXXXX'\n"
                        .to_string(),
                ),
                SshStageFailure::Chmod => ("chmod", "#!/bin/sh\nexit 1\n".to_string()),
                SshStageFailure::FileFsync => {
                    ("perl", fake_perl_body(FSYNC_FILE_HOOK, 1))
                }
                SshStageFailure::Publish => ("perl", fake_perl_body("link(", 1)),
                SshStageFailure::ParentFsync => {
                    ("perl", fake_perl_body(FSYNC_DIR_HOOK, 9))
                }
            };
            let p = fakebin.join(name);
            crate::test_support::write_executable(&p, body.as_bytes());

            let out = run_sh_stdin(
                &format!(
                    "PATH={fake}:$PATH; {cmd}",
                    fake = shell_quote(&fakebin.to_string_lossy())
                ),
                b"payload-data",
            );
            prop_assert_ne!(
                out.status.code(),
                Some(0),
                "the faulted stage must fail the attempt"
            );
            prop_assert_ne!(
                out.status.code(),
                Some(SSH_TWRITE_CONFLICT_EXIT),
                "a stage failure is NEVER the conflict verdict — the verdict is ONLY a confirmed EEXIST, got: {:?}",
                out.status.code()
            );
            match stage {
                SshStageFailure::ParentFsync => {
                    // The install completed; the failure is EXACTLY the final
                    // durability step, and the record is fully written.
                    prop_assert_eq!(
                        std::fs::read(&dest).unwrap(),
                        b"payload-data",
                        "the parent-sync failure must come after a fully-written install"
                    );
                }
                _ => {
                    prop_assert!(
                        !dest.exists(),
                        "a pre-install/publish failure must install nothing"
                    );
                }
            }
        }
    }
}
