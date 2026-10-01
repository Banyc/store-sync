//! THE bounded subprocess runner every ssh operation goes through: hard
//! deadline, kill, and deterministic reap, so no operation can run unbounded
//! after connection establishment.

use crate::env::SysEnv;
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

// Connect timeout in seconds applied to every `ssh` connection (`-o
// ConnectTimeout=N`) and to the `ssh-keyscan` key-pin step (native `-T N`
// plus the runner's process-level deadline, see [`SshRunner`] and
// [`SshTransport::pin_known_hosts`]). A dead or unreachable host must fail
// fast instead of hanging the transport indefinitely; 10s bounds the
// connection phase while leaving slow but reachable hosts (cold VPN routes,
// slow DNS) enough headroom.
pub(crate) const SSH_CONNECT_TIMEOUT_SECS: u64 = 10;

// Deadline in seconds applied by [`SshRunner`] to every ssh operation AFTER
// connection establishment: remote commands ([`SshTransport::run_remote`] /
// [`SshTransport::run_remote_ok`]) and uploads. `-o ConnectTimeout=N` bounds
// ONLY the connection phase, so without this bound a remote command on a hung
// host (stuck filesystem, wedged service) would run indefinitely and hang the
// whole push. 60s is deliberately DISTINCT from the 10s connection bound: a
// slow-but-healthy remote (large upload over a slow link, cold NFS) legitimately
// needs longer than connection establishment once connected. The `ssh-keyscan`
// pin keeps `SSH_CONNECT_TIMEOUT_SECS` (it IS a connection-establishment
// probe), and `Remote::exec` keeps its caller-supplied timeout.
pub(crate) const SSH_COMMAND_TIMEOUT_SECS: u64 = 60;

/// The assumed MINIMUM transfer rate (bytes/sec) used to scale the deadline
/// of a size-known upload ([`SshTransport::upload_bytes`]): the deadline is
/// `max(SSH_COMMAND_TIMEOUT_SECS, bytes / MIN_RATE)`, so a large upload over
/// a slow link is never killed mid-transfer (the fixed 60s command deadline
/// would truncate a 24MB binary at ~0.2MB/s and the truncated object would
/// fail its post-upload integrity re-hash). 64KB/s is deliberately far below
/// any healthy link — it only extends the bound for genuinely slow hosts —
/// while still bounding a hung upload (a remote that stops reading stdin).
/// A link that sits AT or below the default (e.g. a Raspberry Pi on wifi,
/// measured ~70-140KB/s) can be tolerated without recompiling by setting
/// `DEPLOY_SSH_MIN_RATE_BYTES_PER_SEC` to a lower rate.
pub(crate) const SSH_TRANSFER_MIN_RATE_BYTES_PER_SEC: u64 = 64 * 1024;

/// The kind of ssh operation the runner is executing. The property test
/// generates these × stall points through an injected fake seam (see the
/// `runner_property_tests` module) and asserts the deadline/kill/reap contract
/// for every one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpKind {
    /// `run_remote`: a plain remote shell command (output returned, status not
    /// checked by the caller).
    Remote,
    /// `run_remote_ok`: a remote shell command that must exit 0.
    RemoteOk,
    /// The stdin-payload path: `ssh` with a payload piped to the remote
    /// `cat` — used by the raw [`SshTransport::upload_bytes`] write AND by
    /// `try_write_new`'s no-clobber install. Both ship their bytes on STDIN
    /// (never embedded in the command string), so arbitrary `Vec<u8>`
    /// round-trips exactly; a remote that stops reading stdin is covered by
    /// the same bounded wait as every other operation.
    Upload,
    /// The `ssh-keyscan` key-pin step.
    KeyscanPin,
    /// `Remote::exec` (caller-supplied timeout).
    Exec,
}

/// How a runner invocation failed. Timeout is distinct so each caller can map
/// it to its own outcome shape: `exec` returns an `ExecOutcome` with
/// `exit_code = -1` and `stderr = "timed out after …"` (existing callers
/// depend on it), every other operation returns a `Result` error.
#[derive(Debug)]
pub(crate) enum RunError {
    /// The child could not be spawned.
    Spawn(String),
    /// The stdin payload write failed (e.g. EPIPE after the deadline kill
    /// closed the pipe). Returned only AFTER the child was reaped: the wait
    /// closure always collects the child before surfacing a saved write
    /// error.
    StdinWrite(String),
    /// Waiting on the child failed (wait error, read error, …).
    Wait(String),
    /// The hard deadline fired; the child was killed and reaped.
    Timeout { after: Duration },
}

/// A spawned child owned by one supervisor. The runner keeps the EXCLUSIVE
/// handle to the live child — its `kill` requests the kill on the OWNED
/// [`std::process::Child`] (never a detached pid) — and a reaping closure the
/// wait thread runs. The closure returns once the child exits — including
/// after a kill request — so the runner's join is a deterministic reap. Once
/// the wait thread has reaped the child the handle is CONSUMED: a kill on it
/// is a no-op by construction, so a pid the OS recycled to an unrelated
/// process can never be signalled.
struct SpawnedChild {
    /// The child's pid, known to the PARENT synchronously at spawn time: the
    /// real seam reads it off the owned [`std::process::Child`] immediately
    /// after spawn (the fake generates its own), and the runner surfaces it
    /// through the test-only spawn observer — so a test asserts the pid is
    /// gone after the deadline kill WITHOUT the child ever writing its own
    /// pid to a file (a child-written pidfile races the kill: the child can
    /// be killed before it writes).
    pid: u32,
    /// Request the force-kill of the live child (SIGKILL on the owned
    /// handle). A no-op once the wait thread has reaped the child. The real
    /// seam locks the child slot shared with the wait thread and calls
    /// [`std::process::Child::kill`]; the fake seam records the Kill event
    /// against its own per-child control block.
    kill: Box<dyn Fn() -> std::io::Result<()> + Send>,
    /// Drain stdout/stderr and wait for the child; must return promptly once
    /// the child exits (or is killed). ALWAYS reaps the child before
    /// returning an error: a saved stdin-write error is surfaced only AFTER
    /// the child was collected, so an error can never leave the child
    /// uncollected (no return-before-reap).
    wait: Box<dyn FnOnce() -> std::result::Result<std::process::Output, RunError> + Send>,
}

/// The subprocess seam behind [`SshRunner`]. The production implementation
/// spawns real `ssh` / `ssh-keyscan` processes; tests inject a fake that
/// RECORDS every operation (`spawn(kind, argv)`, and per-handle kills and
/// reaps) and simulates the stall points, so the runner's deadline logic is
/// driven without any real subprocess or sleep.
trait SshRunnerSeam: Send + Sync {
    /// Spawn `argv[0]` with the remaining arguments. When `stdin` is `Some`,
    /// those bytes are piped to the child's stdin as part of the wait, so a
    /// child that stops reading is covered by the same deadline. Returns a
    /// handle whose `kill` requests the kill on the OWNED child and whose
    /// `wait` drains the child and returns once it exits.
    fn spawn(
        &self,
        op: OpKind,
        argv: &[String],
        stdin: Option<Vec<u8>>,
    ) -> std::io::Result<SpawnedChild>;
}

/// Production seam: real `ssh` / `ssh-keyscan` subprocesses.
struct RealRunner {
    /// The child environment snapshot: every spawned child receives THIS
    /// snapshot as its ENTIRE environment ([`SysEnv::apply_to_command`]:
    /// `env_clear` first, then the snapshot's variables) — a deterministic
    /// HERMETIC environment resolved at the transport boundary, never
    /// whatever the parent env looks like at spawn time, and nothing else.
    env: SysEnv,
}

impl RealRunner {
    fn new(env: &SysEnv) -> Self {
        RealRunner { env: env.clone() }
    }
}

impl SshRunnerSeam for RealRunner {
    fn spawn(
        &self,
        op: OpKind,
        argv: &[String],
        stdin: Option<Vec<u8>>,
    ) -> std::io::Result<SpawnedChild> {
        // The platform-specific spawn (process-group lifecycle on Unix,
        // plain spawn + owned-handle kill on Windows) lives in the
        // [`unix`] / [`windows`] submodules behind ONE cfg switch.
        platform::spawn(&self.env, op, argv, stdin)
    }
}

pub(crate) struct SshRunner {
    seam: Arc<dyn SshRunnerSeam>,
    /// Deadline for the connect-bound `ssh-keyscan` pin.
    connect_deadline: Duration,
    /// Deadline for post-connect remote command/upload operations.
    command_deadline: Duration,
    /// Test-only spawn observer: records each spawned child's pid in the
    /// PARENT at spawn time (called synchronously right after a successful
    /// spawn, before the deadline clock starts). Production installs nothing;
    /// a test installs a recording closure via
    /// [`SshRunner::with_spawn_observer`] and afterwards asserts the recorded
    /// pid is gone — the parent-side replacement for a child-written pidfile,
    /// which races the deadline kill (the child can be killed before it
    /// writes its own pid).
    spawn_observer: Option<Arc<dyn Fn(u32) + Send + Sync>>,
}

impl SshRunner {
    /// The bound the runner applies to post-connect commands AND uploads
    /// (the upload scales it up for large payloads via
    /// [`crate::transport::ssh::upload_deadline`]) — exposed so the
    /// size-aware upload deadline is computed from THIS (the injected test
    /// bound or the production 60s), never a hardcoded constant.
    pub(crate) fn command_deadline(&self) -> Duration {
        self.command_deadline
    }

    /// Build the runner for the environment snapshot `env`: every real child
    /// this runner spawns receives the snapshot as its ENTIRE environment
    /// (see [`SysEnv::apply_to_command`]).
    pub(crate) fn new(env: &SysEnv) -> Self {
        SshRunner {
            seam: Arc::new(RealRunner::new(env)),
            connect_deadline: Duration::from_secs(SSH_CONNECT_TIMEOUT_SECS),
            command_deadline: Duration::from_secs(SSH_COMMAND_TIMEOUT_SECS),
            spawn_observer: None,
        }
    }

    /// Test-only constructor with an injected seam and (tiny) deadlines, so the
    /// property test can drive the deadline/kill/reap logic against a fake
    /// without any real subprocess or wall-clock waits.
    #[cfg(test)]
    fn with_seam(
        seam: Arc<dyn SshRunnerSeam>,
        connect_deadline: Duration,
        command_deadline: Duration,
    ) -> Self {
        SshRunner {
            seam,
            connect_deadline,
            command_deadline,
            spawn_observer: None,
        }
    }

    /// Test-only spawn observer: install a closure that records each spawned
    /// child's pid in the PARENT at spawn time (synchronously, before the
    /// deadline clock starts) — the parent-side replacement for a
    /// child-written pidfile, which races the deadline kill.
    #[cfg(test)]
    fn with_spawn_observer(mut self, observer: Arc<dyn Fn(u32) + Send + Sync>) -> Self {
        self.spawn_observer = Some(observer);
        self
    }

    /// Run `op` with `argv`, bounding the whole wait by a hard deadline: the
    /// runner's policy for the op kind, unless `timeout` is `Some` (`exec`'s
    /// caller-supplied bound). On deadline the child is killed and the wait
    /// thread joined (deterministic reap) BEFORE the Timeout is returned.
    pub(crate) fn run(
        &self,
        op: OpKind,
        argv: &[String],
        stdin: Option<&[u8]>,
        timeout: Option<Duration>,
    ) -> std::result::Result<std::process::Output, RunError> {
        let deadline = match timeout {
            Some(t) => t,
            None => match op {
                OpKind::KeyscanPin => self.connect_deadline,
                _ => self.command_deadline,
            },
        };
        let child = self
            .seam
            .spawn(op, argv, stdin.map(<[u8]>::to_vec))
            .map_err(|e| RunError::Spawn(format!("spawn {:?}: {e}", argv)))?;
        // Split the owned handle into the kill request (the deadline path)
        // and the wait closure (the wait thread). The kill and the wait share
        // the child EXCLUSIVELY through the seam's handle, so the deadline
        // path can kill while the wait thread is mid-wait and a kill after
        // the wait has reaped the child is a no-op by construction.
        let SpawnedChild { pid, kill, wait } = child;
        // The test-only spawn observer records the pid in the PARENT here,
        // synchronously, immediately after spawn — before the deadline clock
        // starts — so a test can assert the pid is gone after the deadline
        // kill without the child ever writing its own pid to a file (a
        // child-written pidfile races the kill: the child can be killed
        // before it writes). Only tests install an observer; production runs
        // with None, so this is a no-op.
        if let Some(observer) = &self.spawn_observer {
            observer(pid);
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let res = wait();
            let _ = tx.send(res);
        });
        match rx.recv_timeout(deadline) {
            Ok(Ok(out)) => {
                // Success: the wait thread reaped the child (its poll loop
                // collected it) and sent the output. Join so the thread — and
                // therefore the child's collection — is complete before we
                // return.
                let _ = handle.join();
                Ok(out)
            }
            Ok(Err(e)) => {
                // The wait closure already reaped the child before returning
                // the error (a saved stdin-write error is surfaced only after
                // the child was collected), and the join collects the thread —
                // so an error path never leaves an uncollected child either.
                let _ = handle.join();
                Err(e)
            }
            Err(_) => {
                // HARD DEADLINE: request a kill through the OWNED child handle
                // — never a libc::kill of a detached pid — then reap by
                // joining the wait thread that owns the child (its `wait`
                // returns promptly after the kill). Both complete before this
                // function returns, so the child is deterministically
                // collected — no zombie, no kill-vs-wait race, no
                // return-before-reap — and a pid the OS recycled after the
                // reap can never be signalled: a kill on a consumed handle is
                // a no-op by construction.
                let _ = kill();
                let _ = handle.join();
                Err(RunError::Timeout { after: deadline })
            }
        }
    }
}

/// Property test for the runner contract: EVERY ssh operation (run_remote,
/// run_remote_ok, upload, keyscan-pin, exec) must go through the ONE bounded
/// runner, and the runner must kill + deterministically reap every stalled
/// child. The generated operations are driven through the REAL transport entry
/// points with an INJECTED fake seam (via `SshTransport::with_runner`), so the
/// runner's deadline logic is exercised end to end while the fake simulates
/// the stall points at the spawn boundary and RECORDS the full
/// spawn/kill/reap call log.
#[cfg(test)]
mod runner_property_tests {
    use super::*;
    use crate::error::Error;
    use crate::transport::Remote;
    use crate::transport::SshTransport;
    #[cfg(test)]
    use proptest::prelude::*;
    #[cfg(test)]
    use proptest::test_runner::RngSeed;
    use std::os::unix::process::ExitStatusExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Instant;

    /// The stall point each generated operation must exhibit.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Stall {
        /// The child hangs forever (until the runner kills it at the deadline).
        Hang,
        /// The child exits 0 promptly.
        Complete,
        /// The child cannot be spawned at all.
        SpawnError,
        /// The child exits non-zero promptly.
        NonZero,
        /// The stdin payload write fails (EPIPE) — but the wait closure STILL
        /// reaps the child (runs `wait_with_output`) before returning the saved
        /// write error: no return-before-reap on the write-error path. Vacuous
        /// (completes normally) for ops that pipe no stdin.
        StdinWriteError,
        /// The wait itself (`wait_with_output`) fails, after the reap attempt.
        WaitError,
    }

    /// Every operation the fake seam records, in order.
    #[derive(Clone, Debug)]
    enum LogEntry {
        Spawn {
            op: OpKind,
            argv: Vec<String>,
            pid: u32,
        },
        Kill {
            pid: u32,
        },
        Reap {
            pid: u32,
        },
    }

    /// Where an injected delay blocks inside the fake seam. The
    /// scheduler-delay property generates these × a delay duration and asserts
    /// the runner's invariants still hold under every interleaving: the
    /// delays perturb the thread schedule around the spawn/deadline/kill/wait
    /// lifecycle instead of delaying everything uniformly, so both the
    /// kill-before-join and join-before-kill orderings are exercised (the
    /// after-reap placement is the delay-driven mirror of the pid-reuse
    /// barrier).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DelayAt {
        /// The fake's `spawn` blocks BEFORE returning the handle: the child is
        /// conceptually live but the runner does not yet hold it.
        Spawn,
        /// The fake's kill closure blocks BEFORE recording the kill and
        /// arming the killed flag: the runner has decided to kill but the
        /// wait thread keeps polling — a kill-before-join with the kill held
        /// open.
        Kill,
        /// The fake's wait closure blocks BEFORE its first wait: the wait
        /// thread is a live waiter while the deadline races it.
        Wait,
        /// The fake's wait closure blocks AFTER recording its reap and BEFORE
        /// returning the completion: a deadline kill in this window finds the
        /// reaped handle consumed and is a no-op — join-before-kill, the
        /// barrier property's window reached via delay injection.
        AfterReap,
    }

    /// How long the injected delay blocks, relative to the runner's deadline:
    /// Tiny stays well inside the deadline (the wait finishes first and the
    /// runner joins without killing), Past crosses it (the deadline fires
    /// while the wait is still blocked and the runner must kill-then-reap).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DelaySize {
        /// No delay: the case runs unperturbed.
        None,
        /// An order of magnitude under the deadline: a scheduling
        /// perturbation, not a deadline crossing.
        Tiny,
        /// Past the deadline, made DETERMINISTIC: instead of racing a
        /// wall-clock margin that a loaded scheduler can overshoot, the wait
        /// blocks until the runner's deadline path arms the per-child
        /// [`DeadlineSignal`], so the delayed value is sent only once the
        /// deadline has demonstrably fired (see [`ChildCtl::injected_delay`]).
        Past,
    }

    impl DelaySize {
        /// The wall-clock delay for a runner deadline of `deadline`. Only the
        /// `Spawn` and `Kill` stages sleep it; at the `Wait`/`AfterReap`
        /// stages a `Past` delay is realised by the deadline latch instead.
        fn delay_for(self, deadline: Duration) -> Duration {
            match self {
                DelaySize::None => Duration::ZERO,
                DelaySize::Tiny => deadline / 10,
                DelaySize::Past => deadline + Duration::from_millis(3),
            }
        }
    }

    /// The backstop on a `Past` wait delay that the runner never releases (a
    /// runner whose deadline logic is broken never requests the kill that
    /// arms the latch): the value is then sent anyway and the test fails
    /// loudly on the outcome instead of hanging. FAR longer than any
    /// plausible scheduler overshoot, so it can never itself race the
    /// deadline of a correct runner.
    const PAST_DELAY_FALLBACK: Duration = Duration::from_secs(5);

    struct FakeState {
        log: Mutex<Vec<LogEntry>>,
        /// Number of fake wait closures still running (children not yet
        /// reaped). Zero after an operation returns proves the runner joined
        /// every wait thread — the thread-level half of "no zombie".
        live_waiters: AtomicUsize,
    }

    impl FakeState {
        fn new() -> Self {
            FakeState {
                log: Mutex::new(Vec::new()),
                live_waiters: AtomicUsize::new(0),
            }
        }
        fn push(&self, entry: LogEntry) {
            self.log.lock().unwrap().push(entry);
        }
        fn spawn(&self) -> (OpKind, Vec<String>, u32) {
            let log = self.log.lock().unwrap();
            match log.iter().find_map(|e| match e {
                LogEntry::Spawn { op, argv, pid } => Some((*op, argv.clone(), *pid)),
                _ => None,
            }) {
                Some(s) => s,
                None => panic!("no spawn recorded"),
            }
        }
        fn kill_pids(&self) -> Vec<u32> {
            self.pids(|e| matches!(e, LogEntry::Kill { .. }))
        }
        fn reap_pids(&self) -> Vec<u32> {
            self.pids(|e| matches!(e, LogEntry::Reap { .. }))
        }
        fn pids(&self, kind: fn(&LogEntry) -> bool) -> Vec<u32> {
            let log = self.log.lock().unwrap();
            log.iter()
                .filter(|e| kind(e))
                .filter_map(|e| match e {
                    LogEntry::Kill { pid } | LogEntry::Reap { pid } => Some(*pid),
                    _ => None,
                })
                .collect()
        }
        fn log_snapshot(&self) -> Vec<(String, u32)> {
            let log = self.log.lock().unwrap();
            log.iter()
                .map(|e| match e {
                    LogEntry::Spawn { pid, .. } => ("spawn".to_string(), *pid),
                    LogEntry::Kill { pid } => ("kill".to_string(), *pid),
                    LogEntry::Reap { pid } => ("reap".to_string(), *pid),
                })
                .collect()
        }
        /// True when the first Kill precedes the first Reap (kill-then-reap).
        fn kill_precedes_reap(&self) -> bool {
            let log = self.log.lock().unwrap();
            let kpos = log.iter().position(|e| matches!(e, LogEntry::Kill { .. }));
            let rpos = log.iter().position(|e| matches!(e, LogEntry::Reap { .. }));
            match (kpos, rpos) {
                (Some(k), Some(r)) => k < r,
                _ => false,
            }
        }
        fn live_waiters(&self) -> usize {
            self.live_waiters.load(Ordering::SeqCst)
        }
    }

    /// A one-shot latch armed by the runner's deadline path (through the
    /// seam's kill request) and awaited by a `Past` wait delay. This replaces
    /// the former wall-clock margin with a DETERMINISTIC premise: the runner
    /// requests a kill ONLY after `recv_timeout` reported the deadline, so
    /// once the latch is armed the deadline has provably passed and any value
    /// sent afterwards can never win the race — however the scheduler
    /// interleaves the threads.
    struct DeadlineSignal {
        fired: Mutex<bool>,
        cv: Condvar,
    }

    impl DeadlineSignal {
        fn new() -> Self {
            DeadlineSignal {
                fired: Mutex::new(false),
                cv: Condvar::new(),
            }
        }

        /// Arm the latch. Called FIRST in the kill closure — before the
        /// reaped/no-op check — because the dead-handle case (join-before-kill)
        /// must arm it too.
        fn arm(&self) {
            *self.fired.lock().unwrap() = true;
            self.cv.notify_all();
        }

        /// Block until armed, or until `budget` elapses (a broken runner never
        /// arms it). Latch semantics: an already-armed call returns at once.
        fn wait(&self, budget: Duration) -> bool {
            let deadline = Instant::now() + budget;
            let mut fired = self.fired.lock().unwrap();
            while !*fired {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return false;
                }
                fired = self
                    .cv
                    .wait_timeout(fired, remaining)
                    .expect("the deadline latch mutex must not be poisoned")
                    .0;
            }
            true
        }
    }

    /// Per-child control block: the fake wait polls `killed`; the runner's
    /// deadline path calls [`FakeSeam::kill`], which sets it, so the blocked
    /// wait unblocks and records the reap — reproducing exactly the real
    /// child's kill-then-reap lifecycle without any subprocess.
    struct ChildCtl {
        pid: u32,
        killed: AtomicBool,
        /// Set the instant the wait has collected the child: from then on a
        /// kill request on this handle is a NO-OP — the fake's mirror of the
        /// real runner's consumed `Child` handle.
        reaped: AtomicBool,
        stall: Stall,
        /// Whether the op pipes a stdin payload: the write-error stall is
        /// meaningful only when there is something to write (the upload op).
        has_stdin: bool,
        /// Real host-key line the fake keyscan emits on Complete, so the pin
        /// path succeeds end-to-end (fingerprint verified with real ssh-keygen).
        keyscan_line: Option<String>,
        /// Test-only barrier for the pid-reuse property: the wait parks on it
        /// AFTER recording its reap and BEFORE returning, exposing the
        /// reaped-but-not-yet-completed window in which a detached-pid kill
        /// would be catastrophic.
        after_reap_barrier: Option<Arc<std::sync::Barrier>>,
        /// Injected scheduler delay (stage + duration) for this child: the
        /// fake blocks for `delay` at `delay_at` — the delay-injection points
        /// of the scheduler-delay property. `Duration::ZERO` disables it.
        delay_at: DelayAt,
        delay: Duration,
        /// The magnitude of the injected delay: only `Past` is gated on the
        /// deadline latch (see [`ChildCtl::injected_delay`]).
        size: DelaySize,
        /// The per-child deadline latch the kill closure arms and a `Past`
        /// wait delay awaits.
        deadline: Arc<DeadlineSignal>,
        state: Arc<FakeState>,
    }

    impl ChildCtl {
        /// The wait closure body: finish immediately (Complete / NonZero /
        /// vacuous StdinWriteError), block until killed (Hang), or fail AFTER
        /// the reap (StdinWriteError with a payload / WaitError); the caller
        /// records the single reap and returns the stubbed output or error.
        fn wait(&self) -> std::result::Result<std::process::Output, RunError> {
            self.state.live_waiters.fetch_add(1, Ordering::SeqCst);
            // Injected scheduler delay at the WAIT stage: the wait thread is a
            // live waiter while the deadline races it — a delay inside the
            // deadline leaves the completion first (join-before-kill), a
            // delay past it leaves the kill first (kill-before-join).
            if self.delay_at == DelayAt::Wait {
                self.injected_delay();
            }
            let res = self.wait_inner();
            // The child is fully reaped now — and the reaped flag is armed
            // BEFORE the Reap becomes observable, so from the moment the log
            // shows the reap a kill request on this handle is a no-op (the
            // real runner's consumed-handle no-op). The barrier parks the wait
            // AFTER the reap but BEFORE the completion notification — the
            // window the pid-reuse test exploits; only that test sets it.
            self.reaped.store(true, Ordering::SeqCst);
            self.state.push(LogEntry::Reap { pid: self.pid });
            // Injected scheduler delay at the AFTER-REAP stage: the child is
            // reaped but the completion has not been delivered — a deadline
            // reached in this window makes the runner's kill a no-op on the
            // consumed handle (join-before-kill), the delay-probe mirror of
            // the pid-reuse barrier.
            if self.delay_at == DelayAt::AfterReap {
                self.injected_delay();
            }
            self.state.live_waiters.fetch_sub(1, Ordering::SeqCst);
            if let Some(barrier) = &self.after_reap_barrier {
                barrier.wait();
            }
            res
        }

        /// Inject the configured scheduler delay. `Tiny`/`None` sleep their
        /// real duration; a `Past` delay waits on the per-child
        /// [`DeadlineSignal`] instead, so the completion cannot be delivered
        /// before the runner has demonstrably timed out and requested the
        /// kill. The value is only sent once the deadline has passed — a
        /// correct runner therefore always reports `Timeout`, and a runner
        /// that never reaches its deadline path leaves the latch unarmed, so
        /// the fallback sends the value and the assertion fails.
        fn injected_delay(&self) {
            match self.size {
                DelaySize::Past => {
                    let _ = self.deadline.wait(PAST_DELAY_FALLBACK);
                }
                DelaySize::None | DelaySize::Tiny => std::thread::sleep(self.delay),
            }
        }

        fn wait_inner(&self) -> std::result::Result<std::process::Output, RunError> {
            // Raw Unix wait status for an exit code: `code << 8` (WEXITSTATUS).
            let exit = |code: i32| std::process::ExitStatus::from_raw(code << 8);
            let output = |code: i32| -> std::process::Output {
                let mut out = std::process::Output {
                    status: exit(code),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                };
                if let Some(line) = &self.keyscan_line {
                    out.stdout = line.as_bytes().to_vec();
                }
                out
            };
            match self.stall {
                Stall::Complete => Ok(output(0)),
                Stall::NonZero => Ok(output(1)),
                Stall::Hang => {
                    // Block until the runner kills us at the deadline. A bounded
                    // backstop turns a broken runner (one that never kills) into
                    // a loud assertion failure instead of a suite-wide hang. The
                    // budget must be FAR above the deadline: under the FULL gate's
                    // heavy parallel load the caller thread that invokes the kill
                    // can itself be descheduled for seconds (the kill is a property
                    // of the runner, not of when the child happens to be scheduled)
                    // — a tight backstop would panic a HEALTHY runner's child
                    // before the (delayed) kill lands.
                    let budget = Instant::now() + Duration::from_secs(60);
                    while !self.killed.load(Ordering::SeqCst) && Instant::now() < budget {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    assert!(
                        self.killed.load(Ordering::SeqCst),
                        "stalled child {} was never killed: ctl={:?} killed={} reaped={} — runner must kill then reap on deadline",
                        self.pid,
                        (self as *const ChildCtl as usize),
                        self.killed.load(Ordering::SeqCst),
                        self.reaped.load(Ordering::SeqCst),
                    );
                    Ok(output(0))
                }
                Stall::StdinWriteError => {
                    if self.has_stdin {
                        // The stdin write fails — but the closure STILL reaps
                        // (the caller records the Reap) and only THEN returns
                        // the saved write error: a return-before-reap on this
                        // path would show up as a missing Reap.
                        Err(RunError::StdinWrite(
                            "simulated stdin write failure".to_string(),
                        ))
                    } else {
                        // No stdin payload: there is nothing to write, so the
                        // stall is vacuous and the child completes normally.
                        Ok(output(0))
                    }
                }
                Stall::WaitError => {
                    // The reap is ATTEMPTED (the caller records the Reap) but
                    // the wait itself fails: surfaces as a wait error after
                    // the reap attempt.
                    Err(RunError::Wait("simulated wait failure".to_string()))
                }
                Stall::SpawnError => unreachable!("spawn errors never yield a child"),
            }
        }
    }

    /// The injected fake seam: records every spawn (kind + argv), and the
    /// per-handle kills and reaps, and simulates the generated stall point.
    struct FakeSeam {
        state: Arc<FakeState>,
        stall: Stall,
        next_pid: AtomicU32,
        keyscan_line: Option<String>,
        /// Test-only barrier for the pid-reuse property: the NEXT spawned
        /// child's wait parks on it AFTER recording its reap and BEFORE
        /// returning, exposing the reaped-but-not-yet-completed window in
        /// which a detached-pid kill would be catastrophic.
        after_reap_barrier: Option<Arc<std::sync::Barrier>>,
        /// Injected scheduler delay (stage + duration) applied to this seam's
        /// spawn/kill/wait closures: the delay-injection points of the
        /// scheduler-delay property.
        delay_at: DelayAt,
        delay: Duration,
        /// The magnitude of the injected delay (see [`ChildCtl::injected_delay`]).
        size: DelaySize,
    }

    impl FakeSeam {
        fn new(stall: Stall, keyscan_line: Option<String>) -> (Arc<Self>, Arc<FakeState>) {
            Self::with_delays(
                stall,
                keyscan_line,
                DelayAt::Wait,
                DelaySize::None,
                Duration::ZERO,
            )
        }

        /// The fake seam with an injected scheduler delay: every spawned
        /// child's spawn/kill/wait closures block for `delay` at the `at`
        /// stage, deliberately perturbing the thread schedule so the
        /// scheduler-delay property races the deadline around the
        /// kill/wait boundary.
        fn with_delays(
            stall: Stall,
            keyscan_line: Option<String>,
            at: DelayAt,
            size: DelaySize,
            delay: Duration,
        ) -> (Arc<Self>, Arc<FakeState>) {
            let state = Arc::new(FakeState::new());
            let seam = FakeSeam {
                state: state.clone(),
                stall,
                next_pid: AtomicU32::new(1),
                keyscan_line,
                after_reap_barrier: None,
                delay_at: at,
                delay,
                size,
            };
            (Arc::new(seam), state)
        }

        /// The pid-reuse simulation: spawn a fresh UNRELATED child that
        /// recycles `pid` — the pid a real OS hands to a new process the
        /// instant the original child is reaped. The spawn is recorded in the
        /// log so the reuse is observable; the returned control block lets the
        /// caller assert the unrelated child was never killed (its wait is
        /// never invoked — only its kill flag is inspected).
        fn spawn_reused_pid(&self, pid: u32, op: OpKind, argv: &[String]) -> Arc<ChildCtl> {
            self.state.push(LogEntry::Spawn {
                op,
                argv: argv.to_vec(),
                pid,
            });
            Arc::new(ChildCtl {
                pid,
                killed: AtomicBool::new(false),
                reaped: AtomicBool::new(false),
                // Benign: the reused child's wait never runs in the test.
                stall: Stall::Complete,
                has_stdin: false,
                keyscan_line: None,
                after_reap_barrier: None,
                delay_at: DelayAt::Wait,
                delay: Duration::ZERO,
                size: DelaySize::None,
                deadline: Arc::new(DeadlineSignal::new()),
                state: self.state.clone(),
            })
        }
    }

    impl SshRunnerSeam for FakeSeam {
        fn spawn(
            &self,
            op: OpKind,
            argv: &[String],
            stdin: Option<Vec<u8>>,
        ) -> std::io::Result<SpawnedChild> {
            let pid = self.next_pid.fetch_add(1, Ordering::SeqCst);
            // Injected scheduler delay at the SPAWN stage: the child is
            // conceptually live but the runner does not yet hold the handle —
            // the launch skew the scheduler-delay property perturbs.
            if self.delay_at == DelayAt::Spawn {
                std::thread::sleep(self.delay);
            }
            self.state.push(LogEntry::Spawn {
                op,
                argv: argv.to_vec(),
                pid,
            });
            if self.stall == Stall::SpawnError {
                return Err(std::io::Error::other("simulated spawn failure"));
            }
            let ctl = Arc::new(ChildCtl {
                pid,
                killed: AtomicBool::new(false),
                reaped: AtomicBool::new(false),
                stall: self.stall,
                has_stdin: stdin.is_some(),
                keyscan_line: self.keyscan_line.clone(),
                after_reap_barrier: self.after_reap_barrier.clone(),
                delay_at: self.delay_at,
                delay: self.delay,
                size: self.size,
                deadline: Arc::new(DeadlineSignal::new()),
                state: self.state.clone(),
            });
            // The kill handle: the runner's deadline path requests the kill
            // through THIS handle — never through a detached pid — and the
            // fake records it against the same child the wait reaps. On a
            // child the wait already reaped (its reaped flag is armed) it is
            // a NO-OP: nothing is recorded, so the log stays proof that a
            // reaped child is never killed.
            let kill_ctl = ctl.clone();
            let kill: Box<dyn Fn() -> std::io::Result<()> + Send> = Box::new(move || {
                // The runner requests a kill ONLY after its `recv_timeout`
                // reported the deadline, so arming the latch here proves the
                // deadline has passed. It is armed BEFORE the reaped/no-op
                // check: the dead-handle (join-before-kill) case must arm it
                // too, and the fake records no kill for it.
                kill_ctl.deadline.arm();
                if kill_ctl.reaped.load(Ordering::SeqCst) {
                    return Ok(());
                }
                // Injected scheduler delay at the KILL stage: the runner has
                // decided to kill but the child has not been told — the wait
                // thread keeps polling while the deadline path is held open.
                if kill_ctl.delay_at == DelayAt::Kill {
                    std::thread::sleep(kill_ctl.delay);
                }
                kill_ctl.state.push(LogEntry::Kill { pid: kill_ctl.pid });
                kill_ctl.killed.store(true, Ordering::SeqCst);
                Ok(())
            });
            let wait_ctl = ctl;
            let wait: Box<
                dyn FnOnce() -> std::result::Result<std::process::Output, RunError> + Send,
            > = Box::new(move || wait_ctl.wait());
            Ok(SpawnedChild { pid, kill, wait })
        }
    }

    /// The per-operation outcome, normalised so one assertion function can
    /// check every generated kind.
    #[derive(Debug)]
    enum PairOutcome {
        Ok,
        Remote(std::process::Output),
        Err(String),
        Exec(std::result::Result<crate::transport::ExecOutcome, Error>),
    }

    /// A real ed25519 host key (never a hardcoded fake), generated once per
    /// test binary: the keyscan "completes" with this key line, so the pin path
    /// verifies it with real `ssh-keygen` and succeeds end-to-end.
    fn host_key() -> (String, String) {
        static KEY: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            let dir =
                crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
            let keyfile = dir.path().join("hostkey");
            let out = std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-f"])
                .arg(&keyfile)
                .output()
                .expect("ssh-keygen must be available");
            assert!(
                out.status.success(),
                "ssh-keygen failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let pubkey = std::fs::read_to_string(keyfile.with_extension("pub"))
                .expect("read generated pubkey")
                .trim()
                .to_string();
            let fp = std::process::Command::new("ssh-keygen")
                .args([
                    "-lf",
                    keyfile.with_extension("pub").to_str().unwrap(),
                    "-E",
                    "sha256",
                ])
                .output()
                .expect("ssh-keygen -lf must run");
            let fingerprint = String::from_utf8_lossy(&fp.stdout)
                .split_whitespace()
                .nth(1)
                .expect("fingerprint field")
                .to_string();
            (pubkey, fingerprint)
        })
        .clone()
    }

    fn transport_for(
        kind: OpKind,
        fingerprint: &str,
        runner: SshRunner,
        cache: &Path,
        env: &crate::env::SysEnv,
    ) -> SshTransport {
        match kind {
            // The pin path requires a configured fingerprint (it reads
            // `self.host_key_fingerprint`), and must never have a known_hosts
            // file or it skips the keyscan entirely.
            OpKind::KeyscanPin => SshTransport::with_runner(
                "deploy",
                "runner-prop.test",
                2222,
                Path::new("/srv/app"),
                None,
                Some(fingerprint),
                cache,
                env,
                runner,
            )
            .unwrap(),
            // Every other op needs a resolvable identity to build `ssh_args`.
            _ => SshTransport::with_runner(
                "deploy",
                "runner-prop.test",
                2222,
                Path::new("/srv/app"),
                Some(Path::new("/dev/null")),
                None,
                cache,
                env,
                runner,
            )
            .unwrap(),
        }
    }

    /// Drive ONE generated (kind × stall) pair through the real transport entry
    /// point with the fake runner injected, then assert the contract.
    fn run_one_pair(kind: OpKind, stall: Stall) {
        let deadline = Duration::from_millis(25);
        let (pubkey, fingerprint) = host_key();
        let (seam, state) = FakeSeam::new(stall, Some(pubkey));
        let runner = SshRunner::with_seam(seam, deadline, deadline);
        // The keyscan pin writes its cache under the RESOLVED per-pair cache
        // dir passed to the transport at construction (never the process
        // env): pointing it at a fresh per-pair temp dir guarantees the pin
        // always performs the keyscan SPAWN (a reused cache file would skip
        // the runner call entirely).
        let cache =
            crate::test_support::fixture_tmpdir(&crate::test_support::fixture_env()).unwrap();
        let env = crate::env::SysEnv::from_map(std::collections::BTreeMap::new());
        let t = transport_for(kind, &fingerprint, runner, cache.path(), &env);

        let outcome = match kind {
            OpKind::Remote => match t.run_remote("printf ok") {
                Ok(out) => PairOutcome::Remote(out),
                Err(e) => PairOutcome::Err(e.to_string()),
            },
            OpKind::RemoteOk => match t.run_remote_ok("true") {
                Ok(()) => PairOutcome::Ok,
                Err(e) => PairOutcome::Err(e.to_string()),
            },
            OpKind::Upload => match t.upload_bytes(Path::new("files/app"), b"payload", 0) {
                Ok(()) => PairOutcome::Ok,
                Err(e) => PairOutcome::Err(e.to_string()),
            },
            OpKind::KeyscanPin => match t.pin_known_hosts() {
                Ok(()) => PairOutcome::Ok,
                Err(e) => PairOutcome::Err(e.to_string()),
            },
            OpKind::Exec => PairOutcome::Exec(t.exec(&["true".into()], deadline)),
        };
        drop(cache);

        assert_pair(kind, stall, deadline, &state, outcome);
    }

    /// The property's assertions for one pair. `state` is the fake's full call
    /// log + live-waiter count.
    fn assert_pair(
        kind: OpKind,
        stall: Stall,
        deadline: Duration,
        state: &FakeState,
        outcome: PairOutcome,
    ) {
        let (spawn_op, spawn_argv, spawn_pid) = state.spawn();
        assert_eq!(
            spawn_op, kind,
            "the recorded spawn kind must match the operation"
        );
        // argv[0] is the binary: `ssh-keyscan` for the pin, `ssh` for every
        // other operation.
        let expect_bin = if kind == OpKind::KeyscanPin {
            "ssh-keyscan"
        } else {
            "ssh"
        };
        assert_eq!(
            spawn_argv.first().map(String::as_str),
            Some(expect_bin),
            "spawn argv must start with the right binary"
        );

        match stall {
            Stall::Hang => {
                // Every stalled child terminates as Timeout: `exec` keeps its
                // ExecOutcome shape (exit_code -1, stderr "timed out after …"),
                // every other op returns a transport error.
                match &outcome {
                    PairOutcome::Exec(res) => {
                        let o = res
                            .as_ref()
                            .expect("exec on a stalled child must return a Timeout ExecOutcome");
                        assert_eq!(o.exit_code, -1, "timeout exec exit_code must be -1");
                        assert_eq!(
                            o.stderr,
                            format!("timed out after {deadline:?}"),
                            "timeout exec stderr must keep the existing shape"
                        );
                    }
                    _ => {
                        let msg = match &outcome {
                            PairOutcome::Err(m) => m,
                            _ => {
                                panic!("stalled op must fail with a timeout error, got {outcome:?}")
                            }
                        };
                        assert!(
                            msg.contains("timed out after"),
                            "stalled op must report the timeout, got: {msg}"
                        );
                    }
                }
                // … and is REAPED: exactly one kill, then exactly one reap, of
                // THE SAME pid, in that order, after the spawn — no kill-vs-
                // wait race, no zombie, no return-before-reap.
                assert_eq!(
                    state.kill_pids(),
                    vec![spawn_pid],
                    "stalled child must be killed exactly once"
                );
                assert_eq!(
                    state.reap_pids(),
                    vec![spawn_pid],
                    "stalled child must be reaped exactly once — full log: {:?}, live_waiters={}",
                    state.log_snapshot(),
                    state.live_waiters.load(Ordering::SeqCst)
                );
                assert!(
                    state.kill_precedes_reap(),
                    "kill must precede reap for a stalled child"
                );
            }
            Stall::Complete => {
                match kind {
                    OpKind::Exec => {
                        let o = match outcome {
                            PairOutcome::Exec(Ok(o)) => o,
                            _ => panic!("exec on a completed child must succeed, got {outcome:?}"),
                        };
                        assert_eq!(o.exit_code, 0);
                    }
                    OpKind::Remote => {
                        let o = match outcome {
                            PairOutcome::Remote(o) => o,
                            _ => panic!(
                                "run_remote on a completed child must succeed, got {outcome:?}"
                            ),
                        };
                        assert!(o.status.success());
                    }
                    _ => assert!(
                        matches!(outcome, PairOutcome::Ok),
                        "completed child must succeed, got {outcome:?}"
                    ),
                }
                assert_eq!(
                    state.kill_pids(),
                    Vec::<u32>::new(),
                    "a completed child must never be killed"
                );
                assert_eq!(
                    state.reap_pids(),
                    vec![spawn_pid],
                    "a completed child is reaped by the normal wait"
                );
            }
            Stall::SpawnError => {
                let msg = match &outcome {
                    PairOutcome::Err(m) => m.clone(),
                    PairOutcome::Exec(Err(e)) => e.to_string(),
                    _ => panic!("spawn failure must surface as a transport error, got {outcome:?}"),
                };
                assert!(
                    msg.contains("spawn"),
                    "spawn failure must surface as a spawn error, got: {msg}"
                );
                assert_eq!(
                    state.kill_pids(),
                    Vec::<u32>::new(),
                    "a failed spawn has nothing to kill"
                );
                assert_eq!(
                    state.reap_pids(),
                    Vec::<u32>::new(),
                    "a failed spawn has nothing to reap"
                );
            }
            Stall::NonZero => {
                match kind {
                    OpKind::Remote => {
                        let o = match outcome {
                            PairOutcome::Remote(o) => o,
                            _ => panic!("run_remote returns the raw output, got {outcome:?}"),
                        };
                        assert!(!o.status.success(), "non-zero exit must be reported");
                    }
                    OpKind::Exec => {
                        let o = match outcome {
                            PairOutcome::Exec(Ok(o)) => o,
                            _ => panic!("exec returns the raw outcome, got {outcome:?}"),
                        };
                        assert_eq!(o.exit_code, 1);
                    }
                    _ => {
                        let msg = match &outcome {
                            PairOutcome::Err(m) => m,
                            _ => panic!("non-zero exit must surface as an error, got {outcome:?}"),
                        };
                        assert!(msg.contains("failed"), "got: {msg}");
                    }
                }
                assert_eq!(
                    state.kill_pids(),
                    Vec::<u32>::new(),
                    "a non-zero exit is a normal wait, not a kill"
                );
                assert_eq!(
                    state.reap_pids(),
                    vec![spawn_pid],
                    "a non-zero child is reaped by the normal wait"
                );
            }
            Stall::StdinWriteError => {
                if kind == OpKind::Upload {
                    // The stdin write fails, but the closure ALWAYS reaps first
                    // (wait_with_output runs; the fake records the Reap) and
                    // only then returns the saved write error — no
                    // return-before-reap — and the error surfaces (not a
                    // Timeout) after the reap.
                    let msg = match &outcome {
                        PairOutcome::Err(m) => m,
                        _ => {
                            panic!(
                                "a stdin-write failure must surface as an error, got {outcome:?}"
                            )
                        }
                    };
                    assert!(
                        msg.contains("stdin write"),
                        "a stdin-write failure must surface the write error, got: {msg}"
                    );
                    assert_eq!(
                        state.kill_pids(),
                        Vec::<u32>::new(),
                        "a stdin-write error surfaces before the deadline: nothing to kill"
                    );
                    assert_eq!(
                        state.reap_pids(),
                        vec![spawn_pid],
                        "the child must be reaped even on a stdin-write error"
                    );
                } else {
                    // No stdin payload: nothing is written, so the stall is
                    // vacuous and the child completes normally.
                    match kind {
                        OpKind::Exec => {
                            let o = match outcome {
                                PairOutcome::Exec(Ok(o)) => o,
                                _ => panic!(
                                    "exec with a vacuous write-error stall must succeed, got {outcome:?}"
                                ),
                            };
                            assert_eq!(o.exit_code, 0);
                        }
                        OpKind::Remote => {
                            let o = match outcome {
                                PairOutcome::Remote(o) => o,
                                _ => panic!(
                                    "run_remote with a vacuous write-error stall must succeed, got {outcome:?}"
                                ),
                            };
                            assert!(o.status.success());
                        }
                        _ => assert!(
                            matches!(outcome, PairOutcome::Ok),
                            "a vacuous write-error stall must succeed, got {outcome:?}"
                        ),
                    }
                    assert_eq!(
                        state.kill_pids(),
                        Vec::<u32>::new(),
                        "a vacuous write-error stall is a normal wait, not a kill"
                    );
                    assert_eq!(
                        state.reap_pids(),
                        vec![spawn_pid],
                        "a vacuous write-error child is reaped by the normal wait"
                    );
                }
            }
            Stall::WaitError => {
                // The wait fails AFTER the reap attempt, and the wait error
                // surfaces (not a Timeout); the child is still recorded as
                // reaped — never a return-before-reap.
                let msg = match &outcome {
                    PairOutcome::Err(m) => m.clone(),
                    PairOutcome::Exec(Err(e)) => e.to_string(),
                    _ => panic!("a wait failure must surface as an error, got {outcome:?}"),
                };
                assert!(
                    msg.contains("wait"),
                    "a wait failure must surface as a wait error, got: {msg}"
                );
                assert_eq!(
                    state.kill_pids(),
                    Vec::<u32>::new(),
                    "a wait error is a normal wait, not a kill"
                );
                assert_eq!(
                    state.reap_pids(),
                    vec![spawn_pid],
                    "the child must be reaped even on a wait error (the reap attempt is recorded)"
                );
            }
        }

        assert_eq!(
            state.live_waiters(),
            0,
            "every wait thread must be joined (reaped) before the operation returns"
        );
    }

    fn op_strategy() -> impl Strategy<Value = OpKind> {
        prop_oneof![
            Just(OpKind::Remote),
            Just(OpKind::RemoteOk),
            Just(OpKind::Upload),
            Just(OpKind::KeyscanPin),
            Just(OpKind::Exec),
        ]
    }

    /// Real-runner sanity check: a REAL subprocess that stalls must be killed
    /// at the deadline AND reaped — the pid must be gone afterwards, because an
    /// un-reaped zombie would still answer `kill(pid, 0)` with success. The
    /// pid comes from the test-only spawn observer: the PARENT records it
    /// synchronously at spawn time, so no child-written pidfile can race the
    /// deadline kill.
    #[test]
    fn real_runner_kills_and_reaps_a_stalled_child() {
        let spawned = Arc::new(Mutex::new(None));
        let runner = SshRunner::new(&crate::test_support::fixture_env()).with_spawn_observer({
            let spawned = spawned.clone();
            Arc::new(move |pid: u32| *spawned.lock().unwrap() = Some(pid))
        });
        // The child execs `sleep`, so the observed pid IS the process the
        // runner must kill and reap.
        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            "exec sleep 30".to_string(),
        ];
        let deadline = Duration::from_millis(100);
        let start = Instant::now();
        let res = runner.run(OpKind::Exec, &argv, None, Some(deadline));
        assert!(matches!(res, Err(RunError::Timeout { after }) if after == deadline));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "a stalled child must be killed at the deadline, not after it"
        );
        // The observer recorded the pid before the deadline clock started, so
        // it is always available after `run` returns — nothing to race.
        let pid: i32 = spawned
            .lock()
            .unwrap()
            .expect("the spawn observer must record the child pid in the parent at spawn time")
            as i32;
        // SAFETY: `kill(pid, 0)` only probes existence; it sends no signal.
        let still_exists = unsafe { libc::kill(pid, 0) } == 0;
        assert!(
            !still_exists,
            "child {pid} must be reaped (a zombie would still exist)"
        );
    }

    /// THE timed-out-upload guarantee: a real child that NEVER reads stdin,
    /// with a payload larger than the pipe buffer (1 MiB » a 16–64 KiB pipe),
    /// blocks the wait closure's stdin write until the tiny deadline fires;
    /// the child is then KILLED — and its pid must be GONE afterwards,
    /// proving the timed-out upload was not only killed but also REAPED (an
    /// uncollected zombie would still answer `kill(pid, 0)`). The pid is
    /// recorded by the test-only spawn observer in the PARENT at spawn time:
    /// the OLD form asked the child to write its own pid to a file, which
    /// RACED the deadline kill (the child can be killed before it writes) —
    /// that was the flaky-test bug.
    #[test]
    fn real_runner_kills_and_reaps_a_timed_out_upload() {
        let spawned = Arc::new(Mutex::new(None));
        let runner = SshRunner::with_seam(
            Arc::new(RealRunner::new(&crate::test_support::fixture_env())),
            Duration::from_millis(50),
            Duration::from_millis(50),
        )
        .with_spawn_observer({
            let spawned = spawned.clone();
            Arc::new(move |pid: u32| *spawned.lock().unwrap() = Some(pid))
        });
        // The child execs `sleep` WITHOUT ever reading stdin: the piped
        // payload fills the pipe buffer and the write blocks until the
        // deadline kill closes the pipe.
        let argv = vec![
            "sh".to_string(),
            "-c".to_string(),
            "exec sleep 30".to_string(),
        ];
        let payload: Vec<u8> = vec![0x5A; 1024 * 1024]; // 1 MiB » pipe buffer
        let start = Instant::now();
        let res = runner.run(OpKind::Upload, &argv, Some(&payload), None);
        assert!(
            matches!(res, Err(RunError::Timeout { after }) if after == Duration::from_millis(50))
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "a timed-out upload must be killed at the deadline, not after it"
        );
        // The observer recorded the pid before the deadline clock started, so
        // it is always present after `run` returns.
        let pid: i32 = spawned
            .lock()
            .unwrap()
            .expect("the spawn observer must record the child pid in the parent at spawn time")
            as i32;
        // SAFETY: `kill(pid, 0)` only probes existence; it sends no signal.
        let still_exists = unsafe { libc::kill(pid, 0) } == 0;
        assert!(
            !still_exists,
            "timed-out upload child {pid} must be reaped (a zombie would still exist)"
        );
    }

    /// Real-runner sanity check: a promptly-completing child returns its output
    /// (no kill, no timeout), and a spawn failure surfaces as a spawn error.
    #[test]
    fn real_runner_completes_and_surfaces_spawn_errors() {
        let runner = SshRunner::new(&crate::test_support::fixture_env());
        let out = runner
            .run(
                OpKind::Exec,
                &["true".to_string()],
                None,
                Some(Duration::from_secs(5)),
            )
            .expect("a completing child must succeed");
        assert!(out.status.success());
        let err = runner
            .run(
                OpKind::Exec,
                &["/definitely/not/a/real/binary".to_string()],
                None,
                Some(Duration::from_secs(5)),
            )
            .expect_err("a missing binary must fail at spawn");
        assert!(matches!(err, RunError::Spawn(_)));
    }

    /// Real-runner check for the consumed-handle contract: a kill request on
    /// a child whose wait ALREADY reaped it must not raise an error and —
    /// where observable from this side of the child — must not signal
    /// anything: the pid is gone (the process was collected), and because the
    /// kill goes through the OWNED handle (never a detached pid), it can
    /// never land on a process the OS recycled the pid to.
    #[test]
    fn kill_after_reap_does_not_raise_or_signal() {
        let seam = Arc::new(RealRunner::new(&crate::test_support::fixture_env()));
        let child = seam
            .spawn(
                OpKind::Exec,
                &["sh".to_string(), "-c".to_string(), "exit 7".to_string()],
                None,
            )
            .expect("spawn must succeed");
        // The pid comes from the PARENT: the seam reads it synchronously at
        // spawn time (`Child::id`) and returns it on the handle — no
        // child-written pidfile.
        let SpawnedChild { pid, kill, wait } = child;
        let out = std::thread::spawn(wait)
            .join()
            .unwrap()
            .expect("a promptly-completing child must reap normally");
        assert_eq!(
            out.status.code(),
            Some(7),
            "the child's exit status must be preserved"
        );
        // The child was REAPED (the wait consumed the handle): a kill request
        // now must be a no-op that raises no error.
        let kill_res = kill();
        assert!(
            kill_res.is_ok(),
            "a kill after the reap must not raise an error, got: {kill_res:?}"
        );
        // Where observable: nothing was signalled — the pid is gone (reaped,
        // not a zombie), so the kill cannot land on an unrelated process.
        let pid: i32 = pid as i32;
        // SAFETY: `kill(pid, 0)` only probes existence; it sends no signal.
        let still_exists = unsafe { libc::kill(pid, 0) } == 0;
        assert!(!still_exists, "reaped child {pid} must be gone");
    }

    fn stall_strategy() -> impl Strategy<Value = Stall> {
        prop_oneof![
            Just(Stall::Hang),
            Just(Stall::Complete),
            Just(Stall::SpawnError),
            Just(Stall::NonZero),
            Just(Stall::StdinWriteError),
            Just(Stall::WaitError),
        ]
    }

    fn delay_at_strategy() -> impl Strategy<Value = DelayAt> {
        prop_oneof![
            Just(DelayAt::Spawn),
            Just(DelayAt::Kill),
            Just(DelayAt::Wait),
            Just(DelayAt::AfterReap),
        ]
    }

    fn delay_size_strategy() -> impl Strategy<Value = DelaySize> {
        prop_oneof![
            Just(DelaySize::None),
            Just(DelaySize::Tiny),
            Just(DelaySize::Past),
        ]
    }

    /// Drive one generated (kind × stall × delay placement × delay size) case
    /// through the runner's deadline logic against the fake seam with the
    /// injected scheduler delay, then assert the invariants that must hold
    /// for EVERY returned outcome.
    fn run_one_delayed(kind: OpKind, stall: Stall, at: DelayAt, size: DelaySize) {
        // A 2ms deadline keeps the injected delays (and therefore the whole
        // property) sub-millisecond-ish: the delay buckets are fractions of
        // it, so the suite stays fast while the cases still race the deadline
        // around the kill/wait boundary.
        let deadline = Duration::from_millis(2);
        let delay = size.delay_for(deadline);
        let (seam, state) = FakeSeam::with_delays(stall, None, at, size, delay);
        let runner = SshRunner::with_seam(seam, deadline, deadline);
        let argv = vec!["ssh".to_string(), "runner-delay.test".to_string()];
        let stdin = (kind == OpKind::Upload).then(|| vec![0x5A; 4096]);
        let timeout = (kind == OpKind::Exec).then_some(deadline);
        let outcome = runner.run(kind, &argv, stdin.as_deref(), timeout);
        assert_delayed_invariants(kind, stall, at, size, &state, outcome);
    }

    /// Whether a generated (stall × delay) pair actually CROSSES the past
    /// deadline: a self-completing child whose wait is blocked past the
    /// deadline cannot finish before the deadline fires, so the runner must
    /// kill-then-reap a still-live wait — the race the delay is meant to
    /// provoke. Pairs that do not cross (a tiny delay, a spawn-stage delay, a
    /// hang that ends at the kill) exercise the opposite interleavings
    /// instead, so both sides of the deadline are covered across the cases.
    fn crosses_deadline(stall: Stall, at: DelayAt, size: DelaySize) -> bool {
        size == DelaySize::Past
            && matches!(at, DelayAt::Wait | DelayAt::AfterReap)
            && matches!(
                stall,
                Stall::Complete | Stall::NonZero | Stall::StdinWriteError | Stall::WaitError
            )
    }

    /// The scheduler-delay property's assertions: for EVERY returned outcome
    /// (timeout, success, write error, wait error, spawn error) zero live
    /// waiters must remain — the runner joined every wait thread before
    /// returning — and the spawned child must have been reaped exactly once
    /// (a failed spawn has no child: zero reaps).
    fn assert_delayed_invariants(
        kind: OpKind,
        stall: Stall,
        at: DelayAt,
        size: DelaySize,
        state: &FakeState,
        outcome: std::result::Result<std::process::Output, RunError>,
    ) {
        let label = format!("{kind:?} × {stall:?} × {at:?} {size:?}");
        assert_eq!(
            state.live_waiters(),
            0,
            "every returned outcome must leave zero live waiters ({label}): {} waiters still live",
            state.live_waiters()
        );
        if stall == Stall::SpawnError {
            assert_eq!(
                state.kill_pids(),
                Vec::<u32>::new(),
                "a failed spawn has nothing to kill ({label})"
            );
            assert_eq!(
                state.reap_pids(),
                Vec::<u32>::new(),
                "a failed spawn has nothing to reap ({label})"
            );
            return;
        }
        let (_, _, pid) = state.spawn();
        assert_eq!(
            state.reap_pids(),
            vec![pid],
            "the spawned child must be reaped exactly once ({label})"
        );
        // The delay must actually CROSS the deadline, not merely delay
        // everything: a self-completing child whose wait is blocked past the
        // deadline must surface as a Timeout — the deadline fired while the
        // wait thread was still live (the wait's own completion can only
        // arrive after the delay, which is past the deadline).
        if crosses_deadline(stall, at, size) {
            assert!(
                matches!(outcome, Err(RunError::Timeout { .. })),
                "a past-deadline wait delay must let the deadline win ({label}), got: {outcome:?}"
            );
        }
    }

    /// The extended seam's new outcomes, driven deterministically: the property
    /// also draws them (6 stalls × 5 ops), but the fixed seed may not pair them
    /// with the upload op in every run. A stdin-write error is returned only
    /// AFTER the child was reaped, and a wait error surfaces after the reap
    /// attempt — never a return-before-reap.
    #[test]
    fn stdin_write_error_is_returned_after_the_reap() {
        run_one_pair(OpKind::Upload, Stall::StdinWriteError);
    }

    #[test]
    fn wait_error_is_returned_after_the_reap() {
        run_one_pair(OpKind::Upload, Stall::WaitError);
    }

    /// THE reused-PID property: the fake reaps the child, then — the barrier
    /// parks the wait AFTER the reap but BEFORE the completion notification —
    /// the OS recycles the child's pid to a fresh UNRELATED child, exactly
    /// what a real OS does the moment a pid is reaped. A kill request made in
    /// that window (the old code would libc::kill the DETACHED pid and murder
    /// the unrelated process) must be a NO-OP on the consumed handle: no Kill
    /// is recorded after the reap, and the unrelated child holding the
    /// recycled pid is never killed.
    #[test]
    fn kill_after_reap_is_a_noop_even_when_the_pid_is_reused() {
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let state = Arc::new(FakeState::new());
        let seam = Arc::new(FakeSeam {
            state: state.clone(),
            stall: Stall::Hang,
            next_pid: AtomicU32::new(1),
            keyscan_line: None,
            after_reap_barrier: Some(barrier.clone()),
            delay_at: DelayAt::Wait,
            delay: Duration::ZERO,
            size: DelaySize::None,
        });
        let argv = vec!["ssh".to_string(), "true".to_string()];
        let child = seam
            .spawn(OpKind::Exec, &argv, None)
            .expect("the fake must spawn the stalling child");
        // Split the handle exactly as the runner does: the kill request (the
        // deadline path) and the wait closure (the wait thread). The pid is
        // the parent's own, read synchronously at spawn.
        let SpawnedChild { pid, kill, wait } = child;

        // The runner's deadline path: request the kill through the OWNED
        // handle.
        kill().expect("killing a live child must succeed");

        // The wait thread reaps the child, then parks on the barrier (reaped
        // but not yet completed).
        let waiter = std::thread::spawn(wait);
        // Same generous backstop as the fake Hang loop: under the FULL gate's
        // parallel load the wait thread can be descheduled for seconds after
        // the kill — the budget only needs to catch a genuinely stuck wait.
        let budget = Instant::now() + Duration::from_secs(5);
        while !state.reap_pids().contains(&pid) && Instant::now() < budget {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            state.reap_pids().contains(&pid),
            "the fake must reap the child before parking on the barrier"
        );

        // PID REUSE: the OS hands the just-reaped pid to an unrelated process.
        let reused = seam.spawn_reused_pid(pid, OpKind::Exec, &argv);

        // An attempted timeout kill on the CONSUMED handle — exactly what the
        // old detached-pid kill could still do — must be a NO-OP: no error,
        // nothing recorded, nothing signalled.
        kill().expect("a kill after the reap must not raise an error");
        assert!(
            !reused.killed.load(Ordering::SeqCst),
            "the unrelated process holding the recycled pid must never be killed"
        );

        // The log: exactly one kill of the reaped child, before its single
        // reap, and NOTHING after the reap can target the pid again — not
        // even once the pid was recycled to the unrelated child.
        assert_eq!(
            state.kill_pids(),
            vec![pid],
            "the reaped child must be killed exactly once"
        );
        assert_eq!(
            state.reap_pids(),
            vec![pid],
            "the reaped child must be reaped exactly once"
        );
        let log = state.log.lock().unwrap();
        let kill_pos = log
            .iter()
            .position(|e| matches!(e, LogEntry::Kill { .. }))
            .expect("the kill must be recorded");
        let reap_pos = log
            .iter()
            .position(|e| matches!(e, LogEntry::Reap { .. }))
            .expect("the reap must be recorded");
        assert!(kill_pos < reap_pos, "kill must precede reap");
        assert!(
            !log[reap_pos + 1..]
                .iter()
                .any(|e| matches!(e, LogEntry::Kill { pid: p } if *p == pid)),
            "no kill may target the reaped child's pid after its reap"
        );
        assert!(
            matches!(log.last(), Some(LogEntry::Spawn { pid: p, .. }) if *p == pid),
            "the reused-pid spawn must be the last recorded event"
        );

        // Release the reaped waiter and collect it.
        barrier.wait();
        waiter
            .join()
            .expect("the wait thread must finish")
            .expect("the reaped child returns its output");
        assert_eq!(state.live_waiters(), 0);
    }

    proptest! {
        // The runner contract property: every generated (operation kind × stall
        // point) pair must honor the ONE-runner deadline/kill/reap semantics —
        // stalled children terminate as Timeout AND are reaped (exactly one
        // kill, then exactly one reap, kill before reap), completed/non-zero
        // children are never killed, spawn failures surface as transport errors
        // with nothing to kill or reap, and stdin-write/wait failures surface
        // their error (not a Timeout) only AFTER the child was reaped — the
        // reap count per pid is 1 for EVERY outcome, so no path ever returns
        // before reaping. FIXED SEED 0x5EED_5EED (repo style) + bounded cases
        // keep the suite deterministic and fast: the fake blocks only until the
        // tiny injected deadline, so no case ever sleeps more than ~25ms. The
        // scheduler-delay test below injects delays (spawn/kill/wait stages ×
        // sub-deadline/past-deadline durations) and asserts EVERY outcome —
        // Timeout, success, write error, wait error, spawn error — leaves
        // zero live waiters and the spawned child reaped exactly once.
        #![proptest_config(ProptestConfig {
            cases: crate::test_support::proptest_cases(16),
            rng_seed: RngSeed::Fixed(0x5EED_5EED),
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn every_ssh_operation_is_deadline_killed_and_reaped(
            pairs in prop::collection::vec((op_strategy(), stall_strategy()), 2..=6)
        ) {
            for (kind, stall) in pairs {
                run_one_pair(kind, stall);
            }
        }

        // The scheduler-delay property: the fake seam's spawn/kill/wait
        // closures inject a controllable delay (placement × duration, both
        // relative to the tiny injected deadline) so the deadline races the
        // kill and wait paths — a self-completing child delayed past the
        // deadline must still be killed and reaped, a delayed kill must not
        // lose the reap, and a reap that lands before the kill must make the
        // kill a no-op. EVERY returned outcome must leave ZERO live waiters
        // and the spawned child reaped exactly once.
        #[test]
        fn every_outcome_leaves_zero_live_waiters_and_a_reaped_child(
            random_cases in prop::collection::vec(
                (op_strategy(), stall_strategy(), delay_at_strategy(), delay_size_strategy()),
                1..=5,
            )
        ) {
            // Every generated vector PREPENDS one guaranteed deadline-crossing
            // pair (a self-completing child whose wait is delayed past the
            // deadline): the property therefore provokes a kill-before-join
            // race in every single run — the injected delays cannot degenerate
            // into merely delaying everything — while the random legs cover
            // the complementary inside-the-deadline and kill-stage
            // interleavings (the join-before-kill reap side is also exercised
            // directly by the pid-reuse barrier test).
            let mut cases =
                vec![(OpKind::Upload, Stall::Complete, DelayAt::Wait, DelaySize::Past)];
            cases.extend(random_cases);
            for (kind, stall, at, size) in cases {
                run_one_delayed(kind, stall, at, size);
            }
        }
    }
}
