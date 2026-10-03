//! THE shared bounded child-runner for local command execution: the ONE owner
//! of every local command child, from spawn to the mandatory reap.
//!
//! # The lifecycle contract
//!
//! `LocalTransport::exec` used to split the child between the caller and a
//! DETACHED reaping thread and, on timeout, fire-and-forget an external
//! `kill -9 <pid>` and return a SUCCESSFUL timeout outcome — before the child
//! was proven dead and reaped, with a kill failure silently ignored and only
//! the direct child (never its process GROUP) signalled. This runner replaces
//! that with a bounded lifecycle:
//!
//! * **Synchronized child ownership** — the runner owns the `Child` handle
//!   exclusively from spawn until the single reap. There is no detached
//!   thread that can outlive the call, and no path that drops the handle
//!   un-reaped: the drop backstop kills and waits (bounded) as a final
//!   resort, so a live child is never abandoned even on an error path that
//!   cannot complete the reap itself.
//! * **Process-group termination (Unix)** — the child is spawned into its
//!   OWN process group (`process_group(0)` — the child becomes the group
//!   leader, pgid == pid), so a timeout terminates the WHOLE group (`killpg`
//!   SIGTERM, then — after a short grace — SIGKILL) and GRANDCHILDREN die
//!   with it. Windows has no process groups: the timeout terminates the
//!   direct child only (a background descendant survives — the documented
//!   weaker guarantee of the Windows port).
//! * **Mandatory wait/join before returning** — every returned outcome
//!   (success, timeout, error) happens only after the child was REAPED: the
//!   runner waits synchronously on its owned handle, `try_wait` consumes the
//!   exit status exactly once, and "proven dead" means the wait returned.
//! * **Foreground-only (Unix)** — commands must not daemonize. After the
//!   direct child exits, the runner checks its process group for LIVE
//!   leftover members (a background descendant the command left behind). The
//!   check is race-free by construction: the child is held as an UNREAPED
//!   ZOMBIE for its duration (`waitid(2)` with `WNOWAIT` — a zombie holds
//!   its pid, and therefore its process-group id (the child is the group
//!   leader, pgid == pid), allocated until reaped, so a `killpg` in that
//!   window can never hit a pid the OS recycled for an unrelated process),
//!   the group is ENUMERATED (Linux: a `/proc/*/stat` scan; macOS:
//!   `proc_listpgrp`) with our own zombie excluded, and any LIVE leftover
//!   member triggers the termination (TERM, grace, KILL — the timeout path's
//!   escalation) plus an ERROR — a command that leaves background processes
//!   is a contract violation, NEVER a successful outcome. The foreground
//!   containment INVARIANT (no live process after the return) covers
//!   IN-GROUP descendants only. A descendant that ESCAPED the group via
//!   `setsid` is OUTSIDE the guarantee: the runner can DETECT a
//!   pipe-holding escapee — the inherited stdio pipes EOF exactly when the
//!   last holder dies, so a pipe still open at the drain bound is a provable
//!   violation → error — but it CANNOT TERMINATE an escaped process, because
//!   no portable way to signal a process outside its group exists without
//!   cgroups/subreaper support (Linux) or a remote supervisor (ssh). The ONE
//!   documented exclusion covers BOTH setsid flavors: the pipe-holding
//!   escapee (detected → error, but not terminated) and the FULLY daemonized
//!   descendant (`setsid` AND closed descriptors — not even detectable);
//!   commands must not daemonize. A CLEAN command (no live members —
//!   the common case) pays one enumeration and its exit code and captured
//!   output are exactly as before. On Windows the foreground-only check is
//!   NOT performed (no process-group enumeration exists) — the documented
//!   weaker guarantee of the Windows port.
//! * **A timeout-kill failure is an ERROR** — if the group kill fails (a real
//!   failure, not the benign ESRCH of a group that is already gone), or the
//!   escalated kill fails, or the reap cannot be confirmed within the bound,
//!   the runner returns `Err` — NEVER a successful `exit_code: -1,
//!   "timed out"` outcome. Only a confirmed terminated-and-reaped group yields
//!   the timeout outcome.
//! * **Bounded** — the lifecycle is bounded: per-exec, no leaked threads
//!   (there are none), no leaked handles, no live processes across calls, and
//!   every kill/reap wait is bounded by a configurable deadline.
//!
//! The kill path is a [`KillSeam`] (a kill-function seam): production uses
//! [`RealKill`] (Unix: `killpg(2)` — no shell, no external `kill` binary;
//! Windows: the owned `Child::kill`), and the property test injects
//! syscall-level faults (a missing/unavailable kill, EPERM, ESRCH, an inert
//! kill) without any subprocess fakery. The process group + escalation
//! primitives are shared with the SSH runner's real seam
//! ([`kill_process_group`], [`TERM_TO_KILL_GRACE`]), so both transports
//! terminate process groups, not bare pids.
//!
//! # The platform split (ONE cfg switch at the module boundary)
//!
//! The platform-dependent lifecycle — spawn (process group vs plain), the
//! wait loop (`waitid` WNOWAIT peek vs `try_wait` poll), termination
//! (`killpg` vs `Child::kill`), the foreground-only check (group enumeration
//! vs none), and the pipe drain (`poll`/`fcntl` non-blocking vs reader
//! threads) — lives in the [`unix`] / [`windows`] submodules, selected by
//! the TWO `mod` declarations below. The rest of the crate calls the
//! re-exported surface and never sees the switch.
//!
//! # The shared liveness decision (single-sourced PER PLATFORM)
//!
//! "Is this process a LIVE member of the group?" must have exactly ONE
//! answer within a platform, or production's enumeration and the test oracle
//! drift (the bug that motivated this rule: an oracle that counted
//! `EXIT_DEAD` as live while production did not). The decision is
//! single-sourced per platform — NOT by one cross-platform predicate,
//! because the two kernels report a process's state in incompatible shapes:
//!
//! * Linux — `is_live_state` over the `/proc/<pid>/stat` state CHARACTER:
//!   `X` (`EXIT_DEAD`) and `Z` (`EXIT_ZOMBIE`) are not live; every other
//!   state, including an unknown one, is live. Production's
//!   `live_group_members` and the oracle's `probe_process` both call it.
//! * macOS — `unix::macos_status_is_not_live` over the BSD process STATUS
//!   (a number): `SZOMB` (= 5) is not live; every other status is live.
//!   Production reads the status as `pbi_status` through
//!   `proc_pidinfo(PROC_PIDTBSDINFO)`; the oracle reads it as `p_stat`
//!   through `sysctl(KERN_PROC_PID)` (it also needs the start-time token,
//!   and `proc_pidinfo` describes no zombie). The accessors differ; the
//!   decision is the one function.

use crate::env::SysEnv;
use std::path::PathBuf;
use std::process::{Child, ExitStatus};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

#[cfg(unix)]
pub use unix::RealKill;
#[cfg(unix)]
pub(crate) use unix::kill_process_group;
// The bounded pipe-drain discipline (non-blocking setup, the running-drain
// and the bounded post-exit drain) is re-exported so the SSH runner's Unix
// seam reuses ONE implementation instead of keeping a divergent copy. The
// [`OwnedChild`] drop backstop is NOT platform-specific (it is defined below,
// in this module), so BOTH platforms' seams share it.
#[cfg(unix)]
pub(crate) use unix::{DrainState, drain_available, drain_to_eof, set_nonblocking};
#[cfg(windows)]
pub use windows::RealKill;

/// Grace between the group SIGTERM and the escalated group SIGKILL: a child
/// (or grandchild) that handles TERM gracefully gets a chance to clean up,
/// one that ignores it is force-killed. Shared with the SSH runner's real
/// seam so both transports use the same termination policy.
pub(crate) const TERM_TO_KILL_GRACE: Duration = Duration::from_millis(200);

/// Bound on the post-termination reap: after the escalation, the child must
/// be collected within this window or the runner reports a reap failure. A
/// SIGKILL'd child dies in microseconds; this bound only guards the
/// pathological cases (an ineffective kill), so it is generous in production
/// and tiny in tests (see [`RunnerConfig::reap_bound`]).
pub(crate) const KILL_REAP_BOUND: Duration = Duration::from_secs(2);

/// THE single LINUX definition of "this `/proc/<pid>/stat` state field names
/// a LIVE process", shared by production's group-member enumeration (the
/// Linux arm of `live_group_members`) and the test oracle's classification
/// (`probe_process`), so the two can never drift apart again. macOS has its
/// own single definition, `unix::macos_status_is_not_live`; the two
/// platforms do NOT share one predicate, because their state encodings are
/// incompatible (a state character vs a numeric BSD status).
///
/// The kernel emits exactly the state characters in `fs/proc/array.c`'s
/// `task_state_array`, selected by `task_index_to_char` in
/// `include/linux/sched.h`:
///
/// * LIVE — `R` running, `S` sleeping, `D` disk sleep, `T` stopped,
///   `t` tracing stop, `P` parked, `I` idle. A stopped/traced task is not
///   exiting: it keeps its resources and can resume, so it is a live group
///   member.
/// * NOT live — `X` dead and `Z` zombie. `X` is `EXIT_DEAD`: the task has
///   already finished exiting (`__task_state_index` reports `X` whenever
///   `exit_state` holds `EXIT_DEAD`) and only awaits its final release, so
///   it must NOT be counted as a live member; `Z` is `EXIT_ZOMBIE`: exited
///   but held unreaped.
///
/// `task_index_to_char` is `"RSDTtXZPI"`: the kernel never emits a lowercase
/// `z` or `x`, but they are accepted as the same dead states defensively. Any
/// other string is not a state a kernel can report (a malformed `stat` line);
/// it conservatively counts as LIVE, so a malformed entry can never let a
/// leftover escape the foreground-only check.
#[cfg(any(target_os = "linux", all(test, unix)))]
pub(crate) fn is_live_state(state: &str) -> bool {
    !matches!(state, "X" | "Z" | "x" | "z")
}

/// The kill seam behind [`ChildRunner`]: the syscall-level termination
/// surface, injectable for tests (a kill-function pointer seam). The runner
/// reports a kill failure as an error only when the seam says the signal
/// could not be delivered; an inert seam (returns `Ok` without signalling) is
/// caught by the reap bound instead.
///
/// Public because [`RunnerConfig`] is public and takes an `Arc<dyn KillSeam>`:
/// a caller building its own [`RunnerConfig`] (and a test injecting a
/// syscall-level fault) needs the trait to name its seam. The crate's own
/// tests drive the runner under injected kill faults through it.
pub trait KillSeam: Send + Sync {
    /// Signal the whole process group `pgid`. On Windows (no process
    /// groups) the implementation falls back to the owned child.
    fn kill_group(&self, pgid: i32, sig: i32) -> std::io::Result<()>;
    /// Signal the OWNED child directly (`Child::kill`): the last-resort rung
    /// that catches a child which escaped its group (e.g. `setsid`), where
    /// the group kill reports the group unreachable. A kill through the owned
    /// handle can never hit a pid the OS recycled: the handle is consumed by
    /// the single reap and nothing is signalled after it.
    fn kill_owned(&self, child: &mut Child) -> std::io::Result<()>;
}

/// The [`OwnedChild::drop`] backstop's bounded wait: after killing the group
/// and the owned child, drop waits this long for the reap before giving up —
/// long enough for a real SIGKILL/TerminateProcess to land (microseconds),
/// short enough that a test-injected inert kill cannot stall a suite.
const DROP_REAP_BOUND: Duration = Duration::from_millis(100);

/// The signal [`OwnedChild::drop`] delivers to the child's process group.
/// `SIGKILL` on Unix; unused on Windows, where [`KillSeam::kill_group`] is a
/// no-op and the owned handle (`TerminateProcess`) is the termination path.
#[cfg(unix)]
const DROP_KILL_SIGNAL: i32 = libc::SIGKILL;
#[cfg(windows)]
const DROP_KILL_SIGNAL: i32 = 0;

/// An owned child with a drop backstop, shared by BOTH real runners AND both
/// platforms so the "every error path leaves no uncollected child" contract
/// has ONE implementation. The local runner owns one directly; the SSH
/// runner's seam owns one inside its shared slot (the same type, the same
/// `Drop`), so a `drain_available`/`try_wait` error that returns early from
/// the wait closure cannot abandon a live `Child` (whose own `Drop` neither
/// waits nor kills — on Unix OR on Windows).
///
/// The handle is shared EXCLUSIVELY between a runner's deadline/kill path and
/// its wait path. A child that exited is consumed by [`OwnedChild::wait`] (or
/// marked with [`OwnedChild::mark_reaped`] when the reap already happened
/// through `try_wait`), after which nothing may signal anything (a pid the OS
/// recycled after the reap can never be hit — the drop backstop returns early).
///
/// The backstop's GROUP kill is a no-op on Windows (no process groups), so
/// there it terminates the direct child only and reaps it — the documented
/// weaker guarantee of the Windows port, with the SAME one-authority backstop
/// shape.
pub(crate) struct OwnedChild {
    /// The owned child. `pub(crate)` so a seam's wait closure can drain its
    /// pipes and poll it; the handle is never signalled directly on Unix — the
    /// kill path goes through [`KillSeam`] / `killpg` so a group, not a bare
    /// pid, is signalled.
    pub(crate) child: Child,
    kill: Arc<dyn KillSeam>,
    /// Set once the exit status is consumed (or the OS has already reaped the
    /// child): from then on nothing may signal anything (a pid the OS recycled
    /// after the reap can never be hit — the drop backstop returns early).
    reaped: bool,
}

impl OwnedChild {
    /// Wrap a freshly spawned child with the drop backstop under the kill
    /// `seam`. On Unix the child is assumed to be spawned into its OWN process
    /// group (pgid == pid) by the caller, so the backstop's `kill_group`
    /// terminates its whole group; on Windows `kill_group` is a no-op and the
    /// owned handle is terminated.
    pub(crate) fn new(child: Child, kill: Arc<dyn KillSeam>) -> Self {
        OwnedChild {
            child,
            kill,
            reaped: false,
        }
    }

    /// Reap the child (a blocking wait on an already-exited zombie returns
    /// immediately with its status) and mark the handle reaped: from here on
    /// nothing may signal anything — the pid is released by this call.
    pub(crate) fn wait(&mut self) -> std::io::Result<ExitStatus> {
        let st = self.child.wait()?;
        self.reaped = true;
        Ok(st)
    }

    /// Mark the handle collected after a `try_wait`/`waitid` peek ALREADY
    /// reaped the child, so the kill and drop backstops never signal the
    /// released pid.
    pub(crate) fn mark_reaped(&mut self) {
        self.reaped = true;
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // Final backstop: never abandon a live child. Kill the whole group
        // (a no-op on Windows), then the owned handle, then wait (bounded) for
        // the reap. Under the production seam a real SIGKILL/TerminateProcess
        // lands in microseconds; under an injected inert kill the bound
        // expires and the child is left to the test's own cleanup (the fault is
        // exactly the kill not working).
        let pgid = self.child.id() as i32;
        let _ = self.kill.kill_group(pgid, DROP_KILL_SIGNAL);
        let _ = self.kill.kill_owned(&mut self.child);
        let budget = Instant::now() + DROP_REAP_BOUND;
        while Instant::now() < budget {
            if let Ok(Some(_)) = self.child.try_wait() {
                self.reaped = true;
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// The runner's policy knobs: termination timing, the reap bound, the kill
/// seam, and (tests only) the spawn/reap observers that record the lifecycle
/// in the parent. Construct via [`RunnerConfig::production`]; tests build
/// their own with injected faults and tiny bounds.
pub struct RunnerConfig {
    /// Grace between the group SIGTERM and the escalated group SIGKILL.
    pub term_to_kill_grace: Duration,
    /// Bound on the post-termination reap: if the child is still alive this
    /// long after the timeout fired, the termination is ineffective and the
    /// runner reports a reap failure (never a fake timeout success).
    pub reap_bound: Duration,
    /// The kill seam (production: [`RealKill`]; tests: injected faults).
    pub kill: Arc<dyn KillSeam>,
    /// Spawn observer: called synchronously in the parent right
    /// after a successful spawn with the child's pid — before the timeout
    /// clock starts — so a test can assert the pid is gone afterwards without
    /// any child-written pidfile (which would race the deadline kill).
    pub spawn_observer: Option<Arc<dyn Fn(u32) + Send + Sync>>,
    /// Reap observer: called exactly once, at the single reap.
    pub reap_observer: Option<Arc<dyn Fn(u32) + Send + Sync>>,
}

impl RunnerConfig {
    /// The production configuration: 200ms TERM→KILL grace, a 2s reap bound,
    /// and the real kill seam.
    pub fn production() -> Self {
        RunnerConfig {
            term_to_kill_grace: TERM_TO_KILL_GRACE,
            reap_bound: KILL_REAP_BOUND,
            kill: Arc::new(RealKill),
            spawn_observer: None,
            reap_observer: None,
        }
    }
}

/// How a runner invocation ended, before the transport maps it to its own
/// outcome shape. The timeout variant exists ONLY after the child (and its
/// group) was proven dead and reaped.
#[derive(Debug)]
pub enum RunOutcome {
    /// The child exited (or was killed by a signal) before the timeout fired.
    Exited {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    /// The timeout fired; the child (and its group on Unix) was terminated
    /// AND reaped.
    TimedOut { stderr: String },
}

/// How a runner invocation failed. Every variant is returned only AFTER the
/// runner cleaned up the child (kill + reap where possible) — an error can
/// never leave a live, un-reaped child behind by contract (the drop backstop
/// covers the paths where even that is impossible).
#[derive(Debug)]
pub enum RunError {
    /// The child could not be spawned.
    Spawn(String),
    /// Waiting on the child failed (wait error, pipe read error).
    Wait(String),
    /// The command exited but left members of its process group alive — a
    /// background descendant the command spawned outlived it. The group was
    /// terminated (TERM → KILL) and the violation is reported as an error:
    /// commands are FOREGROUND-ONLY, a command that leaves background
    /// processes is never a successful outcome. (Unix only — Windows has no
    /// process-group enumeration, so this variant is never produced there.)
    Background(String),
    /// A timeout-termination signal could not be delivered (kill failure).
    Kill(String),
    /// The child was not collected within the reap bound after termination.
    Reap(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Spawn(m) => write!(f, "{m}"),
            RunError::Wait(m) => write!(f, "{m}"),
            RunError::Background(m) => write!(f, "{m}"),
            RunError::Kill(m) => write!(f, "kill failure: {m}"),
            RunError::Reap(m) => write!(f, "reap failure: {m}"),
        }
    }
}

/// THE shared bounded child-runner for local command execution: spawn the
/// child (into its OWN process group on Unix), wait with the caller's
/// timeout, on timeout terminate (TERM, grace, KILL on Unix; the owned
/// child on Windows), and return every outcome — success, timeout, error —
/// only after the child was REAPED exactly once. A timeout-kill or reap
/// failure is an ERROR, never a successful timeout outcome.
///
/// The runner is per-exec and owns nothing between calls: the child lives
/// inside the platform exec and is collected before the call returns, so
/// there are no leaked threads, handles, or processes across calls — the
/// lifecycle is bounded.
pub struct ChildRunner {
    /// The child environment snapshot: every spawned child receives THIS
    /// snapshot as its ENTIRE environment ([`SysEnv::apply_to_command`]:
    /// `env_clear` first, then the snapshot's variables) — deterministic and
    /// hermetic, never whatever the parent env looks like at spawn time.
    env: SysEnv,
    /// The child's working directory (the transport root).
    cwd: PathBuf,
    config: RunnerConfig,
}

impl ChildRunner {
    /// Build a runner that spawns children with the environment snapshot
    /// `env` in working directory `cwd` under the policy `config`.
    pub fn new(env: &SysEnv, cwd: PathBuf, config: RunnerConfig) -> Self {
        ChildRunner {
            env: env.clone(),
            cwd,
            config,
        }
    }

    /// Execute `argv` (no shell) bounding the CHILD by `timeout`. Returns
    /// [`RunOutcome::Exited`] when the child finishes in time (exit code +
    /// captured stdout/stderr) AND (on Unix) left no members of its process
    /// group behind (commands are FOREGROUND-ONLY), [`RunOutcome::TimedOut`]
    /// ONLY after the child (and its group on Unix) was terminated AND the
    /// child was reaped, or an error when the spawn, the wait, the
    /// termination kill, or the reap failed — a failed timeout kill never
    /// yields a successful timeout outcome, and a command that exited but
    /// left background processes in its group is a violation, never a
    /// successful outcome. `timeout` is ADDITIVE with the termination and
    /// bounded-drain tail (TERM grace + the post-exit drain), so a timed-out
    /// call returns up to about `timeout + 2.2 s` later, never at `timeout`
    /// exactly; a command that exits inside `timeout` still reports its real
    /// result (a pipe-holding leftover is [`RunError::Background`], never a
    /// deadline flip). The platform-specific lifecycle (process groups, the
    /// foreground-only check, the pipe drain) lives in the [`unix`] /
    /// [`windows`] submodules.
    pub fn exec(
        &self,
        argv: &[String],
        timeout: Duration,
    ) -> std::result::Result<RunOutcome, RunError> {
        platform::exec(&self.env, &self.cwd, &self.config, argv, timeout)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Instant;

    /// How long the oracle polls for a process to disappear. The runner's own
    /// reap/kill bound is seconds, so this must outlast a correct run while
    /// staying finite: a genuinely live leftover keeps the assertion failing
    /// after the budget instead of hanging the suite.
    const GONE_BUDGET: Duration = Duration::from_secs(5);

    /// The identity of a process: its pid plus the kernel's start-time token.
    /// The token is fixed for a process's whole life and distinct between any
    /// two processes that ever held the same pid, so a pid the OS recycled to
    /// an unrelated process can never be mistaken for the tracked one.
    #[derive(Clone, Copy, Debug)]
    struct ProcessId {
        pid: u32,
        start: u64,
    }

    /// The kernel's view of a pid. A ZOMBIE has exited but is not yet reaped.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ProcessState {
        Live,
        Zombie,
    }

    impl ProcessState {
        /// Classify a `/proc/<pid>/stat` state field through the SAME Linux
        /// [`is_live_state`] predicate production's Linux arm uses. The
        /// oracle does not re-derive the live/gone rule, so an
        /// oracle/production divergence is impossible by construction. (The
        /// macOS arm shares `unix::macos_status_is_not_live` the same way.)
        fn of_proc_state(state: &str) -> Self {
            if is_live_state(state) {
                ProcessState::Live
            } else {
                ProcessState::Zombie
            }
        }
    }

    /// The kernel's `(state, start-time token)` for `pid`, or `None` when the
    /// pid names no process at all (reaped, or never existed). A ZOMBIE is
    /// reported with the start token it had while alive — which is what lets
    /// [`ProcessId::capture`] record a child that exited before the observer
    /// ran — but is never reported as live. Both arms share production's ONE
    /// liveness decision for their platform rather than agreeing with
    /// `kill(pid, 0)` (which a zombie still answers): on Linux,
    /// [`is_live_state`] over the `/proc` state character (with `X` =
    /// `EXIT_DEAD` also not live); on macOS, `macos_status_is_not_live` over
    /// the `p_stat` status this accessor reads.
    #[cfg(target_os = "macos")]
    fn probe_process(pid: u32) -> Option<(ProcessState, u64)> {
        // `KERN_PROC_PID` fills a `struct kinfo_proc`: `p_starttime` is two
        // u64 halves at offset 0 and `p_stat` at offset 36 — and, unlike
        // `proc_pidinfo(PROC_PIDTBSDINFO)` (which returns nothing for a
        // zombie), it ALSO describes zombies, the property the identity
        // capture relies on. The buffer is DELIBERATELY larger than today's
        // 648-byte struct (whose prefix layout is the stable part) so a future
        // growth still returns a readable entry rather than a short write. A
        // reaped pid yields a zero-length result (rc == 0, len == 0).
        const P_STAT_OFFSET: usize = 36;
        let mut buf = [0u8; 1024];
        let mut len = buf.len();
        let mut mib = [
            libc::CTL_KERN,
            libc::KERN_PROC,
            libc::KERN_PROC_PID,
            pid as i32,
        ];
        // SAFETY: `sysctl` writes the kernel's process entry into `buf`; the
        // mib is the documented `KERN_PROC_PID` selector and `len` starts as
        // the buffer size and is updated by the kernel to the bytes written.
        let rc = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                buf.as_mut_ptr().cast(),
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 || len < P_STAT_OFFSET + 1 {
            return None;
        }
        let sec = u64::from_ne_bytes(buf[0..8].try_into().unwrap());
        let usec = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
        let state = if unix::macos_status_is_not_live(u32::from(buf[P_STAT_OFFSET])) {
            ProcessState::Zombie
        } else {
            ProcessState::Live
        };
        Some((state, sec * 1_000_000 + usec))
    }

    /// Linux: `/proc/<pid>/stat` — `pid (comm) state ppid ...`, with
    /// `starttime` as field 22 (19 fields after `state`). A zombie is still
    /// listed (it holds the pid) with its original start token; a reaped pid
    /// is unreadable and reads as absent.
    #[cfg(target_os = "linux")]
    fn probe_process(pid: u32) -> Option<(ProcessState, u64)> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // `comm` may contain spaces AND ')' — anchor on the LAST ')'.
        let rest = stat.rsplit_once(')')?.1;
        let mut fields = rest.split_whitespace();
        let state = fields.next()?;
        // `state` is field 3; `starttime` is field 22, i.e. `nth(18)` of the
        // fields that follow `state` (field 4 is `nth(0)`).
        let start: u64 = fields.nth(18)?.parse().ok()?;
        let state = ProcessState::of_proc_state(state);
        Some((state, start))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn probe_process(_pid: u32) -> Option<(ProcessState, u64)> {
        compile_error!("the process oracle is implemented for Linux and macOS only");
    }

    /// The bounded poll shared by the oracles: `true` once the pid names
    /// nothing, a ZOMBIE, or a process whose start token differs (the pid was
    /// recycled and the tracked process is gone); `false` only while the SAME
    /// live process is still there when the budget expires.
    fn wait_until<F>(pid: u32, budget: Duration, gone: F) -> bool
    where
        F: Fn(ProcessState, u64) -> bool,
    {
        let deadline = Instant::now() + budget;
        loop {
            match probe_process(pid) {
                None => return true,
                Some((state, start)) if gone(state, start) => return true,
                Some(_) => {}
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    impl ProcessId {
        /// Record `pid`'s identity while it is known to be the tracked
        /// process. `None` only when the pid already names nothing; a zombie
        /// still yields its token, so a child that exited before the observer
        /// ran is still captured.
        fn capture(pid: u32) -> Option<Self> {
            probe_process(pid).map(|(_, start)| ProcessId { pid, start })
        }

        /// Bounded wait for THIS process to be GONE by the runner's own
        /// definition of alive: `live_group_members` excludes zombies, so a
        /// zombie is dead, and a recycled pid carries a different start token
        /// so it is a different process. `false` means the same live process
        /// outlived the budget — a genuine leftover, which must fail the test.
        fn wait_until_gone(self, budget: Duration) -> bool {
            wait_until(self.pid, budget, |state, start| {
                state == ProcessState::Zombie || start != self.start
            })
        }
    }

    /// The token-less fallback, used only where an identity could not be
    /// captured before the kill (a starved capture poll): gone means the pid
    /// names nothing or a ZOMBIE. A live process still fails, so a genuine
    /// leftover is never missed — only the pid-reuse guard is unavailable.
    fn wait_until_not_live(pid: u32, budget: Duration) -> bool {
        wait_until(pid, budget, |state, _| state == ProcessState::Zombie)
    }

    /// Poll `marker` for the pid the shell writes, then capture that process's
    /// identity WHILE IT IS STILL THE ORIGINAL — before the runner's timeout
    /// kill re-parents it and launchd reaps it, when the pid could be
    /// recycled. `None` when the marker never appeared or the pid was already
    /// reaped; the caller then falls back to the token-less check.
    fn capture_grandchild(marker: &std::path::Path, budget: Duration) -> Option<ProcessId> {
        let deadline = Instant::now() + budget;
        loop {
            // Require the trailing newline `echo` writes: a marker seen
            // without it is a PARTIAL write, and parsing a truncated pid would
            // track an unrelated process.
            if let Ok(text) = std::fs::read_to_string(marker)
                && text.ends_with('\n')
                && let Ok(pid) = text.trim().parse::<u32>()
            {
                return ProcessId::capture(pid);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn fixture_runner(cwd: &std::path::Path, config: RunnerConfig) -> ChildRunner {
        ChildRunner::new(&SysEnv::from_process(), cwd.to_path_buf(), config)
    }

    /// A promptly-completing child returns its exit code and captured output,
    /// the single reap is observed (never a zombie), and the recorded pid is
    /// gone after the call.
    #[test]
    fn quick_child_is_reaped_and_output_captured() {
        let pid_slot: Arc<Mutex<Option<ProcessId>>> = Arc::new(Mutex::new(None));
        let reaped = Arc::new(AtomicBool::new(false));
        let config = RunnerConfig {
            spawn_observer: Some({
                let slot = pid_slot.clone();
                Arc::new(move |pid: u32| *slot.lock().unwrap() = ProcessId::capture(pid))
            }),
            reap_observer: Some({
                let reaped = reaped.clone();
                Arc::new(move |_pid: u32| reaped.store(true, Ordering::SeqCst))
            }),
            ..RunnerConfig::production()
        };
        let env = SysEnv::from_process();
        let runner = fixture_runner(&env.temp_dir(), config);
        let out = runner
            .exec(
                &["sh".into(), "-c".into(), "printf ok; exit 3".into()],
                Duration::from_secs(5),
            )
            .expect("a promptly-completing child must succeed");
        match out {
            RunOutcome::Exited {
                exit_code, stdout, ..
            } => {
                assert_eq!(exit_code, 3);
                assert_eq!(stdout, "ok");
            }
            other => panic!("expected Exited, got {other:?}"),
        }
        let pid = pid_slot
            .lock()
            .unwrap()
            .expect("the spawn observer must record the pid at spawn time");
        assert!(
            pid.wait_until_gone(GONE_BUDGET),
            "child {} must be reaped, not signalled-and-left",
            pid.pid
        );
        assert!(
            reaped.load(Ordering::SeqCst),
            "the reap observer must fire exactly once"
        );
    }

    /// A child that outlives the timeout is killed WITH ITS WHOLE PROCESS
    /// GROUP (the backgrounded grandchild dies too) and the outcome is
    /// `TimedOut` only after the reap.
    #[test]
    fn timeout_kills_the_whole_process_group() {
        let env = SysEnv::from_process();
        let dir = tempfile::Builder::new()
            .tempdir_in(env.temp_dir())
            .expect("tempdir");
        let marker = dir.path().join("grandchild.pid");
        let config = RunnerConfig {
            term_to_kill_grace: Duration::from_millis(50),
            reap_bound: Duration::from_secs(5),
            ..RunnerConfig::production()
        };
        let runner = fixture_runner(dir.path(), config);
        let script = format!("sleep 30 & echo $! > {}; wait", marker.display());
        // Capture the grandchild's identity CONCURRENTLY with the run, while
        // it is still the original process: after the group kill it is
        // re-parented and launchd reaps it asynchronously, and only a token
        // taken before that can tell it apart from a recycled pid.
        let captured = {
            let marker = marker.clone();
            let reader = std::thread::spawn(move || capture_grandchild(&marker, GONE_BUDGET));
            let out = runner
                .exec(
                    &["sh".into(), "-c".into(), script],
                    Duration::from_millis(500),
                )
                .expect("the timeout path must terminate and reap the group");
            assert!(
                matches!(out, RunOutcome::TimedOut { .. }),
                "expected TimedOut, got {out:?}"
            );
            reader
                .join()
                .expect("the identity-capture thread must not panic")
        };
        let grandchild: u32 = std::fs::read_to_string(&marker)
            .expect("the child writes the grandchild pid immediately")
            .trim()
            .parse()
            .expect("pid");
        match captured {
            Some(id) => assert!(
                id.wait_until_gone(GONE_BUDGET),
                "the grandchild {} must die with the group (not merely be signalled, and not linger as a zombie)",
                id.pid
            ),
            None => assert!(
                wait_until_not_live(grandchild, GONE_BUDGET),
                "the grandchild {grandchild} must die with the group"
            ),
        }
    }

    /// The foreground-only contract: a child that exits but leaves a live
    /// member of its process group behind is reported as an ERROR (the group
    /// is terminated), never a successful outcome.
    #[test]
    fn exiting_child_that_leaves_a_background_process_is_an_error() {
        let env = SysEnv::from_process();
        let dir = tempfile::Builder::new()
            .tempdir_in(env.temp_dir())
            .expect("tempdir");
        let marker = dir.path().join("leftover.pid");
        let config = RunnerConfig {
            term_to_kill_grace: Duration::from_millis(50),
            reap_bound: Duration::from_secs(5),
            ..RunnerConfig::production()
        };
        let runner = fixture_runner(dir.path(), config);
        let script = format!("sleep 30 & echo $! > {}; exit 0", marker.display());
        // Same concurrent identity capture as the timeout test: the leftover
        // is killed by the foreground-only check and reaped asynchronously.
        let captured = {
            let marker = marker.clone();
            let reader = std::thread::spawn(move || capture_grandchild(&marker, GONE_BUDGET));
            let err = runner
                .exec(&["sh".into(), "-c".into(), script], Duration::from_secs(5))
                .expect_err("a command that leaves background processes must error");
            assert!(
                matches!(err, RunError::Background(_)),
                "expected Background, got {err:?}"
            );
            reader
                .join()
                .expect("the identity-capture thread must not panic")
        };
        let leftover: u32 = std::fs::read_to_string(&marker)
            .expect("the child writes the leftover pid immediately")
            .trim()
            .parse()
            .expect("pid");
        match captured {
            Some(id) => assert!(
                id.wait_until_gone(GONE_BUDGET),
                "the leftover {} must be terminated, not merely signalled and left",
                id.pid
            ),
            None => assert!(
                wait_until_not_live(leftover, GONE_BUDGET),
                "the leftover {leftover} must be terminated"
            ),
        }
    }

    /// Every returned outcome happens only after the child was reaped: a
    /// timeout kill failure is an error, and no live child survives the call.
    #[test]
    fn timed_out_child_is_never_left_live() {
        let pid_slot: Arc<Mutex<Option<ProcessId>>> = Arc::new(Mutex::new(None));
        let config = RunnerConfig {
            term_to_kill_grace: Duration::from_millis(50),
            reap_bound: Duration::from_secs(5),
            spawn_observer: Some({
                let slot = pid_slot.clone();
                Arc::new(move |pid: u32| *slot.lock().unwrap() = ProcessId::capture(pid))
            }),
            ..RunnerConfig::production()
        };
        let env = SysEnv::from_process();
        let runner = fixture_runner(&env.temp_dir(), config);
        let out = runner
            .exec(
                &["sh".into(), "-c".into(), "exec sleep 30".into()],
                Duration::from_millis(200),
            )
            .expect("the timeout path must terminate and reap");
        assert!(matches!(out, RunOutcome::TimedOut { .. }));
        let pid = pid_slot.lock().unwrap().expect("spawn observer");
        assert!(
            pid.wait_until_gone(GONE_BUDGET),
            "child {} must be reaped, not left live",
            pid.pid
        );
    }

    /// The shared LINUX predicate's mapping over every state the kernel can
    /// emit, plus the defensive lowercase and unknown cases. Pinned so the
    /// ONE Linux definition cannot drift: production's Linux enumeration and
    /// the oracle both read this mapping.
    #[test]
    fn is_live_state_classifies_kernel_states() {
        // LIVE: the non-exit states `task_state_array` can report.
        for state in ["R", "S", "D", "T", "t", "P", "I"] {
            assert!(is_live_state(state), "{state} is a live kernel state");
        }
        // DEAD: `X` (EXIT_DEAD) and `Z` (EXIT_ZOMBIE), plus the lowercase
        // spellings a kernel never emits but a defensive reader accepts.
        for state in ["X", "Z", "x", "z"] {
            assert!(!is_live_state(state), "{state} is a dead kernel state");
        }
        // Unknown or malformed input conservatively counts as LIVE, so a
        // leftover can never hide behind an unparsed state.
        for state in ["", "Q", "?", "RS", " Z", "r"] {
            assert!(
                is_live_state(state),
                "{state:?} is not a kernel state and must default to live"
            );
        }
    }

    /// The oracle's own semantics, pinned against the kernel's state table so
    /// it can never silently diverge from production. The shared rule is PER
    /// PLATFORM: on Linux the oracle classifies a `/proc` state character
    /// through the SAME `is_live_state` predicate production uses, and the
    /// state-table loop below pins that mapping — so a regression that counts
    /// `X` (EXIT_DEAD) as live again, the exact bug this definition exists to
    /// catch, fails here. On macOS the oracle classifies the BSD status
    /// through the SAME `unix::macos_status_is_not_live` production uses
    /// (pinned by `macos_status_classifies_bsd_process_states` in `unix`),
    /// and the live-child and un-reaped-zombie probes below exercise that
    /// shared decision end to end. On top of the table: a LIVE process is not
    /// gone, a ZOMBIE is gone, and a pid whose start token moved is a
    /// DIFFERENT process, so the tracked one is gone even though the number
    /// still answers.
    #[test]
    fn process_oracle_matches_the_live_definition() {
        // The Linux kernel state table, checked through the shared
        // `is_live_state` predicate AND the oracle's derivation from it.
        // Pinning the shared rule pins both sides at once (the oracle does
        // not re-derive it).
        for state in ["R", "S", "D", "T", "t", "P", "I"] {
            assert!(
                is_live_state(state),
                "{state} is a live kernel state; production and the oracle must agree it is live"
            );
            assert_eq!(
                ProcessState::of_proc_state(state),
                ProcessState::Live,
                "the oracle must classify {state} as live, matching production"
            );
        }
        for state in ["X", "Z", "x", "z"] {
            assert!(
                !is_live_state(state),
                "{state} is a dead kernel state (X = EXIT_DEAD, Z = EXIT_ZOMBIE); \
                 production must not count it as a live member"
            );
            assert_eq!(
                ProcessState::of_proc_state(state),
                ProcessState::Zombie,
                "the oracle must classify {state} as gone, matching production"
            );
        }

        // A live child is NOT gone, even after the budget elapses.
        let mut live = std::process::Command::new("sleep")
            .arg("30")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn a live child");
        let live_id = ProcessId::capture(live.id()).expect("a live child is capturable");
        assert!(
            !live_id.wait_until_gone(Duration::from_millis(50)),
            "a live process must not read as gone: the oracle would be vacuous"
        );
        live.kill().expect("kill the live child");
        live.wait().expect("reap the live child");
        assert!(
            live_id.wait_until_gone(GONE_BUDGET),
            "a killed-and-reaped child must read as gone"
        );

        // A child left as an un-reaped ZOMBIE is gone: it still holds its pid,
        // so `kill(pid, 0)` succeeds, but the runner's `live_group_members`
        // excludes zombies — the exact definition the oracle must share.
        let mut zombie = std::process::Command::new("sh")
            .args(["-c", "exit 0"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn a promptly-exiting child");
        let zombie_id = {
            let deadline = Instant::now() + GONE_BUDGET;
            loop {
                match probe_process(zombie.id()) {
                    Some((ProcessState::Zombie, start)) => {
                        break ProcessId {
                            pid: zombie.id(),
                            start,
                        };
                    }
                    Some((ProcessState::Live, _)) => {}
                    None => panic!("the child vanished before it could be observed as a zombie"),
                }
                assert!(Instant::now() < deadline, "the child never became a zombie");
                std::thread::sleep(Duration::from_millis(1));
            }
        };
        assert!(
            zombie_id.wait_until_gone(GONE_BUDGET),
            "an un-reaped zombie must read as gone (the runner counts only live members)"
        );
        zombie.wait().expect("reap the zombie");

        // PID REUSE: the same pid with a moved start token is a different
        // process, so the tracked process is gone.
        let self_id = ProcessId::capture(std::process::id()).expect("this test process is live");
        let forged = ProcessId {
            start: self_id.start.wrapping_add(1),
            ..self_id
        };
        assert!(
            forged.wait_until_gone(Duration::from_millis(50)),
            "a pid whose start token moved must read as the tracked process being gone"
        );
    }
}
