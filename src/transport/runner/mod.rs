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

use crate::env::SysEnv;
use std::path::PathBuf;
use std::process::Child;
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

#[cfg(unix)]
pub use unix::{RealKill, kill_process_group};
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

/// The kill seam behind [`ChildRunner`]: the syscall-level termination
/// surface, injectable for tests (a kill-function pointer seam). The runner
/// reports a kill failure as an error only when the seam says the signal
/// could not be delivered; an inert seam (returns `Ok` without signalling) is
/// caught by the reap bound instead.
///
/// Public so the serialized real-process lifecycle integration target
/// (`tests/process_lifecycle.rs`) can drive the runner under injected kill
/// faults.
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

    /// Execute `argv` (no shell) bounded by `timeout`. Returns
    /// [`RunOutcome::Exited`] when the child finishes in time (exit code +
    /// captured stdout/stderr) AND (on Unix) left no members of its process
    /// group behind (commands are FOREGROUND-ONLY), [`RunOutcome::TimedOut`]
    /// ONLY after the child (and its group on Unix) was terminated AND the
    /// child was reaped, or an error when the spawn, the wait, the
    /// termination kill, or the reap failed — a failed timeout kill never
    /// yields a successful timeout outcome, and a command that exited but
    /// left background processes in its group is a violation, never a
    /// successful outcome. The platform-specific lifecycle (process groups,
    /// the foreground-only check, the pipe drain) lives in the [`unix`] /
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

    /// True while `pid` answers `kill(pid, 0)`. A REAPED child (or a child
    /// that never existed) is gone: an uncollected ZOMBIE would still answer
    /// success, so this probe is the observable form of "killed AND reaped".
    fn pid_alive(pid: u32) -> bool {
        // SAFETY: `kill(pid, 0)` only probes existence; it sends no signal.
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }

    fn fixture_runner(cwd: &std::path::Path, config: RunnerConfig) -> ChildRunner {
        ChildRunner::new(&SysEnv::from_process(), cwd.to_path_buf(), config)
    }

    /// A promptly-completing child returns its exit code and captured output,
    /// the single reap is observed (never a zombie), and the recorded pid is
    /// gone after the call.
    #[test]
    fn quick_child_is_reaped_and_output_captured() {
        let pid_slot: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
        let reaped = Arc::new(AtomicBool::new(false));
        let config = RunnerConfig {
            spawn_observer: Some({
                let slot = pid_slot.clone();
                Arc::new(move |pid: u32| *slot.lock().unwrap() = Some(pid))
            }),
            reap_observer: Some({
                let reaped = reaped.clone();
                Arc::new(move |_pid: u32| reaped.store(true, Ordering::SeqCst))
            }),
            ..RunnerConfig::production()
        };
        let runner = fixture_runner(&std::env::temp_dir(), config);
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
        assert!(!pid_alive(pid), "child {pid} must be reaped");
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
        let grandchild: u32 = std::fs::read_to_string(&marker)
            .expect("the child writes the grandchild pid immediately")
            .trim()
            .parse()
            .expect("pid");
        assert!(
            !pid_alive(grandchild),
            "the grandchild {grandchild} must die with the group"
        );
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
        let err = runner
            .exec(&["sh".into(), "-c".into(), script], Duration::from_secs(5))
            .expect_err("a command that leaves background processes must error");
        assert!(
            matches!(err, RunError::Background(_)),
            "expected Background, got {err:?}"
        );
        let leftover: u32 = std::fs::read_to_string(&marker)
            .expect("the child writes the leftover pid immediately")
            .trim()
            .parse()
            .expect("pid");
        assert!(
            !pid_alive(leftover),
            "the leftover {leftover} must be terminated"
        );
    }

    /// Every returned outcome happens only after the child was reaped: a
    /// timeout kill failure is an error, and no live child survives the call.
    #[test]
    fn timed_out_child_is_never_left_live() {
        let pid_slot: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
        let config = RunnerConfig {
            term_to_kill_grace: Duration::from_millis(50),
            reap_bound: Duration::from_secs(5),
            spawn_observer: Some({
                let slot = pid_slot.clone();
                Arc::new(move |pid: u32| *slot.lock().unwrap() = Some(pid))
            }),
            ..RunnerConfig::production()
        };
        let runner = fixture_runner(&std::env::temp_dir(), config);
        let out = runner
            .exec(
                &["sh".into(), "-c".into(), "exec sleep 30".into()],
                Duration::from_millis(200),
            )
            .expect("the timeout path must terminate and reap");
        assert!(matches!(out, RunOutcome::TimedOut { .. }));
        let pid = pid_slot.lock().unwrap().expect("spawn observer");
        assert!(!pid_alive(pid), "child {pid} must be reaped");
    }
}
