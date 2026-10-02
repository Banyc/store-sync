//! The Unix implementation of the bounded child-runner: process-group
//! lifecycle (`process_group(0)` spawn, `waitid` WNOWAIT peek, `killpg`
//! termination), the foreground-only group check (Linux `/proc` scan,
//! macOS `proc_listpgrp`), and `poll`/`fcntl` non-blocking pipe drains.
//! Selected by the single `#[cfg(unix)]` `mod` declaration in [`super`].

use super::*;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, ExitStatus, Stdio};
use std::time::Instant;

/// The [`OwnedChild::drop`] backstop's bounded wait: after killing the group
/// and the owned child, drop waits this long for the reap before giving up —
/// long enough for a real SIGKILL to land (microseconds), short enough that a
/// test-injected inert kill cannot stall a suite.
const DROP_REAP_BOUND: Duration = Duration::from_millis(100);

pub fn kill_process_group(pgid: i32, sig: i32) -> std::io::Result<()> {
    // SAFETY: `killpg` on a process group this runner created for its own
    // child; `pgid` is the child's pid (positive) and `sig` is a valid libc
    // signal constant.
    let rc = unsafe { libc::killpg(pgid, sig) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// True when the direct child has EXITED but has NOT been reaped yet
/// (`waitid(2)` with `WNOHANG | WNOWAIT | WEXITED`): the child remains a
/// ZOMBIE, and a zombie holds its pid — and therefore its process-group id
/// (the child is the group leader, pgid == pid) — allocated until reaped.
/// The foreground-only check runs between this peek and the reap, so a
/// `killpg(pgid, ...)` in that window can never race a pid the OS recycled
/// for an unrelated process: the group being signalled is provably ours.
/// ECHILD (the child is gone — reaped or never ours) is treated as exited so
/// the caller proceeds to the reap instead of spinning.
fn child_exited_unreaped(pid: u32) -> std::io::Result<bool> {
    let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: `waitid` on our own child (a positive pid, the direct child of
    // this process); `WNOWAIT` leaves it waitable for the subsequent reap;
    // `WNOHANG` never blocks; `WEXITED` reports the exited transition; the
    // zero-initialized siginfo is written by the kernel only on success.
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as _,
            &mut si,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ECHILD) {
            return Ok(true);
        }
        return Err(e);
    }
    Ok(siginfo_pid(&si) != 0)
}

/// The `si_pid` of a `siginfo_t` after a successful `waitid`: a FIELD on
/// macOS, a METHOD on Linux (libc 0.2.155+ exposes the union members as
/// methods there) — the accessor hides the platform difference so the
/// caller is portable.
#[cfg(target_os = "linux")]
fn siginfo_pid(si: &libc::siginfo_t) -> libc::pid_t {
    // SAFETY: the union field is valid after a successful `waitid` wrote
    // the siginfo.
    unsafe { si.si_pid() }
}
#[cfg(not(target_os = "linux"))]
fn siginfo_pid(si: &libc::siginfo_t) -> libc::pid_t {
    si.si_pid
}

/// The LIVE members of the process group `pgid` — judged by the shared
/// `is_live_state` rule, so `Z` (EXIT_ZOMBIE) AND `X` (EXIT_DEAD) are
/// excluded — minus the runner's own child `exclude_pid`. This is the
/// FOREGROUND-ONLY detection:
/// after the direct child exits (held as a zombie), any remaining live member
/// is a background descendant the command left behind. The enumeration never
/// uses the fault-injected [`KillSeam`] — it is a pure detection primitive,
/// so an injected kill fault cannot turn a clean group into a false
/// "leftover". A scan error (a vanished/EPERM process mid-scan) skips that
/// entry; only a fully failed scan degrades to an empty list.
#[cfg(target_os = "linux")]
fn live_group_members(pgid: i32, exclude_pid: u32) -> Vec<i32> {
    let mut members = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return members;
    };
    for entry in entries.flatten() {
        // Bind the OsString first: `file_name().to_str()` borrows from a
        // temporary that dies at the end of the let-else, so the `&str`
        // would dangle (E0716).
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        if pid == exclude_pid as i32 {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // Format: `pid (comm) state ppid pgrp session ...` — `comm` may
        // contain spaces AND ')' — anchor on the LAST ')'.
        let Some(rest) = stat.rsplit_once(')') else {
            continue;
        };
        let mut fields = rest.1.split_whitespace();
        let state = fields.next().unwrap_or("");
        let _ppid = fields.next();
        let pgrp: i32 = fields.next().and_then(|s| s.parse().ok()).unwrap_or(-1);
        if pgrp == pgid && is_live_state(state) {
            members.push(pid);
        }
    }
    members
}

#[cfg(target_os = "macos")]
fn live_group_members(pgid: i32, exclude_pid: u32) -> Vec<i32> {
    // `proc_listpgrppids(3)`: the pids of every process in the group —
    // ZOMBIES INCLUDED (a killed descendant that launchd has not yet reaped
    // is still listed). A zombie is NOT live, so every member's state is
    // read via `proc_pidinfo(PROC_PIDTBSDINFO)` (the `pbi_status` field at
    // byte offset 4; `SZOMB` = 5) and zombies are excluded — otherwise a
    // command whose descendants were killed would be falsely reported as
    // having left background processes. Our own zombie child is excluded by
    // pid (it is the group leader, still waitable until we reap it). A
    // member whose state cannot be read has vanished (reaped) in the window
    // between the enumeration and the read — it is not live, so it is
    // excluded too.
    let mut buf = [0i32; 4096]; // room for up to 4096 group members
    let n = unsafe { proc_listpgrppids(pgid, buf.as_mut_ptr().cast(), (buf.len() * 4) as i32) };
    if n <= 0 {
        return Vec::new();
    }
    let n = (n as usize).min(buf.len());
    buf[..n]
        .iter()
        .copied()
        .filter(|p| *p != exclude_pid as i32 && !macos_is_not_live(*p))
        .collect()
}

/// Whether the member is NOT live — a zombie (`SZOMB` = 5) or already
/// vanished (reaped in the window between the enumeration and the read,
/// which makes `proc_pidinfo` fail): either way it must be EXCLUDED from
/// the live-members list, or a command whose descendants were killed would
/// be falsely reported as having left background processes.
#[cfg(target_os = "macos")]
fn macos_is_not_live(pid: i32) -> bool {
    // The first 8 bytes of `struct proc_bsdinfo` are `pbi_flags` (offset 0)
    // and `pbi_status` (offset 4, a uint32 copy of the process state); the
    // full struct (with rusage) is ~136 bytes on modern macOS, so the buffer
    // must be at least that large for `proc_pidinfo` to write anything. A
    // zombie (`SZOMB` = 5 from sys/proc.h) is not live. A failed read means
    // the process has vanished — not live either.
    const PROC_PIDTBSDINFO: i32 = 3;
    const SZOMB: u32 = 5;
    let mut bsd = [0u8; 256];
    let n = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            bsd.as_mut_ptr().cast(),
            bsd.len() as i32,
        )
    };
    if n < 8 {
        return true; // gone (or unreadable) — not a live member
    }
    u32::from_le_bytes([bsd[4], bsd[5], bsd[6], bsd[7]]) == SZOMB
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
unsafe extern "C" {
    fn proc_listpgrppids(pid: i32, buffer: *mut std::ffi::c_void, buffersize: i32) -> i32;
    fn proc_pidinfo(
        pid: i32,
        flavor: i32,
        arg: u64,
        buffer: *mut std::ffi::c_void,
        buffersize: i32,
    ) -> i32;
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn live_group_members(_pgid: i32, _exclude_pid: u32) -> Vec<i32> {
    compile_error!("live group-member enumeration is implemented for Linux and macOS only");
}

/// The kill seam behind [`ChildRunner`]: the syscall-level termination
/// surface, injectable for tests (a kill-function pointer seam). The runner
/// reports a kill failure as an error only when the seam says the signal
/// could not be delivered; an inert seam (returns `Ok` without signalling) is
/// caught by the reap bound instead.
///
/// Public so the serialized real-process lifecycle integration target
/// (`tests/process_lifecycle.rs`) can drive the runner under injected kill
pub struct RealKill;

impl KillSeam for RealKill {
    fn kill_group(&self, pgid: i32, sig: i32) -> std::io::Result<()> {
        kill_process_group(pgid, sig)
    }
    fn kill_owned(&self, child: &mut Child) -> std::io::Result<()> {
        child.kill()
    }
}

/// The runner's policy knobs: termination timing, the reap bound, the kill
/// seam, and (tests only) the spawn/reap observers that record the lifecycle
/// in the parent. Construct via [`RunnerConfig::production`]; tests build
struct OwnedChild {
    child: Child,
    kill: Arc<dyn KillSeam>,
    /// Set by the single successful `try_wait`: from then on the exit status
    /// is consumed and nothing may signal anything (a pid the OS recycled
    /// after the reap can never be hit — the drop backstop returns early).
    reaped: bool,
}

impl OwnedChild {
    /// Reap the child (a blocking wait on an already-exited zombie returns
    /// immediately with its status) and mark the handle reaped: from here on
    /// nothing may signal anything — the pid is released by this call.
    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        let st = self.child.wait()?;
        self.reaped = true;
        Ok(st)
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // Final backstop: never abandon a live child. Kill the whole group,
        // then the owned handle, then wait (bounded) for the reap. Under the
        // production seam a real SIGKILL lands in microseconds; under an
        // injected inert kill the bound expires and the child is left to the
        // test's own cleanup (the fault is exactly the kill not working).
        let pgid = self.child.id() as i32;
        let _ = self.kill.kill_group(pgid, libc::SIGKILL);
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

/// THE shared bounded child-runner for local command execution: spawn the
/// child into its OWN process group with piped stdout/stderr, wait with the
/// caller's timeout, on timeout terminate the GROUP (TERM, grace, KILL) and
/// escalate to the owned handle, and return every outcome — success, timeout,
/// error — only after the child was REAPED exactly once. A timeout-kill or
/// reap failure is an ERROR, never a successful timeout outcome.
///
/// The runner is per-exec and owns nothing between calls: the child lives in
/// `OwnedChild` inside [`exec`] and is collected before the call returns, so
/// there are no leaked threads, handles, or processes across calls — the
/// lifecycle is bounded.
///
/// Execute `argv` (no shell) bounded by `timeout` — the Unix lifecycle:
/// spawn into an OWN process group, `waitid` WNOWAIT peek, `killpg`
/// termination, the foreground-only group check, and `poll`/`fcntl`
/// non-blocking pipe drains. See [`super::ChildRunner::exec`] for the
/// contract.
pub(crate) fn exec(
    env: &SysEnv,
    cwd: &Path,
    config: &RunnerConfig,
    argv: &[String],
    timeout: Duration,
) -> std::result::Result<RunOutcome, RunError> {
    let mut cmd = std::process::Command::new(&argv[0]);
    env.apply_to_command(&mut cmd);
    cmd.args(&argv[1..]);
    cmd.current_dir(cwd);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // The child becomes its OWN process-group leader (pgid == pid):
    // timeout termination signals the WHOLE group, so grandchildren die
    // with it. Unix-only crate; `process_group` is the std Unix API.
    cmd.process_group(0);
    let child = cmd
        .spawn()
        .map_err(|e| RunError::Spawn(format!("spawn {argv:?}: {e}")))?;
    let mut owned = OwnedChild {
        child,
        kill: config.kill.clone(),
        reaped: false,
    };
    let pid = owned.child.id();
    let pgid = pid as i32;
    // The parent records the pid synchronously at spawn time — before the
    // timeout clock starts — so tests can assert the pid is gone after
    // the outcome without a child-written pidfile (which would race the
    // deadline kill).
    if let Some(observer) = &config.spawn_observer {
        observer(pid);
    }
    // Non-blocking pipe read ends: the wait loop drains without blocking
    // and the post-reap EOF drain is bounded — a grandchild that keeps a
    // pipe open can never hang the outcome.
    set_nonblocking(&mut owned.child.stdout).map_err(|e| RunError::Wait(e.to_string()))?;
    set_nonblocking(&mut owned.child.stderr).map_err(|e| RunError::Wait(e.to_string()))?;

    let deadline = Instant::now() + timeout;
    let mut stdout: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let mut timed_out = false;
    let mut term_started = Instant::now();
    let mut sent_kill = false;
    let mut sent_owned = false;
    let mut kill_error: Option<String> = None;

    // Wait loop: detect the child's exit WITHOUT reaping it (`waitid`
    // WNOWAIT peek — the child becomes a ZOMBIE and stays waitable,
    // holding its pid/pgid allocated for the foreground-only check
    // that follows the loop). On timeout, terminate the group and
    // escalate exactly as before; every kill failure is recorded.
    loop {
        drain_available(&mut owned.child.stdout, &mut stdout)
            .map_err(|e| RunError::Wait(e.to_string()))?;
        drain_available(&mut owned.child.stderr, &mut stderr)
            .map_err(|e| RunError::Wait(e.to_string()))?;
        if child_exited_unreaped(pid).map_err(|e| RunError::Wait(format!("wait {argv:?}: {e}")))? {
            break;
        }
        let now = Instant::now();
        if !timed_out && now >= deadline {
            timed_out = true;
            term_started = now;
            // Graceful TERM of the WHOLE process group.
            if let Err(e) = config.kill.kill_group(pgid, libc::SIGTERM) {
                // ESRCH is benign only when the child itself is already
                // gone (it exited as the deadline fired — the peek
                // reports it next); a live child behind an unreachable
                // group is a real termination failure. The liveness
                // check must NOT reap: the child stays a zombie until
                // the post-loop foreground check.
                let alive = child_exited_unreaped(pid)
                    .map(|exited| !exited)
                    .unwrap_or(false);
                if alive {
                    kill_error = Some(format!("TERM group {pgid}: {e}"));
                }
            }
        }
        if timed_out {
            let since = now.duration_since(term_started);
            if since >= config.term_to_kill_grace && !sent_kill {
                sent_kill = true;
                // Escalate to KILL on the whole group: a child that
                // ignores TERM must still die.
                if let Err(e) = config.kill.kill_group(pgid, libc::SIGKILL) {
                    let alive = child_exited_unreaped(pid)
                        .map(|exited| !exited)
                        .unwrap_or(false);
                    if alive {
                        kill_error = Some(format!("KILL group {pgid}: {e}"));
                    }
                }
            }
            if since >= config.term_to_kill_grace * 2 && !sent_owned {
                sent_owned = true;
                // Last-resort direct kill on the OWNED handle: catches a
                // child that escaped its group (e.g. setsid).
                if let Err(e) = config.kill.kill_owned(&mut owned.child) {
                    kill_error = Some(format!("kill child {pid}: {e}"));
                }
            }
            if since >= config.reap_bound {
                // The child is STILL alive after every termination
                // attempt: the kill did not take effect. This is a reap
                // failure — NEVER a successful timeout outcome.
                return Err(RunError::Reap(format!(
                    "child {pid} still alive {:?} after the timeout termination",
                    config.reap_bound
                )));
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    // The child has EXITED but is still a ZOMBIE: the `waitid` WNOWAIT
    // peek above left it waitable, so its pid — and therefore its
    // process-group id (the child is the group leader, pgid == pid) — is
    // still allocated. Every foreground-only check and group termination
    // below happens while the zombie holds the pgid, so a `killpg` can
    // NEVER race a pid the OS recycled for an unrelated process (the
    // failure mode that made a probe-after-reap racy under parallel
    // execution).
    //
    // FOREGROUND-ONLY: enumerate the LIVE members of the child's process
    // group (our zombie excluded). If any remain, the command left a
    // background descendant: terminate the WHOLE group (TERM → grace →
    // KILL, the timeout path's escalation) and report the violation as
    // an ERROR, never a successful outcome; the essential contract — no
    // live process of the group after the return — is enforced BEFORE
    // the outcome escapes. A CLEAN command (no live members — the common
    // case) pays one enumeration and proceeds exactly as before.
    let live = live_group_members(pgid, pid);
    if !live.is_empty() {
        // Terminate the whole group; a kill failure is surfaced inside
        // the violation error (the leftover member must not survive even
        // when a kill fails — the fault-injected paths that cannot land
        // a kill are covered by the caller's own cleanup, and the drop
        // backstop remains the final resort for the owned child).
        let mut term_error: Option<String> = None;
        if let Err(e) = config.kill.kill_group(pgid, libc::SIGTERM) {
            term_error = Some(format!("TERM group {pgid}: {e}"));
        }
        std::thread::sleep(config.term_to_kill_grace);
        if let Err(e) = config.kill.kill_group(pgid, libc::SIGKILL)
            && term_error.is_none()
        {
            term_error = Some(format!("KILL group {pgid}: {e}"));
        }
        // Confirm the group is gone (bounded): a killed descendant is
        // reparented to init and reaped there; the poll covers the
        // transient zombie window. On expiry (an injected inert kill) the
        // error still names the violation — the fault IS the kill not
        // working.
        let verify_deadline = Instant::now() + config.reap_bound;
        while !live_group_members(pgid, pid).is_empty() && Instant::now() < verify_deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        // Reap the direct child (a zombie — the wait returns immediately,
        // releasing the pid) BEFORE the error escapes.
        owned
            .wait()
            .map_err(|e| RunError::Wait(format!("wait {argv:?}: {e}")))?;
        if let Some(observer) = &config.reap_observer {
            observer(pid);
        }
        let detail = term_error.map(|e| format!(" ({e})")).unwrap_or_default();
        let leftover = live
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        return Err(RunError::Background(format!(
            "command {argv:?} left background processes in its process group \
                 (live members: {leftover}); commands are foreground-only{detail}"
        )));
    }

    // The direct child is the only group member: reap it — the SINGLE
    // reap, releasing the pid. From here on nothing signals anything.
    let status = owned
        .wait()
        .map_err(|e| RunError::Wait(format!("wait {argv:?}: {e}")))?;
    if let Some(observer) = &config.reap_observer {
        observer(pid);
    }
    // Bounded drain to EOF: the child is dead and its pipes hold the
    // remaining output. A grandchild that keeps a pipe open cannot hang
    // the outcome — the drain gives up after the reap bound.
    // PIPE-EOF CONTAINMENT: the direct child is reaped (its descriptors
    // closed by the kernel); the inherited stdout/stderr write ends EOF
    // exactly when the LAST holder — the child or any descendant that
    // kept the pipes — dies. EOF within the bound proves no pipe-holding
    // descendant lives (the clean path stays clean); a pipe still open
    // at the bound proves a live descendant HOLDS it — a descendant that
    // escaped the group via `setsid` but kept the inherited pipes is
    // still DETECTED here, and the violation is reported as an ERROR,
    // never a successful outcome. Only a FULLY daemonized descendant
    // (`setsid` AND closed descriptors) is outside the contract (see the
    // module doc) — commands must not daemonize.
    let drain_bound = config.reap_bound;
    let stdout_drain = drain_to_eof(&mut owned.child.stdout, &mut stdout, drain_bound)
        .map_err(|e| RunError::Wait(e.to_string()))?;
    if matches!(stdout_drain, DrainState::BoundExpired) {
        return Err(RunError::Background(format!(
            "command {argv:?} left processes holding its output pipes open; \
                 commands are foreground-only"
        )));
    }
    let stderr_drain = drain_to_eof(&mut owned.child.stderr, &mut stderr, drain_bound)
        .map_err(|e| RunError::Wait(e.to_string()))?;
    if matches!(stderr_drain, DrainState::BoundExpired) {
        return Err(RunError::Background(format!(
            "command {argv:?} left processes holding its error pipes open; \
                 commands are foreground-only"
        )));
    }

    if timed_out {
        // A timeout outcome is legitimate ONLY when the termination was
        // effective: a kill failure is an ERROR, never a fake timeout.
        if let Some(e) = kill_error {
            return Err(RunError::Kill(format!("timeout termination failed: {e}")));
        }
        return Ok(RunOutcome::TimedOut {
            stderr: format!("timed out after {timeout:?}"),
        });
    }
    Ok(RunOutcome::Exited {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

/// Put a child pipe read end into non-blocking mode, so reads never block and
fn set_nonblocking<R: AsRawFd>(stream: &mut Option<R>) -> std::io::Result<()> {
    let Some(stream) = stream.as_mut() else {
        return Ok(());
    };
    let fd = stream.as_raw_fd();
    // SAFETY: fcntl on a pipe read end this runner opened for its own child.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above; O_NONBLOCK only changes the read blocking semantics.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Drain whatever bytes a running child currently has buffered in a pipe
/// WITHOUT blocking: `poll(2)` with a zero timeout reports readability first,
/// then a single `read`, so the wait loop never parks on a pipe while the
/// child is still running — a child that produces a lot of output is drained
/// while running instead of filling its pipe and stalling.
fn drain_available<R>(stream: &mut Option<R>, buf: &mut Vec<u8>) -> std::io::Result<()>
where
    R: Read + AsRawFd,
{
    let Some(stream) = stream.as_mut() else {
        return Ok(());
    };
    let mut pfd = libc::pollfd {
        fd: stream.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` with a zero timeout on a real pipe read end this runner
    // opened for its own child; the fd is always valid here and never blocks.
    if unsafe { libc::poll(&mut pfd, 1, 0) } <= 0 {
        return Ok(());
    }
    let mut chunk = [0u8; 8192];
    match stream.read(&mut chunk) {
        Ok(0) => Ok(()),
        Ok(n) => {
            buf.extend_from_slice(&chunk[..n]);
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
        Err(e) => Err(e),
    }
}

/// The outcome of a bounded post-exit drain: EOF proves the pipe's last
/// writer closed (no live descendant holds it); a bound expiry proves a
/// live writer STILL holds it (a descendant that escaped the group but kept
/// the inherited stdio pipes — the pipe-EOF containment signal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainState {
    /// `read` returned 0: every write end closed — no pipe-holding
    /// descendant remains.
    Eof,
    /// The drain bound expired with the pipe still open (poll timed out or
    /// the deadline passed between reads): a live writer holds the pipe.
    BoundExpired,
}

/// Drain a child pipe to EOF, bounded: reads never block (non-blocking read
/// ends), and between reads `poll` waits only up to `bound` — a grandchild
/// that outlives the direct child and keeps a pipe open cannot hang the
/// outcome. Returns [`DrainState::Eof`] when the pipe reached EOF within the
/// bound (no live holder remains) and [`DrainState::BoundExpired`] when the
/// bound expired with the pipe still open (a live holder — a contract
/// violation the caller reports, never a silent clean outcome).
fn drain_to_eof<R>(
    stream: &mut Option<R>,
    buf: &mut Vec<u8>,
    bound: Duration,
) -> std::io::Result<DrainState>
where
    R: Read + AsRawFd,
{
    let Some(stream) = stream.as_mut() else {
        return Ok(DrainState::Eof);
    };
    let deadline = Instant::now() + bound;
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(DrainState::Eof),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Ok(DrainState::BoundExpired);
                }
                let ms = remaining.as_millis().min(i32::MAX as u128) as i32;
                let mut pfd = libc::pollfd {
                    fd: stream.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: `poll` on a real pipe read end this runner owns.
                let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
                if rc < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if rc == 0 {
                    return Ok(DrainState::BoundExpired);
                }
            }
            Err(e) => return Err(e),
        }
    }
}
