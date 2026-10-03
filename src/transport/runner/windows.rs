//! The Windows implementation of the bounded child-runner: no process
//! groups (the child is spawned plain and terminated via the OWNED handle),
//! no foreground-only group check (no process-group enumeration exists on
//! Windows), and reader THREADS for the pipe drains (no `poll`/`fcntl`
//! non-blocking pipes). The documented weaker guarantees of the Windows
//! port: a background descendant survives a timeout (only the direct child
//! is terminated), and a command that leaves background processes is
//! detected only when it holds the output pipes (the bounded drain reports
//! the violation; a fully daemonized descendant is outside the contract, as
//! on Unix). Selected by the single `#[cfg(windows)]` `mod` declaration in
//! [`super`].

use super::*;
use std::io::Read;
use std::path::Path;
use std::process::Stdio;
use std::sync::mpsc;
use std::time::Instant;

/// Production seam: Windows has no process groups — the group kill is a
/// no-op (the owned-child kill is the termination path).
pub struct RealKill;

impl KillSeam for RealKill {
    fn kill_group(&self, _pgid: i32, _sig: i32) -> std::io::Result<()> {
        // No process groups on Windows: the group kill is a no-op (the
        // owned-child kill is the termination path).
        Ok(())
    }
    fn kill_owned(&self, child: &mut Child) -> std::io::Result<()> {
        child.kill()
    }
}

/// Execute `argv` (no shell) bounded by `timeout` — the Windows lifecycle:
/// spawn plain, drain stdout/stderr via reader THREADS, poll `try_wait`
/// with the timeout, terminate the OWNED child on timeout, collect the
/// readers (bounded), reap. No foreground-only group check (no
/// process-group enumeration on Windows) — the documented weaker
/// guarantee. See [`super::ChildRunner::exec`] for the contract.
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
    let child = cmd
        .spawn()
        .map_err(|e| RunError::Spawn(format!("spawn {argv:?}: {e}")))?;
    let pid = child.id();
    // The parent records the pid synchronously at spawn time — before the
    // timeout clock starts — so tests can assert the pid is gone after the
    // outcome without a child-written pidfile (which would race the
    // deadline kill).
    if let Some(observer) = &config.spawn_observer {
        observer(pid);
    }
    // The platform-neutral [`OwnedChild`] backstop: every early error return
    // below drops this handle, whose `Drop` terminates and reaps the child.
    // A bare `std::process::Child`'s own `Drop` neither waits nor kills, so
    // without it a `try_wait` error (or a reap-bound expiry) would abandon a
    // live child. On Windows the group kill is a no-op — only the DIRECT child
    // is terminated, the documented weaker guarantee of this port.
    let mut child = OwnedChild::new(child, config.kill.clone());
    // Reader threads: drain stdout/stderr to EOF (the pipes EOF when the
    // child — and any descendant that kept them — dies). Each thread sends
    // its buffer on a channel; the main loop collects them bounded.
    let stdout_rx = spawn_reader(child.child.stdout.take());
    let stderr_rx = spawn_reader(child.child.stderr.take());

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let mut kill_error: Option<String> = None;
    // Wait loop: poll `try_wait` (no `waitid` WNOWAIT peek on Windows — the
    // child is reaped by the final `wait`). On timeout, terminate the OWNED
    // child (TerminateProcess); every kill failure is recorded.
    loop {
        match child.child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(e) => return Err(RunError::Wait(format!("wait {argv:?}: {e}"))),
        }
        let now = Instant::now();
        if !timed_out && now >= deadline {
            timed_out = true;
            // Terminate the OWNED child. No process group: a background
            // descendant survives — the documented weaker guarantee of the
            // Windows port.
            if let Err(e) = config.kill.kill_owned(&mut child.child) {
                kill_error = Some(format!("kill child {pid}: {e}"));
            }
        }
        if timed_out && now.duration_since(deadline) >= config.reap_bound {
            // The child is STILL alive after the termination attempt: the
            // kill did not take effect. This is a reap failure — NEVER a
            // successful timeout outcome.
            return Err(RunError::Reap(format!(
                "child {pid} still alive {:?} after the timeout termination",
                config.reap_bound
            )));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    // Reap the child — the SINGLE reap, releasing the pid. From here on
    // nothing signals anything.
    let status = child
        .wait()
        .map_err(|e| RunError::Wait(format!("wait {argv:?}: {e}")))?;
    if let Some(observer) = &config.reap_observer {
        observer(pid);
    }
    // Collect the reader buffers, BOUNDED: the pipes EOF when the last
    // holder dies. A channel still open at the bound proves a live
    // descendant HOLDS the pipe — the pipe-EOF containment signal (the
    // same violation the Unix drain reports). The blocked reader thread is
    // left to EOF when the descendant dies (the documented weaker
    // guarantee of the Windows port).
    let drain_bound = config.reap_bound;
    let stdout = recv_bounded(&stdout_rx, drain_bound).ok_or_else(|| {
        RunError::Background(format!(
            "command {argv:?} left processes holding its output pipes open; \
             commands are foreground-only"
        ))
    })?;
    let stderr = recv_bounded(&stderr_rx, drain_bound).ok_or_else(|| {
        RunError::Background(format!(
            "command {argv:?} left processes holding its error pipes open; \
             commands are foreground-only"
        ))
    })?;

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

/// Spawn a thread that reads `stream` to EOF into a buffer and sends it on
/// a channel. The channel is the bounded-collection handle: the main loop
/// receives with a deadline, so a pipe held open by a live descendant is
/// DETECTED (the receive times out) instead of hanging the outcome.
fn spawn_reader<R: Read + Send + 'static>(stream: Option<R>) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut s) = stream {
            // Best-effort: a read error mid-drain (e.g. the child dying)
            // yields the partial buffer; the outcome's captured output is
            // best-effort on Windows.
            let _ = s.read_to_end(&mut buf);
        }
        let _ = tx.send(buf);
    });
    rx
}

/// Receive the reader's buffer within `bound`, or `None` when the bound
/// expires (a live descendant holds the pipe open).
fn recv_bounded(rx: &mpsc::Receiver<Vec<u8>>, bound: Duration) -> Option<Vec<u8>> {
    rx.recv_timeout(bound).ok()
}
