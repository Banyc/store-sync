//! The Unix implementation of the ssh subprocess seam: process-group
//! lifecycle and `poll`/`fcntl` non-blocking pipe drains. Selected by the
//! single `#[cfg(unix)]` `mod` declaration in [`super`].

use super::*;
use crate::transport::runner::{TERM_TO_KILL_GRACE, kill_process_group};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The Unix spawn: the child becomes its OWN process-group leader
/// (`process_group(0)`), the kill terminates the WHOLE group (`killpg`
/// TERM → grace → KILL, with the owned-handle fallback), and the wait
/// drains the pipes with `poll`/`fcntl` non-blocking reads. Selected by
/// the single `#[cfg(unix)]` `mod` declaration in [`super`].
pub(crate) fn spawn(
    env: &SysEnv,
    _op: OpKind,
    argv: &[String],
    stdin: Option<Vec<u8>>,
) -> std::io::Result<SpawnedChild> {
    let mut cmd = std::process::Command::new(&argv[0]);
    env.apply_to_command(&mut cmd);
    cmd.args(&argv[1..]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(Stdio::piped());
    }
    // The child becomes its OWN process-group leader (pgid == pid) — the
    // shared bounded child-runner's spawn rule — so the deadline kill
    // terminates the WHOLE group (killpg), and any local helper process
    // the child spawned dies with it.
    cmd.process_group(0);
    let child = cmd.spawn()?;
    // The parent reads the pid synchronously at spawn time and surfaces it
    // through the runner's spawn observer: the child never needs to write
    // its own pid to a file.
    let pid = child.id();
    // The child is shared EXCLUSIVELY between the runner's deadline path
    // and the wait thread through this slot: the wait thread polls the
    // child (`try_wait`) with the slot locked and CONSUMES it on exit
    // (the slot becomes None), the deadline path locks the same slot and
    // terminates the WHOLE process group (`killpg` TERM then KILL, with a
    // fallback to `Child::kill` on the OWNED handle) — never a detached
    // pid. A kill on a slot the wait thread already reaped (None) is a
    // no-op by construction: a consumed handle cannot signal anything, so
    // a pid the OS recycled to an unrelated process can never be hit.
    let child: Arc<Mutex<Option<std::process::Child>>> = Arc::new(Mutex::new(Some(child)));
    let kill_child = child.clone();
    let kill: Box<dyn Fn() -> std::io::Result<()> + Send> = Box::new(move || {
        let mut guard = kill_child.lock().unwrap();
        let Some(child) = guard.as_mut() else {
            // The wait thread already reaped the child: a kill on the
            // consumed handle is a NO-OP by construction — a pid the OS
            // recycled to an unrelated process can never be signalled.
            return Ok(());
        };
        // Terminate the WHOLE process group (shared with the local
        // child-runner): graceful TERM first, then — after the shared
        // grace — an escalated KILL, so a child that ignores TERM (and
        // any grandchild in the group) still dies.
        let pgid = child.id() as i32;
        match kill_process_group(pgid, libc::SIGTERM) {
            Ok(()) => {
                std::thread::sleep(TERM_TO_KILL_GRACE);
                match kill_process_group(pgid, libc::SIGKILL) {
                    Ok(()) => Ok(()),
                    // The group already died on TERM (the wait thread
                    // reaps the child): nothing left to kill.
                    Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(()),
                    // The escalated group kill failed: fall back to the
                    // OWNED handle so the direct child still dies and the
                    // join reaps it; the failure is surfaced.
                    Err(e) => child.kill().or(Err(e)),
                }
            }
            // The group is already gone (the child exited, or escaped via
            // setsid): fall back to the OWNED handle so a live direct
            // child is still terminated.
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => child.kill(),
            // A real group-kill failure: fall back to the owned handle so
            // the direct child still dies (the join then reaps it), and
            // surface the failure.
            Err(e) => child.kill().or(Err(e)),
        }
    });
    let wait_child = child.clone();
    // The stdin payload is written from INSIDE the wait closure (which
    // the runner's deadline bounds) but WITHOUT holding the child slot:
    // the payload pipe is taken out of the child, the slot is released,
    // and the blocking write is interrupted by the deadline kill (the
    // child's read end closes on death, the write fails with EPIPE —
    // SIGPIPE is ignored by the Rust runtime). A remote that stops
    // reading stdin mid-upload therefore blocks only until the deadline,
    // never indefinitely, and — crucially — the blocked write does not
    // pin the child out of the slot, so the deadline can still kill it.
    let wait: Box<dyn FnOnce() -> std::result::Result<std::process::Output, RunError> + Send> =
        Box::new(move || {
            use std::io::Write;
            let mut stdin_pipe = wait_child
                .lock()
                .unwrap()
                .as_mut()
                .and_then(|c| c.stdin.take());
            // Write the payload FIRST, saving any error: `?` here would
            // return BEFORE the child is collected — a write error (EPIPE
            // after the deadline kill, or a hung-remote pipe) would leave
            // an un-reaped child. The error is therefore saved, and the
            // poll loop below ALWAYS collects the child before the saved
            // write error is surfaced.
            let write_res = match (&stdin, stdin_pipe.as_mut()) {
                (Some(data), Some(sin)) => sin.write_all(data),
                _ => Ok(()),
            };
            drop(stdin_pipe);
            // Poll loop: the child lives in the shared slot; every pass
            // drains its pipes (non-blocking) so a large output can never
            // fill a pipe and stall the child, then `try_wait`. Between
            // passes the slot is released so the runner's deadline kill
            // can grab it — each pass is short, so a kill never blocks
            // long. When the child exits the slot is consumed (reaped)
            // and the remaining output drained to EOF.
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let wait_res = loop {
                let mut exited: Option<(std::process::Child, std::process::ExitStatus)> = None;
                {
                    let mut guard = wait_child.lock().unwrap();
                    let c = guard
                        .as_mut()
                        .expect("the wait thread is the sole consumer of the child slot");
                    drain_available(&mut c.stdout, &mut stdout)?;
                    drain_available(&mut c.stderr, &mut stderr)?;
                    match c.try_wait() {
                        Ok(Some(status)) => {
                            exited = guard.take().map(|c| (c, status));
                        }
                        Ok(None) => {}
                        Err(e) => return Err(RunError::Wait(format!("wait: {e}"))),
                    }
                }
                if let Some((mut c, status)) = exited {
                    drain_to_eof(&mut c.stdout, &mut stdout)?;
                    drain_to_eof(&mut c.stderr, &mut stderr)?;
                    break Ok(std::process::Output {
                        status,
                        stdout,
                        stderr,
                    });
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            // The saved stdin-write error is surfaced only AFTER the
            // child was collected.
            match write_res {
                Err(e) => Err(RunError::StdinWrite(format!("stdin write: {e}"))),
                Ok(()) => wait_res,
            }
        });
    Ok(SpawnedChild { pid, kill, wait })
}

/// Drain whatever bytes a running child currently has buffered in a pipe
/// WITHOUT blocking: `poll(2)` with a zero timeout reports readability first,
/// then a single `read` (a pipe that became readable stays readable for the
/// immediate read, and at EOF the read returns 0), so the wait thread's poll
/// loop never parks on a pipe while the child is still running — the
/// non-blocking equivalent of the concurrent drain `wait_with_output` used to
/// perform, so a child that produces a lot of output is drained while running
/// instead of filling its pipe and stalling.
fn drain_available<R>(
    stream: &mut Option<R>,
    buf: &mut Vec<u8>,
) -> std::result::Result<(), RunError>
where
    R: std::io::Read + std::os::fd::AsFd,
{
    let Some(stream) = stream.as_mut() else {
        return Ok(());
    };
    let mut pfd = libc::pollfd {
        fd: stream.as_fd().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` on a real pipe read end this runner opened for its own
    // child; a zero timeout never blocks and the fd is always valid here.
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
        Err(e) => Err(RunError::Wait(format!("read: {e}"))),
    }
}

/// Drain a child pipe to EOF. Called only AFTER the child exited, when its
/// write ends are closed: the reads return the buffered data then 0, never
/// blocking — collecting the child's full output.
fn drain_to_eof<R: std::io::Read>(
    stream: &mut Option<R>,
    buf: &mut Vec<u8>,
) -> std::result::Result<(), RunError> {
    let Some(stream) = stream.as_mut() else {
        return Ok(());
    };
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(RunError::Wait(format!("read: {e}"))),
        }
    }
}
