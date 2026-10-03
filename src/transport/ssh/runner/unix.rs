//! The Unix implementation of the ssh subprocess seam: process-group
//! lifecycle and `poll`/`fcntl` non-blocking pipe drains. Selected by the
//! single `#[cfg(unix)]` `mod` declaration in [`super`].

use super::*;
use crate::transport::runner::{
    DrainState, KILL_REAP_BOUND, OwnedChild, RealKill, TERM_TO_KILL_GRACE, drain_available,
    drain_to_eof, kill_process_group, set_nonblocking,
};
use std::os::unix::process::CommandExt;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
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
    let mut child = cmd.spawn()?;
    // The parent reads the pid synchronously at spawn time and surfaces it
    // through the runner's spawn observer: the child never needs to write
    // its own pid to a file.
    let pid = child.id();
    // Non-blocking pipe read ends, exactly as the shared local runner does
    // (the helpers are shared, not copied): the wait loop drains without
    // blocking, and — the reason this matters — the post-exit drain can give
    // up on schedule instead of parking on a pipe another process still
    // holds open. Done here, before the wait thread exists, so a setup
    // failure is handled while the child is still OURS: it is killed and
    // reaped first, so even this path cannot leave a live, un-reaped child.
    if let Err(e) =
        set_nonblocking(&mut child.stdout).and_then(|()| set_nonblocking(&mut child.stderr))
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    // The child is shared EXCLUSIVELY between the runner's deadline path
    // and the wait thread through this slot: the wait thread polls the
    // child (`try_wait`) with the slot locked and CONSUMES it on exit
    // (the slot becomes None), the deadline path locks the same slot and
    // terminates the WHOLE process group (`killpg` TERM then KILL, with a
    // fallback to `Child::kill` on the OWNED handle) — never a detached
    // pid. A kill on a slot the wait thread already reaped (None) is a
    // no-op by construction: a consumed handle cannot signal anything, so
    // a pid the OS recycled to an unrelated process can never be hit.
    //
    // The slot holds the SAME [`OwnedChild`] the local runner owns, so the
    // SSH runner inherits the local runner's drop backstop (ONE authority
    // for "every error path leaves no uncollected child"): a `drain_available`
    // or `try_wait` error that returns early from the wait closure drops the
    // slot — and the owned child with it — kills the group, and reaps, where
    // a bare `Child`'s own `Drop` would neither wait nor kill.
    let child: Arc<Mutex<Option<OwnedChild>>> =
        Arc::new(Mutex::new(Some(OwnedChild::new(child, Arc::new(RealKill)))));
    // The typed "the child has already been reaped" fact the runner's deadline
    // path reads to tell a deadline kill from a drain that merely gave up on a
    // completed command. Armed the instant `try_wait` consumes the exit
    // status, before the bounded post-exit drain begins.
    let reaped = Arc::new(AtomicBool::new(false));
    let kill_child = child.clone();
    let kill: Box<dyn Fn() -> std::io::Result<()> + Send> = Box::new(move || {
        let mut guard = kill_child.lock().unwrap();
        let Some(owned) = guard.as_mut() else {
            // The wait thread already reaped the child: a kill on the
            // consumed handle is a NO-OP by construction — a pid the OS
            // recycled to an unrelated process can never be signalled.
            return Ok(());
        };
        // Terminate the WHOLE process group (shared with the local
        // child-runner): graceful TERM first, then — after the shared
        // grace — an escalated KILL, so a child that ignores TERM (and
        // any grandchild in the group) still dies.
        let pgid = owned.child.id() as i32;
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
                    Err(e) => owned.child.kill().or(Err(e)),
                }
            }
            // The group is already gone (the child exited, or escaped via
            // setsid): fall back to the OWNED handle so a live direct
            // child is still terminated.
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => owned.child.kill(),
            // A real group-kill failure: fall back to the owned handle so
            // the direct child still dies (the join then reaps it), and
            // surface the failure.
            Err(e) => owned.child.kill().or(Err(e)),
        }
    });
    let wait_child = child.clone();
    let wait_reaped = reaped.clone();
    // Own the argv for the wait closure: the bounded-drain violation message
    // names the command (the local runner's `{argv:?}` wording).
    let argv = argv.to_vec();
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
                .and_then(|c| c.child.stdin.take());
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
                let mut exited: Option<(OwnedChild, std::process::ExitStatus)> = None;
                // Bytes drained THIS pass. A pass that moved data must not
                // sleep before the next one: the old shape drained one chunk
                // per 1 ms pass, capping every remote read at ~8 MiB/s
                // regardless of the link (the fixed command deadline then
                // killed a large read). Progress means no sleep; a silent
                // running child yields so the loop does not busy-spin and the
                // deadline path can still take the child slot.
                let mut drained = 0usize;
                {
                    let mut guard = wait_child.lock().unwrap();
                    let owned = guard
                        .as_mut()
                        .expect("the wait thread is the sole consumer of the child slot");
                    drained += drain_available(&mut owned.child.stdout, &mut stdout)
                        .map_err(|e| RunError::Wait(format!("read: {e}")))?;
                    drained += drain_available(&mut owned.child.stderr, &mut stderr)
                        .map_err(|e| RunError::Wait(format!("read: {e}")))?;
                    match owned.child.try_wait() {
                        Ok(Some(status)) => {
                            // `try_wait` consumed the exit status: the child
                            // is reaped, so mark the handle collected (never
                            // signal the released pid) and arm the typed
                            // deadline fact before the drain begins.
                            let mut taken =
                                guard.take().expect("the slot was occupied a moment ago");
                            taken.mark_reaped();
                            wait_reaped.store(true, Ordering::SeqCst);
                            exited = Some((taken, status));
                        }
                        Ok(None) => {}
                        Err(e) => return Err(RunError::Wait(format!("wait: {e}"))),
                    }
                }
                if let Some((mut owned, status)) = exited {
                    // BOUNDED drain (the same helper, and the same bound, the
                    // shared local runner uses): the child is reaped and its
                    // pipes hold the remaining output. A process that outlived
                    // the child but still holds a pipe — the ssh mux master on
                    // a timed-out far side, or any pipe-holding escapee — cannot
                    // pin the operation open: the drain gives up at
                    // [`KILL_REAP_BOUND`] and the violation is reported, never a
                    // silent clean outcome.
                    let stdout_drain =
                        drain_to_eof(&mut owned.child.stdout, &mut stdout, KILL_REAP_BOUND)
                            .map_err(|e| RunError::Wait(format!("read: {e}")))?;
                    if matches!(stdout_drain, DrainState::BoundExpired) {
                        return Err(RunError::Background(format!(
                            "command {argv:?} left processes holding its output pipes open"
                        )));
                    }
                    let stderr_drain =
                        drain_to_eof(&mut owned.child.stderr, &mut stderr, KILL_REAP_BOUND)
                            .map_err(|e| RunError::Wait(format!("read: {e}")))?;
                    if matches!(stderr_drain, DrainState::BoundExpired) {
                        return Err(RunError::Background(format!(
                            "command {argv:?} left processes holding its error pipes open"
                        )));
                    }
                    break Ok(std::process::Output {
                        status,
                        stdout,
                        stderr,
                    });
                }
                if drained == 0 {
                    std::thread::sleep(Duration::from_millis(1));
                }
            };
            // The saved stdin-write error is surfaced only AFTER the
            // child was collected — which means the child's OWN stderr (and
            // exit status) are already drained and available. Preserve them
            // on the error: without the far-side diagnostic, a FAILED UPLOAD
            // to a full disk (`cat: -: No space left on device`) was
            // indistinguishable from a dead host, because the caller saw
            // only `stdin write: Broken pipe`. The error CLASS stays
            // [`RunError::StdinWrite`] — the local write DID fail — and the
            // far side's own words are appended so the CAUSE is recoverable.
            match write_res {
                Err(e) => {
                    let (far_side, status) = match &wait_res {
                        Ok(out) => (
                            String::from_utf8_lossy(&out.stderr).trim().to_string(),
                            match out.status.code() {
                                Some(code) => format!("; the far side exited {code}"),
                                None => "; the far side was killed by a signal".to_string(),
                            },
                        ),
                        // A wait error already carries its own detail.
                        Err(_) => (String::new(), String::new()),
                    };
                    let detail = if far_side.is_empty() {
                        status
                    } else {
                        format!("{status}; the far side reported: {far_side}")
                    };
                    Err(RunError::StdinWrite(format!("stdin write: {e}{detail}")))
                }
                Ok(()) => wait_res,
            }
        });
    Ok(SpawnedChild {
        pid,
        reaped,
        kill,
        wait,
    })
}

/// Real-subprocess tests for the Unix ssh seam: the drain's throughput, and
/// the far-side diagnostic preserved on a failed upload. Both drive
/// [`SshRunner`] through the REAL seam with an injected tiny command deadline,
/// so a regression cannot hang the suite: the runner kills the child at the
/// deadline and returns.
#[cfg(test)]
mod real_seam_tests {
    use super::*;

    fn real_runner(command_deadline: Duration) -> SshRunner {
        SshRunner::with_seam(
            Arc::new(RealRunner::new(&crate::test_support::fixture_env())),
            Duration::from_secs(10),
            command_deadline,
        )
    }

    /// D1: the running-phase drain must not be capped at one 8192-byte chunk
    /// per 1 ms wait-loop pass. Pre-fix that capped every remote read at
    /// ~8 MiB/s, so this 64 MiB read outlived the tiny 3 s command deadline
    /// and was KILLED (`RunError::Timeout`); post-fix the same tiny deadline
    /// is ample because the drain runs at syscall speed. The injected
    /// deadline means the pre-fix path fails fast instead of hanging.
    #[test]
    fn large_read_completes_under_a_tiny_command_deadline() {
        const BYTES: usize = 64 * 1024 * 1024;
        let runner = real_runner(Duration::from_secs(3));
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("head -c {BYTES} /dev/zero"),
        ];
        let out = runner
            .run(OpKind::Remote, &argv, None, None)
            .expect("a 64 MiB read must complete within the deadline after the drain fix");
        assert_eq!(
            out.stdout.len(),
            BYTES,
            "the whole read must be drained, not a truncated prefix"
        );
        assert!(out.status.success());
    }

    /// D2: a failed stdin write (the far side stopped reading / exited) must
    /// carry the far side's OWN stderr, so a full disk is not reported as a
    /// bare `Broken pipe`. Pre-fix the message was only
    /// `stdin write: Broken pipe (os error 32)` and the far-side
    /// `No space left on device` line was discarded.
    #[test]
    fn stdin_write_failure_preserves_the_far_side_stderr() {
        let runner = real_runner(Duration::from_secs(10));
        // The child never reads stdin and exits non-zero with a diagnostic on
        // stderr, exactly as a far-side `cat` does when the write fails. The
        // payload is larger than the pipe buffer, so `write_all` blocks, the
        // child exits, the read end closes, and the write fails with EPIPE.
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "echo 'cat: -: No space left on device' >&2; exit 1".to_string(),
        ];
        let payload = vec![0u8; 4 * 1024 * 1024];
        let err = runner
            .run(OpKind::Upload, &argv, Some(&payload), None)
            .expect_err("a writer whose reader exited must fail the stdin write");
        match err {
            RunError::StdinWrite(message) => {
                assert!(
                    message.contains("No space left on device"),
                    "the far side's stderr must be preserved on the StdinWrite error: {message}"
                );
                assert!(
                    message.contains("stdin write:"),
                    "the local write failure must still be named: {message}"
                );
                assert!(
                    message.contains("the far side exited 1"),
                    "the far-side exit status must be preserved: {message}"
                );
            }
            other => panic!("expected RunError::StdinWrite, got {other:?}"),
        }
    }
}
