//! The Windows implementation of the ssh subprocess seam: plain spawn (no
//! process groups), owned-handle termination (`TerminateProcess`), and
//! reader THREADS for the pipe drains (no `poll`/`fcntl` non-blocking
//! pipes). The documented weaker guarantees of the Windows port: a
//! background descendant survives a kill (only the direct child is
//! terminated), and a command that leaves a descendant holding the output
//! pipes can block the wait (the runner's deadline kill closes the direct
//! child's handles, EOFing the pipes — a grandchild holding them is the
//! documented exclusion, as on Unix). Selected by the single
//! `#[cfg(windows)]` `mod` declaration in [`super`].

use super::*;
use crate::transport::runner::{OwnedChild, RealKill};
use std::io::Read;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

/// The Windows spawn: the child is spawned plain (no process group), the
/// kill terminates the OWNED child (`TerminateProcess`), and the wait
/// drains the pipes via reader THREADS.
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
    let child = cmd.spawn()?;
    let pid = child.id();
    // The child is shared EXCLUSIVELY between the runner's deadline path
    // and the wait thread through this slot (the same discipline as the
    // Unix seam): the wait thread polls `try_wait` with the slot locked and
    // CONSUMES it on exit; the deadline path locks the same slot and
    // terminates the OWNED child. A kill on a slot the wait thread already
    // reaped (None) is a no-op by construction.
    //
    // The slot holds the SAME platform-neutral [`OwnedChild`] the local
    // runner owns, so the Windows SSH seam inherits the SAME drop backstop the
    // Unix seam has (ONE authority for "every error path leaves no uncollected
    // child"): a `try_wait`/reader error that returns early from the wait
    // closure drops the slot — and the owned child with it — and
    // `OwnedChild::drop` terminates and reaps it (`TerminateProcess`; the group
    // kill is a no-op on Windows), where a bare `std::process::Child`'s own
    // `Drop` neither waits nor kills. On Windows the backstop terminates only
    // the DIRECT child — a background descendant survives, the documented
    // weaker guarantee of this port.
    let child: Arc<Mutex<Option<OwnedChild>>> =
        Arc::new(Mutex::new(Some(OwnedChild::new(child, Arc::new(RealKill)))));
    // The typed "the child has already been reaped" fact the runner's deadline
    // path reads to tell a deadline kill from a drain that merely gave up on a
    // completed command (see `SpawnedChild::reaped`).
    let reaped = Arc::new(AtomicBool::new(false));
    let kill_child = child.clone();
    let kill: Box<dyn Fn() -> std::io::Result<()> + Send> = Box::new(move || {
        let mut guard = kill_child.lock().unwrap();
        let Some(owned) = guard.as_mut() else {
            // The wait thread already reaped the child: a kill on the
            // consumed handle is a NO-OP by construction.
            return Ok(());
        };
        // No process groups on Windows: terminate the OWNED child
        // (TerminateProcess). A background descendant survives — the
        // documented weaker guarantee of the Windows port.
        owned.child.kill()
    });
    let wait_child = child.clone();
    let wait_reaped = reaped.clone();
    let wait: Box<dyn FnOnce() -> std::result::Result<std::process::Output, RunError> + Send> =
        Box::new(move || {
            use std::io::Write;
            let mut stdin_pipe = wait_child
                .lock()
                .unwrap()
                .as_mut()
                .and_then(|c| c.child.stdin.take());
            // Write the payload FIRST, saving any error (the same
            // collect-before-surface discipline as the Unix seam).
            let write_res = match (&stdin, stdin_pipe.as_mut()) {
                (Some(data), Some(sin)) => sin.write_all(data),
                _ => Ok(()),
            };
            drop(stdin_pipe);
            // Reader threads own the output pipes (no poll/fcntl on
            // Windows): they read to EOF and send the buffer on a channel.
            let stdout_rx = {
                let mut guard = wait_child.lock().unwrap();
                spawn_reader(guard.as_mut().and_then(|c| c.child.stdout.take()))
            };
            let stderr_rx = {
                let mut guard = wait_child.lock().unwrap();
                spawn_reader(guard.as_mut().and_then(|c| c.child.stderr.take()))
            };
            // Poll loop: `try_wait` with the slot locked; when the child
            // exits the slot is consumed (reaped) and the reader buffers
            // collected.
            let wait_res = loop {
                let mut exited: Option<(OwnedChild, std::process::ExitStatus)> = None;
                {
                    let mut guard = wait_child.lock().unwrap();
                    let c = guard
                        .as_mut()
                        .expect("the wait thread is the sole consumer of the child slot");
                    match c.child.try_wait() {
                        Ok(Some(status)) => {
                            exited = guard.take().map(|c| (c, status));
                        }
                        Ok(None) => {}
                        Err(e) => return Err(RunError::Wait(format!("wait: {e}"))),
                    }
                }
                if let Some((mut owned, status)) = exited {
                    // The child is reaped; mark the handle collected (never
                    // signal the released pid) and arm the typed deadline fact
                    // before the reader buffers are collected. Its handles are
                    // closed, so the reader threads EOF and send their buffers.
                    owned.mark_reaped();
                    wait_reaped.store(true, Ordering::SeqCst);
                    let stdout = stdout_rx
                        .recv()
                        .map_err(|_| RunError::Wait("stdout reader failed".into()))?;
                    let stderr = stderr_rx
                        .recv()
                        .map_err(|_| RunError::Wait("stderr reader failed".into()))?;
                    break Ok(std::process::Output {
                        status,
                        stdout,
                        stderr,
                    });
                }
                std::thread::sleep(Duration::from_millis(1));
            };
            // The saved stdin-write error is surfaced only AFTER the child
            // was collected.
            match write_res {
                Err(e) => Err(RunError::StdinWrite(format!("stdin write: {e}"))),
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

/// Spawn a thread that reads `stream` to EOF into a buffer and sends it on
/// a channel.
fn spawn_reader<R: Read + Send + 'static>(stream: Option<R>) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut s) = stream {
            // Best-effort: a read error mid-drain yields the partial buffer.
            let _ = s.read_to_end(&mut buf);
        }
        let _ = tx.send(buf);
    });
    rx
}
