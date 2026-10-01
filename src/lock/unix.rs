//! The Unix advisory lock: POSIX `flock` on the open file descriptor.
//! Selected by the single `#[cfg(unix)]` `mod` declaration in [`super`].

pub(crate) use super::LockAttempt;
use std::os::unix::io::AsRawFd;

/// Try to acquire the exclusive, non-blocking advisory lock.
pub(crate) fn try_lock(file: &std::fs::File) -> LockAttempt {
    let fd = file.as_raw_fd();
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if ret == 0 {
        LockAttempt::Acquired
    } else {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN => {
                LockAttempt::Contended
            }
            _ => LockAttempt::Failed(err),
        }
    }
}

/// Release the advisory lock (best-effort — the kernel releases it when
/// the descriptor drops even if this never ran).
pub(crate) fn unlock(file: &std::fs::File) {
    unsafe {
        libc::flock(file.as_raw_fd(), libc::LOCK_UN);
    }
}

/// The errno that means "another holder" (EWOULDBLOCK) — the wait/retry
/// policy's contention signal.
pub(crate) fn contended_errno() -> i32 {
    libc::EWOULDBLOCK
}
