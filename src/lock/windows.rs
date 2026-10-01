//! The Windows advisory lock: `LockFileEx`/`UnlockFileEx` on the open file
//! handle (the byte-range lock over the whole file, exclusive and
//! non-blocking — the Windows counterpart of POSIX `flock`). The lock
//! file is never removed (the same stable-file discipline as Unix: every
//! acquisition locks the same file, so no unlock→unlink split window can
//! exist). Selected by the single `#[cfg(windows)]` `mod` declaration in
//! [`super`].

pub(crate) use super::LockAttempt;
use std::os::windows::io::AsRawHandle;

/// Try to acquire the exclusive, non-blocking advisory lock over the whole
/// file (bytes 0..u32::MAX).
pub(crate) fn try_lock(file: &std::fs::File) -> LockAttempt {
    use windows_sys::Win32::Storage::FileSystem::{
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx,
    };
    let handle = file.as_raw_handle();
    let mut overlapped: windows_sys::Win32::System::IO::OVERLAPPED = unsafe { std::mem::zeroed() };
    // SAFETY: `LockFileEx` on the file handle this lock owns; the
    // OVERLAPPED is zeroed (a byte-range lock over the whole file).
    let ret = unsafe {
        LockFileEx(
            handle,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            0,
            &mut overlapped,
        )
    };
    if ret != 0 {
        LockAttempt::Acquired
    } else {
        let err = std::io::Error::last_os_error();
        // ERROR_LOCK_VIOLATION (33): another process holds the lock.
        if err.raw_os_error() == Some(33) {
            LockAttempt::Contended
        } else {
            LockAttempt::Failed(err)
        }
    }
}

/// Release the advisory lock (best-effort — the OS releases it when the
/// handle drops even if this never ran).
pub(crate) fn unlock(file: &std::fs::File) {
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    let handle = file.as_raw_handle();
    let mut overlapped: windows_sys::Win32::System::IO::OVERLAPPED = unsafe { std::mem::zeroed() };
    // SAFETY: `UnlockFileEx` on the file handle this lock owns; the
    // OVERLAPPED matches the lock's byte range.
    unsafe {
        UnlockFileEx(handle, 0, u32::MAX, 0, &mut overlapped);
    }
}

/// The error code that means "another holder" (ERROR_LOCK_VIOLATION = 33) —
/// the wait/retry policy's contention signal.
pub(crate) fn contended_errno() -> i32 {
    33
}
