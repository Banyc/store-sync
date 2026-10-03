//! The Windows advisory lock: `LockFileEx`/`UnlockFileEx` on the open file
//! handle (the byte-range lock over the whole file, exclusive and
//! non-blocking — the Windows counterpart of POSIX `flock`). The lock
//! file is never removed (the same stable-file discipline as Unix: every
//! acquisition locks the same file, so no unlock→unlink split window can
//! exist). Selected by the single `#[cfg(windows)]` `mod` declaration in
//! [`super`].

pub(crate) use super::LockAttempt;
use std::os::windows::io::AsRawHandle;

/// Open (creating on first use) the lock record WITHOUT FOLLOWING A REPARSE
/// POINT (symlink) at the record's own path, and without a truncating open. A
/// reparse point is opened itself (`FILE_FLAG_OPEN_REPARSE_POINT`) and then
/// REFUSED by inspecting the opened handle, so the `set_len`/write below can
/// never be redirected through the link into an arbitrary victim file (A2).
pub(crate) fn open_lock_file(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
        GetFileInformationByHandle,
    };
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = opts.open(path)?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the lock record path is a reparse point (symlink); refusing rather than \
             redirecting the lock through it",
        ));
    }
    Ok(file)
}

/// Whether an error from [`open_lock_file`] is the REPARSE-POINT refusal (rather
/// than a real open failure), so the caller can name the condition.
pub(crate) fn is_symlink_open_error(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::InvalidInput
}

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
