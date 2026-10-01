//! Platform helpers: the small Unix/Windows divergences (file mode bits,
//! symlinks) consolidated behind ONE cfg switch at this module boundary.
//!
//! * [`chmod`] — set a file's mode bits; a no-op on Windows (no Unix mode
//!   bits; file ACLs are the privacy mechanism).
//! * [`file_mode`] — read a file's mode bits; a fixed conventional mode on
//!   Windows.
//! * [`symlink`] — create a symlink; on Windows, best-effort via the
//!   platform symlink API (which requires admin/developer mode — a failure
//!   propagates, documented).
//!
//! The rest of the crate calls these helpers and never sees the switch.

use std::path::Path;

/// Set a file's mode bits — a no-op on Windows (no Unix mode bits; file
/// ACLs are the privacy mechanism). Documented weaker guarantee of the
/// Windows port.
pub fn chmod(path: &Path, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(windows)]
    {
        let _ = (path, mode);
        Ok(())
    }
}

/// Read a file's mode bits — a fixed conventional mode (0o644) on Windows
/// (no Unix mode bits). Documented weaker guarantee of the Windows port.
pub fn file_mode(path: &Path) -> std::io::Result<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(std::fs::metadata(path)?.mode())
    }
    #[cfg(windows)]
    {
        let _ = path;
        Ok(0o644)
    }
}

/// The mode bits of an already-read [`std::fs::Metadata`] — a fixed
/// conventional mode (0o644) on Windows (no Unix mode bits). Documented
/// weaker guarantee of the Windows port.
pub fn metadata_mode(m: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        m.mode()
    }
    #[cfg(windows)]
    {
        let _ = m;
        0o644
    }
}

/// Create a symlink — on Windows, best-effort via the platform symlink API
/// (which requires admin/developer mode; a failure propagates). Documented
/// weaker guarantee of the Windows port.
pub fn symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{symlink_dir, symlink_file};
        // Best-effort: try a directory symlink first (the common case — the
        // `current`/`root` layout links point at directories), then a file
        // symlink. Both require admin/developer mode on Windows; a failure
        // propagates.
        match symlink_dir(target, link) {
            Ok(()) => Ok(()),
            Err(_) => symlink_file(target, link),
        }
    }
}
