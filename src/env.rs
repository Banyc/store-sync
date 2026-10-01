//! The environment snapshot: the ONE place the process environment enters
//! the system, resolved at the process boundary and passed down.
//!
//! [`SysEnv`] is pure data (a `BTreeMap<OsString, OsString>` snapshot) with
//! pure typed accessors: ALL XDG fallback logic (data home, config home) and
//! the temp-dir resolution live HERE, never in subsystem code. Subsystem code
//! takes `&SysEnv` or a value resolved from it; it never reads the process
//! environment itself.
//!
//! The house pattern: the process boundary takes [`SysEnv::from_process`]
//! ONCE and threads it down. The only other place `std::env::` is allowed is
//! the child-process boundary ([`SysEnv::apply_to_command`]): every spawned
//! child receives this snapshot as its ENTIRE environment (`env_clear` + the
//! snapshot's variables), so a child's `PATH` (and any fake-bin/test
//! variable) is the deterministic snapshot, never whatever `PATH` won the
//! race in the parent — and nothing else leaks in.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

/// A snapshot of the process environment: pure data, no `std::env` reads.
///
/// Constructed at the process boundary via [`SysEnv::from_process`], or by
/// tests via [`SysEnv::from_map`] to build a hermetic environment that is
/// passed to the fixture instead of mutating the process-global env.
#[derive(Clone, Debug)]
pub struct SysEnv {
    vars: BTreeMap<OsString, OsString>,
}

impl SysEnv {
    /// Snapshot the current process environment (`std::env::vars_os`).
    /// This is THE process-boundary entry point: call it exactly once per
    /// command invocation and pass the snapshot down. Every other subsystem
    /// reads env state through this value or a resolved accessor — never from
    /// the live process env.
    pub fn from_process() -> SysEnv {
        SysEnv {
            vars: std::env::vars_os().collect(),
        }
    }

    /// Build a snapshot from an explicit map (test constructor): a hermetic
    /// environment that replaces the process env entirely — no `set_var`/
    /// `remove_var`, no lock, no cross-test interference.
    pub fn from_map(vars: BTreeMap<OsString, OsString>) -> SysEnv {
        SysEnv { vars }
    }

    /// Look up a single variable (raw `OsString` form).
    pub fn get(&self, k: &str) -> Option<OsString> {
        self.vars.get(OsStr::new(k)).cloned()
    }

    /// The `PATH` variable, if set.
    pub fn path(&self) -> Option<OsString> {
        self.get("PATH")
    }

    /// The temp directory: `TMPDIR` when set and non-empty, else the platform
    /// temp dir (`/tmp` on Unix). Pure: no process reads.
    pub fn temp_dir(&self) -> PathBuf {
        self.get("TMPDIR")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"))
    }

    /// The user data home: `XDG_DATA_HOME` when set and non-empty, else
    /// `$HOME`, else `.` (the current directory).
    pub fn data_home(&self) -> PathBuf {
        self.get("XDG_DATA_HOME")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                self.get("HOME")
                    .filter(|s| !s.is_empty())
                    .map(PathBuf::from)
            })
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// The user config home: `XDG_CONFIG_HOME` when set and non-empty, else
    /// `$HOME/.config`, else `.config`.
    pub fn config_home(&self) -> PathBuf {
        match self
            .get("XDG_CONFIG_HOME")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
        {
            Some(xdg) => xdg,
            None => match self.get("HOME").filter(|s| !s.is_empty()) {
                Some(home) => PathBuf::from(home).join(".config"),
                None => PathBuf::from(".config"),
            },
        }
    }

    /// The full variable list as `(key, value)` pairs. Used by tests to build
    /// snapshot-based fixtures and by [`SysEnv::apply_to_command`] internally.
    /// Production child-process boundaries MUST call
    /// [`SysEnv::apply_to_command`] instead: a bare `envs` overlay would let
    /// the parent env leak into a supposedly-hermetic snapshot.
    pub fn child_env(&self) -> Vec<(OsString, OsString)> {
        self.vars
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Apply this snapshot to a child `Command` as the child's ENTIRE
    /// environment: `env_clear()` first (the child inherits NOTHING from the
    /// parent — an overlay would leak the parent env into a supposedly-hermetic
    /// snapshot), then set exactly this snapshot's variables. Call this at EVERY
    /// child-process boundary.
    pub fn apply_to_command(&self, cmd: &mut std::process::Command) {
        cmd.env_clear();
        cmd.envs(self.vars.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> BTreeMap<OsString, OsString> {
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(*k), OsString::from(*v)))
            .collect()
    }

    #[test]
    fn temp_dir_prefers_tmpdir() {
        let env = SysEnv::from_map(map(&[("TMPDIR", "/hermetic/tmp")]));
        assert_eq!(env.temp_dir(), PathBuf::from("/hermetic/tmp"));
        // An empty TMPDIR falls back to the platform temp dir.
        let env = SysEnv::from_map(map(&[("TMPDIR", "")]));
        assert_eq!(env.temp_dir(), PathBuf::from("/tmp"));
        let env = SysEnv::from_map(map(&[]));
        assert_eq!(env.temp_dir(), PathBuf::from("/tmp"));
    }

    #[test]
    fn data_home_fallbacks() {
        // XDG_DATA_HOME wins.
        let env = SysEnv::from_map(map(&[("XDG_DATA_HOME", "/x/data"), ("HOME", "/h")]));
        assert_eq!(env.data_home(), PathBuf::from("/x/data"));
        // HOME falls back.
        let env = SysEnv::from_map(map(&[("HOME", "/h")]));
        assert_eq!(env.data_home(), PathBuf::from("/h"));
        // Neither -> ".".
        let env = SysEnv::from_map(map(&[]));
        assert_eq!(env.data_home(), PathBuf::from("."));
    }

    #[test]
    fn config_home_fallbacks() {
        // XDG_CONFIG_HOME wins verbatim (no extra .config appended).
        let env = SysEnv::from_map(map(&[("XDG_CONFIG_HOME", "/x/.config"), ("HOME", "/h")]));
        assert_eq!(env.config_home(), PathBuf::from("/x/.config"));
        // HOME falls back to $HOME/.config.
        let env = SysEnv::from_map(map(&[("HOME", "/h")]));
        assert_eq!(env.config_home(), PathBuf::from("/h/.config"));
        // Neither -> .config
        let env = SysEnv::from_map(map(&[]));
        assert_eq!(env.config_home(), PathBuf::from(".config"));
    }

    #[test]
    fn get_and_child_env_round_trip() {
        let env = SysEnv::from_map(map(&[("PATH", "/bin:/usr/bin"), ("TMPDIR", "/t")]));
        assert_eq!(env.get("PATH"), Some(OsString::from("/bin:/usr/bin")));
        assert_eq!(env.path(), Some(OsString::from("/bin:/usr/bin")));
        assert_eq!(env.get("UNSET"), None);
        let child = env.child_env();
        assert_eq!(child.len(), 2);
        assert!(child.contains(&(OsString::from("PATH"), OsString::from("/bin:/usr/bin"))));
        assert!(child.contains(&(OsString::from("TMPDIR"), OsString::from("/t"))));
    }

    #[test]
    fn apply_to_command_is_hermetic() {
        let env = SysEnv::from_map(map(&[("PATH", "/snapshot/bin:/usr/bin")]));
        let mut cmd = std::process::Command::new("true");
        // A parent env that would leak through a plain `envs` overlay.
        cmd.env("PATH", "/parent/bin");
        cmd.env("LEAKY_VAR", "parent-value");
        env.apply_to_command(&mut cmd);
        // The child's env is EXACTLY the snapshot: nothing from the parent.
        let vars: BTreeMap<OsString, OsString> = cmd
            .get_envs()
            .filter_map(|(k, v)| v.map(|v| (k.to_owned(), v.to_owned())))
            .collect();
        assert_eq!(vars.len(), 1);
        assert_eq!(
            vars.get(OsStr::new("PATH")),
            Some(&OsString::from("/snapshot/bin:/usr/bin"))
        );
        assert_eq!(vars.get(OsStr::new("LEAKY_VAR")), None);
    }
}
