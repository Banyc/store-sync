//! The deterministic fake [`Exec`] seam for property tests: scripted
//! outcomes keyed by argv, NO subprocess, no wall-clock. A harness builds
//! its transports with [`ScriptedExec`] so outcomes feed the SAME logic
//! branches (success, non-zero failure, transport error) without spawning
//! real processes — the suites stay parallel-safe, deterministic, and fast
//! even under the in-process (`cargo test --lib`) harness.

use crate::error::{Error, Result};
use crate::transport::{Exec, ExecOutcome};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

/// One scripted exec outcome (what a real command would have reported).
#[derive(Clone, Debug)]
pub(crate) struct ScriptedOutcome {
    pub(crate) exit_code: i32,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

impl ScriptedOutcome {
    /// A zero-exit success (the outcome every healthy verification reports).
    pub(crate) fn success() -> Self {
        ScriptedOutcome {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    /// A non-zero failure (the outcome that drives the compensation /
    /// rollback logic branches).
    pub(crate) fn failure(stderr: impl Into<String>) -> Self {
        ScriptedOutcome {
            exit_code: 1,
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }
}

/// The deterministic fake exec: `exec` looks up the EXACT argv in the
/// scripted table, falls back to the default outcome for anything unscripted,
/// and a scripted failure list forces a transport `Err` (the `Err` arm of
/// [`Exec::exec`]) for matching argv. No process is ever spawned and no
/// wall-clock is consulted: the outcome is a pure function of the argv plus
/// the script. Every executed argv is recorded (shared across the harness's
/// transports via `Arc`) so tests can assert the RENDERED command vectors
/// exactly as they did with the recording remotes.
#[derive(Clone)]
pub(crate) struct ScriptedExec {
    /// Exact-argv -> scripted outcome (a `BTreeMap` for determinism).
    by_argv: BTreeMap<Vec<String>, ScriptedOutcome>,
    /// Exact-argv -> scripted TRANSPORT ERROR (the `Err` arm of `exec`).
    errors: BTreeMap<Vec<String>, String>,
    /// The outcome for any argv without an exact script.
    default: ScriptedOutcome,
    /// Every executed argv, in order (shared across the harness's
    /// transports).
    executed: std::sync::Arc<Mutex<Vec<Vec<String>>>>,
}

impl ScriptedExec {
    /// Every argv succeeds (exit 0) — the deterministic default the
    /// deployment/state-machine properties need: their variants' verification
    /// contracts (`["true"]`, `["true", "a"]`, rendered template argv) all
    /// succeed, so the properties exercise the SUCCESS branches; tests that
    /// need a failure script it explicitly.
    pub(crate) fn default_success() -> Self {
        ScriptedExec {
            by_argv: BTreeMap::new(),
            errors: BTreeMap::new(),
            default: ScriptedOutcome::success(),
            executed: std::sync::Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Script an exact argv to return `outcome` (e.g. `["false"]` -> a
    /// failure, driving the verification-failure compensation branch).
    pub(crate) fn with_outcome(mut self, argv: &[&str], outcome: ScriptedOutcome) -> Self {
        self.by_argv
            .insert(argv.iter().map(|a| a.to_string()).collect(), outcome);
        self
    }

    /// Script an exact argv to return a transport `Err` (the `Err` arm of
    /// `exec` — the fault a real spawn/run failure would surface as).
    pub(crate) fn with_error(mut self, argv: &[&str], msg: impl Into<String>) -> Self {
        self.errors
            .insert(argv.iter().map(|a| a.to_string()).collect(), msg.into());
        self
    }

    /// The executed argv vectors, in order.
    pub(crate) fn executed(&self) -> Vec<Vec<String>> {
        self.executed.lock().unwrap().clone()
    }
}

impl Exec for ScriptedExec {
    fn exec(&self, argv: &[String], _timeout: Duration) -> Result<ExecOutcome> {
        self.executed.lock().unwrap().push(argv.to_vec());
        if let Some(msg) = self.errors.get(argv) {
            return Err(Error::transport(msg.clone()));
        }
        let out = self.by_argv.get(argv).unwrap_or(&self.default);
        Ok(ExecOutcome {
            exit_code: out.exit_code,
            stdout: out.stdout.clone(),
            stderr: out.stderr.clone(),
            timeout_cause: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fake is a PURE function of the argv + script: no process, no
    /// wall-clock — the deterministic property the parallel-safety relies on.
    #[test]
    fn scripted_exec_is_deterministic_and_records_argv() {
        let exec = ScriptedExec::default_success()
            .with_outcome(&["false"], ScriptedOutcome::failure("boom"))
            .with_error(&["crash"], "scripted spawn failure");
        let ok = exec
            .exec(&["true".into()], Duration::from_secs(30))
            .unwrap();
        assert_eq!(ok.exit_code, 0);
        assert!(ok.success());
        let bad = exec
            .exec(&["false".into()], Duration::from_secs(30))
            .unwrap();
        assert_eq!(bad.exit_code, 1);
        assert!(!bad.success());
        assert_eq!(bad.stderr, "boom");
        let err = exec
            .exec(&["crash".into()], Duration::from_secs(30))
            .unwrap_err();
        assert!(err.to_string().contains("scripted spawn failure"));
        assert_eq!(
            exec.executed(),
            vec![
                vec!["true".to_string()],
                vec!["false".to_string()],
                vec!["crash".to_string()],
            ]
        );
        // Unscripted argv falls back to the default (success).
        let other = exec.exec(
            &["sh".into(), "-c".into(), "x".into()],
            Duration::from_secs(1),
        );
        assert!(other.unwrap().success());
    }
}
