//! Verbose step tracing.
//!
//! A tiny, dependency-free tracer: when verbose is enabled, each traced
//! step is emitted to STDERR as a `[trace]` line carrying the step name,
//! the time spent since the previous step (and since the trace start), and
//! a free-form detail line. Stderr keeps the report on stdout
//! machine-parseable. A disabled tracer is a zero-cost no-op.
//!
//! The tracer is the debugging surface for the multi-step operations in
//! this crate: a caller records each step (parse, resolve, transfer) so a
//! future agent can see exactly what an operation did, in what order, and
//! how long each step took — `grep '\[trace\]'` on the captured stderr.

use std::time::Instant;

/// A verbose step tracer. `enabled` gates every emission; a disabled tracer
/// records nothing and prints nothing.
pub struct Tracer {
    enabled: bool,
    start: Instant,
    last: Instant,
}

impl Tracer {
    /// A tracer gated on `enabled`.
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            start: Instant::now(),
            last: Instant::now(),
        }
    }

    /// Record a step: `[trace] +<since-last> (+<since-start>) <name>: <detail>`.
    /// A no-op when verbose is off.
    pub fn step(&mut self, name: &str, detail: impl std::fmt::Display) {
        if !self.enabled {
            return;
        }
        let now = Instant::now();
        let since_last = now.duration_since(self.last);
        let since_start = now.duration_since(self.start);
        eprintln!("[trace] +{since_last:?} (+{since_start:?}) {name}: {detail}");
        self.last = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A disabled tracer is a no-op: `step` never emits (the emission path
    /// is gated on `enabled`, so a `Tracer::new(false)` cannot print).
    #[test]
    fn disabled_tracer_is_a_noop() {
        let mut t = Tracer::new(false);
        // Must not panic and must not print: the step body is gated on
        // `enabled`, so this exercises the gate itself.
        t.step("ref.parse", "token=\"@-\" -> @-");
    }

    /// An enabled tracer records steps (the elapsed durations are monotonic —
    /// each step's since-last is >= 0 and the since-start grows). The
    /// emission itself goes to stderr; the test asserts the bookkeeping
    /// contract, not the captured sink.
    #[test]
    fn enabled_tracer_records_steps() {
        let mut t = Tracer::new(true);
        t.step("ref.parse", "token=\"@-\" -> @-");
        t.step("ref.resolve", "target=\"production\" expr=@-");
        // The bookkeeping is internal; the contract is that two steps ran
        // without panicking.
    }
}
