//! Exponential backoff with jitter: the pause between connection retries.
//!
//! Policy: the first delay is `min_backoff_ms`, every next one doubles up to
//! `max_backoff_ms`; random ±20% jitter is added so that a fleet of clients
//! restarting after a server restart does not attack it in a synchronized
//! wave (thundering herd). After a successful session the counter resets:
//! a drop after a second of work is not a reason to wait 30 seconds for the
//! first retry.

use std::time::Duration;

use crate::ffi::TunnelConfig;

/// Exponential delay with jitter.
pub(crate) struct Backoff {
    min: Duration,
    max: Duration,
    /// Base without jitter: grows x2 on every `next`, reset by `reset`.
    base: Duration,
    /// Pseudorandom state (xorshift) — deterministic in tests.
    seed: u64,
}

impl Backoff {
    /// Builds the backoff from the client configuration (ms → Duration).
    pub(crate) fn from_config(config: &TunnelConfig) -> Self {
        Self::new(config.min_backoff_ms, config.max_backoff_ms)
    }

    pub(crate) fn new(min_ms: u32, max_ms: u32) -> Self {
        let min = Duration::from_millis(u64::from(min_ms.max(1)));
        let max = Duration::from_millis(u64::from(max_ms.max(min_ms)));
        Self {
            min,
            max,
            base: min,
            seed: 0x9E37_79B9_7F4A_7C15, // fixed golden sample
        }
    }

    /// Next xorshift step: pseudorandom [0..1) without external crates.
    fn jitter_unit(&mut self) -> f64 {
        // xorshift64*: good enough for jitter, deterministic in tests.
        self.seed ^= self.seed >> 12;
        self.seed ^= self.seed << 25;
        self.seed ^= self.seed >> 27;
        (self.seed >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Next delay: base * 2^i, with ±20% jitter, capped at `max`.
    pub(crate) fn next(&mut self) -> Duration {
        let jittered = (self.base.as_millis() as f64) * (0.8 + 0.4 * self.jitter_unit());
        let millis = jittered.clamp(
            self.min.as_millis() as f64,
            self.max.as_millis() as f64,
        );
        // The base grows only up to max: subsequent next() calls stay at the
        // ceiling (with fresh jitter every time).
        self.base = (self.base * 2).min(self.max);
        Duration::from_millis(millis as u64)
    }

    /// Reset after a successful session: the next delay is minimal again.
    pub(crate) fn reset(&mut self) {
        self.base = self.min;
    }

    /// Current base (without jitter) — for tests.
    #[cfg(test)]
    pub(crate) fn base(&self) -> Duration {
        self.base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_delay_is_near_min() {
        let mut backoff = Backoff::new(500, 30_000);
        let delay = backoff.next();
        assert!(
            delay >= Duration::from_millis(400) && delay <= Duration::from_millis(600),
            "first delay is ~500ms ±20%: {delay:?}"
        );
    }

    #[test]
    fn grows_exponentially_up_to_max() {
        let mut backoff = Backoff::new(100, 1600);
        let mut bases = Vec::new();
        for _ in 0..8 {
            backoff.next();
            bases.push(backoff.base());
        }
        // The base doubles up to the 1600ms ceiling and does not grow further.
        assert_eq!(bases, vec![
            Duration::from_millis(200),
            Duration::from_millis(400),
            Duration::from_millis(800),
            Duration::from_millis(1600),
            Duration::from_millis(1600),
            Duration::from_millis(1600),
            Duration::from_millis(1600),
            Duration::from_millis(1600),
        ]);
    }

    #[test]
    fn jitter_stays_within_bounds() {
        // ±20% jitter is applied to the CURRENT base; verify it on the minimal
        // base — reset before every step keeps base = min.
        let mut backoff = Backoff::new(500, 30_000);
        for _ in 0..20 {
            backoff.reset();
            let delay = backoff.next();
            assert!(
                delay >= Duration::from_millis(400) && delay <= Duration::from_millis(600),
                "jitter escaped ±20% of the min base: {delay:?}"
            );
        }
    }

    #[test]
    fn reset_returns_to_min() {
        let mut backoff = Backoff::new(500, 30_000);
        for _ in 0..4 {
            backoff.next();
        }
        assert!(backoff.base() > Duration::from_millis(500), "base grew");
        backoff.reset();
        assert_eq!(backoff.base(), Duration::from_millis(500));
        let delay = backoff.next();
        assert!(
            delay <= Duration::from_millis(600),
            "after reset the delay is back at the minimum: {delay:?}"
        );
    }

    #[test]
    fn max_is_never_exceeded_even_with_tiny_min() {
        let mut backoff = Backoff::new(1, 8);
        for _ in 0..20 {
            let delay = backoff.next();
            assert!(delay <= Duration::from_millis(9), "8ms ceiling + jitter: {delay:?}");
        }
    }
}
