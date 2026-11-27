//! Per-client token-bucket rate limiting for the data plane.
//!
//! Each session with a configured bandwidth cap (the optional `:mbps`
//! suffix in `tokens.txt`) gets a bucket filled at that rate; every inbound
//! datagram consumes `len` bytes of tokens. When the bucket is empty,
//! datagrams are dropped — UDP semantics, no error is reported to the peer.
//! Control-plane traffic (handshake, ping/pong) is never throttled, so a
//! throttled session stays observable and reconnectable.
//!
//! Buckets are keyed by the session's virtual address and therefore survive
//! QUIC connection migration: a client that moves networks (rebinding its
//! endpoint) keeps its bucket, and its quota does not reset.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::Instant;

/// How much traffic the bucket may accumulate, in seconds of the configured
/// rate. Bursts shorter than this window never see a drop.
const BURST_WINDOW_SECS: f64 = 1.0;
/// Minimal bucket capacity, bytes: even a tiny configured rate admits a few
/// full-size datagrams instead of dropping everything outright.
const MIN_BURST_BYTES: f64 = 4_096.0;
/// One Mbps expressed in bytes per second.
const BYTES_PER_MBPS_PER_SEC: f64 = 125_000.0;

/// One client's bucket state.
#[derive(Debug)]
struct Bucket {
    /// Bytes available right now, capped at `capacity`.
    tokens: f64,
    /// Maximum storable tokens: one burst window of the configured rate.
    capacity: f64,
    /// Refill speed, bytes per second.
    rate_bytes_per_sec: f64,
    /// Moment of the last lazy refill.
    last_refill: Instant,
}

/// Per-session rate limiter: `vip → token bucket`. Sessions without a
/// configured limit (or not registered at all) are unlimited.
#[derive(Debug, Default)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<Ipv4Addr, Bucket>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a session's bucket; `limit_mbps == None` stores nothing and
    /// keeps the session unlimited. Re-registration replaces the bucket.
    pub fn register(&self, vip: Ipv4Addr, limit_mbps: Option<u32>) {
        let Some(mbps) = limit_mbps else {
            return;
        };
        let rate_bytes_per_sec = f64::from(mbps) * BYTES_PER_MBPS_PER_SEC;
        let capacity = (rate_bytes_per_sec * BURST_WINDOW_SECS).max(MIN_BURST_BYTES);
        self.buckets
            .lock()
            .expect("limiter mutex")
            .insert(vip, Bucket {
                tokens: capacity,
                capacity,
                rate_bytes_per_sec,
                last_refill: Instant::now(),
            });
    }

    /// Removes the session's bucket (idempotent).
    pub fn unregister(&self, vip: Ipv4Addr) {
        self.buckets.lock().expect("limiter mutex").remove(&vip);
    }

    /// Whether `bytes` may pass now; refills the bucket lazily first.
    /// Unregistered sessions are always allowed. A failed check consumes
    /// nothing: tokens are never reserved for a datagram that was dropped.
    pub fn try_consume(&self, vip: Ipv4Addr, bytes: usize) -> bool {
        let mut buckets = self.buckets.lock().expect("limiter mutex");
        let Some(bucket) = buckets.get_mut(&vip) else {
            return true;
        };
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * bucket.rate_bytes_per_sec).min(bucket.capacity);
        bucket.last_refill = now;

        let needed = bytes as f64;
        if bucket.tokens >= needed {
            bucket.tokens -= needed;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn vip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 66, 0, last)
    }

    #[test]
    fn unregistered_and_limitless_sessions_pass_everything() {
        let limiter = RateLimiter::new();
        assert!(limiter.try_consume(vip(2), 1_000_000), "no bucket at all");

        limiter.register(vip(3), None);
        assert!(limiter.try_consume(vip(3), 1_000_000), "no configured limit");
    }

    #[tokio::test]
    async fn limited_session_drains_then_drops() {
        // 1 Mbps = 125_000 bytes per second; the initial bucket holds exactly
        // one second of traffic. Fail-assertions use amounts no plausible
        // scheduler stall could refill, pass-assertions use amounts the
        // guaranteed refill always covers.
        let limiter = RateLimiter::new();
        limiter.register(vip(2), Some(1));

        assert!(limiter.try_consume(vip(2), 125_000), "the full bucket passes");
        assert!(
            !limiter.try_consume(vip(2), 60_000),
            "an empty bucket drops: refilling this much takes 0.5s"
        );

        // 20 ms of sleep refills at least 125_000 × 0.02 = 2_500 bytes
        // (sleep guarantees at least the requested duration).
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(limiter.try_consume(vip(2), 2_000), "the refill is available");
        assert!(
            !limiter.try_consume(vip(2), 125_000),
            "refill is capped at the capacity: at most 123_000 tokens remain"
        );
    }

    #[tokio::test]
    async fn dropped_datagrams_consume_no_tokens() {
        let limiter = RateLimiter::new();
        limiter.register(vip(2), Some(1));

        assert!(limiter.try_consume(vip(2), 100_000)); // 25_000 left
        assert!(limiter.try_consume(vip(2), 9_000)); // 16_000 left
        assert!(limiter.try_consume(vip(2), 9_000)); // 7_000 left
        assert!(
            !limiter.try_consume(vip(2), 9_000),
            "the bucket is short — the datagram is dropped"
        );
        // The dropped datagram consumed nothing: the leftover still admits
        // 6_500 bytes. Refill can only help this assertion, never hurt it.
        assert!(limiter.try_consume(vip(2), 6_500));
    }

    #[tokio::test]
    async fn sessions_are_independent_and_reregistration_resets() {
        let limiter = RateLimiter::new();
        limiter.register(vip(2), Some(1));
        limiter.register(vip(3), Some(1));
        assert!(limiter.try_consume(vip(2), 125_000));
        assert!(
            limiter.try_consume(vip(3), 125_000),
            "each vip has its own bucket"
        );

        // The reconnected client gets a fresh bucket, not an empty one.
        limiter.register(vip(2), Some(1));
        assert!(limiter.try_consume(vip(2), 125_000), "the bucket was reset");

        // Unregistration removes any cap for the address.
        limiter.unregister(vip(2));
        assert!(limiter.try_consume(vip(2), 1_000_000));
    }
}
