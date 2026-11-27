//! Lock-free atomic telemetry counters shared by the client and the server.
//! A snapshot ([`MetricsSnapshot`]) is copied on demand; the client FFI layer
//! reports it to the platform as lifetime traffic.

use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic tunnel counters (one instance per client/server).
#[derive(Debug, Default)]
pub struct Metrics {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    datagrams_sent: AtomicU64,
    datagrams_received: AtomicU64,
    packets_dropped: AtomicU64,
    sessions_established: AtomicU64,
    reconnects: AtomicU64,
}

impl Metrics {
    /// Records `n` payload bytes sent.
    pub fn record_bytes_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    /// Records `n` payload bytes received.
    pub fn record_bytes_received(&self, n: u64) {
        self.bytes_received.fetch_add(n, Ordering::Relaxed);
    }

    /// Records one sent data-plane datagram.
    pub fn record_datagram_sent(&self) {
        self.datagrams_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Records one received data-plane datagram.
    pub fn record_datagram_received(&self) {
        self.datagrams_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Records dropped packets (queue overflow, unknown frame, ...).
    pub fn record_packets_dropped(&self, n: u64) {
        self.packets_dropped.fetch_add(n, Ordering::Relaxed);
    }

    /// Records an established session (after `Welcome`).
    pub fn record_session_established(&self) {
        self.sessions_established.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a reconnect after an established session dropped.
    pub fn record_reconnect(&self) {
        self.reconnects.fetch_add(1, Ordering::Relaxed);
    }

    /// Takes a snapshot. Fields are read independently, so cross-field
    /// consistency is not guaranteed — sufficient for operational telemetry.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        MetricsSnapshot {
            bytes_sent: load(&self.bytes_sent),
            bytes_received: load(&self.bytes_received),
            datagrams_sent: load(&self.datagrams_sent),
            datagrams_received: load(&self.datagrams_received),
            packets_dropped: load(&self.packets_dropped),
            sessions_established: load(&self.sessions_established),
            reconnects: load(&self.reconnects),
        }
    }
}

/// Point-in-time copy of the counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MetricsSnapshot {
    /// Payload bytes sent through the tunnel.
    pub bytes_sent: u64,
    /// Payload bytes received from the tunnel.
    pub bytes_received: u64,
    /// Data-plane datagrams sent.
    pub datagrams_sent: u64,
    /// Data-plane datagrams received.
    pub datagrams_received: u64,
    /// Packets dropped (queue overflow, garbage frames).
    pub packets_dropped: u64,
    /// Established sessions (handshakes ending with `Welcome`).
    pub sessions_established: u64,
    /// Reconnects after an established session dropped.
    pub reconnects: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate_into_an_independent_snapshot() {
        let metrics = Metrics::default();
        assert_eq!(
            metrics.snapshot(),
            MetricsSnapshot::default(),
            "fresh counters are zero"
        );

        metrics.record_bytes_sent(100);
        metrics.record_bytes_received(50);
        metrics.record_datagram_sent();
        metrics.record_datagram_sent();
        metrics.record_datagram_received();
        metrics.record_packets_dropped(3);
        metrics.record_session_established();
        metrics.record_reconnect();

        let snap = metrics.snapshot();
        assert_eq!(snap.bytes_sent, 100);
        assert_eq!(snap.bytes_received, 50);
        assert_eq!(snap.datagrams_sent, 2);
        assert_eq!(snap.datagrams_received, 1);
        assert_eq!(snap.packets_dropped, 3);
        assert_eq!(snap.sessions_established, 1);
        assert_eq!(snap.reconnects, 1);

        // A snapshot is a copy, not a live view.
        metrics.record_bytes_sent(10);
        assert_eq!(snap.bytes_sent, 100);
        assert_eq!(metrics.snapshot().bytes_sent, 110);
    }
}
