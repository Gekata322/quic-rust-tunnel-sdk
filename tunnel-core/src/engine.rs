//! Core engine: the session loop, exponential reconnects, stop coordination
//! and network changes.
//!
//! The engine lives in a dedicated background thread (a single-threaded tokio
//! runtime — frugal for mobile devices). The FFI object
//! [`crate::ffi::TunnelClient`] talks to it through the shared
//! [`EngineShared`] (a state channel + packet queues) without owning async
//! types directly.
//!
//! Every status visible to the partner through the callback is computed here
//! ([`EngineShared::notify_status`]): `Connected` → `Reconnecting` →
//! `Disconnected` without duplicates, see the docs in `ffi`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc as std_mpsc};
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use tunnel_proto::Metrics;

use crate::backoff::Backoff;
use crate::ffi::{ConnectionStatus, ConnectionStatusCallback, TunnelConfig, TunnelState};
use crate::session::{SessionOutcome, run_session};

/// Length of the packet queues (both directions). When the inbound queue
/// overflows, `send_packet` returns `false` to the platform; the outbound
/// queue drops the packet and increments `packets_dropped` — UDP semantics,
/// not congestion.
const PACKET_QUEUE_LEN: usize = 256;

/// State shared between the FFI object and the engine thread.
pub(crate) struct EngineShared {
    pub(crate) config: TunnelConfig,
    state_tx: watch::Sender<TunnelState>,
    pub(crate) state_rx: watch::Receiver<TunnelState>,
    /// Platform → tunnel (tokio, bounded queue).
    pub(crate) packet_in_tx: mpsc::Sender<Vec<u8>>,
    /// Tunnel → platform (std sync_channel; FFI drains it with a timeout).
    /// The receiver is wrapped in a Mutex: a std type is not Sync, and
    /// parallel recv calls are serialized by design anyway (one consumer).
    pub(crate) packet_out_tx: std_mpsc::SyncSender<Vec<u8>>,
    pub(crate) packet_out_rx: Mutex<std_mpsc::Receiver<Vec<u8>>>,
    /// Telemetry: atomic counters, a snapshot is copied into FFI on demand.
    pub(crate) metrics: Arc<Metrics>,
    /// RTT of the last ping/pong, ms; 0 — not measured in this session yet.
    pub(crate) last_ping_ms: AtomicU64,
    /// The active QUIC connection — for force-closing on a network change.
    active_conn: Mutex<Option<quinn::Connection>>,
    /// Partner status callback (uniffi callback-interface).
    callback: Mutex<Option<Box<dyn ConnectionStatusCallback>>>,
    /// The last status sent to the callback — for notification deduplication.
    last_status: Mutex<Option<ConnectionStatus>>,
    /// Whether at least one session succeeded: "Connecting after that" is
    /// `Reconnecting`, not `Disconnected`.
    ever_connected: AtomicBool,
}

impl EngineShared {
    /// Builds the channels and metrics. The inbound packet receiver is
    /// returned separately: the engine thread takes it in
    /// `TunnelClient::connect`.
    pub(crate) fn new(config: TunnelConfig) -> (Arc<Self>, mpsc::Receiver<Vec<u8>>) {
        let (state_tx, state_rx) = watch::channel(TunnelState::Disconnected);
        let (packet_in_tx, packet_in_rx) = mpsc::channel(PACKET_QUEUE_LEN);
        let (packet_out_tx, packet_out_rx) = std_mpsc::sync_channel(PACKET_QUEUE_LEN);
        let shared = Arc::new(Self {
            config,
            state_tx,
            state_rx,
            packet_in_tx,
            packet_out_tx,
            packet_out_rx: Mutex::new(packet_out_rx),
            metrics: Arc::new(Metrics::default()),
            last_ping_ms: AtomicU64::new(0),
            active_conn: Mutex::new(None),
            callback: Mutex::new(None),
            last_status: Mutex::new(None),
            ever_connected: AtomicBool::new(false),
        });
        (shared, packet_in_rx)
    }

    /// Publishes a new state to FFI observers and the partner callback.
    pub(crate) fn set_state(&self, state: TunnelState) {
        self.state_tx.send_replace(state);
        self.notify_status();
    }

    /// Registers the partner callback (`None` — remove).
    /// After registration the callback immediately receives the current status.
    pub(crate) fn set_callback(&self, callback: Option<Box<dyn ConnectionStatusCallback>>) {
        if let Ok(mut slot) = self.callback.lock() {
            *slot = callback;
        }
        if let Ok(mut last) = self.last_status.lock() {
            // Force a repeat of the current status to the new callback.
            *last = None;
        }
        self.notify_status();
    }

    /// Computes the status from the internal state and notifies the callback
    /// only on a real change (no duplicates on every retry).
    fn notify_status(&self) {
        let state = self.state_rx.borrow().clone();
        if matches!(state, TunnelState::Connected { .. }) {
            self.ever_connected.store(true, Ordering::Relaxed);
        }
        let status = match &state {
            TunnelState::Connected { mtu, vip } => ConnectionStatus::Connected {
                mtu: *mtu,
                vip: vip.clone(),
            },
            // Graceful stop or permanent error — there is no connection.
            TunnelState::Stopping | TunnelState::Stopped => ConnectionStatus::Disconnected,
            // Connect attempt/backoff: before the first successful session it
            // is simply "no connection", afterwards it is recovery.
            TunnelState::Connecting | TunnelState::Disconnected => {
                if self.ever_connected.load(Ordering::Relaxed) {
                    ConnectionStatus::Reconnecting
                } else {
                    ConnectionStatus::Disconnected
                }
            }
        };

        let Ok(mut last) = self.last_status.lock() else {
            return;
        };
        if *last == Some(status.clone()) {
            return;
        }
        *last = Some(status.clone());
        drop(last);

        // The callback runs under the mutex: re-entrant set_status_callback
        // from inside a callback is impossible — the contract requires a fast,
        // non-reentrant handler (see the `ConnectionStatusCallback` docs).
        if let Ok(slot) = self.callback.lock() {
            if let Some(callback) = slot.as_ref() {
                callback.on_status_change(status);
            }
        }
    }

    /// Resets the ping (a new session invalidates old measurements).
    pub(crate) fn reset_ping(&self) {
        self.last_ping_ms.store(0, Ordering::Relaxed);
    }

    /// Remembers the active QUIC connection (or clears the slot).
    pub(crate) fn set_active_conn(&self, conn: Option<quinn::Connection>) {
        if let Ok(mut slot) = self.active_conn.lock() {
            *slot = conn;
        }
    }

    /// Takes the active QUIC connection out of the slot (for a graceful close
    /// after the session future was cancelled by the stop command).
    pub(crate) fn take_active_conn(&self) -> Option<quinn::Connection> {
        self.active_conn.lock().ok()?.take()
    }

    /// Network change hint: the active QUIC connection is closed immediately,
    /// the engine leaves the session and reconnects (already on the new interface).
    pub(crate) fn force_reconnect(&self) {
        let conn = match self.active_conn.lock() {
            Ok(mut slot) => slot.take(),
            Err(_) => return,
        };
        if let Some(conn) = conn {
            tracing::info!("network changed: closing the active QUIC connection");
            conn.close(quinn::VarInt::from_u32(0), b"network-changed");
        }
    }

    /// Graceful stop: idempotent, `Stopped` is not overwritten.
    pub(crate) fn request_stop(&self) {
        let changed = self.state_tx.send_if_modified(|state| {
            if matches!(state, TunnelState::Stopped) {
                false
            } else {
                *state = TunnelState::Stopping;
                true
            }
        });
        if changed {
            self.notify_status();
        }
    }

    /// Final state after the engine loop completes.
    pub(crate) fn finish_stop(&self) {
        let changed = self.state_tx.send_if_modified(|state| {
            if matches!(state, TunnelState::Stopped) {
                false
            } else {
                *state = TunnelState::Stopped;
                true
            }
        });
        if changed {
            self.notify_status();
        }
    }
}

/// Waits for a stop command (Stopping/Stopped) on a clone of the watch channel.
pub(crate) async fn wait_stopping(stop_rx: &mut watch::Receiver<TunnelState>) {
    loop {
        if matches!(*stop_rx.borrow(), TunnelState::Stopping | TunnelState::Stopped) {
            return;
        }
        // The channel lives as long as the FFI object: an error means the
        // sender was dropped — treat it as a stop.
        if stop_rx.changed().await.is_err() {
            return;
        }
    }
}

/// The main engine loop: session attempt → outcome → backoff → retry.
/// Terminates on `request_stop()` (`Shutdown`) or a permanent error.
pub(crate) async fn run(shared: Arc<EngineShared>, mut packet_in_rx: mpsc::Receiver<Vec<u8>>) {
    let mut backoff = Backoff::from_config(&shared.config);
    shared.set_state(TunnelState::Connecting);

    loop {
        let outcome = run_session(&shared, &mut packet_in_rx).await;
        let mut stop_rx = shared.state_rx.clone();
        match outcome {
            // `disconnect()` or dropping the FFI object — leave the loop.
            SessionOutcome::Shutdown => {
                // The stop command cancels the session future, so its own
                // `conn.close()` may never run: send CONNECTION_CLOSE here,
                // otherwise the peer keeps the session until the idle timeout
                // (the address stays taken, routing stays registered).
                if let Some(conn) = shared.take_active_conn() {
                    let locally_initiated = conn.close_reason().is_none();
                    conn.close(quinn::VarInt::from_u32(0), b"client-stop");
                    if locally_initiated {
                        // `closed()` resolves instantly for a local close, so
                        // instead keep the runtime alive while the connection
                        // drivers flush CONNECTION_CLOSE to the peer.
                        tokio::time::sleep(Duration::from_millis(crate::session::CLOSE_DRAIN_MS)).await;
                    }
                }
                break;
            }
            SessionOutcome::Closed { cause, established } => {
                // Permanent errors (token, version, config) are not healed by retries.
                if cause.is_permanent() {
                    tracing::warn!(%cause, "permanent error: engine stopped");
                    shared.set_active_conn(None);
                    shared.set_state(TunnelState::Stopped);
                    return;
                }
                shared.set_active_conn(None);
                if established {
                    // The session was working: retry fast, count a reconnect.
                    tracing::info!(%cause, "session dropped: reconnecting");
                    shared.metrics.record_reconnect();
                    backoff.reset();
                } else {
                    tracing::info!(%cause, "attempt failed: backing off");
                }
                shared.set_state(TunnelState::Disconnected);
                let delay = backoff.next();
                tokio::select! {
                    biased;
                    _ = wait_stopping(&mut stop_rx) => break,
                    _ = tokio::time::sleep(delay) => shared.set_state(TunnelState::Connecting),
                }
            }
        }
    }

    shared.finish_stop();
}

#[cfg(test)]
mod tests {
    // unwrap/expect are acceptable in tests: a failing test is the signal.
    use super::*;
    use std::time::Duration;

    fn sample_config() -> TunnelConfig {
        TunnelConfig {
            server_host: "127.0.0.1".to_owned(),
            server_name: "localhost".to_owned(),
            server_port: 4433,
            auth_token: "sample-token".to_owned(),
            client_id: "engine-test".to_owned(),
            pinned_server_cert_der: vec![0x30],
            connect_timeout_ms: 1000,
            min_backoff_ms: 50,
            max_backoff_ms: 200,
            keepalive_interval_secs: 0,
        }
    }

    #[test]
    fn packet_queues_are_bounded() {
        let (shared, mut packet_in_rx) = EngineShared::new(sample_config());
        // Inbound queue: PACKET_QUEUE_LEN packets fit, the next one does not.
        let packet = vec![0x45, 0x00];
        for _ in 0..PACKET_QUEUE_LEN {
            assert!(shared.packet_in_tx.try_send(packet.clone()).is_ok());
        }
        assert!(
            shared.packet_in_tx.try_send(packet).is_err(),
            "the inbound queue must be bounded"
        );
        // Outbound queue: the receiver drains everything back.
        assert!(shared.packet_out_tx.try_send(vec![0x60]).is_ok());
        let drained = shared.packet_out_rx.lock().unwrap().recv().unwrap();
        assert_eq!(drained, vec![0x60]);
        let _ = packet_in_rx.try_recv();
    }

    /// Test callback: collects statuses into a shared buffer.
    struct Collector {
        events: Arc<Mutex<Vec<ConnectionStatus>>>,
    }
    impl ConnectionStatusCallback for Collector {
        fn on_status_change(&self, status: ConnectionStatus) {
            self.events.lock().unwrap().push(status);
        }
    }

    #[test]
    fn status_callback_full_lifecycle() {
        let (shared, _rx) = EngineShared::new(sample_config());
        let events = Arc::new(Mutex::new(Vec::new()));
        shared.set_callback(Some(Box::new(Collector { events: Arc::clone(&events) })));

        // Registration repeats the current status: before connect() it is Disconnected.
        assert_eq!(*events.lock().unwrap(), vec![ConnectionStatus::Disconnected]);

        // First connect attempt: no "recovery" yet — Reconnecting only makes
        // sense after a successful session.
        shared.set_state(TunnelState::Connecting);
        assert_eq!(*events.lock().unwrap(), vec![ConnectionStatus::Disconnected]);

        shared.set_state(TunnelState::Connected {
            mtu: 1280,
            vip: "10.66.0.2".to_owned(),
        });
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                ConnectionStatus::Disconnected,
                ConnectionStatus::Connected {
                    mtu: 1280,
                    vip: "10.66.0.2".to_owned(),
                },
            ]
        );

        // Session drop and the retry loop: one Reconnecting, no duplicates.
        shared.set_state(TunnelState::Connecting);
        shared.set_state(TunnelState::Disconnected);
        shared.set_state(TunnelState::Connecting);
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                ConnectionStatus::Disconnected,
                ConnectionStatus::Connected {
                    mtu: 1280,
                    vip: "10.66.0.2".to_owned(),
                },
                ConnectionStatus::Reconnecting,
            ]
        );

        // Graceful stop → Disconnected; the final Stopped does not duplicate.
        shared.request_stop();
        shared.finish_stop();
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                ConnectionStatus::Disconnected,
                ConnectionStatus::Connected {
                    mtu: 1280,
                    vip: "10.66.0.2".to_owned(),
                },
                ConnectionStatus::Reconnecting,
                ConnectionStatus::Disconnected,
            ]
        );
    }

    #[tokio::test]
    async fn wait_stopping_fires_on_request() {
        let (shared, _rx) = EngineShared::new(sample_config());
        let mut stop_rx = shared.state_rx.clone();
        tokio::select! {
            _ = wait_stopping(&mut stop_rx) => panic!("must not finish without a stop command"),
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
        shared.request_stop();
        tokio::select! {
            _ = wait_stopping(&mut stop_rx) => {} // command observed
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                panic!("wait_stopping did not see request_stop")
            }
        }
    }
}
