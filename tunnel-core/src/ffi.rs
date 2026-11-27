//! Public SDK interface of the core (`uniffi`): the contract for partner SDKs.
//!
//! Session control is exactly **five methods**:
//!
//! | Method | Purpose |
//! |---|---|
//! | `TunnelClient(config)` | create the client (config validation) |
//! | `connect()` | start the background engine (idempotent) |
//! | `disconnect()` | stop gracefully (non-blocking) |
//! | `get_telemetry()` | traffic (bytes) and the last ping |
//! | `set_status_callback(cb)` | connection status change notifications |
//!
//! Plus the data plane a tunnel cannot do without: `send_packet` /
//! `recv_packet` (poll model) and the network-change hint `on_network_changed`.
//! Packet exchange is deliberately callback-free: the poll model gives natural
//! backpressure and works reliably over FFI on iOS/Android (see method docs).
//!
//! The status callback, on the contrary, inverts control: the partner does not
//! need to poll the state — the core itself notifies about
//! [`ConnectionStatus::Connected`], [`ConnectionStatus::Reconnecting`] and
//! [`ConnectionStatus::Disconnected`].

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::engine::{EngineShared, run};
use crate::error::CoreError;

/// Internal engine state (not part of the FFI contract; the partner sees
/// [`ConnectionStatus`]). Visible to tests via [`TunnelClient::state`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelState {
    /// Not started or waiting for a retry.
    Disconnected,
    /// Connection/handshake in progress (or backoff before a retry).
    Connecting,
    /// Session established: MTU and the virtual address from `Welcome`.
    Connected { mtu: u16, vip: String },
    /// Graceful stop after `disconnect()` is in progress.
    Stopping,
    /// Stopped on a permanent error (rejected token, protocol version,
    /// broken certificate). The engine will not recover — create a new client.
    Stopped,
}

/// Connection status for the partner callback — exactly three states.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectionStatus {
    /// Session established: `mtu` — MTU of the virtual interface (configure
    /// the TUN with it), `vip` — the assigned client address (interface address).
    Connected { mtu: u16, vip: String },
    /// The engine is restoring the connection after at least one successful
    /// session: a connect attempt or backoff before a retry is in progress.
    Reconnecting,
    /// No connection: the client was created, stopped by `disconnect()`, or
    /// the engine stopped on a permanent error (token, protocol version).
    Disconnected,
}

/// Status change callback; implemented on the platform side (uniffi
/// callback-interface). Called from core-internal threads: it must be fast
/// and must NOT call SDK methods inside itself (deadlock risk).
#[uniffi::export(callback_interface)]
pub trait ConnectionStatusCallback: Send + Sync {
    /// The only notification; statuses arrive without duplicates.
    fn on_status_change(&self, status: ConnectionStatus);
}

/// Telemetry for the partner: traffic and the last ping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct Telemetry {
    /// Payload bytes sent through the tunnel (since client creation).
    pub bytes_sent: u64,
    /// Payload bytes received from the tunnel (since client creation).
    pub bytes_received: u64,
    /// RTT of the last ping/pong, ms; `None` — not measured yet.
    pub ping_ms: Option<u32>,
}

/// Client configuration. Required fields: `server_host`, `server_port`,
/// `auth_token`, `pinned_server_cert_der`; the rest have recommended defaults
/// applied at the FFI boundary (in Kotlin/Swift/Python).
#[derive(Debug, Clone, uniffi::Record)]
pub struct TunnelConfig {
    /// Server host or IP (DNS is resolved on every retry).
    pub server_host: String,
    /// Server name for SNI and certificate verification; empty — `server_host` is used.
    #[uniffi(default = "")]
    pub server_name: String,
    /// Server UDP port (usually 443).
    pub server_port: u16,
    /// B2B authentication token (issued to the partner by the server operator).
    pub auth_token: String,
    /// Client identifier for server logs/telemetry; empty — `sdk-client`.
    #[uniffi(default = "")]
    pub client_id: String,
    /// DER bytes of the server certificate (pinned root) — the only trusted
    /// TLS root; public CAs are not used.
    pub pinned_server_cert_der: Vec<u8>,
    /// Connect + handshake deadline, ms.
    #[uniffi(default = 8000)]
    pub connect_timeout_ms: u32,
    /// Minimum delay before a retry, ms.
    #[uniffi(default = 500)]
    pub min_backoff_ms: u32,
    /// Maximum delay before a retry, ms.
    #[uniffi(default = 30000)]
    pub max_backoff_ms: u32,
    /// Application-level ping period, sec; 0 — from the server `Welcome`, otherwise 15 sec.
    #[uniffi(default = 0)]
    pub keepalive_interval_secs: u32,
}

/// Fills in defaults for optional configuration fields.
fn normalize_config(mut config: TunnelConfig) -> TunnelConfig {
    if config.server_name.trim().is_empty() {
        config.server_name = config.server_host.clone();
    }
    if config.client_id.trim().is_empty() {
        config.client_id = "sdk-client".to_owned();
    }
    config
}

/// Validates the configuration before the engine starts: early and clear
/// errors instead of silently failing connections.
fn validate_config(config: &TunnelConfig) -> Result<(), CoreError> {
    let check = |cond: bool, message: &str| {
        if cond {
            Ok(())
        } else {
            Err(CoreError::InvalidConfig(message.to_owned()))
        }
    };
    check(!config.server_host.trim().is_empty(), "server_host is empty")?;
    check(config.server_port > 0, "server_port is zero")?;
    check(!config.auth_token.is_empty(), "auth_token is empty")?;
    check(!config.pinned_server_cert_der.is_empty(), "pinned_server_cert_der is empty")?;
    check(config.connect_timeout_ms > 0, "connect_timeout_ms is zero")?;
    check(config.min_backoff_ms > 0, "min_backoff_ms is zero")?;
    check(
        config.max_backoff_ms >= config.min_backoff_ms,
        "max_backoff_ms is below min_backoff_ms",
    )?;
    Ok(())
}

/// SDK entry point: five control methods + packet exchange.
///
/// All methods are thread-safe. `recv_packet` blocks the thread until the
/// timeout — call it from a dedicated background thread (NOT from the
/// main/UI thread).
#[derive(uniffi::Object)]
pub struct TunnelClient {
    shared: Arc<EngineShared>,
    /// Platform → tunnel receiver; taken in `connect()` and handed to the engine.
    packet_in_rx: Mutex<Option<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    /// Holder of the engine thread; not joined in `disconnect()` (non-blocking stop).
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

#[uniffi::export]
impl TunnelClient {
    /// Creates the client and validates the configuration; the connection is
    /// established after `connect()`. The method does not block.
    #[uniffi::constructor]
    pub fn new(config: TunnelConfig) -> Result<Self, CoreError> {
        let config = normalize_config(config);
        validate_config(&config)?;
        let (shared, packet_in_rx) = EngineShared::new(config);
        Ok(Self {
            shared,
            packet_in_rx: Mutex::new(Some(packet_in_rx)),
            worker: Mutex::new(None),
        })
    }

    /// Starts the background engine (reconnects, keepalive, data plane).
    /// Idempotent: a second call on a live engine is a no-op.
    /// After a permanent error the engine does not recover — create a new client.
    pub fn connect(&self) -> Result<(), CoreError> {
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| CoreError::Internal("worker mutex poisoned".to_owned()))?;
        if worker.is_some() {
            return Ok(());
        }
        let packet_in_rx = self
            .packet_in_rx
            .lock()
            .map_err(|_| CoreError::Internal("packet mutex poisoned".to_owned()))?
            .take()
            .ok_or_else(|| {
                CoreError::Internal(
                    "the engine already completed its full lifecycle; create a new TunnelClient"
                        .to_owned(),
                )
            })?;

        let shared = Arc::clone(&self.shared);
        let handle = std::thread::Builder::new()
            .name("tunnel-core".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        tracing::error!(%err, "failed to create the tokio runtime");
                        shared.finish_stop();
                        return;
                    }
                };
                runtime.block_on(run(shared, packet_in_rx));
            })
            .map_err(|err| CoreError::Internal(format!("failed to spawn the engine thread: {err}")))?;
        *worker = Some(handle);
        Ok(())
    }

    /// Stops the engine gracefully. Non-blocking: the engine thread exits on
    /// its own once it sees the stop command (connect, session, retry).
    /// Idempotent.
    pub fn disconnect(&self) {
        self.shared.request_stop();
        // The thread handle is not joined so that disconnect() does not block
        // the FFI thread while the session drains; the thread exits via
        // wait_stopping.
        if let Ok(mut worker) = self.worker.lock() {
            let _ = worker.take();
        }
    }

    /// Registers the status change callback (`None` — remove it).
    ///
    /// The callback is called from core-internal threads; it must be fast and
    /// must not call SDK methods inside itself. Right after registration the
    /// current status arrives — the partner does not need to query the state.
    pub fn set_status_callback(&self, callback: Option<Box<dyn ConnectionStatusCallback>>) {
        self.shared.set_callback(callback);
    }

    /// Telemetry snapshot: traffic and the last ping (since client creation).
    pub fn get_telemetry(&self) -> Telemetry {
        let snapshot = self.shared.metrics.snapshot();
        let ping = self.shared.last_ping_ms.load(Ordering::Relaxed);
        Telemetry {
            bytes_sent: snapshot.bytes_sent,
            bytes_received: snapshot.bytes_received,
            ping_ms: if ping == 0 {
                None
            } else {
                Some(ping.min(u32::MAX as u64) as u32)
            },
        }
    }

    /// Sends a raw IP packet from the platform TUN into the tunnel.
    ///
    /// Non-blocking. Returns `false` when the queue is full — the packet is
    /// dropped (UDP semantics; TCP streams inside the tunnel retransmit
    /// themselves).
    pub fn send_packet(&self, packet: Vec<u8>) -> bool {
        if packet.is_empty() {
            return false;
        }
        self.shared.packet_in_tx.try_send(packet).is_ok()
    }

    /// Drains one packet from the tunnel for writing into the platform TUN.
    ///
    /// Blocks the thread up to `timeout_ms`; `None` — timeout or the engine
    /// closed the stream. Call from a dedicated background thread; parallel
    /// calls are serialized (the contract has a single consumer).
    pub fn recv_packet(&self, timeout_ms: u32) -> Option<Vec<u8>> {
        let rx = self.shared.packet_out_rx.lock().ok()?;
        rx.recv_timeout(Duration::from_millis(u64::from(timeout_ms)))
            .ok()
    }

    /// Network change hint (Wi-Fi ↔ cellular): the active QUIC connection is
    /// closed and the engine immediately reconnects on the new interface.
    pub fn on_network_changed(&self) {
        self.shared.force_reconnect();
    }
}

/// Methods for Rust tests: not part of the FFI contract (the partner only
/// needs `ConnectionStatus` and `get_telemetry`).
impl TunnelClient {
    /// Current internal engine state.
    pub fn state(&self) -> TunnelState {
        self.shared.state_rx.borrow().clone()
    }

    /// MTU negotiated by the server in the current session (`Welcome.mtu`).
    pub fn negotiated_mtu(&self) -> Option<u16> {
        match self.shared.state_rx.borrow().clone() {
            TunnelState::Connected { mtu, .. } => Some(mtu),
            _ => None,
        }
    }

    /// Virtual address of the client in the current session (`Welcome.vip`).
    pub fn negotiated_vip(&self) -> Option<String> {
        match self.shared.state_rx.borrow().clone() {
            TunnelState::Connected { vip, .. } => Some(vip),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    // unwrap/expect are acceptable in tests: a failing test is the signal.
    use super::*;

    fn config() -> TunnelConfig {
        TunnelConfig {
            server_host: "127.0.0.1".to_owned(),
            server_name: "localhost".to_owned(),
            server_port: 443,
            auth_token: "token".to_owned(),
            client_id: "test".to_owned(),
            pinned_server_cert_der: vec![0x30],
            connect_timeout_ms: 1000,
            min_backoff_ms: 50,
            max_backoff_ms: 200,
            keepalive_interval_secs: 0,
        }
    }

    #[test]
    fn config_validation() {
        assert!(validate_config(&config()).is_ok());

        let mut bad = config();
        bad.auth_token = String::new();
        assert!(matches!(validate_config(&bad), Err(CoreError::InvalidConfig(_))));

        let mut bad = config();
        bad.max_backoff_ms = 10;
        bad.min_backoff_ms = 100;
        assert!(matches!(validate_config(&bad), Err(CoreError::InvalidConfig(_))));

        let mut bad = config();
        bad.pinned_server_cert_der = Vec::new();
        assert!(matches!(validate_config(&bad), Err(CoreError::InvalidConfig(_))));

        let mut bad = config();
        bad.connect_timeout_ms = 0;
        assert!(matches!(validate_config(&bad), Err(CoreError::InvalidConfig(_))));
    }

    #[test]
    fn normalize_fills_optional_fields() {
        let mut cfg = config();
        cfg.server_name = "  ".to_owned();
        cfg.client_id = String::new();
        let cfg = normalize_config(cfg);
        assert_eq!(cfg.server_name, "127.0.0.1", "server_name → server_host");
        assert_eq!(cfg.client_id, "sdk-client");
    }

    /// Test callback: collects statuses into a shared buffer.
    struct Collector {
        events: Arc<std::sync::Mutex<Vec<ConnectionStatus>>>,
    }
    impl ConnectionStatusCallback for Collector {
        fn on_status_change(&self, status: ConnectionStatus) {
            self.events.lock().unwrap().push(status);
        }
    }

    #[test]
    fn set_callback_repeats_current_status_then_dedupes() {
        let client = TunnelClient::new(config()).expect("client");
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        client.set_status_callback(Some(Box::new(Collector {
            events: Arc::clone(&events),
        })));

        // The callback immediately receives the current status — no separate
        // state query is needed.
        assert_eq!(*events.lock().unwrap(), vec![ConnectionStatus::Disconnected]);

        // disconnect() before connect(): transitions into the same statuses
        // are not duplicated.
        client.disconnect();
        assert_eq!(*events.lock().unwrap(), vec![ConnectionStatus::Disconnected]);
    }
}
