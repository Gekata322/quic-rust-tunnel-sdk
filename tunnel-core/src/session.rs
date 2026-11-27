//! Client network session: one connection attempt until the link drops.
//!
//! Flow:
//! 1. resolve the server address (DNS on every retry — a changed IP is picked up);
//! 2. build the QUIC config: pinned root + ALPN + keepalive + MTU discovery;
//! 3. connect and run the `Hello → Welcome/Reject` handshake over bi-stream #0;
//! 4. run the data plane (QUIC datagrams ⇄ platform queues) and the control
//!    plane (ping/pong over stream #0) in parallel; both watch the stop command.
//!
//! RTT is computed from `Pong`: the `sent_unix_ms` stamp is returned by the
//! server unchanged, the core measures the difference to the moment the `Ping`
//! was sent and stores it in `EngineShared::last_ping_ms` (visible to the
//! partner in `get_telemetry`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use rustls::pki_types::CertificateDer;
use tokio::sync::{mpsc, watch};

use tunnel_proto::frame::{decode_frame_zero_copy, encode_frame, KIND_IPV4};
use tunnel_proto::messages::{MAX_CONTROL_MESSAGE_SIZE, decode_control, encode_control, unix_ms};
use tunnel_proto::{
    ALPN_TUNNEL_V1, ControlFromClient, ControlFromServer, Hello, Ping, Pong, Reject, RejectCode,
    Welcome, PROTOCOL_VERSION,
};

use crate::engine::{EngineShared, wait_stopping};
use crate::error::CoreError;
use crate::ffi::{TunnelConfig, TunnelState};

/// Default keepalive when the server did not set the interval in `Welcome`, sec.
const DEFAULT_KEEPALIVE_SECS: u32 = 15;
/// Wait for the CONNECTION_CLOSE drain before dropping the endpoint, ms.
pub(crate) const CLOSE_DRAIN_MS: u64 = 300;
/// QUIC transport keepalive: refreshes the NAT table between application pings.
const TRANSPORT_KEEPALIVE_SECS: u64 = 10;
/// QUIC idle timeout: a silent connection is torn down and retried instead of
/// hanging until a system-level TCP timeout.
const MAX_IDLE_TIMEOUT_SECS: u64 = 30;

/// Outcome of a session attempt.
#[derive(Debug)]
pub(crate) enum SessionOutcome {
    /// The engine was told to stop (`disconnect()`) — no retry is needed.
    Shutdown,
    /// The session closed by itself or never started: `established` = did it
    /// reach `Welcome` (affects the backoff reset and the reconnect counter).
    Closed { cause: CoreError, established: bool },
}

/// Pair of control streams left over after the handshake.
struct ControlStreams {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

/// How the session planes ended.
#[derive(Debug)]
enum PlaneEnd {
    Stopped,
    /// The platform send queue was closed — the engine dies with the client.
    InputClosed,
    ConnClosed(String),
}

/// An established session: the connection, control streams and server parameters.
struct Established {
    conn: quinn::Connection,
    control: ControlStreams,
    welcome: Welcome,
}

/// One session attempt; cancelled instantly when the engine switches to Stopping.
pub(crate) async fn run_session(
    shared: &Arc<EngineShared>,
    packet_in_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> SessionOutcome {
    let mut stop_rx = shared.state_rx.clone();
    tokio::select! {
        biased;
        _ = wait_stopping(&mut stop_rx) => SessionOutcome::Shutdown,
        outcome = attempt_session(shared, packet_in_rx) => outcome,
    }
}

/// The actual attempt: connect → handshake → run both planes to the end.
async fn attempt_session(
    shared: &Arc<EngineShared>,
    packet_in_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> SessionOutcome {
    let config = &shared.config;
    let connect_timeout = Duration::from_millis(u64::from(config.connect_timeout_ms));

    let established = match establish(config, connect_timeout).await {
        Ok(established) => established,
        Err(cause) => return SessionOutcome::Closed { cause, established: false },
    };

    run_established(shared, established, packet_in_rx).await
}

/// DNS → QUIC connect → protocol handshake. Every failure maps into
/// [`CoreError`] via `?`, so the happy path stays flat.
async fn establish(
    config: &TunnelConfig,
    connect_timeout: Duration,
) -> Result<Established, CoreError> {
    let server_addr = resolve_server(config).await?;
    let client_config = build_client_config(config)?;

    let bind_addr: SocketAddr = "0.0.0.0:0".parse().expect("wildcard address is valid");
    let mut endpoint = quinn::Endpoint::client(bind_addr)
        .map_err(|err| CoreError::Io(format!("failed to open a UDP endpoint: {err}")))?;
    endpoint.set_default_client_config(client_config);

    let connecting = endpoint
        .connect(server_addr, &config.server_name)
        .map_err(|err| CoreError::ConnectFailed(format!("QUIC connect did not start: {err}")))?;
    let conn = tokio::time::timeout(connect_timeout, connecting)
        .await
        .map_err(|_| {
            CoreError::TimedOut(format!(
                "QUIC connect to {server_addr} did not complete within {}ms",
                config.connect_timeout_ms
            ))
        })?
        .map_err(|err| CoreError::ConnectFailed(format!("QUIC/TLS handshake: {err}")))?;

    let handshake = handshake(&conn, config);
    let (control, welcome) = tokio::time::timeout(connect_timeout, handshake)
        .await
        .map_err(|_| CoreError::TimedOut("protocol handshake did not finish".to_owned()))??;

    Ok(Established { conn, control, welcome })
}

/// Runs the established session: publishes state, runs both planes, closes cleanly.
async fn run_established(
    shared: &Arc<EngineShared>,
    session: Established,
    packet_in_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> SessionOutcome {
    let Established { conn, control, welcome } = session;

    tracing::info!(vip = %welcome.vip, mtu = welcome.mtu, "session established");
    shared.metrics.record_session_established();
    shared.reset_ping();
    shared.set_active_conn(Some(conn.clone()));
    shared.set_state(TunnelState::Connected {
        mtu: welcome.mtu,
        vip: welcome.vip.to_string(),
    });

    if conn.max_datagram_size().is_none() {
        // A data plane without datagrams is useless: the server disabled DATAGRAM.
        conn.close(quinn::VarInt::from_u32(1), b"no-datagrams");
        return SessionOutcome::Closed {
            cause: CoreError::SessionClosed("the server does not support QUIC datagrams".to_owned()),
            established: true,
        };
    }

    // Two planes until the link drops: control (ping/pong) and data (datagrams).
    // Separate clones: two &mut on one watch receiver cannot coexist in select.
    let mut stop_for_wait = shared.state_rx.clone();
    let mut stop_for_control = shared.state_rx.clone();
    let end = tokio::select! {
        biased;
        _ = wait_stopping(&mut stop_for_wait) => PlaneEnd::Stopped,
        end = control_loop(control, welcome.keepalive_interval_secs, shared, &mut stop_for_control) => end,
        end = data_loop(&conn, &welcome, shared, packet_in_rx) => end,
    };

    // Graceful close: let CONNECTION_CLOSE reach the network before the drop.
    // `closed()` resolves instantly for a locally initiated close, so the only
    // way to give the drivers transmission time is to keep awaiting here.
    let locally_initiated = conn.close_reason().is_none();
    conn.close(quinn::VarInt::from_u32(0), b"session-closed");
    if locally_initiated {
        tokio::time::sleep(Duration::from_millis(CLOSE_DRAIN_MS)).await;
    }

    match end {
        PlaneEnd::Stopped => SessionOutcome::Shutdown,
        PlaneEnd::InputClosed => SessionOutcome::Closed {
            cause: CoreError::SessionClosed("the platform inbound queue was closed".to_owned()),
            established: true,
        },
        PlaneEnd::ConnClosed(reason) => SessionOutcome::Closed {
            cause: CoreError::SessionClosed(reason),
            established: true,
        },
    }
}

/// Resolves the server address; DNS runs on every attempt — a server move to
/// another IP is picked up without recreating the client.
async fn resolve_server(config: &TunnelConfig) -> Result<SocketAddr, CoreError> {
    let host = config.server_host.trim();
    tokio::net::lookup_host((host, config.server_port))
        .await
        .map_err(|err| CoreError::ConnectFailed(format!("DNS for {host:?}: {err}")))?
        .next()
        .ok_or_else(|| CoreError::ConnectFailed(format!("DNS for {host:?} returned no addresses")))
}

/// Builds the QUIC config: the pinned root is the only trusted TLS root.
fn build_client_config(config: &TunnelConfig) -> Result<quinn::ClientConfig, CoreError> {
    let server_cert = CertificateDer::from(config.pinned_server_cert_der.clone());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(server_cert)
        .map_err(|err| CoreError::InvalidServerCert(format!("DER rejected: {err}")))?;

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|err| CoreError::Internal(format!("TLS profiles unavailable: {err}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN_TUNNEL_V1.to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(TRANSPORT_KEEPALIVE_SECS)));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(MAX_IDLE_TIMEOUT_SECS))
            .expect("30s fits into a VarInt"),
    ));
    // MTU discovery: on paths with a larger MTU datagrams pack more densely.
    transport.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));

    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|err| CoreError::Internal(format!("QUIC over TLS failed to build: {err}")))?;
    let mut client = quinn::ClientConfig::new(Arc::new(quic));
    client.transport_config(Arc::new(transport));
    Ok(client)
}

/// Protocol handshake: Hello → Welcome/Reject over stream #0.
async fn handshake(
    conn: &quinn::Connection,
    config: &TunnelConfig,
) -> Result<(ControlStreams, Welcome), CoreError> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|err| CoreError::ConnectFailed(format!("the bi-stream did not open: {err}")))?;
    let hello = ControlFromClient::Hello(Hello {
        protocol_version: PROTOCOL_VERSION,
        client_id: config.client_id.clone(),
        auth_token: config.auth_token.clone(),
    });
    send.write_all(&encode_control(&hello))
        .await
        .map_err(|err| CoreError::ConnectFailed(format!("failed to send Hello: {err}"))?;

    let message = read_control_message(&mut recv).await?;
    let (reply, _) = decode_control::<ControlFromServer>(&message)
        .map_err(|err| CoreError::ProtocolMismatch(format!("unreadable server response: {err}")))?
        .ok_or_else(|| {
            CoreError::ProtocolMismatch("the server sent a truncated handshake message".to_owned())
        })?;

    match reply {
        ControlFromServer::Welcome(welcome) => {
            if welcome.mtu == 0 {
                return Err(CoreError::ProtocolMismatch(format!(
                    "the server issued MTU {} — rejecting",
                    welcome.mtu
                )));
            }
            Ok((ControlStreams { send, recv }, welcome))
        }
        ControlFromServer::Reject(Reject { code, message }) => Err(match code {
            RejectCode::InvalidToken => CoreError::AuthRejected(message),
            RejectCode::ProtocolMismatch => CoreError::ProtocolMismatch(message),
            RejectCode::ServerBusy => CoreError::ServerBusy(message),
        }),
        other => Err(CoreError::ProtocolMismatch(format!(
            "expected Welcome/Reject, got {other:?}"
        ))),
    }
}

/// Reads one full control frame (length prefix + body).
async fn read_control_message(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, CoreError> {
    let mut prefix = [0u8; 4];
    recv.read_exact(&mut prefix)
        .await
        .map_err(|err| CoreError::SessionClosed(format!("the control stream closed: {err}")))?;
    let len = u32::from_le_bytes(prefix) as usize;
    if len > MAX_CONTROL_MESSAGE_SIZE {
        return Err(CoreError::SessionClosed(format!(
            "a {len}-byte message exceeds the limit of {MAX_CONTROL_MESSAGE_SIZE}"
        )));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .map_err(|err| CoreError::SessionClosed(format!("the message body was cut off: {err}")))?;
    let mut full = prefix.to_vec();
    full.extend_from_slice(&body);
    Ok(full)
}

/// Control plane: ping with RTT telemetry over stream #0.
async fn control_loop(
    control: ControlStreams,
    keepalive_hint_secs: u32,
    shared: &Arc<EngineShared>,
    stop_rx: &mut watch::Receiver<TunnelState>,
) -> PlaneEnd {
    let ControlStreams { mut send, mut recv } = control;
    let secs = if keepalive_hint_secs == 0 {
        DEFAULT_KEEPALIVE_SECS
    } else {
        keepalive_hint_secs
    };
    let mut ticker = tokio::time::interval(Duration::from_secs(u64::from(secs)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut seq: u32 = 0;

    loop {
        tokio::select! {
            biased;
            _ = wait_stopping(stop_rx) => return PlaneEnd::Stopped,
            message = read_control_message(&mut recv) => match message {
                Err(err) => return PlaneEnd::ConnClosed(err.to_string()),
                Ok(buf) => match decode_control::<ControlFromServer>(&buf) {
                    Err(err) => return PlaneEnd::ConnClosed(format!("malformed message: {err}")),
                    Ok(None) => return PlaneEnd::ConnClosed("truncated message".to_owned()),
                    Ok(Some((ControlFromServer::Pong(Pong { seq: echoed, sent_unix_ms, .. }), _))) => {
                        // RTT = time from sending the ping to receiving the pong.
                        // Sub-millisecond values are stored as 0 and hidden by
                        // the telemetry (None = not measured).
                        let rtt = unix_ms().saturating_sub(sent_unix_ms).clamp(1, u32::MAX as u64);
                        shared.last_ping_ms.store(rtt, Ordering::Relaxed);
                        tracing::debug!(seq = echoed, rtt_ms = rtt, "pong received");
                    }
                    Ok(Some((ControlFromServer::Reject(Reject { code, message }), _))) => {
                        return PlaneEnd::ConnClosed(format!(
                            "the server rejected the session ({code:?}): {message}"
                        ));
                    }
                    Ok(Some((other, _))) => {
                        tracing::debug!(?other, "unexpected control message");
                    }
                },
            },
            _ = ticker.tick() => {
                let ping = ControlFromClient::Ping(Ping { seq, sent_unix_ms: unix_ms() });
                if let Err(err) = send.write_all(&encode_control(&ping)).await {
                    return PlaneEnd::ConnClosed(format!("failed to send ping: {err}"));
                }
                seq = seq.wrapping_add(1);
            }
        }
    }
}

/// Data plane: QUIC datagrams ⇄ platform queues; reconnects are invisible here.
async fn data_loop(
    conn: &quinn::Connection,
    welcome: &Welcome,
    shared: &Arc<EngineShared>,
    packet_in_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> PlaneEnd {
    let mtu = usize::from(welcome.mtu);
    loop {
        tokio::select! {
            biased;
            // Platform → tunnel: IP packet → frame → datagram.
            inbound = packet_in_rx.recv() => match inbound {
                // The FFI object is dead: no reason for the engine to live on.
                None => return PlaneEnd::InputClosed,
                Some(packet) if packet.len() > mtu => {
                    shared.metrics.record_packets_dropped(1);
                    tracing::debug!(len = packet.len(), mtu, "packet longer than MTU — dropped");
                }
                Some(packet) => match conn.send_datagram(Bytes::from(encode_frame(KIND_IPV4, &packet))) {
                    Ok(()) => {
                        shared.metrics.record_datagram_sent();
                        shared.metrics.record_bytes_sent(packet.len() as u64);
                    }
                    Err(quinn::SendDatagramError::TooLarge) => {
                        shared.metrics.record_packets_dropped(1);
                        tracing::debug!(len = packet.len(), "datagram too large — dropped");
                    }
                    Err(quinn::SendDatagramError::ConnectionLost(err)) => {
                        return PlaneEnd::ConnClosed(format!("connection lost: {err}"));
                    }
                    Err(err) => {
                        shared.metrics.record_packets_dropped(1);
                        tracing::debug!(%err, "datagram did not go out — dropped");
                    }
                },
            },
            // Tunnel → platform: datagram → frame → packet.
            inbound = conn.read_datagram() => match inbound {
                Err(err) => return PlaneEnd::ConnClosed(format!("failed to read datagrams: {err}")),
                Ok(datagram) => match decode_frame_zero_copy(&datagram) {
                    Ok(frame) if frame.kind == KIND_IPV4 => {
                        if frame.payload.len() > mtu {
                            shared.metrics.record_packets_dropped(1);
                            continue;
                        }
                        match shared.packet_out_tx.try_send(frame.payload.to_vec()) {
                            Ok(()) => {
                                shared.metrics.record_datagram_received();
                                shared.metrics.record_bytes_received(frame.payload.len() as u64);
                            }
                            // The platform queue is full: UDP semantics — drop.
                            Err(_) => shared.metrics.record_packets_dropped(1),
                        }
                    }
                    Ok(frame) => {
                        // IPv6 and other kinds: no route configured — drop.
                        tracing::debug!(kind = frame.kind, "frame without a route — dropped");
                        shared.metrics.record_packets_dropped(1);
                    }
                    Err(err) => {
                        tracing::debug!(%err, "malformed datagram — dropped");
                        shared.metrics.record_packets_dropped(1);
                    }
                },
            },
        }
    }
}
