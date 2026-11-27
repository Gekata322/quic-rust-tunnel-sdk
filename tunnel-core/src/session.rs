//! Client network session: one connection attempt until the session drops.
//!
//! Flow:
//! 1. resolve the server address (DNS on every retry — a changed IP is picked up);
//! 2. build the QUIC config: pinned root + ALPN + keepalive + MTU discovery;
//! 3. connect and run the `Hello → Welcome/Reject` handshake over stream #0;
//! 4. run the data plane (QUIC datagrams ⇄ platform queues) and the control
//!    plane (ping/pong on stream #0) in parallel; both honor the stop command.
//!
//! RTT is computed from `Pong`: the server echoes `sent_unix_ms` unchanged,
//! the core measures the difference from its own send time and stores it in
//! `EngineShared::last_ping_ms` (visible to partners via `get_telemetry`).

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
    ALPN_TUNNEL_V1, ControlFromClient, ControlFromServer, Hello, Ping, Pong, Reject, Welcome,
    PROTOCOL_VERSION,
};

use crate::engine::{EngineShared, wait_stopping};
use crate::error::CoreError;
use crate::ffi::{TunnelConfig, TunnelState};

/// Default keepalive when the server did not set an interval in `Welcome`.
const DEFAULT_KEEPALIVE_SECS: u32 = 15;
/// Wait for the close handshake to drain before dropping the endpoint, ms.
/// The peer must acknowledge CONNECTION_CLOSE, so this covers a full RTT
/// plus one retransmission; on timeout the peer falls back to its QUIC
/// idle timeout.
const CLOSE_DRAIN_MS: u64 = 1000;
/// Transport-level QUIC keepalive: keeps the NAT table warm between
/// application pings.
const TRANSPORT_KEEPALIVE_SECS: u64 = 10;
/// QUIC idle timeout: a silently dead connection tears down and retries
/// instead of hanging until the OS TCP timeout.
const MAX_IDLE_TIMEOUT_SECS: u64 = 30;

/// Outcome of one session attempt.
#[derive(Debug)]
pub(crate) enum SessionOutcome {
    /// The engine was told to stop (`disconnect()`) — no retry needed.
    Shutdown,
    /// The session closed on its own or never started. `established` tells
    /// whether `Welcome` was reached (affects backoff reset and reconnects).
    Closed { cause: CoreError, established: bool },
}

/// Control stream pair left over after the handshake.
struct ControlStreams {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

/// How the session planes ended.
#[derive(Debug)]
enum PlaneEnd {
    Stopped,
    /// The platform send queue closed — the engine dies with the client.
    InputClosed,
    ConnClosed(String),
}

/// Everything needed to run the planes after a successful handshake.
struct Established {
    /// Kept alive until the clean close drains: dropping the endpoint kills
    /// its driver task, which would prevent CONNECTION_CLOSE from reaching
    /// the peer and leave the server holding the client's address until the
    /// QUIC idle timeout.
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    control: ControlStreams,
    welcome: Welcome,
}

/// One session attempt. Stop cancellation applies only while the connection
/// is being established — nothing is registered server-side yet, so dropping
/// is safe there. Once the session is up, stopping is handled inside the
/// planes with a clean `conn.close()`: dropping the endpoint without draining
/// would leave the server waiting for the QUIC idle timeout and holding the
/// client's virtual address the whole time.
pub(crate) async fn run_session(
    shared: &Arc<EngineShared>,
    packet_in_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> SessionOutcome {
    let mut stop_rx = shared.state_rx.clone();
    let established = tokio::select! {
        biased;
        _ = wait_stopping(&mut stop_rx) => return SessionOutcome::Shutdown,
        result = establish(shared) => match result {
            Ok(established) => established,
            Err(cause) => return SessionOutcome::Closed { cause, established: false },
        },
    };
    run_established(established, shared, packet_in_rx).await
}

/// Connection setup: DNS → config → connect → handshake. Returns the
/// established connection state or the failure cause.
async fn establish(shared: &Arc<EngineShared>) -> Result<Established, CoreError> {
    let config = &shared.config;
    let connect_timeout = Duration::from_millis(u64::from(config.connect_timeout_ms));

    let server_addr = resolve_server(config).await?;
    let client_config = build_client_config(config)?;
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().expect("any local port"))
        .map_err(|err| CoreError::Io(format!("failed to open the UDP endpoint: {err}")))?;
    endpoint.set_default_client_config(client_config);

    let connecting = endpoint
        .connect(server_addr, &config.server_name)
        .map_err(|err| CoreError::ConnectFailed(format!("QUIC connect did not start: {err}")))?;
    let conn = match tokio::time::timeout(connect_timeout, connecting).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(err)) => {
            return Err(CoreError::ConnectFailed(format!("QUIC TLS handshake: {err}")));
        }
        Err(_) => {
            return Err(CoreError::TimedOut(format!(
                "QUIC connection to {server_addr} did not complete within {}ms",
                config.connect_timeout_ms
            )));
        }
    };

    // Handshake over stream #0: Hello → Welcome/Reject.
    let handshake = async {
        let (streams, welcome) = handshake(&conn, config).await?;
        Ok::<(ControlStreams, Welcome), CoreError>((streams, welcome))
    };
    let (control, welcome) = match tokio::time::timeout(connect_timeout, handshake).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(cause)) => return Err(cause),
        Err(_) => return Err(CoreError::TimedOut("protocol handshake did not complete".to_owned())),
    };

    Ok(Established {
        endpoint,
        conn,
        control,
        welcome,
    })
}

/// The planes: publish the established state, run control + data until one
/// of them ends, then close the connection cleanly.
async fn run_established(
    established: Established,
    shared: &Arc<EngineShared>,
    packet_in_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> SessionOutcome {
    let Established {
        endpoint,
        conn,
        control,
        welcome,
    } = established;

    // Session established: publish the state and parameters to the platform.
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
            cause: CoreError::SessionClosed("server does not support QUIC datagrams".to_owned()),
            established: true,
        };
    }

    // Two planes until the session drops: control (ping/pong) and data
    // (datagrams). Separate clones: two &mut on one watch receiver cannot
    // coexist inside select.
    let mut stop_for_wait = shared.state_rx.clone();
    let mut stop_for_control = shared.state_rx.clone();
    let end = tokio::select! {
        biased;
        _ = wait_stopping(&mut stop_for_wait) => PlaneEnd::Stopped,
        end = control_loop(control, welcome.keepalive_interval_secs, shared, &mut stop_for_control) => end,
        end = data_loop(&conn, &welcome, shared, packet_in_rx) => end,
    };

    // Clean close: hold the endpoint until the peer acknowledges the close.
    // `conn.closed()` alone is not enough — it completes immediately after a
    // local close, and killing the runtime right after would prevent the
    // driver from ever transmitting CONNECTION_CLOSE.
    conn.close(quinn::VarInt::from_u32(0), b"session-closed");
    let _ = tokio::time::timeout(Duration::from_millis(CLOSE_DRAIN_MS), endpoint.wait_idle()).await;

    match end {
        PlaneEnd::Stopped => SessionOutcome::Shutdown,
        PlaneEnd::InputClosed => SessionOutcome::Closed {
            cause: CoreError::SessionClosed("platform input queue closed".to_owned()),
            established: true,
        },
        PlaneEnd::ConnClosed(reason) => SessionOutcome::Closed {
            cause: CoreError::SessionClosed(reason),
            established: true,
        },
    }
}

/// Resolves the server address; DNS runs on every attempt so a server moving
/// to a different IP is picked up without recreating the client.
async fn resolve_server(config: &TunnelConfig) -> Result<SocketAddr, CoreError> {
    let host = config.server_host.trim();
    tokio::net::lookup_host((host, config.server_port))
        .await
        .map_err(|err| CoreError::ConnectFailed(format!("DNS for \"{host}\": {err}")))?
        .next()
        .ok_or_else(|| CoreError::ConnectFailed(format!("DNS for \"{host}\" returned no addresses")))
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
            .expect("30s fits a VarInt"),
    ));
    // MTU discovery: on paths with a larger MTU, datagrams pack tighter.
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
        .map_err(|err| CoreError::ConnectFailed(format!("failed to open a bi-stream: {err}")))?;
    let hello = ControlFromClient::Hello(Hello {
        protocol_version: PROTOCOL_VERSION,
        client_id: config.client_id.clone(),
        auth_token: config.auth_token.clone(),
    });
    send.write_all(&encode_control(&hello))
        .await
        .map_err(|err| CoreError::ConnectFailed(format!("Hello was not sent: {err}")))?;

    let message = read_control_message(&mut recv).await?;
    match decode_control::<ControlFromServer>(&message) {
        Ok(Some((ControlFromServer::Welcome(welcome), _))) => {
            if welcome.mtu == 0 {
                return Err(CoreError::ProtocolMismatch(format!(
                    "server issued MTU {} — rejecting",
                    welcome.mtu
                )));
            }
            Ok((ControlStreams { send, recv }, welcome))
        }
        Ok(Some((ControlFromServer::Reject(Reject { code, message }), _))) => {
            let cause = match code {
                tunnel_proto::RejectCode::InvalidToken => CoreError::AuthRejected(message),
                tunnel_proto::RejectCode::ProtocolMismatch => CoreError::ProtocolMismatch(message),
                tunnel_proto::RejectCode::ServerBusy => CoreError::ServerBusy(message),
            };
            Err(cause)
        }
        Ok(Some((other, _))) => Err(CoreError::ProtocolMismatch(format!(
            "expected Welcome/Reject, got {other:?}"
        ))),
        Ok(None) => Err(CoreError::ProtocolMismatch(
            "server sent a truncated handshake message".to_owned(),
        )),
        Err(err) => Err(CoreError::ProtocolMismatch(format!(
            "server response is unreadable: {err}"
        ))),
    }
}

/// Reads one full control frame (length prefix + body).
async fn read_control_message(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, CoreError> {
    let mut prefix = [0u8; 4];
    recv.read_exact(&mut prefix)
        .await
        .map_err(|err| CoreError::SessionClosed(format!("control stream closed: {err}")))?;
    let len = u32::from_le_bytes(prefix) as usize;
    if len > MAX_CONTROL_MESSAGE_SIZE {
        return Err(CoreError::SessionClosed(format!(
            "message of {len} bytes exceeds the limit of {MAX_CONTROL_MESSAGE_SIZE}"
        )));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .map_err(|err| CoreError::SessionClosed(format!("message body truncated: {err}")))?;
    let mut full = prefix.to_vec();
    full.extend_from_slice(&body);
    Ok(full)
}

/// Control plane: pings with RTT telemetry over stream #0.
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
                Ok(buf) => match decode_control::<ControlFromServer>(&buf) {
                    Ok(Some((ControlFromServer::Pong(Pong { seq: echoed, sent_unix_ms, .. }), _))) => {
                        // RTT = time from the ping send to the pong receipt.
                        // Sub-millisecond values are stored as 0 and hidden
                        // by telemetry (None = not measured yet).
                        let rtt = unix_ms().saturating_sub(sent_unix_ms).clamp(1, u32::MAX as u64);
                        shared.last_ping_ms.store(rtt, Ordering::Relaxed);
                        tracing::debug!(seq = echoed, rtt_ms = rtt, "pong received");
                    }
                    Ok(Some((ControlFromServer::Reject(Reject { code, message }), _))) => {
                        return PlaneEnd::ConnClosed(format!(
                            "server rejected the session ({code:?}): {message}"
                        ));
                    }
                    Ok(Some((other, _))) => {
                        tracing::debug!(?other, "unexpected control message");
                    }
                    Ok(None) => return PlaneEnd::ConnClosed("truncated message".to_owned()),
                    Err(err) => return PlaneEnd::ConnClosed(format!("corrupt message: {err}")),
                },
                Err(err) => return PlaneEnd::ConnClosed(err.to_string()),
            },
            _ = ticker.tick() => {
                let ping = ControlFromClient::Ping(Ping { seq, sent_unix_ms: unix_ms() });
                if let Err(err) = send.write_all(&encode_control(&ping)).await {
                    return PlaneEnd::ConnClosed(format!("ping was not sent: {err}"));
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
                Some(packet) => {
                    if packet.len() > mtu {
                        shared.metrics.record_packets_dropped(1);
                        tracing::debug!(len = packet.len(), mtu, "packet longer than MTU — dropped");
                        continue;
                    }
                    match conn.send_datagram(Bytes::from(encode_frame(KIND_IPV4, &packet))) {
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
                            tracing::debug!(%err, "datagram not sent — dropped");
                        }
                    }
                }
                // The FFI object is gone: the engine has no reason to live.
                None => return PlaneEnd::InputClosed,
            },
            // Tunnel → platform: datagram → frame → packet.
            inbound = conn.read_datagram() => match inbound {
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
                        tracing::debug!(%err, "corrupt datagram — dropped");
                        shared.metrics.record_packets_dropped(1);
                    }
                },
                Err(err) => return PlaneEnd::ConnClosed(format!("datagram read: {err}")),
            },
        }
    }
}
