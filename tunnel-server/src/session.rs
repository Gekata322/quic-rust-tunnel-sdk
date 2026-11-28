//! Server state and client session handling.
//!
//! Session flow (see `endpoint::accept_loop` → `handle_connection`):
//! 1. bi-stream #0: `Hello{version, client_id, token}` → protocol version and
//!    token verification ([`tunnel_proto::auth::TokenStore::verify`]);
//! 2. an address is issued from the [`IpPool`], the client is registered in
//!    the [`RoutingTable`];
//! 3. `Welcome{vip, mtu, keepalive}`; then the control plane (`Ping → Pong`
//!    over stream #0) and the data plane (datagrams):
//!    - **anti-spoofing**: a packet with `src != the assigned address` is dropped;
//!    - loopback mode: a packet to `server_vip` is echoed back with the
//!      addresses swapped;
//!    - production mode: a client packet is written to the TUN; packets from
//!      the TUN are routed to the client by the destination address.
//!
//! - **rate limiting**: a client with a configured bandwidth cap (the optional
//!   `:mbps` suffix in `tokens.txt`) has its data plane throttled by the
//!   per-session token bucket ([`crate::ratelimit`]); control traffic is
//!   never throttled;
//! - **idle reaping**: a session silent for [`crate::reaper::IDLE_SESSION_TIMEOUT`]
//!   is force-closed by the background reaper and its address returns to the
//!   pool;
//! - **token revocation**: `DELETE /tokens/{client_id}` on the admin API
//!   ([`crate::admin`]) removes the token and force-closes every live session
//!   of that client.
//!
//! The address is returned to the pool on every session end — reuse.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use tunnel_proto::frame::{decode_frame_zero_copy, encode_frame, KIND_IPV4};
use tunnel_proto::messages::{decode_control, encode_control, unix_ms};
use tunnel_proto::{
    ControlFromClient, ControlFromServer, Hello, Metrics, Ping, Pong, Reject, RejectCode,
    Welcome, MAX_CONTROL_MESSAGE_SIZE, PROTOCOL_VERSION,
};
use tunnel_proto::auth::TokenStore;
use tunnel_proto::ipv4;

use crate::config::ServerConfig;
use crate::pool::IpPool;
use crate::ratelimit::RateLimiter;
use crate::reaper::{SessionInfo, SessionTracker};
use crate::registry::TokenRegistry;
use crate::routing::RoutingTable;
use crate::tun::TunDevice;

/// Handshake timeout: the client must send `Hello` and wait for the answer.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Length of the "server → client" queue (datagrams from the TUN/other clients).
const OUTBOUND_QUEUE_LEN: usize = 256;

/// Server state startup errors.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The pool subnet is invalid.
    #[error("address pool: {0}")]
    Pool(#[from] crate::pool::PoolError),

    /// The TUN interface did not come up.
    #[error("TUN interface: {0}")]
    Tun(#[from] std::io::Error),
}

/// Errors while reading a control frame from a QUIC stream.
#[derive(Debug, thiserror::Error)]
enum ControlReadError {
    /// The stream ended or the connection dropped mid-frame.
    #[error("control stream closed: {0}")]
    Stream(#[from] quinn::ReadExactError),
    /// The frame body exceeds [`MAX_CONTROL_MESSAGE_SIZE`] (DoS guard).
    #[error("control message of {len} bytes exceeds the limit of {MAX_CONTROL_MESSAGE_SIZE}")]
    Oversized { len: usize },
}

/// Shared server state: common to all sessions.
/// The `server_vip` and `metrics` fields are visible to tests and operators.
pub struct ServerShared {
    /// Server address inside the tunnel subnet (the first pool address).
    pub server_vip: Ipv4Addr,
    /// Server telemetry (bytes, datagrams, sessions).
    pub metrics: Arc<Metrics>,
    /// MTU of the clients' virtual interface.
    mtu: u16,
    /// Application ping period sent in `Welcome`.
    keepalive_interval_secs: u32,
    /// Partner tokens: a live registry — the admin API adds and revokes
    /// entries while the server runs (see [`crate::registry`]).
    tokens: TokenRegistry,
    /// Virtual address pool.
    pool: IpPool,
    /// "Address → client" table.
    routing: RoutingTable,
    /// Live sessions with their last inbound activity (the reaper's input).
    sessions: SessionTracker,
    /// Per-session data-plane token buckets.
    limiter: RateLimiter,
    /// TUN interface of production mode (`None` — loopback).
    tun: Option<Arc<TunDevice>>,
}

impl ServerShared {
    /// Builds the server state: an address pool from `config.pool`, tokens,
    /// an optional TUN (production mode) or loopback.
    pub fn new(
        config: &ServerConfig,
        tokens: TokenStore,
        tun: Option<TunDevice>,
    ) -> Result<Arc<Self>, ServerError> {
        let pool = IpPool::from_subnet(&config.pool)?;
        Ok(Arc::new(Self {
            server_vip: pool.server_vip(),
            metrics: Arc::new(Metrics::default()),
            mtu: config.mtu,
            keepalive_interval_secs: config.keepalive_interval_secs,
            tokens: TokenRegistry::from_store(&tokens),
            pool,
            routing: RoutingTable::new(),
            sessions: SessionTracker::new(),
            limiter: RateLimiter::new(),
            tun: tun.map(Arc::new),
        }))
    }

    /// Whether there is a TUN (production mode) or loopback.
    pub fn is_loopback(&self) -> bool {
        self.tun.is_none()
    }

    /// Routing table (tests and diagnostics).
    pub fn routing(&self) -> &RoutingTable {
        &self.routing
    }

    /// Number of active clients.
    pub fn active_clients(&self) -> usize {
        self.routing.active()
    }

    /// Number of pool addresses currently issued (tests and diagnostics).
    pub fn allocated_addresses(&self) -> usize {
        self.pool.allocated()
    }

    /// Pool capacity for clients (admin `/stats`).
    pub fn pool_capacity(&self) -> usize {
        self.pool.capacity()
    }

    /// The mutable token registry (admin token management).
    pub fn tokens(&self) -> &TokenRegistry {
        &self.tokens
    }

    /// Read-only snapshot of the live sessions (admin `/stats`).
    pub fn session_infos(&self) -> Vec<SessionInfo> {
        self.sessions.infos()
    }

    /// Spawns the idle-session reaper with the production timeouts (45s idle,
    /// 5s scan — see [`crate::reaper`]).
    pub fn spawn_idle_reaper(self: &Arc<Self>) {
        crate::reaper::spawn_idle_reaper(self);
    }

    /// Force-closes the sessions silent for longer than `idle_timeout`: the
    /// QUIC connection is closed, the route is removed and the virtual
    /// address returns to the pool. Called by the reaper loop; public for
    /// tests and ops tooling.
    pub fn reap_idle_sessions(&self, idle_timeout: Duration) {
        for (vip, stale) in self.sessions.take_idle(idle_timeout) {
            let idle = stale.last_activity.elapsed();
            tracing::info!(
                client_id = %stale.client_id,
                vip = %vip,
                idle_secs = idle.as_secs(),
                "idle session reaped — closing the connection and returning the address"
            );
            self.evict_session(vip, &stale, "idle-reaped");
        }
    }

    /// Force-closes every session of `client_id` (token revocation): the QUIC
    /// connection is closed with the `token-revoked` reason, routes and rate
    /// buckets are removed, virtual addresses return to the pool. Returns the
    /// number of killed sessions. The caller has already removed the token
    /// entry, so the client's next handshake is rejected as unknown.
    pub fn revoke_client_sessions(&self, client_id: &str) -> usize {
        let taken = self.sessions.take_by_client(client_id);
        let count = taken.len();
        for (vip, stale) in taken {
            tracing::info!(client_id = %client_id, vip = %vip, "token revoked — kicking the session");
            self.evict_session(vip, &stale, "token-revoked");
        }
        count
    }

    /// Common finalization of an evicted session (the reaper and the
    /// revocation path). Idempotent: the session task's own later cleanup is
    /// a no-op on every step.
    fn evict_session(&self, vip: Ipv4Addr, stale: &crate::reaper::TrackedSession, reason: &str) {
        stale.conn.close(quinn::VarInt::from_u32(0), reason.as_bytes());
        self.routing.unregister(vip, &stale.outbound_tx);
        self.limiter.unregister(vip);
        let _ = self.pool.release(vip);
    }

    /// Starts the TUN reader: packets from the kernel → clients by the `RoutingTable`.
    pub fn spawn_tun_reader(self: &Arc<Self>) {
        let Some(tun) = self.tun.clone() else { return };
        let shared = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                match tun.read_packet().await {
                    Ok(packet) => {
                        let Some(header) = ipv4::parse(&packet) else {
                            shared.metrics.record_packets_dropped(1);
                            continue;
                        };
                        let dst = Ipv4Addr::from(header.dst);
                        match shared.routing.route(dst) {
                            Some(sender) => {
                                if sender.send(packet).await.is_err() {
                                    // The client is already dead: the packet is
                                    // lost, its session task cleans up the table.
                                    shared.metrics.record_packets_dropped(1);
                                }
                            }
                            None => {
                                // The address was not issued to anyone: not our packets.
                                shared.metrics.record_packets_dropped(1);
                            }
                        }
                    }
                    Err(err) => {
                        tracing::error!(%err, "TUN read failed — routing stopped");
                        return;
                    }
                }
            }
        });
    }
}

/// Lifecycle of one session: handshake → planes → cleanup.
pub async fn handle_connection(shared: Arc<ServerShared>, conn: quinn::Connection) {
    let peer = conn.remote_address();
    let (mut send, mut recv) = match conn.accept_bi().await {
        Ok(streams) => streams,
        Err(err) => {
            tracing::debug!(%peer, %err, "the handshake bi-stream did not open");
            return;
        }
    };

    // --- Handshake: Hello → Welcome/Reject ---
    let hello = match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_hello(&mut recv)).await {
        Ok(Ok(hello)) => hello,
        Ok(Err(reject)) => {
            send_reject(&mut send, &conn, reject).await;
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "handshake did not finish within {}s", HANDSHAKE_TIMEOUT.as_secs());
            return;
        }
    };
    let Hello { protocol_version, client_id, auth_token } = hello;

    if protocol_version != PROTOCOL_VERSION {
        tracing::warn!(
            client_id = %client_id,
            got = protocol_version,
            want = PROTOCOL_VERSION,
            "unsupported protocol version"
        );
        send_reject(
            &mut send,
            &conn,
            Reject {
                code: RejectCode::ProtocolMismatch,
                message: format!("protocol version {PROTOCOL_VERSION} is required; update the SDK"),
            },
        )
        .await;
        return;
    }

    if !shared.tokens.verify(&client_id, &auth_token) {
        tracing::warn!(client_id = %client_id, "token rejected — denying");
        send_reject(
            &mut send,
            &conn,
            Reject {
                code: RejectCode::InvalidToken,
                message: "token not found or revoked".to_owned(),
            },
        )
        .await;
        return;
    }

    // The bandwidth cap rides with the token: after a constant-time verify,
    // look up this client's data-plane limit (`None` — unlimited).
    let rate_limit_mbps = shared.tokens.limit_of(&client_id);

    let vip = match shared.pool.alloc() {
        Some(vip) => vip,
        None => {
            tracing::warn!(client_id = %client_id, "virtual address pool exhausted — denying");
            send_reject(
                &mut send,
                &conn,
                Reject {
                    code: RejectCode::ServerBusy,
                    message: "virtual address pool exhausted, try again later".to_owned(),
                },
            )
            .await;
            return;
        }
    };

    // --- Welcome and client registration ---
    let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE_LEN);
    shared.routing.register(vip, outbound_tx.clone());
    // The session is tracked from here: even a client that stalls while
    // reading `Welcome` stays reapable, so its address cannot leak.
    shared.sessions.register(vip, &client_id, conn.clone(), outbound_tx.clone());
    shared.limiter.register(vip, rate_limit_mbps);

    let welcome = ControlFromServer::Welcome(Welcome {
        vip,
        mtu: shared.mtu,
        keepalive_interval_secs: shared.keepalive_interval_secs,
    });
    if send.write_all(&encode_control(&welcome)).await.is_err() {
        cleanup(&shared, vip, &outbound_tx);
        return;
    }
    tracing::info!(client_id = %client_id, vip = %vip, "session established");
    shared.metrics.record_session_established();

    // The "server → client" send task (return traffic).
    let sender_task = tokio::spawn(send_loop(Arc::clone(&shared), conn.clone(), outbound_rx));

    // --- Working loop: control plane + data plane ---
    loop {
        tokio::select! {
            biased;
            control = read_control_message(&mut recv) => match control {
                Err(err) => {
                    tracing::debug!(client_id = %client_id, %err, "control plane closed");
                    break;
                }
                Ok(buf) => {
                    // Any inbound bytes prove the client is alive.
                    shared.sessions.touch(vip);
                    match decode_control::<ControlFromClient>(&buf) {
                        Err(err) => {
                            tracing::debug!(client_id = %client_id, %err, "malformed control message");
                            break;
                        }
                        Ok(None) => {
                            tracing::debug!(client_id = %client_id, "truncated control message");
                            break;
                        }
                        Ok(Some((ControlFromClient::Ping(Ping { seq, sent_unix_ms }), _))) => {
                            let pong = ControlFromServer::Pong(Pong {
                                seq,
                                sent_unix_ms,
                                server_unix_ms: unix_ms(),
                            });
                            if send.write_all(&encode_control(&pong)).await.is_err() {
                                break;
                            }
                        }
                        Ok(Some((other, _))) => {
                            tracing::debug!(client_id = %client_id, ?other, "unexpected control message");
                        }
                    }
                }
            },
            datagram = conn.read_datagram() => match datagram {
                Err(err) => {
                    tracing::debug!(client_id = %client_id, %err, "data plane closed");
                    break;
                }
                Ok(datagram) => {
                    // Liveness counts even for datagrams the limiter drops.
                    shared.sessions.touch(vip);
                    if !shared.limiter.try_consume(vip, datagram.len()) {
                        shared.metrics.record_rate_limited(1);
                        tracing::debug!(
                            client_id = %client_id,
                            bytes = datagram.len(),
                            "rate limit exceeded — datagram dropped"
                        );
                        continue;
                    }
                    match process_inbound(&shared, vip, &datagram) {
                        PacketAction::Echo(reply) => {
                            // Echo carries a raw IP packet — frame it as the data plane.
                            if conn.send_datagram(Bytes::from(encode_frame(KIND_IPV4, &reply))).is_err() {
                                break;
                            }
                        }
                        PacketAction::Forward(packet) => {
                            let Some(tun) = shared.tun.as_ref() else {
                                tracing::debug!(client_id = %client_id, "packet without a TUN route — dropped");
                                shared.metrics.record_packets_dropped(1);
                                continue;
                            };
                            if let Err(err) = tun.write_packet(&packet).await {
                                tracing::warn!(%err, "failed to write to the TUN");
                                shared.metrics.record_packets_dropped(1);
                            }
                        }
                        PacketAction::RouteTo(sender, packet) => {
                            if sender.send(packet).await.is_err() {
                                shared.metrics.record_packets_dropped(1);
                            }
                        }
                        PacketAction::Drop(reason) => {
                            tracing::debug!(client_id = %client_id, reason, "packet dropped");
                            shared.metrics.record_packets_dropped(1);
                        }
                    }
                }
            },
        }
    }

    cleanup(&shared, vip, &outbound_tx);
    sender_task.abort();
    conn.close(quinn::VarInt::from_u32(0), b"session-end");
    tracing::info!(client_id = %client_id, vip = %vip, "session finished");
}

/// How long to wait while the client reads the `Reject` before closing the
/// connection.
const REJECT_DRAIN: Duration = Duration::from_millis(200);

/// Sends a `Reject` and drains: without the pause CONNECTION_CLOSE overtakes
/// the stream data, the client sees a bare "connection lost" instead of the
/// rejection reason — and retries what cannot be retried. Finishes the send
/// direction (FIN) and waits up to `REJECT_DRAIN` for the client to close the
/// connection itself.
async fn send_reject(send: &mut quinn::SendStream, conn: &quinn::Connection, reject: Reject) {
    let payload = encode_control(&ControlFromServer::Reject(reject));
    if send.write_all(&payload).await.is_ok() {
        let _ = send.finish();
        let _ = tokio::time::timeout(REJECT_DRAIN, conn.closed()).await;
    }
}

/// Reads and decodes `Hello` from the control stream, or builds the typed
/// `Reject` reason. Every failure maps through `?`, keeping the flow flat.
async fn read_hello(recv: &mut quinn::RecvStream) -> Result<Hello, Reject> {
    let buf = read_control_message(recv).await.map_err(|err| Reject {
        code: RejectCode::ProtocolMismatch,
        message: err.to_string(),
    })?;
    let (message, _) = decode_control::<ControlFromClient>(&buf)
        .map_err(|err| Reject {
            code: RejectCode::ProtocolMismatch,
            message: format!("unreadable message: {err}"),
        })?
        .ok_or_else(|| Reject {
            code: RejectCode::ProtocolMismatch,
            message: "truncated handshake message".to_owned(),
        })?;
    match message {
        ControlFromClient::Hello(hello) => Ok(hello),
        other => Err(Reject {
            code: RejectCode::ProtocolMismatch,
            message: format!("expected Hello, got {other:?}"),
        }),
    }
}

/// Frees everything the session held: the tracker entry, the rate-limit
/// bucket, the route and the virtual address. Every step is idempotent, so
/// the reaper and the session task may clean up the same session safely.
fn cleanup(shared: &Arc<ServerShared>, vip: Ipv4Addr, outbound_tx: &mpsc::Sender<Vec<u8>>) {
    shared.sessions.remove(vip);
    shared.limiter.unregister(vip);
    shared.routing.unregister(vip, outbound_tx);
    let _ = shared.pool.release(vip);
}

/// Task sending queued packets to a concrete client.
async fn send_loop(
    shared: Arc<ServerShared>,
    conn: quinn::Connection,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
) {
    while let Some(packet) = outbound_rx.recv().await {
        match conn.send_datagram(Bytes::from(encode_frame(KIND_IPV4, &packet))) {
            Ok(()) => {
                shared.metrics.record_datagram_sent();
                shared.metrics.record_bytes_sent(packet.len() as u64);
            }
            Err(quinn::SendDatagramError::TooLarge) => {
                shared.metrics.record_packets_dropped(1);
            }
            Err(quinn::SendDatagramError::ConnectionLost(err)) => {
                tracing::debug!(%err, "client connection lost — send task finished");
                return;
            }
            Err(err) => {
                shared.metrics.record_packets_dropped(1);
                tracing::debug!(%err, "datagram did not reach the client");
            }
        }
    }
}

/// Reads one full control frame (length prefix + body).
async fn read_control_message(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, ControlReadError> {
    let mut prefix = [0u8; 4];
    recv.read_exact(&mut prefix).await?;
    let len = u32::from_le_bytes(prefix) as usize;
    if len > MAX_CONTROL_MESSAGE_SIZE {
        return Err(ControlReadError::Oversized { len });
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await?;
    let mut full = prefix.to_vec();
    full.extend_from_slice(&body);
    Ok(full)
}

/// What the server does with a client's inbound datagram.
enum PacketAction {
    /// Loopback echo: the packet returns to the client with addresses swapped.
    Echo(Vec<u8>),
    /// Production mode: the packet goes into the TUN (outside / a kernel service).
    Forward(Vec<u8>),
    /// The packet is addressed to another client: its send task channel.
    RouteTo(mpsc::Sender<Vec<u8>>, Vec<u8>),
    /// A drop with a reason.
    Drop(&'static str),
}

/// Parses and classifies an inbound client packet.
/// Check order: valid IPv4 → anti-spoofing (`src == vip`) → destination.
fn process_inbound(shared: &ServerShared, vip: Ipv4Addr, datagram: &[u8]) -> PacketAction {
    // The frame must be IPv4: IPv6 is on the roadmap.
    let datagram = Bytes::copy_from_slice(datagram);
    let Ok(frame) = decode_frame_zero_copy(&datagram) else {
        return PacketAction::Drop("malformed datagram frame");
    };
    if frame.kind != KIND_IPV4 {
        return PacketAction::Drop("IPv6 frames are not supported");
    }
    let packet = frame.payload;
    let Some(header) = ipv4::parse(&packet) else {
        return PacketAction::Drop("not an IPv4 packet");
    };

    // Anti-spoofing: the client must send from its assigned address.
    if header.src != vip.octets() {
        tracing::warn!(
            vip = %vip,
            claimed_src = %Ipv4Addr::from(header.src),
            "spoofing: a packet with a foreign source address was dropped"
        );
        return PacketAction::Drop("source address spoofing");
    }
    shared.metrics.record_bytes_received(u64::from(header.total_len));

    let dst = Ipv4Addr::from(header.dst);
    if dst == shared.server_vip {
        if shared.is_loopback() {
            // Loopback echo: the addresses swap (src ← server_vip).
            let mut reply = packet.to_vec();
            if !ipv4::rewrite_addresses(&mut reply, shared.server_vip.octets(), vip.octets()) {
                return PacketAction::Drop("the packet cannot be rewritten");
            }
            return PacketAction::Echo(reply);
        }
        // Production mode: the server address is a kernel service via the TUN.
        return PacketAction::Forward(packet.to_vec());
    }
    // Addressed to another client — direct delivery through its channel.
    if let Some(sender) = shared.routing.route(dst) {
        return PacketAction::RouteTo(sender, packet.to_vec());
    }
    if shared.is_loopback() {
        PacketAction::Drop("echo only to the server address")
    } else {
        PacketAction::Forward(packet.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TokensSource;

    fn config() -> ServerConfig {
        ServerConfig {
            listen: "127.0.0.1:0".parse().expect("address"),
            pool: "10.66.0.0/24".to_owned(),
            mtu: 1280,
            keepalive_interval_secs: 15,
            dns_servers: vec![],
            tun_name: None,
            server_name: "localhost".to_owned(),
            tokens: TokensSource::Inline(vec![("c".to_owned(), "t".to_owned())]),
            admin: None,
        }
    }

    fn shared_state() -> Arc<ServerShared> {
        let cfg = config();
        ServerShared::new(&cfg, cfg.load_tokens().expect("tokens"), None).expect("server state")
    }

    #[test]
    fn server_shared_wires_pool_and_vip() {
        let shared = shared_state();
        assert_eq!(shared.server_vip, Ipv4Addr::new(10, 66, 0, 1));
        assert!(shared.is_loopback());
        assert_eq!(shared.active_clients(), 0);
        assert_eq!(shared.allocated_addresses(), 0);
        let snap = shared.metrics.snapshot();
        assert_eq!(snap.sessions_established, 0);
    }

    #[tokio::test]
    async fn reap_idle_sessions_without_sessions_is_a_noop() {
        let shared = shared_state();
        shared.reap_idle_sessions(std::time::Duration::from_millis(1));
        assert_eq!(shared.active_clients(), 0);
        assert_eq!(shared.allocated_addresses(), 0);
    }

    #[test]
    fn revoking_an_unknown_client_is_a_noop() {
        let shared = shared_state();
        assert_eq!(shared.revoke_client_sessions("nobody"), 0);
        assert_eq!(shared.active_clients(), 0);
        assert_eq!(shared.allocated_addresses(), 0);
        assert_eq!(shared.pool_capacity(), 253, "/24 minus network, broadcast, server");
        assert_eq!(shared.tokens().len(), 1);
        assert!(shared.session_infos().is_empty());
    }

    #[test]
    fn bad_pool_subnet_fails_fast() {
        let mut cfg = config();
        cfg.pool = "not-a-subnet".to_owned();
        assert!(matches!(
            ServerShared::new(&cfg, cfg.load_tokens().expect("tokens"), None),
            Err(ServerError::Pool(_))
        ));
    }

    /// IPv4 packet from a client: src=vip, dst=server_vip (an inner IP frame).
    fn ipv4_packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0x45, 0x00, 0x00, 0x00, 0, 1, 0x40, 0x00, 64, 17, 0, 0];
        pkt[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        pkt.extend_from_slice(&src);
        pkt.extend_from_slice(&dst);
        pkt.extend_from_slice(payload);
        pkt
    }

    /// Datagram: [kind][IP packet].
    fn datagram(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        tunnel_proto::frame::encode_frame(KIND_IPV4, &ipv4_packet(src, dst, payload))
    }

    #[test]
    fn loopback_echo_swaps_addresses_and_counts_bytes() {
        let shared = shared_state();
        let vip = Ipv4Addr::new(10, 66, 0, 2);
        let inbound = datagram([10, 66, 0, 2], [10, 66, 0, 1], &[0xDE, 0xAD]);
        match process_inbound(&shared, vip, &inbound) {
            PacketAction::Echo(reply) => {
                // Echo is a raw IP packet (framed in handle_connection).
                let header = ipv4::parse(&reply).expect("valid IPv4");
                assert_eq!(header.src, shared.server_vip.octets(), "src becomes the server");
                assert_eq!(header.dst, [10, 66, 0, 2], "dst becomes the client");
                assert_eq!(&reply[20..], &[0xDE, 0xAD], "payload untouched");
            }
            _ => panic!("loopback must echo packets addressed to server_vip"),
        }
        assert_eq!(shared.metrics.snapshot().bytes_received, 22);
    }

    #[test]
    fn spoofed_source_is_dropped() {
        let shared = shared_state();
        // A client with address .2 tries to send on behalf of .3.
        let inbound = datagram([10, 66, 0, 3], [10, 66, 0, 1], &[0x01]);
        match process_inbound(&shared, Ipv4Addr::new(10, 66, 0, 2), &inbound) {
            PacketAction::Drop(reason) => {
                assert_eq!(reason, "source address spoofing");
            }
            _ => panic!("spoofing must be dropped"),
        }
    }

    #[test]
    fn loopback_rejects_packets_to_other_clients() {
        let shared = shared_state();
        // dst = an address that is not in the table (nobody is connected).
        let inbound = datagram([10, 66, 0, 2], [10, 66, 0, 9], &[0x01]);
        match process_inbound(&shared, Ipv4Addr::new(10, 66, 0, 2), &inbound) {
            PacketAction::Drop(reason) => assert_eq!(reason, "echo only to the server address"),
            _ => panic!("in loopback a packet without a route must be dropped"),
        }
    }

    #[tokio::test]
    async fn inter_client_route_bypasses_loopback_restriction() {
        let shared = shared_state();
        let (tx, mut rx) = mpsc::channel(8);
        shared.routing().register(Ipv4Addr::new(10, 66, 0, 3), tx);
        let inner = ipv4_packet([10, 66, 0, 2], [10, 66, 0, 3], &[0x01]);
        let inbound = tunnel_proto::frame::encode_frame(KIND_IPV4, &inner);
        match process_inbound(&shared, Ipv4Addr::new(10, 66, 0, 2), &inbound) {
            PacketAction::RouteTo(sender, pkt) => {
                assert_eq!(
                    pkt, inner,
                    "the client receives the IP packet without the frame kind byte"
                );
                sender.send(pkt).await.expect("channel alive");
                assert_eq!(rx.recv().await, Some(inner));
            }
            _ => panic!("a live client's address is routed even in loopback"),
        }
    }

    #[test]
    fn garbage_datagram_is_dropped() {
        let shared = shared_state();
        assert!(matches!(
            process_inbound(&shared, Ipv4Addr::new(10, 66, 0, 2), &[0xFF, 0x00]),
            PacketAction::Drop("malformed datagram frame")
        ));
    }

    #[test]
    fn ipv6_datagram_is_dropped_with_reason() {
        let shared = shared_state();
        let inbound = tunnel_proto::frame::encode_frame(tunnel_proto::frame::KIND_IPV6, &[0x60, 1, 2]);
        match process_inbound(&shared, Ipv4Addr::new(10, 66, 0, 2), &inbound) {
            PacketAction::Drop(reason) => assert_eq!(reason, "IPv6 frames are not supported"),
            _ => panic!("IPv6 must be dropped (roadmap)"),
        }
    }
}
