//! E2E test: the production `tunnel-server` (loopback mode, no TUN) against
//! the real `tunnel-core` client engine.
//!
//! Covered — the full "buyer of the library" production path: a client
//! connects with a token and the pinned server certificate, receives a
//! virtual address, sends an IP packet to the server address — the server
//! echoes it back with the addresses swapped; parallel clients get distinct
//! addresses; a wrong token is rejected without retries. Stage-1 additions:
//! a wrong protocol version is rejected, a released VIP is reused by the next
//! client, and pool exhaustion yields a retryable `ServerBusy`, not a
//! permanent stop. Stage-3 additions: an idle session is reaped and its VIP
//! returns to the pool while a live session survives, and a capped client
//! has its excess datagrams dropped by the token bucket. Stage-4 addition:
//! the admin API — auth, hot token add, and hot revocation that kicks the
//! live session, frees the VIP and stops the engine permanently.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::{oneshot, watch};
use tunnel_core::ffi::TunnelState;
use tunnel_core::{TunnelClient, TunnelConfig};
use tunnel_proto::auth::{TokenEntry, TokenStore};
use tunnel_proto::frame::{encode_frame, KIND_IPV4};
use tunnel_proto::messages::{decode_control, encode_control};
use tunnel_proto::{
    ControlFromClient, ControlFromServer, Hello, Welcome, PROTOCOL_VERSION,
};
use tunnel_server::config::{ServerConfig, TokensSource};
use tunnel_server::endpoint::{accept_loop, build_endpoint, generate_certificate};
use tunnel_server::session::ServerShared;

/// A running test server.
struct TestServer {
    addr: SocketAddr,
    cert_der: Vec<u8>,
    shared: Arc<ServerShared>,
    /// Kept alive so accept_loop (and the admin API) do not see a closed
    /// stop channel; `shutdown_rx()` hands out receivers.
    shutdown_tx: watch::Sender<bool>,
}

impl TestServer {
    /// A fresh shutdown receiver for the admin API.
    fn shutdown_rx(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }
}

/// Starts a server on 127.0.0.1:0 in loopback mode (TUN is unavailable in CI).
/// Full [`TokenStore`] input: limits per client are supported.
async fn start_server_with_tokens(tokens: TokenStore, pool: &str) -> TestServer {
    let config = ServerConfig {
        listen: "127.0.0.1:0".parse().expect("address"),
        pool: pool.to_owned(),
        mtu: 1280,
        keepalive_interval_secs: 1,
        dns_servers: vec![],
        tun_name: None,
        server_name: "localhost".to_owned(),
        // The store is passed directly; the source in the config is unused.
        tokens: TokensSource::Inline(Vec::new()),
        // The admin API is spawned per-test where needed (an ephemeral port).
        admin: None,
    };
    let cert = generate_certificate("localhost").expect("certificate");
    let cert_der = cert.der.as_ref().to_vec();
    let endpoint = build_endpoint(&cert, config.listen).expect("endpoint");
    let addr = endpoint.local_addr().expect("local address");
    let shared = ServerShared::new(&config, tokens, None).expect("server state");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(accept_loop(Arc::clone(&shared), endpoint, shutdown_rx));
    TestServer {
        addr,
        cert_der,
        shared,
        shutdown_tx,
    }
}

/// The common harness: `(client_id, token)` pairs without limits.
async fn start_server(tokens: Vec<(String, String)>, pool: &str) -> TestServer {
    start_server_with_tokens(TokenStore::from_pairs(tokens), pool).await
}

fn client_config(server: &TestServer, token: &str, client_id: &str) -> TunnelConfig {
    TunnelConfig {
        server_host: "127.0.0.1".to_owned(),
        server_name: "localhost".to_owned(),
        server_port: server.addr.port(),
        auth_token: token.to_owned(),
        client_id: client_id.to_owned(),
        pinned_server_cert_der: server.cert_der.clone(),
        connect_timeout_ms: 5000,
        min_backoff_ms: 100,
        max_backoff_ms: 1000,
        keepalive_interval_secs: 0,
    }
}

/// Polls until the state satisfies `predicate`, with a deadline.
async fn wait_state(
    client: &TunnelClient,
    predicate: impl Fn(&TunnelState) -> bool,
    secs: u64,
) -> TunnelState {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let state = client.state();
        if predicate(&state) {
            return state;
        }
        assert!(
            Instant::now() < deadline,
            "state not reached within {secs}s, current: {state:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Minimal IPv4 packet (the checksum does not matter — the server ignores it).
fn build_ipv4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0x45, 0x00, 0x00, 0x00, 0, 1, 0x40, 0x00, 64, 17, 0, 0];
    pkt[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(payload);
    pkt
}

/// Parses `negotiated_vip()` ("a.b.c.d") into address bytes.
fn parse_vip(text: &str) -> [u8; 4] {
    let octets: Vec<u8> = text
        .split('.')
        .map(|part| part.parse().expect("a vip consists of four octets"))
        .collect();
    let octets: [u8; 4] = octets.try_into().expect("a vip has exactly 4 octets");
    octets
}

/// A raw QUIC client endpoint pinned to the test server's certificate. The
/// engine always sends the current protocol version and always speaks, so
/// protocol-level and silence-based tests need a hand-rolled connection.
fn raw_quic_client(cert_der: &[u8]) -> quinn::Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(cert_der.to_vec()))
        .expect("pinned certificate");
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![tunnel_proto::ALPN_TUNNEL_V1.to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC over TLS");
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(10)).expect("10s fits a VarInt"),
    ));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("bind address"))
        .expect("client endpoint");
    endpoint.set_default_client_config(client_config);
    endpoint
}

/// A hand-rolled session held open after the handshake. The control streams
/// are kept by value: dropping the SendStream resets the stream and the
/// server closes the session ("control plane closed") — a raw client must
/// look as alive as a real one.
struct RawSession {
    conn: quinn::Connection,
    welcome: Welcome,
    /// Held so the control stream is not reset by a drop.
    _control: (quinn::SendStream, quinn::RecvStream),
}

/// Raw handshake over stream #0: sends `Hello` with the given credentials and
/// reads the server's `Welcome`. The endpoint must outlive the connection.
async fn raw_handshake(
    endpoint: &mut quinn::Endpoint,
    server: &TestServer,
    client_id: &str,
    token: &str,
) -> RawSession {
    let conn = endpoint
        .connect(server.addr, "localhost")
        .expect("connect started")
        .await
        .expect("QUIC handshake");

    let (mut send, mut recv) = conn.open_bi().await.expect("control stream");
    let hello = ControlFromClient::Hello(Hello {
        protocol_version: PROTOCOL_VERSION,
        client_id: client_id.to_owned(),
        auth_token: token.to_owned(),
    });
    send.write_all(&encode_control(&hello)).await.expect("Hello sent");

    let mut prefix = [0u8; 4];
    recv.read_exact(&mut prefix).await.expect("reply prefix");
    let len = u32::from_le_bytes(prefix) as usize;
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await.expect("reply body");
    let (reply, _) = decode_control::<ControlFromServer>(&[prefix.as_slice(), &body].concat())
        .expect("valid frame")
        .expect("complete frame");
    match reply {
        ControlFromServer::Welcome(welcome) => RawSession {
            conn,
            welcome,
            _control: (send, recv),
        },
        other => panic!("expected Welcome, got {other:?}"),
    }
}

/// Sends a 200-datagram burst (10 batches × 20 × 1021 bytes). Batching is
/// deliberate: the batches are separated by sleeps (gentle on the QUIC
/// receive queues, so the accounting stays exact), but within a batch the
/// datagrams land back-to-back at ~4 MB/s — far above a 1 Mbps refill — so
/// the limiter engages regardless of the runner's sleep granularity.
async fn send_burst(conn: &quinn::Connection, vip: [u8; 4], server_vip: [u8; 4]) {
    for _ in 0..10 {
        for _ in 0..20 {
            let packet = build_ipv4(vip, server_vip, &[0u8; 1000]);
            conn.send_datagram(Bytes::from(encode_frame(KIND_IPV4, &packet)))
                .expect("datagram queued");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Sends a packet through the client and waits for the reply on a side thread
/// (the way the platform code over FFI will do it).
async fn echo_roundtrip(
    client: &Arc<TunnelClient>,
    server: Option<&TestServer>,
    packet: Vec<u8>,
) -> Vec<u8> {
    assert!(client.send_packet(packet.clone()), "the queue must not be full");
    let (tx, rx) = oneshot::channel();
    let recv_client = Arc::clone(client);
    std::thread::spawn(move || {
        let _ = tx.send(recv_client.recv_packet(3000));
    });
    match tokio::time::timeout(Duration::from_secs(5), rx).await {
        Ok(Ok(Some(echoed))) => echoed,
        other => {
            if let Some(server) = server {
                println!("echo miss: server metrics = {:?}", server.shared.metrics.snapshot());
            }
            println!("echo miss: client telemetry = {:?}", client.get_telemetry());
            println!("echo miss: client state = {:?}", client.state());
            panic!("no echo returned: {other:?}");
        }
    }
}

#[tokio::test]
async fn client_echo_via_server_vip() {
    let server = start_server(vec![("e2e-client".to_owned(), "e2e-token".to_owned())], "10.66.0.0/24").await;
    let client = Arc::new(
        TunnelClient::new(client_config(&server, "e2e-token", "e2e-client")).expect("client"),
    );
    client.connect().expect("engine start");

    let state = wait_state(&client, |s| matches!(s, TunnelState::Connected { .. }), 5).await;
    assert!(
        matches!(state, TunnelState::Connected { mtu: 1280, .. }),
        "unexpected state: {state:?}"
    );
    assert_eq!(client.negotiated_mtu(), Some(1280));

    // The only client of the pool always gets the first address .2.
    let vip = parse_vip(&client.negotiated_vip().expect("vip issued by the server"));
    assert_eq!(vip, [10, 66, 0, 2]);

    let server_vip = server.shared.server_vip.octets();
    let packet = build_ipv4(vip, server_vip, &[0xDE, 0xAD]);
    let echoed = echo_roundtrip(&client, Some(&server), packet).await;

    assert_eq!(&echoed[12..16], &server_vip, "src replaced with the server address");
    assert_eq!(&echoed[16..20], &vip, "dst replaced with the client address");
    assert_eq!(&echoed[20..], &[0xDE, 0xAD], "payload untouched");
    assert_eq!(server.shared.metrics.snapshot().bytes_received, 22);

    client.disconnect();
    wait_state(&client, |s| matches!(s, TunnelState::Stopped), 5).await;
}

#[tokio::test]
async fn two_clients_get_distinct_addresses() {
    let server = start_server(vec![
        ("client-a".to_owned(), "multi-token".to_owned()),
        ("client-b".to_owned(), "multi-token".to_owned()),
    ], "10.66.0.0/24").await;
    let client_a = Arc::new(
        TunnelClient::new(client_config(&server, "multi-token", "client-a")).expect("client A"),
    );
    let client_b = Arc::new(
        TunnelClient::new(client_config(&server, "multi-token", "client-b")).expect("client B"),
    );
    client_a.connect().expect("start A");
    wait_state(&client_a, |s| matches!(s, TunnelState::Connected { .. }), 5).await;
    client_b.connect().expect("start B");
    wait_state(&client_b, |s| matches!(s, TunnelState::Connected { .. }), 5).await;

    // Addresses are read from the client states (who connected first does not
    // matter): a real platform also configures the TUN from negotiated_vip.
    let vip_a = parse_vip(&client_a.negotiated_vip().expect("vip A"));
    let vip_b = parse_vip(&client_b.negotiated_vip().expect("vip B"));
    assert_ne!(vip_a, vip_b, "the pool must issue distinct addresses");
    assert!(vip_a == [10, 66, 0, 2] || vip_a == [10, 66, 0, 3]);
    assert!(vip_b == [10, 66, 0, 2] || vip_b == [10, 66, 0, 3]);

    let server_vip = server.shared.server_vip.octets();
    let packet_a = build_ipv4(vip_a, server_vip, b"AAA");
    let packet_b = build_ipv4(vip_b, server_vip, b"BBB");
    let (echoed_a, echoed_b) = tokio::join!(
        echo_roundtrip(&client_a, Some(&server), packet_a),
        echo_roundtrip(&client_b, Some(&server), packet_b)
    );

    assert_eq!(&echoed_a[16..20], &vip_a, "the echo is addressed to client A");
    assert_eq!(&echoed_a[20..], b"AAA");
    assert_eq!(&echoed_b[16..20], &vip_b, "the echo is addressed to client B");
    assert_eq!(&echoed_b[20..], b"BBB");

    let snap = server.shared.metrics.snapshot();
    assert_eq!(snap.sessions_established, 2);
    assert!(snap.bytes_received >= 23 + 23, "telemetry of both clients: {snap:?}");

    client_a.disconnect();
    client_b.disconnect();
}

#[tokio::test]
async fn unknown_token_is_rejected_without_session() {
    let server = start_server(vec![("known-client".to_owned(), "known-token".to_owned())], "10.66.0.0/24").await;
    let client = TunnelClient::new(client_config(&server, "wrong-token", "known-client"))
        .expect("client");
    client.connect().expect("engine start");

    wait_state(&client, |s| matches!(s, TunnelState::Stopped), 5).await;

    let snap = server.shared.metrics.snapshot();
    assert_eq!(snap.sessions_established, 0, "the session must not have opened");
}

/// A client announcing an unsupported protocol version must receive a typed
/// `Reject{ProtocolMismatch}` before any session state is created.
#[tokio::test]
async fn wrong_protocol_version_is_rejected() {
    let server = start_server(vec![("proto-client".to_owned(), "proto-token".to_owned())], "10.66.0.0/24").await;

    // Raw QUIC client: the engine always sends the current version, so the
    // mismatch is emulated at the protocol level.
    let endpoint = raw_quic_client(&server.cert_der);
    let conn = endpoint
        .connect(server.addr, "localhost")
        .expect("connect started")
        .await
        .expect("QUIC handshake");

    let (mut send, mut recv) = conn.open_bi().await.expect("control stream");
    let hello = ControlFromClient::Hello(Hello {
        protocol_version: PROTOCOL_VERSION + 1,
        client_id: "proto-client".to_owned(),
        auth_token: "proto-token".to_owned(),
    });
    send.write_all(&encode_control(&hello)).await.expect("Hello sent");

    let mut prefix = [0u8; 4];
    recv.read_exact(&mut prefix).await.expect("reply prefix");
    let len = u32::from_le_bytes(prefix) as usize;
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await.expect("reply body");
    let (reply, _) = decode_control::<ControlFromServer>(&[prefix.as_slice(), &body].concat())
        .expect("valid frame")
        .expect("complete frame");

    match reply {
        ControlFromServer::Reject(reject) => {
            assert!(
                matches!(reject.code, tunnel_proto::RejectCode::ProtocolMismatch),
                "expected ProtocolMismatch, got: {:?}",
                reject.code
            );
            assert!(
                reject.message.contains(&PROTOCOL_VERSION.to_string()),
                "the reason must name the supported version: {}",
                reject.message
            );
        }
        other => panic!("expected a Reject, got {other:?}"),
    }

    let snap = server.shared.metrics.snapshot();
    assert_eq!(snap.sessions_established, 0, "no session state for a version mismatch");
}

/// A released VIP is returned to the pool and reused by the next client. A
/// /30 pool has exactly one client address, so the second client only
/// connects after the first one's session released the address.
#[tokio::test]
async fn released_vip_is_reused_by_next_client() {
    let server = start_server(vec![
        ("client-a".to_owned(), "reuse-token".to_owned()),
        ("client-b".to_owned(), "reuse-token".to_owned()),
    ], "10.66.0.0/30").await;

    let client_a = TunnelClient::new(client_config(&server, "reuse-token", "client-a")).expect("client A");
    client_a.connect().expect("start A");
    let state = wait_state(&client_a, |s| matches!(s, TunnelState::Connected { .. }), 5).await;
    let vip_a = match state {
        TunnelState::Connected { vip, .. } => vip,
        other => panic!("unexpected state: {other:?}"),
    };
    assert_eq!(parse_vip(&vip_a), [10, 66, 0, 2], "the single /30 address is .2");

    client_a.disconnect();
    wait_state(&client_a, |s| matches!(s, TunnelState::Stopped), 5).await;

    // Client B retries through ServerBusy until A's address is released and
    // handed out again — the pool must return to the same .2.
    let client_b = Arc::new(TunnelClient::new(client_config(&server, "reuse-token", "client-b")).expect("client B"));
    client_b.connect().expect("start B");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if matches!(client_b.state(), TunnelState::Connected { ref vip, .. } if vip == &vip_a) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "client B never received the released VIP {}; state: {:?}",
            vip_a,
            client_b.state()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    client_b.disconnect();
}

/// Pool exhaustion must be a transient failure: the rejected client keeps
/// retrying (Reconnecting) instead of stopping permanently.
#[tokio::test]
async fn pool_exhaustion_is_transient_not_permanent() {
    let server = start_server(vec![
        ("client-a".to_owned(), "busy-token".to_owned()),
        ("client-b".to_owned(), "busy-token".to_owned()),
    ], "10.66.0.0/30").await;

    let client_a = TunnelClient::new(client_config(&server, "busy-token", "client-a")).expect("client A");
    client_a.connect().expect("start A");
    wait_state(&client_a, |s| matches!(s, TunnelState::Connected { .. }), 5).await;

    // The pool has one address and it is taken: B is rejected with ServerBusy.
    let client_b = TunnelClient::new(client_config(&server, "busy-token", "client-b")).expect("client B");
    client_b.connect().expect("start B");

    // Give B time for at least one handshake + rejection cycle.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let snap = server.shared.metrics.snapshot();
    assert_eq!(snap.sessions_established, 1, "only client A established a session");
    let state = client_b.state();
    assert_ne!(
        state,
        TunnelState::Stopped,
        "ServerBusy is transient: the engine must keep retrying"
    );

    client_a.disconnect();
    client_b.disconnect();
    wait_state(&client_a, |s| matches!(s, TunnelState::Stopped), 5).await;
}

/// Stage 3: the reaper frees the address of a client that vanished without a
/// close. A raw client goes completely silent after `Welcome` (no pings, no
/// data — like a laptop that lost its network); after the idle timeout the
/// reaper closes its session and returns the VIP to the pool. A live client
/// is never reaped and later takes the freed address. A /30 pool has exactly
/// one client address, so the reuse check is deterministic.
#[tokio::test]
async fn idle_session_is_reaped_and_vip_is_reused() {
    let server = start_server(vec![("idle-client".to_owned(), "idle-token".to_owned())], "10.66.0.0/30").await;
    // Shortened timeouts: the reaper fires within ~1.2s instead of 45s.
    tunnel_server::reaper::spawn_idle_reaper_with(
        &server.shared,
        Duration::from_millis(1000),
        Duration::from_millis(100),
    );

    // The raw connection is held open: only the reaper may clean it up.
    let mut endpoint = raw_quic_client(&server.cert_der);
    let session = raw_handshake(&mut endpoint, &server, "idle-client", "idle-token").await;
    let vanished_vip = session.welcome.vip;
    assert_eq!(vanished_vip.octets(), [10, 66, 0, 2]);

    // Wait for the reaper: the route disappears and the address is freed.
    let deadline = Instant::now() + Duration::from_secs(5);
    while server.shared.active_clients() > 0 || server.shared.allocated_addresses() > 0 {
        assert!(
            Instant::now() < deadline,
            "the idle session was not reaped within 5s"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // The freed address goes to a fully live client (the engine pings every
    // second per the server's keepalive hint): reuse plus proof that active
    // sessions survive the reaper.
    let client = Arc::new(
        TunnelClient::new(client_config(&server, "idle-token", "idle-client")).expect("client"),
    );
    client.connect().expect("engine start");
    wait_state(&client, |s| matches!(s, TunnelState::Connected { .. }), 5).await;
    let vip = parse_vip(&client.negotiated_vip().expect("vip issued"));
    assert_eq!(vip, vanished_vip.octets(), "the reaped address is reused");

    tokio::time::sleep(Duration::from_millis(2500)).await;
    let state = client.state();
    assert!(
        matches!(state, TunnelState::Connected { .. }),
        "an active session must survive the reaper: {state:?}"
    );
    assert_eq!(server.shared.active_clients(), 1);
    assert_eq!(server.shared.allocated_addresses(), 1);

    client.disconnect();
    wait_state(&client, |s| matches!(s, TunnelState::Stopped), 5).await;
}

/// Stage 3: a client with a bandwidth cap has its excess datagrams dropped by
/// the token bucket, while an uncapped client passes its whole burst. The
/// accounting invariant: every datagram is either counted in `bytes_received`
/// or in `rate_limited` — never both, never neither.
#[tokio::test]
async fn rate_limit_drops_datagrams_over_the_cap() {
    let tokens = TokenStore::from_entries(vec![
        TokenEntry {
            client_id: "fast-client".to_owned(),
            token: "rate-token".to_owned(),
            rate_limit_mbps: None,
        },
        TokenEntry {
            client_id: "slow-client".to_owned(),
            token: "rate-token".to_owned(),
            rate_limit_mbps: Some(1),
        },
    ]);
    let server = start_server_with_tokens(tokens, "10.66.0.0/24").await;

    // Packet shape: 1000 payload bytes → a 1020-byte IP packet inside a
    // 1021-byte frame, well under the initial QUIC datagram limit.
    const BURST: u64 = 200;
    const PACKET_BYTES: u64 = 1020; // header.total_len the server accounts
    let server_vip = server.shared.server_vip.octets();

    // Phase A — no cap: every datagram of the burst reaches the data plane.
    let mut fast_endpoint = raw_quic_client(&server.cert_der);
    let fast_session =
        raw_handshake(&mut fast_endpoint, &server, "fast-client", "rate-token").await;
    let fast_vip = fast_session.welcome.vip.octets();
    let before = server.shared.metrics.snapshot();
    send_burst(&fast_session.conn, fast_vip, server_vip).await;
    let after_fast = server.shared.metrics.snapshot();
    assert_eq!(
        after_fast.rate_limited - before.rate_limited,
        0,
        "an uncapped client is never rate limited"
    );
    assert_eq!(
        after_fast.bytes_received - before.bytes_received,
        BURST * PACKET_BYTES,
        "every datagram of an uncapped burst reaches the data plane"
    );

    // Phase B — 1 Mbps cap: the 125 KB bucket admits roughly half of the
    // burst; the rest is dropped by the limiter.
    let mut slow_endpoint = raw_quic_client(&server.cert_der);
    let slow_session =
        raw_handshake(&mut slow_endpoint, &server, "slow-client", "rate-token").await;
    let slow_vip = slow_session.welcome.vip.octets();
    send_burst(&slow_session.conn, slow_vip, server_vip).await;
    let after_slow = server.shared.metrics.snapshot();
    let dropped = after_slow.rate_limited - after_fast.rate_limited;
    let received = after_slow.bytes_received - after_fast.bytes_received;
    assert!(
        dropped >= 10,
        "the cap must drop a meaningful part of the burst: dropped={dropped}"
    );
    assert!(
        dropped < BURST,
        "the bucket must admit part of the burst: dropped={dropped}"
    );
    assert_eq!(
        received,
        (BURST - dropped) * PACKET_BYTES,
        "each datagram is either counted or rate limited — never both, never neither"
    );
    // The limiter drops datagrams, not the session: the throttled client
    // stays connected and routable.
    assert!(
        server.shared.routing().route(slow_session.welcome.vip).is_some(),
        "the capped session is still routable"
    );
}

/// Sends one HTTP/1.1 request to the admin API over a raw TCP socket and
/// returns `(status, json body)`. `Connection: close` makes the server close
/// the socket after the answer, so reading to EOF is a complete response.
/// A hand-rolled client keeps the E2E dependency tree lean (no reqwest) and
/// exercises the real socket path end to end.
async fn admin_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    key: Option<&str>,
    body: Option<&str>,
) -> (u16, serde_json::Value) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("admin server is reachable");
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(key) = key {
        request.push_str(&format!("X-Admin-Key: {key}\r\n"));
    }
    if let Some(body) = body {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("request written");
    if let Some(body) = body {
        stream.write_all(body.as_bytes()).await.expect("body written");
    }

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("response read to EOF");
    let text = std::str::from_utf8(&response).expect("a UTF-8 HTTP response");
    let status: u16 = text
        .split_whitespace()
        .nth(1)
        .expect("a status line")
        .parse()
        .expect("a numeric status code");
    let body_start = text
        .find("\r\n\r\n")
        .expect("headers are terminated") + 4;
    let json = if body_start < text.len() {
        serde_json::from_str(&text[body_start..]).expect("a JSON body")
    } else {
        serde_json::Value::Null
    };
    (status, json)
}

/// Stage 4: the admin API protects itself with `X-Admin-Key`, hot-adds tokens
/// that work for new handshakes without a restart, and hot-revokes a token:
/// the live session is kicked (the VIP returns to the pool), the client's
/// reconnect attempt is rejected with `InvalidToken` — a permanent error —
/// so the engine stops, and an unrelated client keeps working.
#[tokio::test]
async fn admin_api_revokes_tokens_and_kills_live_sessions() {
    let server = start_server(vec![("victim".to_owned(), "victim-token".to_owned())], "10.66.0.0/24").await;
    let admin_addr = tunnel_server::admin::spawn_admin_server(
        Arc::clone(&server.shared),
        &tunnel_server::config::AdminConfig {
            listen: "127.0.0.1:0".parse().expect("bind address"),
            key: "stage4-admin-key".to_owned(),
        },
        server.shutdown_rx(),
    )
    .await
    .expect("admin server bound");
    assert_ne!(admin_addr.port(), 0, "the OS issued an ephemeral port");

    // The victim is connected before any admin call.
    let victim = Arc::new(
        TunnelClient::new(client_config(&server, "victim-token", "victim")).expect("client"),
    );
    victim.connect().expect("engine start");
    wait_state(&victim, |s| matches!(s, TunnelState::Connected { .. }), 5).await;
    let victim_vip = parse_vip(&victim.negotiated_vip().expect("vip issued"));

    // --- Authorization: no key and a wrong key are indistinguishable 401s.
    for key in [None, Some("wrong-key")] {
        let (status, body) = admin_request(admin_addr, "GET", "/stats", key, None).await;
        assert_eq!(status, 401, "key: {key:?}");
        assert_eq!(body["error"], "missing or invalid X-Admin-Key header");
    }

    // --- GET /stats with the correct key sees the live session.
    let (status, stats) = admin_request(admin_addr, "GET", "/stats", Some("stage4-admin-key"), None).await;
    assert_eq!(status, 200);
    assert_eq!(stats["mode"], "loopback");
    assert_eq!(stats["active_clients"], 1);
    assert_eq!(stats["allocated_addresses"], 1);
    assert_eq!(stats["tokens"], 1);
    assert_eq!(stats["metrics"]["sessions_established"], 1);
    let sessions = stats["sessions"].as_array().expect("a session list");
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["client_id"], "victim");
    assert_eq!(sessions[0]["vip"], "10.66.0.2");

    // --- POST /tokens: validation errors first.
    for bad_body in [
        r#"{"client_id":"  ","token":"tok"}"#,
        r#"{"client_id":"guest","token":"  "}"#,
        r#"{"client_id":"guest","token":"tok","rate_limit_mbps":0}"#,
    ] {
        let (status, _) = admin_request(
            admin_addr,
            "POST",
            "/tokens",
            Some("stage4-admin-key"),
            Some(bad_body),
        )
        .await;
        assert_eq!(status, 400, "body: {bad_body}");
    }

    // --- POST /tokens hot-add: 201, then a brand-new client connects with
    // the fresh token — no server restart involved.
    let (status, body) = admin_request(
        admin_addr,
        "POST",
        "/tokens",
        Some("stage4-admin-key"),
        Some(r#"{"client_id":"guest","token":"guest-token","rate_limit_mbps":10}"#),
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(body["created"], true);
    assert_eq!(body["rate_limit_mbps"], 10);
    assert!(server.shared.tokens().verify("guest", "guest-token"));

    let guest = Arc::new(
        TunnelClient::new(client_config(&server, "guest-token", "guest")).expect("client"),
    );
    guest.connect().expect("engine start");
    wait_state(&guest, |s| matches!(s, TunnelState::Connected { .. }), 5).await;
    let guest_vip = parse_vip(&guest.negotiated_vip().expect("vip issued"));
    assert_ne!(victim_vip, guest_vip, "two live clients hold distinct VIPs");

    // Replacing the same client answers 200 created=false and swaps the secret.
    let (status, body) = admin_request(
        admin_addr,
        "POST",
        "/tokens",
        Some("stage4-admin-key"),
        Some(r#"{"client_id":"guest","token":"guest-token-2"}"#),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["created"], false);
    assert!(server.shared.tokens().verify("guest", "guest-token-2"));
    // The already-connected guest keeps its session; restore the original token.
    let (status, _) = admin_request(
        admin_addr,
        "POST",
        "/tokens",
        Some("stage4-admin-key"),
        Some(r#"{"client_id":"guest","token":"guest-token"}"#),
    )
    .await;
    assert_eq!(status, 200);

    // --- DELETE /tokens/victim: hot revocation kicks the live session.
    let (status, body) =
        admin_request(admin_addr, "DELETE", "/tokens/victim", Some("stage4-admin-key"), None).await;
    assert_eq!(status, 200);
    assert_eq!(body["revoked"], true);
    assert_eq!(body["sessions_killed"], 1);
    assert_eq!(body["client_id"], "victim");

    // Server state is cleaned synchronously: the route is gone, the VIP is back.
    assert_eq!(server.shared.active_clients(), 1, "the guest stays");
    assert_eq!(server.shared.allocated_addresses(), 1, "the victim's VIP is freed");
    assert!(
        server
            .shared
            .routing()
            .route(std::net::Ipv4Addr::from(victim_vip))
            .is_none(),
        "the victim's route is removed"
    );

    // A second revocation finds nothing: 404.
    let (status, _) =
        admin_request(admin_addr, "DELETE", "/tokens/victim", Some("stage4-admin-key"), None).await;
    assert_eq!(status, 404);

    // The victim's engine sees its session drop, retries, gets Reject
    // {InvalidToken} — permanent — and stops instead of retrying forever.
    wait_state(&victim, |s| matches!(s, TunnelState::Stopped), 10).await;
    // Exactly two sessions were ever established (victim + guest): the
    // rejected reconnect attempt never opened a new one.
    let snap = server.shared.metrics.snapshot();
    assert_eq!(
        snap.sessions_established, 2,
        "no session is established with a revoked token: {snap:?}"
    );

    // /stats reflects the revocation: one token left, one live client and
    // the session list contains only the guest.
    let (status, stats) =
        admin_request(admin_addr, "GET", "/stats", Some("stage4-admin-key"), None).await;
    assert_eq!(status, 200);
    assert_eq!(stats["tokens"], 1, "the victim's entry is gone");
    assert_eq!(stats["active_clients"], 1);
    let sessions = stats["sessions"].as_array().expect("a session list");
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["client_id"], "guest");

    // The guest is untouched by the victim's revocation and still exchanges
    // packets (keepalive pings count as inbound activity for the reaper, so
    // a full echo roundtrip is the strongest liveness proof here).
    let server_vip = server.shared.server_vip.octets();
    let echoed = echo_roundtrip(&guest, Some(&server), build_ipv4(guest_vip, server_vip, b"alive")).await;
    assert_eq!(&echoed[16..20], &guest_vip);
    assert_eq!(&echoed[20..], b"alive");

    guest.disconnect();
    victim.disconnect();
    wait_state(&guest, |s| matches!(s, TunnelState::Stopped), 5).await;
}
