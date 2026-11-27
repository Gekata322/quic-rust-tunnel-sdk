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
//! permanent stop.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{oneshot, watch};
use tunnel_core::ffi::TunnelState;
use tunnel_core::{TunnelClient, TunnelConfig};
use tunnel_proto::messages::{decode_control, encode_control};
use tunnel_proto::{
    ControlFromClient, ControlFromServer, Hello, PROTOCOL_VERSION,
};
use tunnel_server::config::{ServerConfig, TokensSource};
use tunnel_server::endpoint::{accept_loop, build_endpoint, generate_certificate};
use tunnel_server::session::ServerShared;

/// A running test server.
struct TestServer {
    addr: SocketAddr,
    cert_der: Vec<u8>,
    shared: Arc<ServerShared>,
    /// Held alive so accept_loop does not see a closed stop channel.
    _shutdown_tx: watch::Sender<bool>,
}

/// Starts a server on 127.0.0.1:0 in loopback mode (TUN is unavailable in CI).
async fn start_server(tokens: Vec<(String, String)>, pool: &str) -> TestServer {
    let config = ServerConfig {
        listen: "127.0.0.1:0".parse().expect("address"),
        pool: pool.to_owned(),
        mtu: 1280,
        keepalive_interval_secs: 1,
        dns_servers: vec![],
        tun_name: None,
        server_name: "localhost".to_owned(),
        tokens: TokensSource::Inline(tokens),
    };
    let cert = generate_certificate("localhost").expect("certificate");
    let cert_der = cert.der.as_ref().to_vec();
    let endpoint = build_endpoint(&cert, config.listen).expect("endpoint");
    let addr = endpoint.local_addr().expect("local address");
    let shared = ServerShared::new(&config, config.load_tokens().expect("tokens"), None)
        .expect("server state");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(accept_loop(Arc::clone(&shared), endpoint, shutdown_rx));
    TestServer {
        addr,
        cert_der,
        shared,
        _shutdown_tx: shutdown_tx,
    }
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
    use quinn::ClientConfig;
    use rustls::pki_types::CertificateDer;

    let server = start_server(vec![("proto-client".to_owned(), "proto-token".to_owned())], "10.66.0.0/24").await;

    // Raw QUIC client: the engine always sends the current version, so the
    // mismatch is emulated at the protocol level.
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(server.cert_der.clone()))
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
    let mut client_config = ClientConfig::new(Arc::new(quic));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(10)).expect("10s fits a VarInt"),
    ));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().expect("bind address"))
        .expect("client endpoint");
    endpoint.set_default_client_config(client_config);
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
