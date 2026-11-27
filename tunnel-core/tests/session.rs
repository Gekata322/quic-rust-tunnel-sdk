//! Integration test of the full `tunnel-core` stack: a local QUIC server
//! ("echo" + a valid control plane) against the real engine with its FFI
//! wrapper.
//!
//! Covered: the handshake with a token and the server MTU, packet exchange
//! via `send_packet`/`recv_packet`, telemetry with RTT, the status callback
//! (`Disconnected → Connected → Disconnected`), graceful stop, and the
//! rejected-token scenario (the engine must move to `Stopped` without retries).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rcgen::{CertifiedKey, generate_simple_self_signed};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tunnel_core::ffi::{ConnectionStatus, ConnectionStatusCallback, TunnelState};
use tunnel_core::{TunnelClient, TunnelConfig};
use tunnel_proto::messages::{decode_control, encode_control};
use tunnel_proto::{
    ControlFromClient, ControlFromServer, Hello, Ping, Pong, Reject, RejectCode, Welcome,
    ALPN_TUNNEL_V1,
};

/// Log initialization: the engine logs via tracing; tests need a subscriber —
/// otherwise failure diagnostics are swallowed silently.
static LOGS: std::sync::Once = std::sync::Once::new();
fn init_logs() {
    LOGS.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
            .with_test_writer()
            .try_init();
    });
}

/// Behavior of the test server.
#[derive(Clone, Copy)]
enum ServerMode {
    /// Valid server: `Welcome`, `Pong` on ping, byte-for-byte datagram echo.
    Echo,
    /// Always `Reject{InvalidToken}` — verifies the engine's permanent stop.
    RejectAll,
}

/// Spawns a local QUIC server with a self-signed certificate.
/// Returns the address and the certificate DER (also the client's pinned root).
async fn spawn_server(mode: ServerMode) -> (SocketAddr, Vec<u8>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).expect("self-signed certificate");
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("default TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("certificate and key");
    tls.alpn_protocols = vec![ALPN_TUNNEL_V1.to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("QUIC over TLS"),
    ));
    let endpoint = quinn::Endpoint::server(
        server_config,
        "127.0.0.1:0".parse().expect("bind address"),
    )
    .expect("server UDP endpoint");
    let addr = endpoint.local_addr().expect("local address");
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            match incoming.await {
                Ok(conn) => {
                    tokio::spawn(handle_connection(mode, conn));
                }
                Err(_) => continue,
            }
        }
    });
    (addr, cert_der.as_ref().to_vec())
}

/// Reads one control message (length prefix + bincode body).
async fn read_control(recv: &mut quinn::RecvStream) -> Option<Vec<u8>> {
    let mut prefix = [0u8; 4];
    recv.read_exact(&mut prefix).await.ok()?;
    let len = u32::from_le_bytes(prefix) as usize;
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await.ok()?;
    let mut full = prefix.to_vec();
    full.extend_from_slice(&body);
    Some(full)
}

/// Connection handling by the test server: handshake, then the control plane
/// (Pong on Ping) and the data plane (datagram echo as-is, byte-for-byte).
async fn handle_connection(mode: ServerMode, conn: quinn::Connection) {
    let (mut send, mut recv) = match conn.accept_bi().await {
        Ok(streams) => streams,
        Err(_) => return,
    };

    let hello = match read_control(&mut recv).await {
        Some(buf) => match decode_control::<ControlFromClient>(&buf) {
            Ok(Some((ControlFromClient::Hello(Hello { auth_token, client_id, .. }), _))) => {
                (auth_token, client_id)
            }
            _ => return,
        },
        None => return,
    };

    match mode {
        ServerMode::RejectAll => {
            let reject = Reject {
                code: RejectCode::InvalidToken,
                message: format!("no token for {}", hello.1),
            };
            let _ = send.write_all(&encode_control(&ControlFromServer::Reject(reject))).await;
            let _ = send.finish();
            // Drain: give the client a chance to read the Reject before the
            // connection closes — otherwise CONNECTION_CLOSE overtakes the
            // stream data (see the server code).
            let _ = tokio::time::timeout(std::time::Duration::from_millis(200), conn.closed()).await;
            return;
        }
        ServerMode::Echo => {}
    }
    // The token "test" is valid in Echo mode (used by the tests below).
    if hello.0 != "test" && hello.0 != "tok" {
        let reject = Reject {
            code: RejectCode::InvalidToken,
            message: "unknown token".to_owned(),
        };
        let _ = send.write_all(&encode_control(&ControlFromServer::Reject(reject))).await;
        let _ = send.finish();
        let _ = tokio::time::timeout(std::time::Duration::from_millis(200), conn.closed()).await;
        return;
    }

    let welcome = Welcome {
        vip: std::net::Ipv4Addr::new(10, 66, 0, 2),
        mtu: 1280,
        keepalive_interval_secs: 1,
    };
    if send
        .write_all(&encode_control(&ControlFromServer::Welcome(welcome)))
        .await
        .is_err()
    {
        return;
    }

    // Two planes while the connection is alive: control and data.
    loop {
        tokio::select! {
            message = read_control(&mut recv) => match message {
                Some(buf) => match decode_control::<ControlFromClient>(&buf) {
                    Ok(Some((ControlFromClient::Ping(Ping { seq, sent_unix_ms }), _))) => {
                        let pong = ControlFromServer::Pong(Pong {
                            seq,
                            sent_unix_ms,
                            server_unix_ms: tunnel_proto::messages::unix_ms(),
                        });
                        if send.write_all(&encode_control(&pong)).await.is_err() {
                            return;
                        }
                    }
                    _ => return,
                },
                None => return,
            },
            datagram = conn.read_datagram() => match datagram {
                Ok(packet) => {
                    if conn.send_datagram(packet).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            },
        }
    }
}

/// Client config against the test server (fast timeouts for tests).
fn test_config(addr: SocketAddr, cert_der: Vec<u8>) -> TunnelConfig {
    TunnelConfig {
        server_host: addr.ip().to_string(),
        server_name: "localhost".to_owned(),
        server_port: addr.port(),
        auth_token: "test".to_owned(),
        client_id: "session-test".to_owned(),
        pinned_server_cert_der: cert_der,
        connect_timeout_ms: 5000,
        min_backoff_ms: 100,
        max_backoff_ms: 1000,
        keepalive_interval_secs: 0,
    }
}

/// Polls until the state satisfies `predicate`, with a shared deadline.
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

/// Waits until the last callback status satisfies `predicate`.
async fn wait_status(events: &Mutex<Vec<ConnectionStatus>>, predicate: impl Fn(&[ConnectionStatus]) -> bool, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if predicate(&events.lock().expect("event buffer")) {
            return;
        }
        assert!(Instant::now() < deadline, "status not reached within {secs}s");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Test callback: collects statuses into a shared buffer.
struct Collector {
    events: Arc<Mutex<Vec<ConnectionStatus>>>,
}
impl ConnectionStatusCallback for Collector {
    fn on_status_change(&self, status: ConnectionStatus) {
        self.events.lock().expect("event buffer").push(status);
    }
}

#[tokio::test]
async fn echo_roundtrip_over_full_stack() {
    init_logs();
    let (addr, cert_der) = spawn_server(ServerMode::Echo).await;
    let client = Arc::new(TunnelClient::new(test_config(addr, cert_der)).expect("client"));

    // Status callback: Disconnected arrives before connect(), then Connected.
    let events = Arc::new(Mutex::new(Vec::new()));
    client.set_status_callback(Some(Box::new(Collector { events: Arc::clone(&events) })));
    assert_eq!(*events.lock().expect("buffer"), vec![ConnectionStatus::Disconnected]);

    client.connect().expect("engine start");

    // Handshake done, the server MTU reached the state.
    let state = wait_state(&client, |s| matches!(s, TunnelState::Connected { .. }), 5).await;
    assert!(
        matches!(state, TunnelState::Connected { mtu: 1280, .. }),
        "unexpected state: {state:?}"
    );
    assert_eq!(client.negotiated_mtu(), Some(1280));
    assert_eq!(client.negotiated_vip(), Some("10.66.0.2".to_owned()));

    // Callbacks: exactly one Connected with the server parameters.
    wait_status(&events, |e| {
        matches!(
            e.last(),
            Some(ConnectionStatus::Connected { mtu: 1280, vip }) if vip == "10.66.0.2"
        )
    }, 5).await;

    // Packet exchange through the poll model; recv runs on a side thread the
    // way the platform code will do it.
    let packet = vec![0x45, 0x00, 0x00, 0x08, 0xAA, 0xBB];
    assert!(client.send_packet(packet.clone()), "the queue must not be full");
    let (tx, rx) = tokio::sync::oneshot::channel();
    let recv_client = Arc::clone(&client);
    std::thread::spawn(move || {
        let _ = tx.send(recv_client.recv_packet(3000));
    });
    let echoed = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("the receive thread did not hang")
        .expect("recv_packet did not fail")
        .expect("no echo arrived");
    assert_eq!(echoed, packet, "the echo must return the packet byte for byte");

    // Telemetry: traffic and ping (the server answered the first ping, 1s interval).
    let deadline = Instant::now() + Duration::from_secs(4);
    let telemetry = loop {
        let telemetry = client.get_telemetry();
        if telemetry.ping_ms.is_some() {
            break telemetry;
        }
        assert!(Instant::now() < deadline, "ping not measured within 4s");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(
        telemetry.bytes_sent >= packet.len() as u64,
        "telemetry: {telemetry:?}"
    );
    assert!(
        telemetry.bytes_received >= packet.len() as u64,
        "telemetry: {telemetry:?}"
    );
    assert!(telemetry.ping_ms.is_some(), "telemetry: {telemetry:?}");

    // Stop: the engine reaches Stopped, the callback sees Disconnected.
    client.disconnect();
    wait_state(&client, |s| matches!(s, TunnelState::Stopped), 5).await;
    wait_status(&events, |e| {
        matches!(e.last(), Some(ConnectionStatus::Disconnected))
    }, 5).await;
}

#[tokio::test]
async fn invalid_token_stops_engine_without_retries() {
    init_logs();
    let (addr, cert_der) = spawn_server(ServerMode::RejectAll).await;
    let client = TunnelClient::new(test_config(addr, cert_der)).expect("client");
    client.connect().expect("engine start");

    // AuthRejected is a permanent error: straight to Stopped, no retries.
    wait_state(&client, |s| matches!(s, TunnelState::Stopped), 5).await;

    // A repeated connect does not revive the engine after a permanent error.
    client.connect().expect("connect is idempotent");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        client.state(),
        TunnelState::Stopped,
        "there must be no retries after a rejected token"
    );
}
