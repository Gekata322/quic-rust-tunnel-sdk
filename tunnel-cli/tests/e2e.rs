//! E2E: the production `tunnel-server` (loopback mode) plus two
//! `tunnel-cli` stacks — the full SOCKS5 path without root.
//!
//! Covered:
//! 1. `socks5_proxy_carries_tcp_through_the_tunnel` — client A runs the
//!    SOCKS5 proxy, client B is the "internet" with a TCP listener; a local
//!    SOCKS5 client CONNECTs to B's VIP and exchanges 64 KiB with the echo
//!    server. The traffic path: local app → SOCKS5 → smoltcp (A) → QUIC
//!    datagrams → tunnel-server → QUIC datagrams → smoltcp (B) → TCP echo.
//! 2. `connect_to_a_dead_port_yields_a_socks5_error` — a CONNECT to a port
//!    nothing listens on comes back as SOCKS5 reply 0x05.
//! 3. `rejected_token_leaves_the_proxy_offline` — a client with a wrong
//!    token is stopped by the server; a CONNECT during the outage gets
//!    reply 0x03 and never reaches the stack.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing_subscriber::EnvFilter;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tunnel_cli::socks5;
use tunnel_cli::stack::Stack;
use tunnel_core::ffi::TunnelState;
use tunnel_core::{TunnelClient, TunnelConfig};
use tunnel_proto::auth::TokenStore;
use tunnel_server::config::{ServerConfig, TokensSource};
use tunnel_server::endpoint::{accept_loop, build_endpoint, generate_certificate};
use tunnel_server::session::ServerShared;

/// Initializes test logging once per process (RUST_LOG controls the level).
fn init_logging() {
    // The closure runs many times; only the first subscriber wins.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug,tunnel_server=debug,tunnel_core=debug,quinn=warn")))
        .with_target(true)
        .try_init();
}

/// A running test server (loopback mode, no TUN — CI has no CAP_NET_ADMIN).
struct TestServer {
    addr: SocketAddr,
    cert_der: Vec<u8>,
    /// Kept alive so accept_loop does not see a closed stop channel.
    _shutdown_tx: watch::Sender<bool>,
}

/// Starts a server on 127.0.0.1:0 with the given `(client_id, token)` pairs.
async fn start_server(tokens: Vec<(String, String)>) -> TestServer {
    let config = ServerConfig {
        listen: "127.0.0.1:0".parse().expect("address"),
        pool: "10.66.0.0/29".to_owned(),
        mtu: 1280,
        keepalive_interval_secs: 1,
        dns_servers: vec![],
        tun_name: None,
        server_name: "localhost".to_owned(),
        // The store is passed directly; the source in the config is unused.
        tokens: TokensSource::Inline(Vec::new()),
        admin: None,
    };
    let cert = generate_certificate("localhost").expect("certificate");
    let cert_der = cert.der.as_ref().to_vec();
    let endpoint = build_endpoint(&cert, config.listen).expect("endpoint");
    let addr = endpoint.local_addr().expect("local address");
    let shared = ServerShared::new(&config, TokenStore::from_pairs(tokens), None).expect("server state");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(accept_loop(Arc::clone(&shared), endpoint, shutdown_rx));
    TestServer {
        addr,
        cert_der,
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

/// Polls until `predicate` holds, with a deadline.
async fn wait_until(predicate: impl Fn() -> bool, secs: u64, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !predicate() {
        assert!(Instant::now() < deadline, "not reached within {secs}s: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Boots a tunnel client and waits for the first session.
async fn bring_up_client(server: &TestServer, token: &str, client_id: &str) -> Arc<TunnelClient> {
    let client = Arc::new(
        TunnelClient::new(client_config(server, token, client_id)).expect("client"),
    );
    client.connect().expect("connect");
    wait_until(
        || matches!(client.state(), TunnelState::Connected { .. }),
        10,
        "the client establishes a session",
    )
    .await;
    client
}

/// Runs the SOCKS5 proxy for one client; returns the listener address.
/// The watch senders stay with the caller: dropping the shutdown sender
/// would stop the proxy immediately.
async fn run_proxy(stack: Stack, connected_rx: watch::Receiver<bool>, shutdown_rx: watch::Receiver<bool>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("SOCKS5 listener");
    let addr = listener.local_addr().expect("listener address");
    tokio::spawn(socks5::serve(listener, stack, connected_rx, shutdown_rx));
    addr
}

/// The SOCKS5 gate: the tunnel is up (true) or down (false).
fn gate(up: bool) -> (watch::Sender<bool>, watch::Receiver<bool>) {
    watch::channel(up)
}

/// The SOCKS5 handshake: greeting → CONNECT `target:port` → reply code.
async fn socks_connect(
    addr: SocketAddr,
    target: Ipv4Addr,
    port: u16,
) -> (TcpStream, u8) {
    let mut stream = TcpStream::connect(addr).await.expect("SOCKS5 reachable");
    stream.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.expect("method reply");
    assert_eq!(method, [5, 0], "the proxy must accept no-auth");
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.octets());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await.expect("request");
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.expect("CONNECT reply");
    (stream, reply[1])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn socks5_proxy_carries_tcp_through_the_tunnel() {
    init_logging();
    let server = start_server(vec![
        ("proxy".to_owned(), "tok-proxy".to_owned()),
        ("far".to_owned(), "tok-far".to_owned()),
    ])
    .await;

    // The far end: a client with a TCP listener that echoes everything.
    let far_client = bring_up_client(&server, "tok-far", "far").await;
    let far_vip: Ipv4Addr = far_client
        .negotiated_vip()
        .expect("the far end got a VIP")
        .parse()
        .expect("VIP parse");
    let far_stack = Stack::spawn(Arc::clone(&far_client)).expect("far stack");
    let mut incoming = far_stack.listen(9001).await.expect("tunnel-side listener");
    tokio::spawn(async move {
        while let Some(mut session) = incoming.recv().await {
            tokio::spawn(async move {
                while let Some(chunk) = session.recv().await {
                    if session.send(chunk).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // The proxy: client A with the full SOCKS5 front-end.
    let proxy_client = bring_up_client(&server, "tok-proxy", "proxy").await;
    let proxy_stack = Stack::spawn(Arc::clone(&proxy_client)).expect("proxy stack");
    let (_gate_tx, gate_rx) = gate(true);
    let (shutdown_tx, shutdown_rx) = gate(false);
    let socks_addr = run_proxy(proxy_stack.clone(), gate_rx, shutdown_rx).await;

    // A local SOCKS5 client CONNECTs to the far end through the proxy.
    let (mut stream, code) = socks_connect(socks_addr, far_vip, 9001).await;
    assert_eq!(code, 0, "CONNECT to a live listener must succeed");
    assert_eq!(proxy_stack.live_sessions(), 1, "one live session on the proxy");

    // 64 KiB of pseudo-random payload, 4 KiB chunks — every byte must come
    // back through: SOCKS5 → stack A → tunnel → server → stack B → echo →
    // stack B → tunnel → server → stack A → SOCKS5.
    let payload: Vec<u8> = (0..64 * 1024u32).map(|i| (i.wrapping_mul(31) ^ 0x5A) as u8).collect();
    let mut received = Vec::with_capacity(payload.len());
    let mut sent = 0usize;
    let mut buffer = vec![0u8; 8 * 1024];
    while received.len() < payload.len() {
        if sent < payload.len() {
            let end = (sent + 4 * 1024).min(payload.len());
            stream
                .write_all(&payload[sent..end])
                .await
                .expect("write through the tunnel");
            sent = end;
        }
        let n = stream.read(&mut buffer).await.expect("read through the tunnel");
        assert!(n > 0, "the echo closed the connection early");
        received.extend_from_slice(&buffer[..n]);
    }
    assert_eq!(received, payload, "the echo must return every byte");

    // Dropping the client side tears the session down on both ends. The
    // closer ends up in TCP TIME_WAIT, which smoltcp bounds at 10 s.
    drop(stream);
    wait_until(
        || proxy_stack.live_sessions() == 0,
        14,
        "the session is reaped after the client leaves",
    )
    .await;

    let _ = shutdown_tx.send(true);
    proxy_client.disconnect();
    far_client.disconnect();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_to_a_dead_port_yields_a_socks5_error() {
    init_logging();
    let server = start_server(vec![
        ("proxy".to_owned(), "tok-proxy".to_owned()),
        ("far".to_owned(), "tok-far".to_owned()),
    ])
    .await;

    // The far end is alive (so the server routes to it) but listens on
    // nothing — its stack answers SYN with RST.
    let far_client = bring_up_client(&server, "tok-far", "far").await;
    let far_vip: Ipv4Addr = far_client
        .negotiated_vip()
        .expect("the far end got a VIP")
        .parse()
        .expect("VIP parse");
    Stack::spawn(Arc::clone(&far_client)).expect("far stack");

    let proxy_client = bring_up_client(&server, "tok-proxy", "proxy").await;
    let proxy_stack = Stack::spawn(Arc::clone(&proxy_client)).expect("proxy stack");
    let (_gate_tx, gate_rx) = gate(true);
    let (shutdown_tx, shutdown_rx) = gate(false);
    let socks_addr = run_proxy(proxy_stack, gate_rx, shutdown_rx).await;

    let (_stream, code) = socks_connect(socks_addr, far_vip, 9999).await;
    assert_eq!(code, 5, "a dead port must surface as SOCKS5 reply 0x05");

    let _ = shutdown_tx.send(true);
    proxy_client.disconnect();
    far_client.disconnect();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejected_token_leaves_the_proxy_offline() {
    init_logging();
    let server = start_server(vec![("other".to_owned(), "tok-other".to_owned())]).await;

    // A client with a wrong token: the server rejects it permanently.
    let client = Arc::new(
        TunnelClient::new(client_config(&server, "wrong-token", "impostor")).expect("client"),
    );
    client.connect().expect("connect");
    // The stack is spawned before the tunnel is up (safe by contract).
    let stack = Stack::spawn(Arc::clone(&client)).expect("stack");

    // The gate says "down": CONNECT requests must get 0x03 without
    // reaching the stack.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("SOCKS5 listener");
    let socks_addr = listener.local_addr().expect("listener address");
    let (_connected_tx, connected_rx) = watch::channel(false);
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(socks5::serve(listener, stack, connected_rx, shutdown_rx));

    let (stream, code) = socks_connect(socks_addr, Ipv4Addr::new(10, 66, 0, 9), 80).await;
    assert_eq!(code, 3, "an offline tunnel must surface as SOCKS5 reply 0x03");
    drop(stream);

    // The wrong token is a permanent error: the engine stops instead of
    // retrying forever.
    wait_until(
        || client.state() == TunnelState::Stopped,
        10,
        "the wrong token stops the engine",
    )
    .await;
    client.disconnect();
}
