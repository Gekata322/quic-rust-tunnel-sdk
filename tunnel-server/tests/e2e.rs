//! E2E-тест: боевой сервер `tunnel-server` (loopback-режим, без TUN) против
//! реального клиентского ядра `tunnel-core`.
//!
//! Проверяется полный продовый путь «покупателя» библиотеки: клиент
//! подключается по токену с pinned-сертификатом сервера, получает виртуальный
//! адрес, шлёт IP-пакет на адрес сервера — сервер отвечает эхом с обменом
//! адресов; параллельные клиенты получают разные адреса; неверный токен
//! отклоняется без ретраев.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{oneshot, watch};
use tunnel_core::ffi::TunnelState;
use tunnel_core::{TunnelClient, TunnelConfig};
use tunnel_server::config::{ServerConfig, TokensSource};
use tunnel_server::endpoint::{accept_loop, build_endpoint, generate_certificate};
use tunnel_server::session::ServerShared;

/// Поднятый тестовый сервер.
struct TestServer {
    addr: SocketAddr,
    cert_der: Vec<u8>,
    shared: Arc<ServerShared>,
    /// Держится живым, чтобы accept_loop не увидел закрытый канал остановки.
    _shutdown_tx: watch::Sender<bool>,
}

/// Поднимает сервер на 127.0.0.1:0 в loopback-режиме (TUN недоступен в CI).
async fn start_server(tokens: Vec<(String, String)>) -> TestServer {
    let config = ServerConfig {
        listen: "127.0.0.1:0".parse().expect("адрес"),
        pool: "10.66.0.0/24".to_owned(),
        mtu: 1280,
        keepalive_interval_secs: 1,
        dns_servers: vec![],
        tun_name: None,
        server_name: "localhost".to_owned(),
        tokens: TokensSource::Inline(tokens),
    };
    let cert = generate_certificate("localhost").expect("сертификат");
    let cert_der = cert.der.as_ref().to_vec();
    let endpoint = build_endpoint(&cert, config.listen).expect("эндпоинт");
    let addr = endpoint.local_addr().expect("локальный адрес");
    let shared = ServerShared::new(&config, config.load_tokens().expect("токены"), None)
        .expect("состояние сервера");

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

/// Крутится до состояния, удовлетворяющего `predicate`, с дедлайном.
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
            "состояние не достигнуто за {secs}с, текущее: {state:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Минимальный IPv4-пакет (checksum не важен — сервер его не проверяет).
fn build_ipv4(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0x45, 0x00, 0x00, 0x00, 0, 1, 0x40, 0x00, 64, 17, 0, 0];
    pkt[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(&src);
    pkt.extend_from_slice(&dst);
    pkt.extend_from_slice(payload);
    pkt
}

/// Разбирает `negotiated_vip()` («a.b.c.d») в байты адреса.
fn parse_vip(text: &str) -> [u8; 4] {
    let octets: Vec<u8> = text
        .split('.')
        .map(|part| part.parse().expect("vip состоит из четырёх октетов"))
        .collect();
    let octets: [u8; 4] = octets.try_into().expect("vip ровно из 4 октетов");
    octets
}

/// Отправляет пакет через клиент и ждёт ответ в отдельном потоке
/// (как будет делать платформенный код поверх FFI).
async fn echo_roundtrip(
    client: &Arc<TunnelClient>,
    server: Option<&TestServer>,
    packet: Vec<u8>,
) -> Vec<u8> {
    assert!(client.send_packet(packet.clone()), "очередь не должна быть полна");
    let (tx, rx) = oneshot::channel();
    let recv_client = Arc::clone(client);
    std::thread::spawn(move || {
        let _ = tx.send(recv_client.recv_packet(3000));
    });
    match tokio::time::timeout(Duration::from_secs(5), rx).await {
        Ok(Ok(Some(echoed))) => echoed,
        other => {
            if let Some(server) = server {
                println!("echo miss: сервер metrics = {:?}", server.shared.metrics.snapshot());
            }
            println!("echo miss: клиент telemetry = {:?}", client.get_telemetry());
            println!("echo miss: клиент state = {:?}", client.state());
            panic!("эхо не вернулось: {other:?}");
        }
    }
}

#[tokio::test]
async fn client_echo_via_server_vip() {
    let server = start_server(vec![("e2e-client".to_owned(), "e2e-token".to_owned())]).await;
    let client = Arc::new(
        TunnelClient::new(client_config(&server, "e2e-token", "e2e-client")).expect("клиент"),
    );
    client.connect().expect("старт движка");

    let state = wait_state(&client, |s| matches!(s, TunnelState::Connected { .. }), 5).await;
    assert!(
        matches!(state, TunnelState::Connected { mtu: 1280, .. }),
        "неожиданный state: {state:?}"
    );
    assert_eq!(client.negotiated_mtu(), Some(1280));

    // Единственный клиент пула всегда получает первый адрес .2.
    let vip = parse_vip(&client.negotiated_vip().expect("vip выдан сервером"));
    assert_eq!(vip, [10, 66, 0, 2]);

    let server_vip = server.shared.server_vip.octets();
    let packet = build_ipv4(vip, server_vip, &[0xDE, 0xAD]);
    let echoed = echo_roundtrip(&client, Some(&server), packet).await;

    assert_eq!(&echoed[12..16], &server_vip, "src заменён на адрес сервера");
    assert_eq!(&echoed[16..20], &vip, "dst заменён на адрес клиента");
    assert_eq!(&echoed[20..], &[0xDE, 0xAD], "payload не тронут");
    assert_eq!(server.shared.metrics.snapshot().bytes_received, 22);

    client.disconnect();
    wait_state(&client, |s| matches!(s, TunnelState::Stopped), 5).await;
}

#[tokio::test]
async fn two_clients_get_distinct_addresses() {
    let server = start_server(vec![
        ("client-a".to_owned(), "multi-token".to_owned()),
        ("client-b".to_owned(), "multi-token".to_owned()),
    ]).await;
    let client_a = Arc::new(
        TunnelClient::new(client_config(&server, "multi-token", "client-a")).expect("клиент A"),
    );
    let client_b = Arc::new(
        TunnelClient::new(client_config(&server, "multi-token", "client-b")).expect("клиент B"),
    );
    client_a.connect().expect("старт A");
    wait_state(&client_a, |s| matches!(s, TunnelState::Connected { .. }), 5).await;
    client_b.connect().expect("старт B");
    wait_state(&client_b, |s| matches!(s, TunnelState::Connected { .. }), 5).await;

    // Адреса берём из состояния клиентов (кто подключился первым — неважно):
    // платформа в реальности тоже настраивает TUN по negotiated_vip.
    let vip_a = parse_vip(&client_a.negotiated_vip().expect("vip A"));
    let vip_b = parse_vip(&client_b.negotiated_vip().expect("vip B"));
    assert_ne!(vip_a, vip_b, "пул обязан выдать клиентам разные адреса");
    assert!(vip_a == [10, 66, 0, 2] || vip_a == [10, 66, 0, 3]);
    assert!(vip_b == [10, 66, 0, 2] || vip_b == [10, 66, 0, 3]);

    let server_vip = server.shared.server_vip.octets();
    let packet_a = build_ipv4(vip_a, server_vip, b"AAA");
    let packet_b = build_ipv4(vip_b, server_vip, b"BBB");
    let (echoed_a, echoed_b) = tokio::join!(
        echo_roundtrip(&client_a, Some(&server), packet_a),
        echo_roundtrip(&client_b, Some(&server), packet_b)
    );

    assert_eq!(&echoed_a[16..20], &vip_a, "эхо адресовано клиенту A");
    assert_eq!(&echoed_a[20..], b"AAA");
    assert_eq!(&echoed_b[16..20], &vip_b, "эхо адресовано клиенту B");
    assert_eq!(&echoed_b[20..], b"BBB");

    let snap = server.shared.metrics.snapshot();
    assert_eq!(snap.sessions_established, 2);
    assert!(snap.bytes_received >= 23 + 23, "телеметрия обоих клиентов: {snap:?}");

    client_a.disconnect();
    client_b.disconnect();
}

#[tokio::test]
async fn unknown_token_is_rejected_without_session() {
    let server = start_server(vec![("known-client".to_owned(), "known-token".to_owned())]).await;
    let client = TunnelClient::new(client_config(&server, "wrong-token", "known-client"))
        .expect("клиент");
    client.connect().expect("старт движка");

    wait_state(&client, |s| matches!(s, TunnelState::Stopped), 5).await;

    let snap = server.shared.metrics.snapshot();
    assert_eq!(snap.sessions_established, 0, "сессия не должна была открыться");
}
