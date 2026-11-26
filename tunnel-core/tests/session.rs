//! Интеграционный тест полного стека `tunnel-core`: локальный QUIC-сервер
//! («эхо» + валидный control plane) против реального движка с FFI-обёрткой.
//!
//! Проверяются: рукопожатие с токеном и выдача MTU, обмен пакетами через
//! `send_packet`/`recv_packet`, телеметрия с RTT, коллбэк статуса
//! (`Disconnected → Connected → Disconnected`), остановка, а также сценарий
//! отклонённого токена (движок обязан перейти в `Stopped` без ретраев).

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

/// Инициализация логов: движок логирует через tracing, в тестах нужен
/// subscriber — иначе диагностика отказов глотается молча.
static LOGS: std::sync::Once = std::sync::Once::new();
fn init_logs() {
    LOGS.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
            .with_test_writer()
            .try_init();
    });
}

/// Поведение тестового сервера.
#[derive(Clone, Copy)]
enum ServerMode {
    /// Валидный сервер: `Welcome`, `Pong` на ping, эхо дейтаграмм data plane.
    Echo,
    /// Всегда `Reject{InvalidToken}` — проверка permanent-остановки движка.
    RejectAll,
}

/// Поднимает локальный QUIC-сервер с самоподписанным сертификатом.
/// Возвращает адрес и DER сертификата (он же — pinned root клиента).
async fn spawn_server(mode: ServerMode) -> (SocketAddr, Vec<u8>) {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_owned()]).expect("самоподписанный сертификат");
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("дефолтные версии TLS")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("сертификат и ключ");
    tls.alpn_protocols = vec![ALPN_TUNNEL_V1.to_vec()];

    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("QUIC поверх TLS"),
    ));
    let endpoint = quinn::Endpoint::server(
        server_config,
        "127.0.0.1:0".parse().expect("bind-адрес"),
    )
    .expect("UDP-эндпоинт сервера");
    let addr = endpoint.local_addr().expect("локальный адрес");
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

/// Читает одно управляющее сообщение (префикс длины + тело bincode).
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

/// Обработка подключения тестовым сервером: рукопожатие, затем control plane
/// (Pong на Ping) и data plane (эхо дейтаграмм как есть — byte-for-byte).
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
                message: format!("токен не найден для {}", hello.1),
            };
            let _ = send.write_all(&encode_control(&ControlFromServer::Reject(reject))).await;
            let _ = send.finish();
            // Дрейн: дать клиенту прочитать Reject до закрытия соединения —
            // иначе CONNECTION_CLOSE обгоняет данные потока (см. сервер).
            let _ = tokio::time::timeout(std::time::Duration::from_millis(200), conn.closed()).await;
            return;
        }
        ServerMode::Echo => {}
    }
    // Токен «test» валиден для Echo-режима (используется в тестах ниже).
    if hello.0 != "test" && hello.0 != "tok" {
        let reject = Reject {
            code: RejectCode::InvalidToken,
            message: "неизвестный токен".to_owned(),
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

    // Две плоскости, пока соединение живо: control и data.
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

/// Конфиг клиента против тестового сервера (быстрые тайм-ауты для тестов).
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

/// Крутится до состояния, удовлетворяющего `predicate`, с общим дедлайном.
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

/// Ждёт, пока последний статус коллбэка удовлетворит `predicate`.
async fn wait_status(events: &Mutex<Vec<ConnectionStatus>>, predicate: impl Fn(&[ConnectionStatus]) -> bool, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if predicate(&events.lock().expect("буфер событий")) {
            return;
        }
        assert!(Instant::now() < deadline, "статус не достигнут за {secs}с");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Тестовый коллбэк: собирает статусы в общий буфер.
struct Collector {
    events: Arc<Mutex<Vec<ConnectionStatus>>>,
}
impl ConnectionStatusCallback for Collector {
    fn on_status_change(&self, status: ConnectionStatus) {
        self.events.lock().expect("буфер событий").push(status);
    }
}

#[tokio::test]
async fn echo_roundtrip_over_full_stack() {
    init_logs();
    let (addr, cert_der) = spawn_server(ServerMode::Echo).await;
    let client = Arc::new(TunnelClient::new(test_config(addr, cert_der)).expect("клиент"));

    // Коллбэк статуса: до connect() приходит Disconnected, затем Connected.
    let events = Arc::new(Mutex::new(Vec::new()));
    client.set_status_callback(Some(Box::new(Collector { events: Arc::clone(&events) })));
    assert_eq!(*events.lock().expect("буфер"), vec![ConnectionStatus::Disconnected]);

    client.connect().expect("старт движка");

    // Рукопожатие завершено, MTU сервера доехал до состояния.
    let state = wait_state(&client, |s| matches!(s, TunnelState::Connected { .. }), 5).await;
    assert!(
        matches!(state, TunnelState::Connected { mtu: 1280, .. }),
        "неожиданный state: {state:?}"
    );
    assert_eq!(client.negotiated_mtu(), Some(1280));
    assert_eq!(client.negotiated_vip(), Some("10.66.0.2".to_owned()));

    // Коллбэки: ровно один Connected с параметрами сервера.
    wait_status(&events, |e| {
        matches!(
            e.last(),
            Some(ConnectionStatus::Connected { mtu: 1280, vip }) if vip == "10.66.0.2"
        )
    }, 5).await;

    // Обмен пакетом через poll-модель; recv вызываем из стороннего потока,
    // как это будет делать платформенный код.
    let packet = vec![0x45, 0x00, 0x00, 0x08, 0xAA, 0xBB];
    assert!(client.send_packet(packet.clone()), "очередь не должна быть полна");
    let (tx, rx) = tokio::sync::oneshot::channel();
    let recv_client = Arc::clone(&client);
    std::thread::spawn(move || {
        let _ = tx.send(recv_client.recv_packet(3000));
    });
    let echoed = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("поток приёма не завис")
        .expect("recv_packet не ошибся")
        .expect("эхо не пришло");
    assert_eq!(echoed, packet, "эхо должно вернуть пакет байт в байт");

    // Телеметрия: трафик и пинг (сервер ответил на первый ping, интервал 1с).
    let deadline = Instant::now() + Duration::from_secs(4);
    let telemetry = loop {
        let telemetry = client.get_telemetry();
        if telemetry.ping_ms.is_some() {
            break telemetry;
        }
        assert!(Instant::now() < deadline, "пинг не измерился за 4с");
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

    // Остановка: движок доходит до Stopped, коллбэк видит Disconnected.
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
    let client = TunnelClient::new(test_config(addr, cert_der)).expect("клиент");
    client.connect().expect("старт движка");

    // AuthRejected — постоянная ошибка: сразу Stopped, без ретраев.
    wait_state(&client, |s| matches!(s, TunnelState::Stopped), 5).await;

    // Повторный connect не поднимает движок после постоянной ошибки.
    client.connect().expect("connect идемпотентен");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        client.state(),
        TunnelState::Stopped,
        "после отклонённого токена ретраев быть не должно"
    );
}
