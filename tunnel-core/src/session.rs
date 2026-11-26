//! Сетевая сессия клиента: одна попытка подключения до разрыва соединения.
//!
//! Поток работы:
//! 1. разрешить адрес сервера (DNS на каждый ретрай — смена IP подхватится);
//! 2. собрать QUIC-конфиг: pinned root + ALPN + keepalive + MTU-discovery;
//! 3. подключиться и рукопожать `Hello → Welcome/Reject` по bi-потоку #0;
//! 4. параллельно вести data plane (QUIC-дейтаграммы ⇄ очереди платформы) и
//!    control plane (ping/pong по потоку #0); оба слушают команду stop.
//!
//! RTT считается по `Pong`: штамп `sent_unix_ms` возвращается сервером
//! без изменений, ядро измеряет разницу с моментом отправки `Ping` и
//! кладёт в `EngineShared::last_ping_ms` (виден партнёру в `get_telemetry`).

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

/// Keepalive по умолчанию, если сервер не задал интервал в `Welcome`, сек.
const DEFAULT_KEEPALIVE_SECS: u32 = 15;
/// Ожидание дрейна CONNECTION_CLOSE перед дропом endpoint, мс.
const CLOSE_DRAIN_MS: u64 = 300;
/// Транспортный QUIC-keepalive: пингуется NAT-таблица между прикладными ping.
const TRANSPORT_KEEPALIVE_SECS: u64 = 10;
/// QUIC idle-тайм-аут: молчащее соединение рвётся и идёт в ретрай, а не
/// зависает до системного TCP-тайм-аута.
const MAX_IDLE_TIMEOUT_SECS: u64 = 30;

/// Итог попытки сессии.
#[derive(Debug)]
pub(crate) enum SessionOutcome {
    /// Движку приказано остановиться (`disconnect()`) — ретрай не нужен.
    Shutdown,
    /// Сессия закрылась сама или не состоялась: `established` = дошло ли до
    /// `Welcome` (влияет на сброс backoff и счётчик reconnects).
    Closed { cause: CoreError, established: bool },
}

/// Пара управляющих потоков, оставшаяся после рукопожатия.
struct ControlStreams {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

/// Чем закончились плоскости сессии.
#[derive(Debug)]
enum PlaneEnd {
    Stopped,
    /// Платформенная очередь отправки закрыта — движок умирает вместе с клиентом.
    InputClosed,
    ConnClosed(String),
}

/// Одна попытка сессии; мгновенно отменяется переходом движка в Stopping.
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

/// Фактическая попытка: DNS → конфиг → connect → рукопожатие → две плоскости.
async fn attempt_session(
    shared: &Arc<EngineShared>,
    packet_in_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> SessionOutcome {
    let config = &shared.config;
    let connect_timeout = Duration::from_millis(u64::from(config.connect_timeout_ms));

    let server_addr = match resolve_server(config).await {
        Ok(addr) => addr,
        Err(cause) => return SessionOutcome::Closed { cause, established: false },
    };
    let client_config = match build_client_config(config) {
        Ok(config) => config,
        Err(cause) => return SessionOutcome::Closed { cause, established: false },
    };
    let mut endpoint = match quinn::Endpoint::client("0.0.0.0:0".parse().expect("любой локальный порт")) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            return SessionOutcome::Closed {
                cause: CoreError::Io(format!("не удалось открыть UDP-эндпоинт: {err}")),
                established: false,
            };
        }
    };
    endpoint.set_default_client_config(client_config);

    let connecting = match endpoint.connect(server_addr, &config.server_name) {
        Ok(connecting) => connecting,
        Err(err) => {
            return SessionOutcome::Closed {
                cause: CoreError::ConnectFailed(format!("QUIC-подключение не началось: {err}")),
                established: false,
            };
        }
    };
    let conn = match tokio::time::timeout(connect_timeout, connecting).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(err)) => {
            return SessionOutcome::Closed {
                cause: CoreError::ConnectFailed(format!("QUIC-рукопожатие TLS: {err}")),
                established: false,
            };
        }
        Err(_) => {
            return SessionOutcome::Closed {
                cause: CoreError::TimedOut(format!(
                    "QUIC-подключение к {server_addr} за {}мс не состоялось",
                    config.connect_timeout_ms
                )),
                established: false,
            };
        }
    };

    // Рукопожатие по bi-потоку #0: Hello → Welcome/Reject.
    let handshake = async {
        let (streams, welcome) = handshake(&conn, config).await?;
        Ok::<(ControlStreams, Welcome), CoreError>((streams, welcome))
    };
    let (control, welcome) = match tokio::time::timeout(connect_timeout, handshake).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(cause)) => return SessionOutcome::Closed { cause, established: false },
        Err(_) => {
            return SessionOutcome::Closed {
                cause: CoreError::TimedOut("рукопожатие протокола не завершилось".to_owned()),
                established: false,
            };
        }
    };

    // Сессия установлена: публикуем состояние и параметры платформе.
    tracing::info!(vip = %welcome.vip, mtu = welcome.mtu, "сессия установлена");
    shared.metrics.record_session_established();
    shared.reset_ping();
    shared.set_active_conn(Some(conn.clone()));
    shared.set_state(TunnelState::Connected {
        mtu: welcome.mtu,
        vip: welcome.vip.to_string(),
    });

    if conn.max_datagram_size().is_none() {
        // Data plane без дейтаграмм бесполезен: сервер выключил DATAGRAM.
        conn.close(quinn::VarInt::from_u32(1), b"no-datagrams");
        return SessionOutcome::Closed {
            cause: CoreError::SessionClosed("сервер не поддерживает QUIC-дейтаграммы".to_owned()),
            established: true,
        };
    }

    // Две плоскости до разрыва: control (ping/pong) и data (дейтаграммы).
    // Отдельные клоны: нельзя два &mut на один watch-приёмник в select.
    let mut stop_for_wait = shared.state_rx.clone();
    let mut stop_for_control = shared.state_rx.clone();
    let end = tokio::select! {
        biased;
        _ = wait_stopping(&mut stop_for_wait) => PlaneEnd::Stopped,
        end = control_loop(control, welcome.keepalive_interval_secs, shared, &mut stop_for_control) => end,
        end = data_loop(&conn, &welcome, shared, packet_in_rx) => end,
    };

    // Корректное закрытие: даём CONNECTION_CLOSE уйти в сеть перед дропом.
    conn.close(quinn::VarInt::from_u32(0), b"session-closed");
    let _ = tokio::time::timeout(Duration::from_millis(CLOSE_DRAIN_MS), conn.closed()).await;

    match end {
        PlaneEnd::Stopped => SessionOutcome::Shutdown,
        PlaneEnd::InputClosed => SessionOutcome::Closed {
            cause: CoreError::SessionClosed("входная очередь платформы закрыта".to_owned()),
            established: true,
        },
        PlaneEnd::ConnClosed(reason) => SessionOutcome::Closed {
            cause: CoreError::SessionClosed(reason),
            established: true,
        },
    }
}

/// Разрешает адрес сервера; DNS ходит на каждую попытку — переезд сервера на
/// другой IP подхватывается без пересоздания клиента.
async fn resolve_server(config: &TunnelConfig) -> Result<SocketAddr, CoreError> {
    let host = config.server_host.trim();
    tokio::net::lookup_host((host, config.server_port))
        .await
        .map_err(|err| CoreError::ConnectFailed(format!("DNS для «{host}»: {err}")))?
        .next()
        .ok_or_else(|| CoreError::ConnectFailed(format!("DNS для «{host}» не вернул адресов")))
}

/// Собирает QUIC-конфиг: pinned root — единственный доверенный корень TLS.
fn build_client_config(config: &TunnelConfig) -> Result<quinn::ClientConfig, CoreError> {
    let server_cert = CertificateDer::from(config.pinned_server_cert_der.clone());
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(server_cert)
        .map_err(|err| CoreError::InvalidServerCert(format!("DER не принят: {err}")))?;

    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|err| CoreError::Internal(format!("профили TLS недоступны: {err}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN_TUNNEL_V1.to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(TRANSPORT_KEEPALIVE_SECS)));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(MAX_IDLE_TIMEOUT_SECS))
            .expect("30с укладываются в VarInt"),
    ));
    // MTU-discovery: на путях с большой MTU дейтаграммы пакуются плотнее.
    transport.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));

    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|err| CoreError::Internal(format!("QUIC поверх TLS не собрался: {err}")))?;
    let mut client = quinn::ClientConfig::new(Arc::new(quic));
    client.transport_config(Arc::new(transport));
    Ok(client)
}

/// Рукопожатие протокола: Hello → Welcome/Reject по потоку #0.
async fn handshake(
    conn: &quinn::Connection,
    config: &TunnelConfig,
) -> Result<(ControlStreams, Welcome), CoreError> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|err| CoreError::ConnectFailed(format!("bi-поток не открылся: {err}")))?;
    let hello = ControlFromClient::Hello(Hello {
        protocol_version: PROTOCOL_VERSION,
        client_id: config.client_id.clone(),
        auth_token: config.auth_token.clone(),
    });
    send.write_all(&encode_control(&hello))
        .await
        .map_err(|err| CoreError::ConnectFailed(format!("Hello не ушёл: {err}")))?;

    let message = read_control_message(&mut recv).await?;
    match decode_control::<ControlFromServer>(&message) {
        Ok(Some((ControlFromServer::Welcome(welcome), _))) => {
            if welcome.mtu == 0 {
                return Err(CoreError::ProtocolMismatch(format!(
                    "сервер выдал MTU {} — отклоняю",
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
            "ожидали Welcome/Reject, получили {other:?}"
        ))),
        Ok(None) => Err(CoreError::ProtocolMismatch(
            "сервер прислал обрезанное сообщение рукопожатия".to_owned(),
        )),
        Err(err) => Err(CoreError::ProtocolMismatch(format!(
            "ответ сервера не читается: {err}"
        ))),
    }
}

/// Читает полный кадр управления (префикс длины + тело).
async fn read_control_message(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, CoreError> {
    let mut prefix = [0u8; 4];
    recv.read_exact(&mut prefix)
        .await
        .map_err(|err| CoreError::SessionClosed(format!("поток управления закрыт: {err}")))?;
    let len = u32::from_le_bytes(prefix) as usize;
    if len > MAX_CONTROL_MESSAGE_SIZE {
        return Err(CoreError::SessionClosed(format!(
            "сообщение {len} байт сверх лимита {MAX_CONTROL_MESSAGE_SIZE}"
        )));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .map_err(|err| CoreError::SessionClosed(format!("тело сообщения оборвано: {err}")))?;
    let mut full = prefix.to_vec();
    full.extend_from_slice(&body);
    Ok(full)
}

/// Control plane: ping с телеметрией RTT по потоку #0.
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
                        // RTT = время от отправки ping до получения pong.
                        // Sub-миллисекундные значения хранятся как 0 и
                        // скрываются телеметрией (None = не измерялся).
                        let rtt = unix_ms().saturating_sub(sent_unix_ms).clamp(1, u32::MAX as u64);
                        shared.last_ping_ms.store(rtt, Ordering::Relaxed);
                        tracing::debug!(seq = echoed, rtt_ms = rtt, "pong");
                    }
                    Ok(Some((ControlFromServer::Reject(Reject { code, message }), _))) => {
                        return PlaneEnd::ConnClosed(format!(
                            "сервер отклонил сессию ({code:?}): {message}"
                        ));
                    }
                    Ok(Some((other, _))) => {
                        tracing::debug!(?other, "неожиданное управляющее сообщение");
                    }
                    Ok(None) => return PlaneEnd::ConnClosed("обрезанное сообщение".to_owned()),
                    Err(err) => return PlaneEnd::ConnClosed(format!("битое сообщение: {err}")),
                },
                Err(err) => return PlaneEnd::ConnClosed(err.to_string()),
            },
            _ = ticker.tick() => {
                let ping = ControlFromClient::Ping(Ping { seq, sent_unix_ms: unix_ms() });
                if let Err(err) = send.write_all(&encode_control(&ping)).await {
                    return PlaneEnd::ConnClosed(format!("ping не ушёл: {err}"));
                }
                seq = seq.wrapping_add(1);
            }
        }
    }
}

/// Data plane: QUIC-дейтаграммы ⇄ очереди платформы, переподключений не видно.
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
            // Платформа → туннель: IP-пакет → кадр → дейтаграмма.
            inbound = packet_in_rx.recv() => match inbound {
                Some(packet) => {
                    if packet.len() > mtu {
                        shared.metrics.record_packets_dropped(1);
                        tracing::debug!(len = packet.len(), mtu, "пакет длиннее MTU — дроп");
                        continue;
                    }
                    match conn.send_datagram(Bytes::from(encode_frame(KIND_IPV4, &packet))) {
                        Ok(()) => {
                            shared.metrics.record_datagram_sent();
                            shared.metrics.record_bytes_sent(packet.len() as u64);
                        }
                        Err(quinn::SendDatagramError::TooLarge) => {
                            shared.metrics.record_packets_dropped(1);
                            tracing::debug!(len = packet.len(), "дейтаграмма слишком велика — дроп");
                        }
                        Err(quinn::SendDatagramError::ConnectionLost(err)) => {
                            return PlaneEnd::ConnClosed(format!("соединение потеряно: {err}"));
                        }
                        Err(err) => {
                            shared.metrics.record_packets_dropped(1);
                            tracing::debug!(%err, "дейтаграмма не ушла — дроп");
                        }
                    }
                }
                // FFI-объект мёртв: движку нет смысла жить.
                None => return PlaneEnd::InputClosed,
            },
            // Туннель → платформа: дейтаграмма → кадр → пакет.
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
                            // Очередь платформы полна: семантика UDP — дроп.
                            Err(_) => shared.metrics.record_packets_dropped(1),
                        }
                    }
                    Ok(frame) => {
                        // IPv6 и прочие виды: маршрут не настроен — дроп.
                        tracing::debug!(kind = frame.kind, "кадр без маршрута — дроп");
                        shared.metrics.record_packets_dropped(1);
                    }
                    Err(err) => {
                        tracing::debug!(%err, "битая дейтаграмма — дроп");
                        shared.metrics.record_packets_dropped(1);
                    }
                },
                Err(err) => return PlaneEnd::ConnClosed(format!("чтение дейтаграмм: {err}")),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_proto::WirePacket;

    #[test]
    fn keepalive_default_applied_when_hint_is_zero() {
        // Хинт 0 → DEFAULT_KEEPALIVE_SECS; логика спрятана в control_loop,
        // здесь проверяем константы, на которые полагается сервер.
        assert_eq!(DEFAULT_KEEPALIVE_SECS, 15);
        assert_eq!(MAX_CONTROL_MESSAGE_SIZE, 16 * 1024);
        assert_eq!(CLOSE_DRAIN_MS, 300);
    }

    #[test]
    fn wire_packet_roundtrip_matches_frame_format() {
        // Кадр [kind][payload] и WirePacket несут одно и то же.
        let packet = vec![0x45u8, 0, 0, 8, 1, 2, 3, 4];
        let framed = encode_frame(KIND_IPV4, &packet);
        let wire = WirePacket { kind: KIND_IPV4, payload: packet };
        assert_eq!(framed[0], wire.kind);
        assert_eq!(&framed[1..], &wire.payload[..]);
    }
}
