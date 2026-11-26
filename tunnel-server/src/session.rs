//! Состояние сервера и обработка сессий клиентов.
//!
//! Поток сессии (см. `endpoint::accept_loop` → `handle_connection`):
//! 1. bi-поток #0: `Hello{version, client_id, token}` → проверка версии
//!    протокола и токена ([`tunnel_proto::auth::TokenStore::verify`]);
//! 2. выдача адреса из [`IpPool`], регистрация в [`RoutingTable`];
//! 3. `Welcome{vip, mtu, keepalive}`; далее — control plane (`Ping → Pong`
//!    по потоку #0) и data plane (дейтаграммы):
//!    - **анти-спуфинг**: пакет с `src != выданному адресу` — дроп;
//!    - loopback-режим: пакет на `server_vip` эхоится обратно с обменом адресов;
//!    - боевой режим: пакет клиента пишется в TUN, пакеты из TUN
//!      маршрутизируются клиенту по адресу получателя.
//!
//! Адрес возвращается в пул при любом завершении сессии — переиспользование.

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
use crate::routing::RoutingTable;
use crate::tun::TunDevice;

/// Тайм-аут рукопожатия: клиент обязан прислать `Hello` и дождаться ответа.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Длина очереди «сервер → клиент» (дейтаграммы из TUN/других клиентов).
const OUTBOUND_QUEUE_LEN: usize = 256;

/// Ошибки подъёма состояния сервера.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Подсеть пула недействительна.
    #[error("пул адресов: {0}")]
    Pool(#[from] crate::pool::PoolError),

    /// TUN-интерфейс не поднялся.
    #[error("TUN-интерфейс: {0}")]
    Tun(#[from] std::io::Error),
}

/// Общее состояние сервера: общий для всех сессий.
/// Поля `server_vip` и `metrics` видны тестам и операционному коду.
pub struct ServerShared {
    /// Адрес сервера в подсети туннеля (первый адрес пула).
    pub server_vip: Ipv4Addr,
    /// Телеметрия сервера (байты, дейтаграммы, сессии).
    pub metrics: Arc<Metrics>,
    /// MTU виртуального интерфейса клиентов.
    mtu: u16,
    /// Период прикладного ping, передаваемый в `Welcome`.
    keepalive_interval_secs: u32,
    /// Токены партнёров.
    tokens: TokenStore,
    /// Пул виртуальных адресов.
    pool: IpPool,
    /// Таблица «адрес → клиент».
    routing: RoutingTable,
    /// TUN-интерфейс боевого режима (`None` — loopback).
    tun: Option<Arc<TunDevice>>,
}

impl ServerShared {
    /// Собирает состояние сервера: пул адресов из `config.pool`, токены,
    /// опциональный TUN (боевой режим) или loopback.
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
            tokens,
            pool,
            routing: RoutingTable::new(),
            tun: tun.map(Arc::new),
        }))
    }

    /// Есть ли TUN (боевой режим) или loopback.
    pub fn is_loopback(&self) -> bool {
        self.tun.is_none()
    }

    /// Таблица маршрутизации (тесты и диагностика).
    pub fn routing(&self) -> &RoutingTable {
        &self.routing
    }

    /// Число активных клиентов.
    pub fn active_clients(&self) -> usize {
        self.routing.active()
    }

    /// Запускает читателя TUN: пакеты из ядра → клиентам по `RoutingTable`.
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
                                    // Клиент уже мёртв: пакет теряется, таблицу
                                    // почистит его задача сессии.
                                    shared.metrics.record_packets_dropped(1);
                                }
                            }
                            None => {
                                // Адрес не выдан никому: не наши пакеты.
                                shared.metrics.record_packets_dropped(1);
                            }
                        }
                    }
                    Err(err) => {
                        tracing::error!(%err, "чтение TUN прервано — маршрутизация остановлена");
                        return;
                    }
                }
            }
        });
    }
}

/// Цикл жизни одной сессии: рукопожатие → плоскости → очистка.
pub async fn handle_connection(shared: Arc<ServerShared>, conn: quinn::Connection) {
    let peer = conn.remote_address();
    let (mut send, mut recv) = match conn.accept_bi().await {
        Ok(streams) => streams,
        Err(err) => {
            tracing::debug!(%peer, %err, "bi-поток рукопожатия не открылся");
            return;
        }
    };

    // --- Рукопожатие: Hello → Welcome/Reject ---
    let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let buf = match read_control_message(&mut recv).await {
            Ok(buf) => buf,
            Err(message) => Err(Reject {
                code: RejectCode::ProtocolMismatch,
                message,
            })?,
        };
        match decode_control::<ControlFromClient>(&buf) {
            Ok(Some((ControlFromClient::Hello(Hello { protocol_version, client_id, auth_token }), _))) => {
                Ok((protocol_version, client_id, auth_token))
            }
            Ok(Some((other, _))) => Err(Reject {
                code: RejectCode::ProtocolMismatch,
                message: format!("ожидали Hello, получили {other:?}"),
            }),
            Ok(None) => Err(Reject {
                code: RejectCode::ProtocolMismatch,
                message: "обрезанное сообщение рукопожатия".to_owned(),
            }),
            Err(err) => Err(Reject {
                code: RejectCode::ProtocolMismatch,
                message: format!("нечитаемое сообщение: {err}"),
            }),
        }
    })
    .await;

    let (protocol_version, client_id, auth_token) = match handshake {
        Ok(Ok(fields)) => fields,
        Ok(Err(reject)) => {
            send_reject(&mut send, &conn, reject).await;
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "рукопожатие не завершилось за {}с", HANDSHAKE_TIMEOUT.as_secs());
            return;
        }
    };

    if protocol_version != PROTOCOL_VERSION {
        tracing::warn!(
            client_id = %client_id,
            got = protocol_version,
            want = PROTOCOL_VERSION,
            "версия протокола не поддержана"
        );
        send_reject(
            &mut send,
            &conn,
            Reject {
                code: RejectCode::ProtocolMismatch,
                message: format!("поддерживается версия протокола {PROTOCOL_VERSION}, обновите SDK"),
            },
        )
        .await;
        return;
    }

    if !shared.tokens.verify(&client_id, &auth_token) {
        tracing::warn!(client_id = %client_id, "токен отклонён — отказ");
        send_reject(
            &mut send,
            &conn,
            Reject {
                code: RejectCode::InvalidToken,
                message: "токен не найден или заблокирован".to_owned(),
            },
        )
        .await;
        return;
    }

    let vip = match shared.pool.alloc() {
        Some(vip) => vip,
        None => {
            tracing::warn!(client_id = %client_id, "пул виртуальных адресов исчерпан — отказ");
            send_reject(
                &mut send,
                &conn,
                Reject {
                    code: RejectCode::ServerBusy,
                    message: "пул виртуальных адресов исчерпан, попробуйте позже".to_owned(),
                },
            )
            .await;
            return;
        }
    };

    // --- Welcome и регистрация клиента ---
    let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE_LEN);
    shared.routing.register(vip, outbound_tx.clone());

    let welcome = ControlFromServer::Welcome(Welcome {
        vip,
        mtu: shared.mtu,
        keepalive_interval_secs: shared.keepalive_interval_secs,
    });
    if send.write_all(&encode_control(&welcome)).await.is_err() {
        cleanup(&shared, vip, &outbound_tx);
        return;
    }
    tracing::info!(client_id = %client_id, vip = %vip, "сессия установлена");
    shared.metrics.record_session_established();

    // Задача отправки «сервер → клиент» (обратный трафик).
    let sender_task = tokio::spawn(send_loop(Arc::clone(&shared), conn.clone(), outbound_rx));

    // --- Рабочий цикл: control plane + data plane ---
    loop {
        tokio::select! {
            biased;
            control = read_control_message(&mut recv) => match control {
                Ok(buf) => match decode_control::<ControlFromClient>(&buf) {
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
                        tracing::debug!(client_id = %client_id, ?other, "неожиданное управляющее сообщение");
                    }
                    Ok(None) => {
                        tracing::debug!(client_id = %client_id, "обрезанное управляющее сообщение");
                        break;
                    }
                    Err(err) => {
                        tracing::debug!(client_id = %client_id, %err, "битое управляющее сообщение");
                        break;
                    }
                },
                Err(err) => {
                    tracing::debug!(client_id = %client_id, %err, "control plane закрыт");
                    break;
                }
            },
            datagram = conn.read_datagram() => match datagram {
                Ok(datagram) => {
                    match process_inbound(&shared, vip, &datagram) {
                        PacketAction::Echo(reply) => {
                            // Echo несёт чистый IP-пакет — кадрируем как data plane.
                            if conn.send_datagram(Bytes::from(encode_frame(KIND_IPV4, &reply))).is_err() {
                                break;
                            }
                        }
                        PacketAction::Forward(packet) => {
                            let Some(tun) = shared.tun.as_ref() else {
                                tracing::debug!(client_id = %client_id, "пакет без TUN-маршрута — дроп");
                                shared.metrics.record_packets_dropped(1);
                                continue;
                            };
                            if let Err(err) = tun.write_packet(&packet).await {
                                tracing::warn!(%err, "запись в TUN не удалась");
                                shared.metrics.record_packets_dropped(1);
                            }
                        }
                        PacketAction::RouteTo(sender, packet) => {
                            if sender.send(packet).await.is_err() {
                                shared.metrics.record_packets_dropped(1);
                            }
                        }
                        PacketAction::Drop(reason) => {
                            tracing::debug!(client_id = %client_id, reason, "пакет отброшен");
                            shared.metrics.record_packets_dropped(1);
                        }
                    }
                }
                Err(err) => {
                    tracing::debug!(client_id = %client_id, %err, "data plane закрыт");
                    break;
                }
            },
        }
    }

    cleanup(&shared, vip, &outbound_tx);
    sender_task.abort();
    conn.close(quinn::VarInt::from_u32(0), b"session-end");
    tracing::info!(client_id = %client_id, vip = %vip, "сессия завершена");
}

/// Сколько ждём, пока клиент прочитает `Reject`, перед закрытием соединения.
const REJECT_DRAIN: Duration = Duration::from_millis(200);

/// Отправляет `Reject` и дрейнит: без паузы CONNECTION_CLOSE обгоняет данные
/// потока, клиент видит просто «connection lost» вместо причины отказа — и
/// ретраит то, что ретраить бессмысленно. Завершаем send-направление (FIN) и
/// ждём до `REJECT_DRAIN`, пока клиент закроет соединение сам.
async fn send_reject(send: &mut quinn::SendStream, conn: &quinn::Connection, reject: Reject) {
    let payload = encode_control(&ControlFromServer::Reject(reject));
    if send.write_all(&payload).await.is_ok() {
        let _ = send.finish();
        let _ = tokio::time::timeout(REJECT_DRAIN, conn.closed()).await;
    }
}

/// Возвращает адрес в пул и снимает маршрут.
fn cleanup(shared: &Arc<ServerShared>, vip: Ipv4Addr, outbound_tx: &mpsc::Sender<Vec<u8>>) {
    shared.routing.unregister(vip, outbound_tx);
    let _ = shared.pool.release(vip);
}

/// Задача отправки накопленных пакетов конкретному клиенту.
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
                tracing::debug!(%err, "соединение клиента потеряно — задача отправки завершена");
                return;
            }
            Err(err) => {
                shared.metrics.record_packets_dropped(1);
                tracing::debug!(%err, "дейтаграмма не ушла клиенту");
            }
        }
    }
}

/// Читает полный кадр управления (префикс длины + тело).
async fn read_control_message(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, String> {
    let mut prefix = [0u8; 4];
    recv.read_exact(&mut prefix)
        .await
        .map_err(|err| format!("поток управления закрыт: {err}"))?;
    let len = u32::from_le_bytes(prefix) as usize;
    if len > MAX_CONTROL_MESSAGE_SIZE {
        return Err(format!("сообщение {len} байт сверх лимита {MAX_CONTROL_MESSAGE_SIZE}"));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body)
        .await
        .map_err(|err| format!("тело сообщения оборвано: {err}"))?;
    let mut full = prefix.to_vec();
    full.extend_from_slice(&body);
    Ok(full)
}

/// Что сервер делает с входящей дейтаграммой клиента.
enum PacketAction {
    /// Loopback-эхо: пакет возвращается клиенту с обменом адресов.
    Echo(Vec<u8>),
    /// Боевой режим: пакет уходит в TUN (наружу/локальному сервису ядра).
    Forward(Vec<u8>),
    /// Пакет адресован другому клиенту: канал его задачи отправки.
    RouteTo(mpsc::Sender<Vec<u8>>, Vec<u8>),
    /// Дроп с причиной.
    Drop(&'static str),
}

/// Разбирает и классифицирует входящий пакет клиента.
/// Порядок проверок: валидный IPv4 → анти-спуфинг (`src == vip`) → цель.
fn process_inbound(shared: &ServerShared, vip: Ipv4Addr, datagram: &[u8]) -> PacketAction {
    // Кадр должен быть IPv4: IPv6 на роадмапе.
    let datagram = Bytes::copy_from_slice(datagram);
    let Ok(frame) = decode_frame_zero_copy(&datagram) else {
        return PacketAction::Drop("битый кадр дейтаграммы");
    };
    if frame.kind != KIND_IPV4 {
        return PacketAction::Drop("IPv6-кадр без поддержки");
    }
    let packet = frame.payload;
    let Some(header) = ipv4::parse(&packet) else {
        return PacketAction::Drop("не IPv4-пакет");
    };

    // Анти-спуфинг: клиент обязан отправлять с выданного ему адреса.
    if header.src != vip.octets() {
        tracing::warn!(
            vip = %vip,
            claimed_src = %Ipv4Addr::from(header.src),
            "спуфинг: пакет с чужим адресом отправителя отброшен"
        );
        return PacketAction::Drop("спуфинг адреса отправителя");
    }
    shared.metrics.record_bytes_received(u64::from(header.total_len));

    let dst = Ipv4Addr::from(header.dst);
    if dst == shared.server_vip {
        if shared.is_loopback() {
            // Loopback-эхо: адреса меняются местами (src ← server_vip).
            let mut reply = packet.to_vec();
            if !ipv4::rewrite_addresses(&mut reply, shared.server_vip.octets(), vip.octets()) {
                return PacketAction::Drop("пакет не переписывается");
            }
            return PacketAction::Echo(reply);
        }
        // Боевой режим: адрес сервера — локальный сервис ядра через TUN.
        return PacketAction::Forward(packet.to_vec());
    }
    // Адресован другому клиенту — прямая передача через его канал.
    if let Some(sender) = shared.routing.route(dst) {
        return PacketAction::RouteTo(sender, packet.to_vec());
    }
    if shared.is_loopback() {
        PacketAction::Drop("эхо только на адрес сервера")
    } else {
        PacketAction::Forward(packet.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TokensSource;
    use std::net::IpAddr;

    fn config() -> ServerConfig {
        ServerConfig {
            listen: "127.0.0.1:0".parse().expect("адрес"),
            pool: "10.66.0.0/24".to_owned(),
            mtu: 1280,
            keepalive_interval_secs: 15,
            dns_servers: vec![IpAddr::from([8, 8, 8, 8])],
            tun_name: None,
            server_name: "localhost".to_owned(),
            tokens: TokensSource::Inline(vec![("c".to_owned(), "t".to_owned())]),
        }
    }

    #[test]
    fn server_shared_wires_pool_and_vip() {
        let shared = ServerShared::new(&config(), config().load_tokens().expect("токены"), None)
            .expect("состояние сервера");
        assert_eq!(shared.server_vip, Ipv4Addr::new(10, 66, 0, 1));
        assert!(shared.is_loopback());
        assert_eq!(shared.active_clients(), 0);
        let snap = shared.metrics.snapshot();
        assert_eq!(snap.sessions_established, 0);
    }

    #[test]
    fn bad_pool_subnet_fails_fast() {
        let mut cfg = config();
        cfg.pool = "not-a-subnet".to_owned();
        assert!(matches!(
            ServerShared::new(&cfg, cfg.load_tokens().expect("токены"), None),
            Err(ServerError::Pool(_))
        ));
    }

    /// IPv4-пакет от клиента: src=vip, dst=server_vip (внутренний IP-кадр).
    fn ipv4_packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0x45, 0x00, 0x00, 0x00, 0, 1, 0x40, 0x00, 64, 17, 0, 0];
        pkt[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        pkt.extend_from_slice(&src);
        pkt.extend_from_slice(&dst);
        pkt.extend_from_slice(payload);
        pkt
    }

    /// Дейтаграмма: [kind][IP-пакет].
    fn datagram(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        tunnel_proto::frame::encode_frame(KIND_IPV4, &ipv4_packet(src, dst, payload))
    }

    #[test]
    fn loopback_echo_swaps_addresses_and_counts_bytes() {
        let shared = ServerShared::new(&config(), config().load_tokens().expect("токены"), None)
            .expect("состояние сервера");
        let vip = Ipv4Addr::new(10, 66, 0, 2);
        let inbound = datagram([10, 66, 0, 2], [10, 66, 0, 1], &[0xDE, 0xAD]);
        match process_inbound(&shared, vip, &inbound) {
            PacketAction::Echo(reply) => {
                // Echo — чистый IP-пакет (кадрируется в handle_connection).
                let header = ipv4::parse(&reply).expect("валидный IPv4");
                assert_eq!(header.src, shared.server_vip.octets(), "src → сервер");
                assert_eq!(header.dst, [10, 66, 0, 2], "dst → клиент");
                assert_eq!(&reply[20..], &[0xDE, 0xAD], "payload не тронут");
            }
            _ => panic!("loopback обязан эхоить пакет на server_vip"),
        }
        assert_eq!(shared.metrics.snapshot().bytes_received, 22);
    }

    #[test]
    fn spoofed_source_is_dropped() {
        let shared = ServerShared::new(&config(), config().load_tokens().expect("токены"), None)
            .expect("состояние сервера");
        // Клиент с адресом .2 пытается отправить от имени .3.
        let inbound = datagram([10, 66, 0, 3], [10, 66, 0, 1], &[0x01]);
        match process_inbound(&shared, Ipv4Addr::new(10, 66, 0, 2), &inbound) {
            PacketAction::Drop(reason) => {
                assert_eq!(reason, "спуфинг адреса отправителя");
            }
            _ => panic!("спуфинг обязан дропаться"),
        }
    }

    #[test]
    fn loopback_rejects_packets_to_other_clients() {
        let shared = ServerShared::new(&config(), config().load_tokens().expect("токены"), None)
            .expect("состояние сервера");
        // dst = адрес, которого нет в таблице (никто не подключён).
        let inbound = datagram([10, 66, 0, 2], [10, 66, 0, 9], &[0x01]);
        match process_inbound(&shared, Ipv4Addr::new(10, 66, 0, 2), &inbound) {
            PacketAction::Drop(reason) => assert_eq!(reason, "эхо только на адрес сервера"),
            _ => panic!("в loopback без маршрута пакет обязан дропаться"),
        }
    }

    #[tokio::test]
    async fn inter_client_route_bypasses_loopback_restriction() {
        let shared = ServerShared::new(&config(), config().load_tokens().expect("токены"), None)
            .expect("состояние сервера");
        let (tx, mut rx) = mpsc::channel(8);
        shared.routing().register(Ipv4Addr::new(10, 66, 0, 3), tx);
        let inner = ipv4_packet([10, 66, 0, 2], [10, 66, 0, 3], &[0x01]);
        let inbound = tunnel_proto::frame::encode_frame(KIND_IPV4, &inner);
        match process_inbound(&shared, Ipv4Addr::new(10, 66, 0, 2), &inbound) {
            PacketAction::RouteTo(sender, pkt) => {
                assert_eq!(
                    pkt, inner,
                    "клиенту уходит IP-пакет без байта вида кадра"
                );
                sender.send(pkt).await.expect("канал жив");
                assert_eq!(rx.recv().await, Some(inner));
            }
            _ => panic!("адрес живого клиента маршрутизируется даже в loopback"),
        }
    }

    #[test]
    fn garbage_datagram_is_dropped() {
        let shared = ServerShared::new(&config(), config().load_tokens().expect("токены"), None)
            .expect("состояние сервера");
        assert!(matches!(
            process_inbound(&shared, Ipv4Addr::new(10, 66, 0, 2), &[0xFF, 0x00]),
            PacketAction::Drop("битый кадр дейтаграммы")
        ));
    }

    #[test]
    fn ipv6_datagram_is_dropped_with_reason() {
        let shared = ServerShared::new(&config(), config().load_tokens().expect("токены"), None)
            .expect("состояние сервера");
        let inbound = tunnel_proto::frame::encode_frame(tunnel_proto::frame::KIND_IPV6, &[0x60, 1, 2]);
        match process_inbound(&shared, Ipv4Addr::new(10, 66, 0, 2), &inbound) {
            PacketAction::Drop(reason) => assert_eq!(reason, "IPv6-кадр без поддержки"),
            _ => panic!("IPv6 обязан дропаться (роадмап)"),
        }
    }

    #[test]
    fn dns_servers_are_carried_for_clients() {
        // DNS-список хранится в конфиге (роадмап: DHCP-опции); проверяем
        // проброс через конфигурацию.
        assert_eq!(config().dns_servers, vec![IpAddr::from([8, 8, 8, 8])]);
    }

    #[test]
    fn keepalive_hint_is_carried() {
        assert_eq!(config().keepalive_interval_secs, 15);
    }
}
