//! Управляющие сообщения control plane: рукопожатие и ping/pong.
//!
//! Формат на проводе: 4-байтовый префикс длины тела (LE) + тело bincode
//! (`bincode::config::legacy()` — fixed-width целые, little-endian). Длина
//! тела ограничена [`MAX_CONTROL_MESSAGE_SIZE`]: сервер не может быть
//! DoS-нут через гигантский префикс.
//!
//! Сценарий рукопожатия (bi-поток #0):
//! 1. клиент → [`ControlFromClient::Hello`] (версия протокола, client_id,
//!    B2B-токен);
//! 2. сервер → [`ControlFromServer::Welcome`] (выданный адрес, MTU, keepalive)
//!    или [`ControlFromServer::Reject`] (типизированная причина).
//!
//! Затем control plane живёт ping/pong'ами: клиент шлёт
//! [`ControlFromClient::Ping`] со штампом отправки, сервер мгновенно
//! возвращает [`ControlFromServer::Pong`] с эхом штампа — клиент считает RTT.

use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use bincode::{Decode, Encode};

/// Версия протокола, отправляемая в `Hello`. Сервер сравнивает со своей.
pub const PROTOCOL_VERSION: u32 = 1;

/// Максимальный размер тела управляющего сообщения (после префикса длины).
/// Токены и client_id укладываются с многократным запасом.
pub const MAX_CONTROL_MESSAGE_SIZE: usize = 16 * 1024;

/// Текущее время в миллисекундах с начала эпохи Unix (для RTT-штампов ping).
pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        // Системные часы раньше 1970 года — дефект среды, не сети.
        .unwrap_or(0)
}

/// Сообщения от клиента к серверу (control plane, поток #0).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum ControlFromClient {
    /// Рукопожатие: первый запрос после подключения QUIC.
    Hello(Hello),
    /// Keepalive со штампом отправки (эхо-поле в `Pong` даёт RTT).
    Ping(Ping),
}

/// Рукопожатие: первый запрос после подключения QUIC.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Hello {
    /// Версия протокола клиента; несовпадение — [`RejectCode::ProtocolMismatch`].
    pub protocol_version: u32,
    /// Идентификатор клиента для логов/телеметрии оператора.
    pub client_id: String,
    /// B2B-токен партнёра (проверяется за константное время).
    pub auth_token: String,
}

/// Keepalive со штампом отправки: эхо-поле `Pong::sent_unix_ms` даёт RTT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct Ping {
    /// Порядковый номер ping'а.
    pub seq: u32,
    /// unix_ms клиента в момент отправки.
    pub sent_unix_ms: u64,
}

/// Сообщения от сервера к клиенту (control plane, поток #0).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum ControlFromServer {
    /// Рукопожатие принято: параметры сессии.
    Welcome(Welcome),
    /// Отказ с типизированной причиной: клиент отличает постоянные ошибки
    /// (ретрай бессмыслен) от временных.
    Reject(Reject),
    /// Эхо-ответ на ping: штамп отправки возвращается без изменений.
    Pong(Pong),
}

/// Рукопожатие принято: параметры сессии.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct Welcome {
    /// Виртуальный адрес клиента — настройте им платформенный TUN.
    /// Каждый исходящий пакет обязан иметь этот адрес отправителем.
    pub vip: Ipv4Addr,
    /// MTU виртуального интерфейса (QUIC-оверлей съедает до ~1252 байт).
    pub mtu: u16,
    /// Период прикладного ping, сек (0 — клиент берёт свой дефолт 15).
    pub keepalive_interval_secs: u32,
}

/// Отказ рукопожатия с типизированной причиной.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Reject {
    /// Код причины.
    pub code: RejectCode,
    /// Человекочитаемое объяснение (для логов партнёра).
    pub message: String,
}

/// Эхо-ответ на ping: штамп отправки возвращается без изменений.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct Pong {
    /// seq из `Ping`.
    pub seq: u32,
    /// sent_unix_ms из `Ping` — по нему клиент считает RTT.
    pub sent_unix_ms: u64,
    /// unix_ms сервера (не участвует в RTT, полезно для диагностики).
    pub server_unix_ms: u64,
}

/// Коды отказа рукопожатия.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum RejectCode {
    /// Токен неизвестен/заблокирован → постоянная ошибка.
    InvalidToken,
    /// Версия протокола не поддерживается → обновить SDK.
    ProtocolMismatch,
    /// Пул адресов исчерпан/сервер перегружен → ретрай уместен.
    ServerBusy,
}

/// Дейтаграмма data plane как bincode-структура: альтернатива ручному кадру
/// [`crate::frame`] для утилит и тестов. В живом data plane используется
/// компактный формат `[kind: u8][payload]` без overhead'а bincode.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct WirePacket {
    /// Вид кадра: [`crate::frame::KIND_IPV4`] или [`crate::frame::KIND_IPV6`].
    pub kind: u8,
    /// IP-пакет целиком (заголовок + payload).
    pub payload: Vec<u8>,
}

/// Кодирует сообщение в кадр управления: префикс длины + bincode-тело.
/// Кодирование уже проверенных сообщений не падает.
pub fn encode_control<T: Encode>(message: &T) -> Vec<u8> {
    let body = bincode::encode_to_vec(message, bincode::config::legacy())
        .expect("управляющее сообщение укладывается в bincode");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Декодирует сообщение из полного кадра (префикс + тело).
///
/// Возвращает `Ok(None)`, если буфер короче префикса или тела — неполное
/// чтение; `Err` — битый кадр (длина сверх лимита или неразборчивое тело).
pub fn decode_control<T: Decode<()>>(buf: &[u8]) -> Result<Option<(T, usize)>, bincode::error::DecodeError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return Ok(None);
    }
    if len > MAX_CONTROL_MESSAGE_SIZE {
        return Err(bincode::error::DecodeError::OtherString(format!(
            "тело управляющего сообщения {len} байт сверх лимита {MAX_CONTROL_MESSAGE_SIZE}"
        )));
    }
    let (value, used) = bincode::decode_from_slice(&buf[4..4 + len], bincode::config::legacy())?;
    Ok(Some((value, used)))
}

/// Кодирует дейтаграмму в bincode (`WirePacket`) — см. док типа.
pub fn encode_wire_packet(packet: &WirePacket) -> Vec<u8> {
    bincode::encode_to_vec(packet, bincode::config::legacy())
        .expect("WirePacket укладывается в bincode")
}

/// Декодирует дейтаграмму из bincode (`WirePacket`).
pub fn decode_wire_packet(buf: &[u8]) -> Result<WirePacket, bincode::error::DecodeError> {
    let (packet, _) = bincode::decode_from_slice(buf, bincode::config::legacy())?;
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::KIND_IPV4;

    #[test]
    fn hello_roundtrip() {
        let hello = ControlFromClient::Hello(Hello {
            protocol_version: PROTOCOL_VERSION,
            client_id: "android-2.1.0".to_owned(),
            auth_token: "b2b-live-secret".to_owned(),
        });
        let encoded = encode_control(&hello);
        assert!(encoded.len() > 4, "префикс + тело");
        let decoded = decode_control::<ControlFromClient>(&encoded)
            .expect("корректный кадр")
            .expect("буфер полный");
        assert_eq!(decoded.0, hello);
        assert_eq!(decoded.1, encoded.len() - 4, "использовано всё тело");
    }

    #[test]
    fn welcome_roundtrip_preserves_address() {
        let welcome = Welcome {
            vip: Ipv4Addr::new(10, 66, 0, 2),
            mtu: 1280,
            keepalive_interval_secs: 15,
        };
        let encoded = encode_control(&ControlFromServer::Welcome(welcome));
        let (decoded, _) = decode_control::<ControlFromServer>(&encoded)
            .expect("корректный кадр")
            .expect("буфер полный");
        match decoded {
            ControlFromServer::Welcome(w) => {
                assert_eq!(w.vip, Ipv4Addr::new(10, 66, 0, 2));
                assert_eq!(w.mtu, 1280);
                assert_eq!(w.keepalive_interval_secs, 15);
            }
            other => panic!("неожиданный вариант: {other:?}"),
        }
    }

    #[test]
    fn ping_pong_roundtrip() {
        let sent_ms = unix_ms();
        let ping = ControlFromClient::Ping(Ping { seq: 7, sent_unix_ms: sent_ms });
        let pong = ControlFromServer::Pong(Pong {
            seq: 7,
            sent_unix_ms: sent_ms,
            server_unix_ms: unix_ms(),
        });
        let (p, _) = decode_control::<ControlFromClient>(&encode_control(&ping))
            .expect("корректный кадр")
            .expect("буфер полный");
        assert_eq!(p, ping, "ping байт в байт после roundtrip");
        let (p, _) = decode_control::<ControlFromServer>(&encode_control(&pong))
            .expect("корректный кадр")
            .expect("буфер полный");
        assert_eq!(p, pong, "pong байт в байт после roundtrip");
    }

    #[test]
    fn reject_roundtrip_all_codes() {
        for (code, text) in [
            (RejectCode::InvalidToken, "токен не найден"),
            (RejectCode::ProtocolMismatch, "нужна версия 2"),
            (RejectCode::ServerBusy, "пул исчерпан"),
        ] {
            let reject = Reject { code, message: text.to_owned() };
            let (decoded, _) = decode_control::<ControlFromServer>(&encode_control(&ControlFromServer::Reject(reject.clone())))
                .expect("корректный кадр")
                .expect("буфер полный");
            assert_eq!(decoded, ControlFromServer::Reject(reject));
        }
    }

    #[test]
    fn incomplete_buffer_is_none_not_error() {
        let full = encode_control(&ControlFromClient::Hello(Hello {
            protocol_version: 1,
            client_id: "c".to_owned(),
            auth_token: "t".to_owned(),
        }));
        // Обрезанный на середине буфер — неполное сообщение, не ошибка.
        for cut in [0, 2, 4, full.len() - 1] {
            assert!(
                decode_control::<ControlFromClient>(&full[..cut]).expect("нет ошибки").is_none(),
                "обрезка {cut} должна давать None"
            );
        }
    }

    #[test]
    fn oversized_length_is_rejected() {
        let mut evil = 0u32.to_le_bytes().to_vec();
        evil.extend_from_slice(&((MAX_CONTROL_MESSAGE_SIZE as u32) + 1).to_le_bytes());
        evil.extend_from_slice(&[0u8; 16]);
        assert!(
            decode_control::<ControlFromClient>(&evil).is_err(),
            "префикс сверх лимита обязан быть ошибкой"
        );
    }

    #[test]
    fn garbage_body_is_error() {
        let mut frame = 2u32.to_le_bytes().to_vec();
        frame.extend_from_slice(&[0xFF; 2]);
        assert!(decode_control::<ControlFromClient>(&frame).is_err());
    }

    #[test]
    fn wire_packet_roundtrip() {
        let packet = WirePacket { kind: KIND_IPV4, payload: vec![0x45, 0, 0, 8] };
        let decoded = decode_wire_packet(&encode_wire_packet(&packet)).expect("bincode-кадр");
        assert_eq!(decoded, packet);
    }

    #[test]
    fn trailing_bytes_after_body_are_ignored() {
        let full = encode_control(&ControlFromServer::Reject(Reject {
            code: RejectCode::ServerBusy,
            message: "retry later".to_owned(),
        }));
        let mut extended = full.clone();
        extended.extend_from_slice(&[0xAA, 0xBB]);
        let (value, used) = decode_control::<ControlFromServer>(&extended)
            .expect("корректный кадр")
            .expect("буфер полный");
        assert!(matches!(value, ControlFromServer::Reject(Reject { .. })));
        assert_eq!(used + 4, full.len(), "использовано ровно тело кадра");
    }

    #[test]
    fn unix_ms_is_monotonic_enough() {
        let a = unix_ms();
        assert!(a > 1_700_000_000_000, "часы идут после 2023 года: {a}");
        let b = unix_ms();
        assert!(b >= a, "unix_ms не уходит назад");
    }

}
