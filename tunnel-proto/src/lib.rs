//! Общий протокол B2B-туннеля — единственный контракт между клиентом
//! (`tunnel-core`) и сервером (`tunnel-server`).
//!
//! Транспорт: QUIC-поток #0 — **control plane** (рукопожатие и ping/pong),
//! QUIC-дейтаграммы — **data plane** (IP-пакеты).
//!
//! Форматы:
//! - управляющее сообщение = 4-байтовый префикс длины (LE) + тело bincode
//!   (`bincode::config::legacy()`, fixed-int);
//! - дейтаграмма = 1 байт вида кадра ([`frame::KIND_IPV4`] /
//!   [`frame::KIND_IPV6`]) + payload IP-пакета;
//! - модуль [`messages`] даёт и bincode-вариант дейтаграммы
//!   (`WirePacket`) для тестов и утилит.
//!
//! Правила безопасности:
//! - токены сравниваются за константное время ([`auth`]);
//! - `MAX_CONTROL_MESSAGE_SIZE` ограничивает управляющие сообщения;
//! - сервер никогда не доверяет полям IPv4-заголовка — адрес отправителя
//!   подменяется на выданный клиенту ([`ipv4::rewrite_addresses`]).

pub mod auth;
pub mod frame;
pub mod ipv4;
pub mod messages;
pub mod metrics;

pub use messages::{
    decode_control, encode_control, unix_ms, ControlFromClient, ControlFromServer, Hello,
    Ping, Pong, Reject, RejectCode, Welcome, WirePacket, MAX_CONTROL_MESSAGE_SIZE,
    PROTOCOL_VERSION,
};
pub use metrics::{Metrics, MetricsSnapshot};

/// ALPN протокола v1: negotiated на QUIC-рукопожатии, несовместимые клиенты
/// отбрасываются ещё до TLS.
pub const ALPN_TUNNEL_V1: &[u8] = b"tunnel/v1";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_matches_version_string() {
        assert_eq!(std::str::from_utf8(ALPN_TUNNEL_V1), Ok("tunnel/v1"));
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}
