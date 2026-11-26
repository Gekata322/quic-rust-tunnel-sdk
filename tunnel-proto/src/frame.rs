//! Кадрирование IP-пакетов для QUIC-дейтаграмм.
//!
//! Формат дейтаграммы — минимальный: `[kind: u8][payload]`. QUIC-дейтаграммы
//! не фрагментируются и не дробятся, поэтому длина не пишется — она известна
//! из размера дейтаграммы. Приём идёт без копий: payload отрезается от
//! `Bytes` как view ([`decode_frame_zero_copy`]).
//!
//! Виды кадра ограничены двумя значениями: неизвестный kind отбрасывается
//! сразу — платформа не увидит мусора в очереди пакетов.

use bytes::Bytes;

/// IPv4-пакет.
pub const KIND_IPV4: u8 = 4;
/// IPv6-пакет (маршрутизация v6 на роадмапе; кадры принимаются и дропаются).
pub const KIND_IPV6: u8 = 6;

/// Максимум payload'а дейтаграммы. QUIC datagram ограничен 65 527 байтами;
/// MTU 1280 делает этот потолок недостижимым на практике.
pub const MAX_DATAGRAM_PAYLOAD: usize = 65_527;

/// Ошибки разбора дейтаграммы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Дейтаграмма пуста — нет даже байта вида кадра.
    Empty,
    /// Неизвестный вид кадра (мусор или версия протокола новее клиента).
    UnknownKind(u8),
    /// Payload сверх [`MAX_DATAGRAM_PAYLOAD`].
    PayloadTooLarge(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "пустая дейтаграмма"),
            Self::UnknownKind(kind) => write!(f, "неизвестный вид кадра: {kind}"),
            Self::PayloadTooLarge(len) => {
                write!(f, "payload {len} байт сверх лимита {MAX_DATAGRAM_PAYLOAD}")
            }
        }
    }
}

/// Разобранная дейтаграмма: `payload` — view внутрь исходного `Bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Вид кадра ([`KIND_IPV4`] / [`KIND_IPV6`]).
    pub kind: u8,
    /// IP-пакет целиком, без копирования.
    pub payload: Bytes,
}

/// Кодирует IP-пакет в дейтаграмму `[kind][payload]`.
pub fn encode_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(kind);
    out.extend_from_slice(payload);
    out
}

/// Разбирает дейтаграмму `[kind][payload]` без копий: payload — slice
/// исходного буфера. Пустой буфер, неизвестный kind и сверхлимитный payload —
/// ошибки.
pub fn decode_frame_zero_copy(datagram: &Bytes) -> Result<Frame, FrameError> {
    let Some(&kind) = datagram.first() else {
        return Err(FrameError::Empty);
    };
    if kind != KIND_IPV4 && kind != KIND_IPV6 {
        return Err(FrameError::UnknownKind(kind));
    }
    let payload = datagram.slice(1..);
    if payload.len() > MAX_DATAGRAM_PAYLOAD {
        return Err(FrameError::PayloadTooLarge(payload.len()));
    }
    Ok(Frame { kind, payload })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram(kind: u8, payload: &[u8]) -> Bytes {
        Bytes::from(encode_frame(kind, payload))
    }

    #[test]
    fn ipv4_roundtrip_without_copy() {
        let payload = vec![0x45u8, 0, 0, 8, 0, 1, 0, 0, 64, 17, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        let datagram = datagram(KIND_IPV4, &payload);
        let frame = decode_frame_zero_copy(&datagram).expect("валидный кадр");
        assert_eq!(frame.kind, KIND_IPV4);
        assert_eq!(frame.payload.as_ref(), &payload, "payload байт в байт");
        // Zero-copy: payload указывает внутрь дейтаграммы (смещение на байт kind).
        // SAFETY: байт kind существует (first() вернулся Some), +1 не выходит
        // за границы буфера.
        assert_eq!(
            frame.payload.as_ptr(),
            unsafe { datagram.as_ptr().add(1) },
            "payload обязан быть view без копии"
        );
    }

    #[test]
    fn ipv6_kind_accepted() {
        let frame = decode_frame_zero_copy(&datagram(KIND_IPV6, &[0x60])).expect("валидный кадр");
        assert_eq!(frame.kind, KIND_IPV6);
        assert_eq!(frame.payload.as_ref(), &[0x60]);
    }

    #[test]
    fn empty_datagram_is_error() {
        assert_eq!(decode_frame_zero_copy(&Bytes::new()), Err(FrameError::Empty));
    }

    #[test]
    fn unknown_kind_is_error() {
        assert_eq!(
            decode_frame_zero_copy(&datagram(99, &[1])),
            Err(FrameError::UnknownKind(99))
        );
        // KIND=0 тоже не допустим: виды кадра — только версии IP.
        assert_eq!(
            decode_frame_zero_copy(&datagram(0, &[1])),
            Err(FrameError::UnknownKind(0))
        );
    }

    #[test]
    fn oversized_payload_is_error() {
        let oversized = vec![0u8; MAX_DATAGRAM_PAYLOAD + 1];
        assert_eq!(
            decode_frame_zero_copy(&datagram(KIND_IPV4, &oversized)),
            Err(FrameError::PayloadTooLarge(MAX_DATAGRAM_PAYLOAD + 1))
        );
    }

    #[test]
    fn max_size_payload_is_ok() {
        let payload = vec![0u8; MAX_DATAGRAM_PAYLOAD];
        let frame = decode_frame_zero_copy(&datagram(KIND_IPV4, &payload)).expect("на пределе — ок");
        assert_eq!(frame.payload.len(), MAX_DATAGRAM_PAYLOAD);
    }

    #[test]
    fn frame_error_display() {
        assert_eq!(FrameError::Empty.to_string(), "пустая дейтаграмма");
        assert_eq!(FrameError::UnknownKind(9).to_string(), "неизвестный вид кадра: 9");
        assert_eq!(
            FrameError::PayloadTooLarge(9).to_string(),
            "payload 9 байт сверх лимита 65527"
        );
    }

    #[test]
    fn encode_frame_shape() {
        let encoded = encode_frame(KIND_IPV4, &[1, 2, 3]);
        assert_eq!(encoded, vec![KIND_IPV4, 1, 2, 3]);
    }
}
