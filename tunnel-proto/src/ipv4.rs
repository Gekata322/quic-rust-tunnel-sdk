//! Разбор IPv4-заголовка и подмена адресов для loopback-эха.
//!
//! Ядро и сервер **не доверяют** полям заголовка: длина пакета проверяется
//! против фактического размера буфера, а при эхе адреса перезаписываются —
//! клиент с чужим `src` никогда не получит трафик другого клиента
//! (анти-спуфинг). Контрольные суммы не пересчитываются: их валидацию делает
//! ядро платформенного TUN, а loopback-эхо меняет только адреса.

/// Длина минимального IPv4-заголовка (IHL=5, без опций).
pub const IPV4_HEADER_LEN: usize = 20;

/// Разобранный IPv4-заголовок (только поля, нужные туннелю).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    /// Версия IP (должна быть 4).
    pub version: u8,
    /// Общая длина пакета по заголовку (заголовок + payload).
    pub total_len: u16,
    /// Адрес отправителя.
    pub src: [u8; 4],
    /// Адрес получателя.
    pub dst: [u8; 4],
    /// Номер протокола верхнего уровня (6=TCP, 17=UDP).
    pub protocol: u8,
}

/// Разбирает минимальные поля IPv4-заголовка. `None` — не IPv4-пакет,
/// буфер короче заголовка или `total_len` противоречит фактической длине.
pub fn parse(buf: &[u8]) -> Option<Ipv4Header> {
    if buf.len() < IPV4_HEADER_LEN {
        return None;
    }
    let version = buf[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = usize::from(buf[0] & 0x0F);
    if ihl < 5 {
        return None;
    }
    let header_len = ihl * 4;
    if buf.len() < header_len {
        return None;
    }
    let total_len = u16::from_be_bytes([buf[2], buf[3]]);
    // total_len не может превышать фактическую длину буфера; буфер может
    // быть длиннее (Ethernet-padding со стороны TUN — допустимо).
    if usize::from(total_len) < header_len || usize::from(total_len) > buf.len() {
        return None;
    }
    let src = [buf[12], buf[13], buf[14], buf[15]];
    let dst = [buf[16], buf[17], buf[18], buf[19]];
    Some(Ipv4Header {
        version,
        total_len,
        src,
        dst,
        protocol: buf[9],
    })
}

/// Подменяет адреса в IPv4-заголовке (loopback-эхо): `src` и `dst` пишутся
/// в байты 12..20. Возвращает `false`, если буфер не валидный IPv4-пакет —
/// адреса в таком случае не трогаются.
pub fn rewrite_addresses(buf: &mut [u8], src: [u8; 4], dst: [u8; 4]) -> bool {
    if parse(buf).is_none() {
        return false;
    }
    buf[12..16].copy_from_slice(&src);
    buf[16..20].copy_from_slice(&dst);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Собирает минимальный IPv4-заголовок + payload.
    fn packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut pkt = vec![0x45, 0x00, 0x00, 0x00, 0, 1, 0x40, 0x00, 64, 17, 0, 0];
        pkt[2..4].copy_from_slice(&((IPV4_HEADER_LEN + payload.len()) as u16).to_be_bytes());
        pkt.extend_from_slice(&src);
        pkt.extend_from_slice(&dst);
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn parse_valid_packet() {
        let header = parse(&packet([10, 66, 0, 2], [10, 66, 0, 1], &[0xDE, 0xAD]))
            .expect("валидный пакет");
        assert_eq!(header.version, 4);
        assert_eq!(header.src, [10, 66, 0, 2]);
        assert_eq!(header.dst, [10, 66, 0, 1]);
        assert_eq!(header.protocol, 17);
        assert_eq!(usize::from(header.total_len), 22);
    }

    #[test]
    fn parse_rejects_short_buffer() {
        assert!(parse(&[0x45, 0, 0, 20]).is_none(), "4 байта — не заголовок");
        assert!(parse(&[]).is_none());
    }

    #[test]
    fn parse_rejects_non_ipv4() {
        let mut pkt = packet([1, 2, 3, 4], [5, 6, 7, 8], b"x");
        pkt[0] = 0x65; // версия 6
        assert!(parse(&pkt).is_none(), "версия 6 не разбирается ipv4-модулем");
    }

    #[test]
    fn parse_rejects_ihl_less_than_five() {
        let mut pkt = packet([1, 2, 3, 4], [5, 6, 7, 8], b"x");
        pkt[0] = 0x44; // IHL=4 — заголовок короче минимального
        assert!(parse(&pkt).is_none());
    }

    #[test]
    fn parse_rejects_total_len_mismatch() {
        let mut pkt = packet([1, 2, 3, 4], [5, 6, 7, 8], &[0u8; 40]);
        // total_len = 20 при фактической длине 60: payload обрезан — валидно.
        pkt[2..4].copy_from_slice(&20u16.to_be_bytes());
        assert!(parse(&pkt).is_some(), "буфер длиннее total_len допустим");
        // total_len больше буфера — противоречие.
        pkt[2..4].copy_from_slice(&6200u16.to_be_bytes());
        assert!(parse(&pkt).is_none(), "total_len сверх буфера — мусор");
        // total_len меньше заголовка — противоречие.
        pkt[2..4].copy_from_slice(&8u16.to_be_bytes());
        assert!(parse(&pkt).is_none());
    }

    #[test]
    fn rewrite_addresses_swaps_and_validates() {
        let mut pkt = packet([10, 66, 0, 2], [10, 66, 0, 1], &[0xDE]);
        assert!(rewrite_addresses(&mut pkt, [10, 66, 0, 1], [10, 66, 0, 2]));
        let header = parse(&pkt).expect("после перезаписи пакет валиден");
        assert_eq!(header.src, [10, 66, 0, 1], "src → сервер");
        assert_eq!(header.dst, [10, 66, 0, 2], "dst → клиент");
        assert_eq!(&pkt[20..], &[0xDE], "payload не тронут");
    }

    #[test]
    fn rewrite_rejects_garbage() {
        let mut garbage = vec![0xFF; 8];
        assert!(!rewrite_addresses(&mut garbage, [1, 2, 3, 4], [5, 6, 7, 8]));
        // Наличие мусора не означает, что адреса остались прежними —
        // гарантируется только отсутствие перезаписи валидной части.
    }
}
