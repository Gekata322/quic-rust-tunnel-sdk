//! IPv4 header parsing and address rewriting for loopback echo.
//!
//! Neither the core nor the server trusts header fields: the packet length is
//! validated against the actual buffer size, and echo replies have addresses
//! rewritten, so a client sending a forged `src` can never receive another
//! client's traffic (anti-spoofing). Checksums are not recomputed: validation
//! belongs to the platform TUN kernel; loopback echo only swaps addresses.

/// Length of the minimal IPv4 header (IHL=5, no options).
pub const IPV4_HEADER_LEN: usize = 20;

/// Parsed IPv4 header (only the fields the tunnel needs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Header {
    /// IP version (must be 4).
    pub version: u8,
    /// Total packet length per the header (header + payload).
    pub total_len: u16,
    /// Sender address.
    pub src: [u8; 4],
    /// Receiver address.
    pub dst: [u8; 4],
    /// Upper-layer protocol number (6=TCP, 17=UDP).
    pub protocol: u8,
}

/// Parses the minimal IPv4 header fields. Returns `None` for non-IPv4
/// packets, buffers shorter than the header, or a `total_len` inconsistent
/// with the actual buffer length.
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
    // total_len must not exceed the real buffer length; the buffer may be
    // longer (Ethernet padding on the TUN side is acceptable).
    if usize::from(total_len) < header_len || usize::from(total_len) > buf.len() {
        return None;
    }
    Some(Ipv4Header {
        version,
        total_len,
        src: [buf[12], buf[13], buf[14], buf[15]],
        dst: [buf[16], buf[17], buf[18], buf[19]],
        protocol: buf[9],
    })
}

/// Rewrites the source and destination addresses in an IPv4 header (loopback
/// echo): both are written into bytes 12..20. Returns `false` when the buffer
/// is not a valid IPv4 packet, leaving it untouched.
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

    /// Builds a minimal IPv4 header + payload.
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
        let header =
            parse(&packet([10, 66, 0, 2], [10, 66, 0, 1], &[0xDE, 0xAD])).expect("valid packet");
        assert_eq!(header.version, 4);
        assert_eq!(header.src, [10, 66, 0, 2]);
        assert_eq!(header.dst, [10, 66, 0, 1]);
        assert_eq!(header.protocol, 17);
        assert_eq!(usize::from(header.total_len), 22);
    }

    #[test]
    fn parse_rejects_short_and_non_ipv4_buffers() {
        assert!(
            parse(&[0x45, 0, 0, 20]).is_none(),
            "4 bytes are not a header"
        );
        assert!(parse(&[]).is_none());
        let mut pkt = packet([1, 2, 3, 4], [5, 6, 7, 8], b"x");
        pkt[0] = 0x65; // version 6
        assert!(
            parse(&pkt).is_none(),
            "version 6 is not handled by the IPv4 parser"
        );
    }

    #[test]
    fn parse_rejects_ihl_less_than_five() {
        let mut pkt = packet([1, 2, 3, 4], [5, 6, 7, 8], b"x");
        pkt[0] = 0x44; // IHL=4: header shorter than the minimum
        assert!(parse(&pkt).is_none());
    }

    #[test]
    fn parse_validates_total_len_against_buffer() {
        let mut pkt = packet([1, 2, 3, 4], [5, 6, 7, 8], &[0u8; 40]);
        // total_len = 20 with a 60-byte buffer: truncated payload is valid.
        pkt[2..4].copy_from_slice(&20u16.to_be_bytes());
        assert!(
            parse(&pkt).is_some(),
            "a buffer longer than total_len is fine"
        );
        // total_len beyond the buffer is a contradiction.
        pkt[2..4].copy_from_slice(&6200u16.to_be_bytes());
        assert!(
            parse(&pkt).is_none(),
            "total_len beyond the buffer is garbage"
        );
        // total_len below the header length is a contradiction too.
        pkt[2..4].copy_from_slice(&8u16.to_be_bytes());
        assert!(parse(&pkt).is_none());
    }

    #[test]
    fn rewrite_addresses_swaps_and_validates() {
        let mut pkt = packet([10, 66, 0, 2], [10, 66, 0, 1], &[0xDE]);
        assert!(rewrite_addresses(&mut pkt, [10, 66, 0, 1], [10, 66, 0, 2]));
        let header = parse(&pkt).expect("packet stays valid after the rewrite");
        assert_eq!(header.src, [10, 66, 0, 1], "src becomes the server");
        assert_eq!(header.dst, [10, 66, 0, 2], "dst becomes the client");
        assert_eq!(&pkt[20..], &[0xDE], "payload untouched");
    }

    #[test]
    fn rewrite_rejects_garbage() {
        let mut garbage = vec![0xFF; 8];
        assert!(!rewrite_addresses(&mut garbage, [1, 2, 3, 4], [5, 6, 7, 8]));
    }
}
