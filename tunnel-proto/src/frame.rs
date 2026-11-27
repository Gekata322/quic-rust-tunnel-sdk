//! IP packet framing for QUIC datagrams.
//!
//! Datagram layout is minimal: `[kind: u8][payload]`. QUIC datagrams are never
//! fragmented or split, so the length is implied by the datagram size and not
//! written to the wire. Decoding is zero-copy: the payload is a view into the
//! original `Bytes` ([`decode_frame_zero_copy`]).
//!
//! Frame kinds are limited to IP versions; an unknown kind is rejected
//! immediately so garbage never reaches the packet queue.

use bytes::Bytes;
use thiserror::Error;

/// IPv4 packet.
pub const KIND_IPV4: u8 = 4;
/// IPv6 packet (v6 routing is a roadmap item; frames are accepted and dropped).
pub const KIND_IPV6: u8 = 6;

/// Maximum datagram payload. QUIC datagrams cap at 65 527 bytes; with the
/// 1280 MTU this ceiling is unreachable in practice.
pub const MAX_DATAGRAM_PAYLOAD: usize = 65_527;

/// Datagram parsing errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FrameError {
    /// Datagram is empty — not even a frame-kind byte.
    #[error("empty datagram")]
    Empty,
    /// Unknown frame kind (garbage or a protocol version newer than this client).
    #[error("unknown frame kind: {0}")]
    UnknownKind(u8),
    /// Payload exceeds [`MAX_DATAGRAM_PAYLOAD`].
    #[error("payload of {0} bytes exceeds the limit of {MAX_DATAGRAM_PAYLOAD}")]
    PayloadTooLarge(usize),
}

/// Decoded datagram: `payload` is a view into the original `Bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Frame kind ([`KIND_IPV4`] / [`KIND_IPV6`]).
    pub kind: u8,
    /// Full IP packet, borrowed without copying.
    pub payload: Bytes,
}

/// Encodes an IP packet into a `[kind][payload]` datagram.
pub fn encode_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.len());
    out.push(kind);
    out.extend_from_slice(payload);
    out
}

/// Decodes a `[kind][payload]` datagram without copying: the payload is a
/// slice of the input buffer. Empty input, unknown kind and oversized payload
/// are errors.
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

    #[test]
    fn roundtrip_is_zero_copy() {
        let payload = [0x45u8, 0, 0, 8, 0, 1, 0, 0, 64, 17, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        let datagram = Bytes::from(encode_frame(KIND_IPV4, &payload));
        let frame = decode_frame_zero_copy(&datagram).expect("valid frame");
        assert_eq!(frame.kind, KIND_IPV4);
        assert_eq!(frame.payload.as_ref(), &payload);
        // Zero-copy guarantee: the payload points one byte past the kind byte.
        // SAFETY: the kind byte exists (first() returned Some), +1 is in bounds.
        assert_eq!(frame.payload.as_ptr(), unsafe { datagram.as_ptr().add(1) });
    }

    #[test]
    fn ipv6_kind_is_accepted() {
        let datagram = Bytes::from(encode_frame(KIND_IPV6, &[0x60]));
        let frame = decode_frame_zero_copy(&datagram).expect("valid frame");
        assert_eq!(frame.kind, KIND_IPV6);
    }

    #[test]
    fn empty_and_unknown_kinds_are_rejected() {
        assert_eq!(decode_frame_zero_copy(&Bytes::new()), Err(FrameError::Empty));
        // Kind 0 is not a valid IP version either.
        assert_eq!(
            decode_frame_zero_copy(&Bytes::from_static(&[0, 1])),
            Err(FrameError::UnknownKind(0))
        );
        assert_eq!(
            decode_frame_zero_copy(&Bytes::from_static(&[99, 1])),
            Err(FrameError::UnknownKind(99))
        );
    }

    #[test]
    fn payload_size_limit_is_enforced() {
        let oversized = vec![0u8; MAX_DATAGRAM_PAYLOAD + 1];
        assert_eq!(
            decode_frame_zero_copy(&Bytes::from(encode_frame(KIND_IPV4, &oversized))),
            Err(FrameError::PayloadTooLarge(MAX_DATAGRAM_PAYLOAD + 1))
        );
        let at_limit = vec![0u8; MAX_DATAGRAM_PAYLOAD];
        let frame =
            decode_frame_zero_copy(&Bytes::from(encode_frame(KIND_IPV4, &at_limit))).expect("at the limit is fine");
        assert_eq!(frame.payload.len(), MAX_DATAGRAM_PAYLOAD);
    }
}
