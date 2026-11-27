//! Control-plane messages: handshake and ping/pong.
//!
//! Wire format: 4-byte body length prefix (LE) + bincode body
//! (`bincode::config::legacy()` — fixed-width ints, little-endian). The body
//! is capped by [`MAX_CONTROL_MESSAGE_SIZE`] so a giant prefix cannot DoS the
//! server.
//!
//! Handshake over bidirectional stream #0:
//! 1. client → [`ControlFromClient::Hello`] (protocol version, client_id,
//!    B2B token);
//! 2. server → [`ControlFromServer::Welcome`] (assigned address, MTU,
//!    keepalive) or [`ControlFromServer::Reject`] (typed reason).
//!
//! Afterwards the control plane carries ping/pong: the client sends
//! [`ControlFromClient::Ping`] with a send timestamp and the server echoes it
//! back in [`ControlFromServer::Pong`] so the client can compute RTT.

use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use bincode::{Decode, Encode};

/// Protocol version sent in `Hello`; the server compares it with its own.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum control-message body size (after the length prefix); tokens and
/// client ids fit with plenty of headroom.
pub const MAX_CONTROL_MESSAGE_SIZE: usize = 16 * 1024;

/// Current time in milliseconds since the Unix epoch (for ping RTT stamps).
pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or(0)
}

/// Messages sent by the client (control plane, stream #0).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum ControlFromClient {
    /// Handshake: the first request after the QUIC connection opens.
    Hello(Hello),
    /// Keepalive with a send timestamp (echoed in `Pong` to compute RTT).
    Ping(Ping),
}

/// Handshake: the first request after the QUIC connection opens.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Hello {
    /// Client protocol version; a mismatch yields [`RejectCode::ProtocolMismatch`].
    pub protocol_version: u32,
    /// Client identifier for operator logs/telemetry.
    pub client_id: String,
    /// B2B partner token (verified in constant time).
    pub auth_token: String,
}

/// Keepalive with a send timestamp; the echoed `Pong::sent_unix_ms` yields RTT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct Ping {
    /// Ping sequence number.
    pub seq: u32,
    /// Client `unix_ms` at send time.
    pub sent_unix_ms: u64,
}

/// Messages sent by the server (control plane, stream #0).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum ControlFromServer {
    /// Handshake accepted: session parameters.
    Welcome(Welcome),
    /// Rejection with a typed reason: the client can distinguish permanent
    /// failures (retrying is pointless) from transient ones.
    Reject(Reject),
    /// Echo reply to a ping: the send timestamp is returned unchanged.
    Pong(Pong),
}

/// Handshake accepted: session parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct Welcome {
    /// Virtual address assigned to the client — configure the platform TUN
    /// with it. Every outgoing packet must carry it as the source address.
    pub vip: Ipv4Addr,
    /// MTU of the virtual interface (the QUIC overlay consumes ~28 bytes).
    pub mtu: u16,
    /// Application-level ping interval in seconds (0 — client picks its
    /// default of 15).
    pub keepalive_interval_secs: u32,
}

/// Handshake rejection with a typed reason.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Reject {
    /// Reason code.
    pub code: RejectCode,
    /// Human-readable explanation (for the partner's logs).
    pub message: String,
}

/// Echo reply to a ping: the send timestamp is returned unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub struct Pong {
    /// `seq` from `Ping`.
    pub seq: u32,
    /// `sent_unix_ms` from `Ping` — the client derives RTT from it.
    pub sent_unix_ms: u64,
    /// Server `unix_ms` (not part of RTT; useful for diagnostics).
    pub server_unix_ms: u64,
}

/// Handshake rejection codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
pub enum RejectCode {
    /// Token unknown or revoked → permanent failure.
    InvalidToken,
    /// Protocol version unsupported → update the SDK.
    ProtocolMismatch,
    /// Address pool exhausted / server overloaded → retry is reasonable.
    ServerBusy,
}

/// Data-plane datagram as a bincode struct: an alternative to the compact
/// [`crate::frame`] format for utilities and tests. The live data plane uses
/// the tight `[kind: u8][payload]` layout with no bincode overhead.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct WirePacket {
    /// Frame kind: [`crate::frame::KIND_IPV4`] or [`crate::frame::KIND_IPV6`].
    pub kind: u8,
    /// Full IP packet (header + payload).
    pub payload: Vec<u8>,
}

/// Encodes a message into a control frame: length prefix + bincode body.
/// Encoding an already-valid message cannot fail.
pub fn encode_control<T: Encode>(message: &T) -> Vec<u8> {
    let body = bincode::encode_to_vec(message, bincode::config::legacy())
        .expect("control message fits bincode");
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// Decodes a message from a complete frame (prefix + body).
///
/// Returns `Ok(None)` when the buffer is shorter than the prefix or the body
/// (incomplete read); `Err` marks a corrupt frame (length over the limit or
/// undecodable body).
pub fn decode_control<T: Decode<()>>(
    buf: &[u8],
) -> Result<Option<(T, usize)>, bincode::error::DecodeError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if buf.len() < 4 + len {
        return Ok(None);
    }
    if len > MAX_CONTROL_MESSAGE_SIZE {
        return Err(bincode::error::DecodeError::OtherString(format!(
            "control message body of {len} bytes exceeds the limit of {MAX_CONTROL_MESSAGE_SIZE}"
        )));
    }
    let (value, used) = bincode::decode_from_slice(&buf[4..4 + len], bincode::config::legacy())?;
    Ok(Some((value, used)))
}

/// Encodes a datagram into bincode ([`WirePacket`]) — see the type docs.
pub fn encode_wire_packet(packet: &WirePacket) -> Vec<u8> {
    bincode::encode_to_vec(packet, bincode::config::legacy()).expect("WirePacket fits bincode")
}

/// Decodes a datagram from bincode ([`WirePacket`]).
pub fn decode_wire_packet(buf: &[u8]) -> Result<WirePacket, bincode::error::DecodeError> {
    let (packet, _) = bincode::decode_from_slice(buf, bincode::config::legacy())?;
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_hello() -> ControlFromClient {
        ControlFromClient::Hello(Hello {
            protocol_version: PROTOCOL_VERSION,
            client_id: "android-2.1.0".to_owned(),
            auth_token: "b2b-live-secret".to_owned(),
        })
    }

    #[test]
    fn incomplete_buffer_is_none_not_error() {
        let full = encode_control(&sample_hello());
        // A buffer cut mid-message is an incomplete read, not an error.
        for cut in [0, 2, 4, full.len() - 1] {
            assert!(
                decode_control::<ControlFromClient>(&full[..cut]).expect("no error").is_none(),
                "cut at {cut} must decode to None"
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
            "a prefix over the limit must be an error (DoS guard)"
        );
    }

    #[test]
    fn garbage_body_is_error() {
        let mut frame = 2u32.to_le_bytes().to_vec();
        frame.extend_from_slice(&[0xFF; 2]);
        assert!(decode_control::<ControlFromClient>(&frame).is_err());
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
            .expect("valid frame")
            .expect("buffer is complete");
        assert!(matches!(value, ControlFromServer::Reject(Reject { .. }))); 
        assert_eq!(used + 4, full.len(), "exactly the frame body is consumed");
    }
}
