//! Wire protocol for the B2B tunnel: the single contract shared by the
//! client core (`tunnel-core`) and the server (`tunnel-server`).
//!
//! Transport split:
//! - QUIC stream #0 is the control plane (handshake, ping/pong);
//! - QUIC datagrams are the data plane (raw IP packets).
//!
//! Wire formats:
//! - control message = 4-byte little-endian length prefix + bincode body
//!   (`bincode::config::legacy()`, fixed-width ints);
//! - datagram = one frame-kind byte ([`frame::KIND_IPV4`] / [`frame::KIND_IPV6`])
//!   followed by the raw IP packet;
//! - [`messages`] additionally exposes a bincode datagram variant
//!   ([`messages::WirePacket`]) for tests and tooling.
//!
//! Security invariants:
//! - tokens are compared in constant time ([`auth`]);
//! - control messages are bounded by `MAX_CONTROL_MESSAGE_SIZE`;
//! - the server never trusts IPv4 header fields: the sender address is
//!   rewritten to the client's assigned VIP ([`ipv4::rewrite_addresses`]).

pub mod auth;
pub mod frame;
pub mod ipv4;
pub mod messages;
pub mod metrics;

pub use messages::{
    decode_control, encode_control, unix_ms, ControlFromClient, ControlFromServer, Hello, Ping,
    Pong, Reject, RejectCode, Welcome, WirePacket, MAX_CONTROL_MESSAGE_SIZE, PROTOCOL_VERSION,
};
pub use metrics::{Metrics, MetricsSnapshot};

/// ALPN identifier negotiated during the QUIC handshake. Incompatible clients
/// are rejected before the TLS handshake completes.
pub const ALPN_TUNNEL_V1: &[u8] = b"tunnel/v1";
