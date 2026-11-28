//! `tunnel-cli`: a local SOCKS5 proxy on top of the QUIC tunnel.
//!
//! The CLI runs the [`tunnel_core::TunnelClient`] engine and terminates TCP
//! connections in userspace: the SOCKS5 front-end accepts local applications
//! (browsers, curl, anything speaking SOCKS5), the userspace TCP/IP stack
//! ([`stack`], smoltcp) turns their streams into IP packets, and the tunnel
//! carries those packets to the server. No TUN device and no root: local
//! applications connect to a plain TCP listener on `127.0.0.1`.
//!
//! Layout:
//! - [`stack`] — smoltcp bridged onto the client's packet queues; outbound
//!   TCP sessions for the proxy and (for tests and embedding) inbound
//!   listeners;
//! - [`socks5`] — the SOCKS5 protocol front-end (CONNECT only, no auth —
//!   the listener is bound to the loopback interface);
//! - [`stats`] — periodic status/RTT/throughput reporting;
//! - [`error`] — the shared error type.

pub mod error;
pub mod socks5;
pub mod stack;
pub mod stats;

pub use error::StackError;
