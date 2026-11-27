//! B2B tunnel server: partner authorization, virtual address assignment,
//! packet routing between clients and to the outside, loopback mode for CI.
//!
//! Layers:
//! - [`config`] — configuration from CLI/file/env, token loading;
//! - [`endpoint`] — the TLS/QUIC endpoint (self-signed certificate, ALPN)
//!   and the accept loop;
//! - [`session`] — server state and session handling: the `Hello →
//!   Welcome/Reject` handshake, the control plane (ping/pong), the data plane
//!   (datagrams ⇄ [`routing`]/[`tun`]);
//! - [`pool`] — the virtual IP pool with address reuse;
//! - [`routing`] — the "assigned address → client" table;
//! - [`ratelimit`] — per-client token-bucket caps for the data plane;
//! - [`reaper`] — the idle-session reaper that protects the address pool
//!   from clients that vanished without a close.

pub mod config;
pub mod endpoint;
pub mod pool;
pub mod ratelimit;
pub mod reaper;
pub mod routing;
pub mod session;
pub mod tun;

pub use pool::IpPool;
pub use routing::RoutingTable;
pub use session::ServerShared;
