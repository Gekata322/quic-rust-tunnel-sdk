//! Client core of the B2B tunnel (`tunnel-core`).
//!
//! A library for embedding into mobile and desktop apps (`cdylib`/`staticlib`,
//! FFI via `uniffi`). Layers:
//!
//! 1. **FFI** ([`ffi`]) — the public SDK surface: five control methods
//!    ([`ffi::TunnelClient`]: `new`/`connect`/`disconnect`/`get_telemetry`/
//!    `set_status_callback`), the data plane `send_packet`/`recv_packet`,
//!    [`ffi::ConnectionStatus`] + callback, [`ffi::Telemetry`],
//!    [`ffi::TunnelConfig`].
//! 2. **Engine** ([`engine`]) — a background thread running the session loop:
//!    exponential backoff ([`backoff`]), network-change handling, stop
//!    coordination, duplicate-free status notifications.
//! 3. **Session** ([`session`]) — one attempt: QUIC connect (`quinn`), the
//!    `Hello → Welcome/Reject` handshake against the pinned server
//!    certificate, data plane over QUIC datagrams, keepalive with RTT.
//!
//! Packets are exchanged with the platform via a poll model (no callback
//! interfaces): the platform writes IP packets to
//! [`ffi::TunnelClient::send_packet`] and drains replies through
//! [`ffi::TunnelClient::recv_packet`] from a background thread. The wire
//! protocol lives in the `tunnel-proto` crate; binding generation (Kotlin,
//! Swift, Python) is `cargo run -p tunnel-core --bin uniffi-bindgen --
//! generate-all --library <lib> --out-dir <dir>`; the full SDK build is
//! `./build_sdk.sh`.

pub mod backoff;
pub(crate) mod engine;
pub mod error;
pub mod ffi;
pub(crate) mod session;

pub use error::CoreError;
pub use ffi::{ConnectionStatus, ConnectionStatusCallback, Telemetry, TunnelClient, TunnelConfig};

// FFI namespace: a literal is required (see uniffi-macros).
uniffi::setup_scaffolding!("tunnel_core");
