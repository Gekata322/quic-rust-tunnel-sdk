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
//! 2. **Engine** ([`engine`]) — a background thread with the session loop:
//!    exponential backoff ([`backoff`]), network-change reaction, stop
//!    coordination, duplicate-free status notifications.
//! 3. **Session** ([`session`]) — a single attempt: QUIC connection (`quinn`),
//!    `Hello → Welcome/Reject` handshake with a pinned server certificate,
//!    data plane over QUIC datagrams, keepalive with RTT measurement.
//!
//! Packet exchange with the platform uses a poll model without callback
//! interfaces: the platform writes IP packets into
//! [`ffi::TunnelClient::send_packet`] and drains replies via
//! [`ffi::TunnelClient::recv_packet`] from a background thread.
//! The protocol lives in the `tunnel-proto` crate; binding generation
//! (Kotlin, Swift, Python) is `cargo run -p tunnel-core --bin uniffi-bindgen --
//! generate-all --library <lib> --out-dir <dir>`; full SDK build —
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
