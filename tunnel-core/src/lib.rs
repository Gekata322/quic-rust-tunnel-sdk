//! Client core of the B2B tunnel (`tunnel-core`).
//!
//! A library for embedding into mobile and desktop applications
//! (`cdylib`/`staticlib`, FFI via `uniffi`). Layers:
//!
//! 1. **FFI** ([`ffi`]) — the public SDK surface: five control methods
//!    ([`ffi::TunnelClient`]: `new`/`connect`/`disconnect`/`get_telemetry`/
//!    `set_status_callback`), the data plane `send_packet`/`recv_packet`,
//!    [`ffi::ConnectionStatus`] + callback, [`ffi::Telemetry`],
//!    [`ffi::TunnelConfig`].
//! 2. **Engine** ([`engine`]) — a background thread running the session loop:
//!    exponential backoff ([`backoff`]), QUIC connection migration on network
//!    changes, stop coordination, duplicate-free status callback notifications.
//! 3. **Session** ([`session`]) — one attempt: QUIC connection (`quinn`),
//!    the `Hello → Welcome/Reject` handshake with the pinned server
//!    certificate, the data plane on QUIC datagrams and keepalive with RTT.
//!
//! A network change (Wi-Fi ↔ cellular) does not cost a reconnect: the engine
//! rebinds the endpoint's UDP socket ([`crate::engine::EngineShared::migrate`])
//! and the QUIC connection migrates per RFC 9000 — the VIP and the data plane
//! survive. A reconnect happens only when the migration cannot be set up.
//!
//! Packets are exchanged with the platform through a poll model without
//! callback interfaces: the platform writes IP packets to
//! [`ffi::TunnelClient::send_packet`] and drains replies via
//! [`ffi::TunnelClient::recv_packet`] from a background thread.
//! The wire protocol is documented in the `tunnel-proto` crate; binding
//! generation (Kotlin, Swift, Python) — `cargo run -p tunnel-core --bin
//! uniffi-bindgen -- generate-all --library <lib> --out-dir <dir>`;
//! full SDK build — `./build_sdk.sh`.

pub mod backoff;
pub(crate) mod engine;
pub mod error;
pub mod ffi;
pub(crate) mod session;

pub use error::CoreError;
pub use ffi::{ConnectionStatus, ConnectionStatusCallback, Telemetry, TunnelClient, TunnelConfig};

// FFI namespace: a string literal is required by uniffi-macros.
uniffi::setup_scaffolding!("tunnel_core");
