//! Клиентское ядро B2B-туннеля (`tunnel-core`).
//!
//! Библиотека для встраивания в мобильные и десктопные приложения
//! (`cdylib`/`staticlib`, FFI через `uniffi`). Слои:
//!
//! 1. **FFI** ([`ffi`]) — публичный SDK-интерфейс: пять методов управления
//!    ([`ffi::TunnelClient`]: `new`/`connect`/`disconnect`/`get_telemetry`/
//!    `set_status_callback`), data plane `send_packet`/`recv_packet`,
//!    [`ffi::ConnectionStatus`] + коллбэк, [`ffi::Telemetry`],
//!    [`ffi::TunnelConfig`].
//! 2. **Движок** ([`engine`]) — фоновый поток с циклом сессий: экспоненциальный
//!    backoff ([`backoff`]), реакция на смену сети, координация остановки,
//!    уведомления коллбэка статуса без дубликатов.
//! 3. **Сессия** ([`session`]) — одна попытка: QUIC-подключение (`quinn`),
//!    рукопожатие `Hello → Welcome/Reject` с pinned-сертификатом сервера,
//!    data plane на QUIC-дейтаграммах и keepalive c измерением RTT.
//!
//! Обмен пакетами с платформой — poll-модель без callback-интерфейсов:
//! платформа пишет IP-пакеты в [`ffi::TunnelClient::send_packet`] и выкачивает
//! ответные через [`ffi::TunnelClient::recv_packet`] из фонового потока.
//! Протокол описан в крейте `tunnel-proto`; генерация биндингов (Kotlin,
//! Swift, Python) — `cargo run -p tunnel-core --bin uniffi-bindgen --
//! generate-all --library <lib> --out-dir <dir>`; сборка SDK целиком —
//! `./build_sdk.sh`.

pub mod backoff;
pub(crate) mod engine;
pub mod error;
pub mod ffi;
pub(crate) mod session;

pub use error::CoreError;
pub use ffi::{ConnectionStatus, ConnectionStatusCallback, Telemetry, TunnelClient, TunnelConfig};

// Пространство имён FFI: литерал обязателен (см. uniffi-macros).
uniffi::setup_scaffolding!("tunnel_core");
