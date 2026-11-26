//! Сервер B2B-туннеля: авторизация партнёров, выдача виртуальных адресов,
//! маршрутизация пакетов между клиентами и наружу, loopback-режим для CI.
//!
//! Слои:
//! - [`config`] — конфигурация из CLI/файла/env, загрузка токенов;
//! - [`endpoint`] — TLS/QUIC-эндпоинт (самоподписанный сертификат, ALPN),
//!   цикл приёма подключений;
//! - [`session`] — состояние сервера и обработка сессий: рукопожатие
//!   `Hello → Welcome/Reject`, control plane (ping/pong), data plane
//!   (дейтаграммы ⇄ [`routing`]/[`tun`]);
//! - [`pool`] — пул виртуальных IP с переиспользованием адресов;
//! - [`routing`] — таблица «выданный адрес → клиент».

pub mod config;
pub mod endpoint;
pub mod pool;
pub mod routing;
pub mod session;
pub mod tun;

pub use pool::IpPool;
pub use routing::RoutingTable;
pub use session::ServerShared;
