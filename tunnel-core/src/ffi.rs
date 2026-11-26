//! Публичный SDK-интерфейс ядра (`uniffi`): контракт для партнёрских SDK.
//!
//! Управление сессией — ровно **пять методов**:
//!
//! | Метод | Назначение |
//! |---|---|
//! | `TunnelClient(config)` | создать клиент (валидация конфига) |
//! | `connect()` | запустить фоновый движок (идемпотентно) |
//! | `disconnect()` | корректно остановить (не блокирует) |
//! | `get_telemetry()` | трафик (байты) и последний пинг |
//! | `set_status_callback(cb)` | уведомления о смене статуса подключения |
//!
//! Плюс обязательный для туннеля data plane: `send_packet` / `recv_packet`
//! (poll-модель) и подсказка о смене сети `on_network_changed`. Обмен пакетами
//! сознательно без коллбэков: poll-модель даёт естественный backpressure и
//! надёжно работает поверх FFI на iOS/Android (см. док на методах).
//!
//! Коллбэк статуса, наоборот, инвертирует управление: партнёру не нужно
//! опрашивать состояние — ядро само уведомляет о [`ConnectionStatus::Connected`],
//! [`ConnectionStatus::Reconnecting`] и [`ConnectionStatus::Disconnected`].

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::engine::{EngineShared, run};
use crate::error::CoreError;

/// Внутреннее состояние движка (в FFI-контракт не входит; партнёру отдается
/// [`ConnectionStatus`]). Видно тестам через [`TunnelClient::state`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelState {
    /// Не запущен либо ожидание ретрая.
    Disconnected,
    /// Идёт установка соединения/рукопожатие (или backoff перед ретраем).
    Connecting,
    /// Сессия установлена: MTU и виртуальный адрес из `Welcome`.
    Connected { mtu: u16, vip: String },
    /// Идёт корректная остановка после `disconnect()`.
    Stopping,
    /// Остановлено на постоянной ошибке (отклонён токен, версия протокола,
    /// битый сертификат). Движок не поднимается — создайте новый клиент.
    Stopped,
}

/// Статус подключения для партнёрского коллбэка — ровно три состояния.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ConnectionStatus {
    /// Сессия установлена: `mtu` — MTU виртуального интерфейса (настройте им
    /// TUN), `vip` — выданный адрес клиента (адрес интерфейса).
    Connected { mtu: u16, vip: String },
    /// Движок восстанавливает соединение после хотя бы одной успешной сессии:
    /// идёт попытка подключения или backoff перед ретраем.
    Reconnecting,
    /// Нет соединения: клиент создан, остановлен `disconnect()` либо движок
    /// остановился на постоянной ошибке (токен, версия протокола).
    Disconnected,
}

/// Коллбэк смены статуса; реализуется на платформенной стороне (uniffi
/// callback-interface). Вызывается из внутренних потоков ядра: обязан быть
/// быстрым и НЕ вызывать методы SDK внутри себя (риск deadlock).
#[uniffi::export(callback_interface)]
pub trait ConnectionStatusCallback: Send + Sync {
    /// Единственное уведомление; статусы идут без дубликатов.
    fn on_status_change(&self, status: ConnectionStatus);
}

/// Телеметрия для партнёра: трафик и последний пинг.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct Telemetry {
    /// Отправлено байт payload через туннель (с момента создания клиента).
    pub bytes_sent: u64,
    /// Принято байт payload из туннеля (с момента создания клиента).
    pub bytes_received: u64,
    /// RTT последнего ping/pong, мс; `None` — ещё не измерялся.
    pub ping_ms: Option<u32>,
}

/// Конфигурация клиента. Обязательные поля: `server_host`, `server_port`,
/// `auth_token`, `pinned_server_cert_der`; у остальных — рекомендованные
/// значения по умолчанию, заданные на FFI-границе (в Kotlin/Swift/Python).
#[derive(Debug, Clone, uniffi::Record)]
pub struct TunnelConfig {
    /// Хост или IP сервера (DNS резолвится на каждый ретрай).
    pub server_host: String,
    /// Имя сервера для SNI и проверки сертификата; пусто — берётся `server_host`.
    #[uniffi(default = "")]
    pub server_name: String,
    /// UDP-порт сервера (обычно 443).
    pub server_port: u16,
    /// B2B-токен авторизации (выдаётся оператором сервера партнёру).
    pub auth_token: String,
    /// Идентификатор клиента для логов/телеметрии сервера; пусто — `sdk-client`.
    #[uniffi(default = "")]
    pub client_id: String,
    /// DER-байты сертификата сервера (pinned root) — единственный доверенный
    /// корень TLS; public CA не используются.
    pub pinned_server_cert_der: Vec<u8>,
    /// Тайм-аут на connect+рукопожатие, мс.
    #[uniffi(default = 8000)]
    pub connect_timeout_ms: u32,
    /// Минимальная задержка перед ретраем, мс.
    #[uniffi(default = 500)]
    pub min_backoff_ms: u32,
    /// Максимальная задержка перед ретраем, мс.
    #[uniffi(default = 30000)]
    pub max_backoff_ms: u32,
    /// Период прикладного ping, сек; 0 — из `Welcome` сервера, иначе 15 сек.
    #[uniffi(default = 0)]
    pub keepalive_interval_secs: u32,
}

/// Подставляет значения по умолчанию для необязательных полей конфига.
fn normalize_config(mut config: TunnelConfig) -> TunnelConfig {
    if config.server_name.trim().is_empty() {
        config.server_name = config.server_host.clone();
    }
    if config.client_id.trim().is_empty() {
        config.client_id = "sdk-client".to_owned();
    }
    config
}

/// Валидация конфигурации до старта движка: ранние и понятные ошибки вместо
/// молчаливо неуспешных подключений.
fn validate_config(config: &TunnelConfig) -> Result<(), CoreError> {
    let check = |cond: bool, message: &str| {
        if cond {
            Ok(())
        } else {
            Err(CoreError::InvalidConfig(message.to_owned()))
        }
    };
    check(!config.server_host.trim().is_empty(), "server_host пуст")?;
    check(config.server_port > 0, "server_port равен нулю")?;
    check(!config.auth_token.is_empty(), "auth_token пуст")?;
    check(!config.pinned_server_cert_der.is_empty(), "pinned_server_cert_der пуст")?;
    check(config.connect_timeout_ms > 0, "connect_timeout_ms равен нулю")?;
    check(config.min_backoff_ms > 0, "min_backoff_ms равен нулю")?;
    check(
        config.max_backoff_ms >= config.min_backoff_ms,
        "max_backoff_ms меньше min_backoff_ms",
    )?;
    Ok(())
}

/// Точка входа SDK: пять методов управления + обмен пакетами.
///
/// Все методы потокобезопасны. `recv_packet` блокирует поток до тайм-аута —
/// вызывайте его из выделенного фонового потока (НЕ из main/UI-потока).
#[derive(uniffi::Object)]
pub struct TunnelClient {
    shared: Arc<EngineShared>,
    /// Приёмник платформа→туннель; изымается в `connect()` и уходит в движок.
    packet_in_rx: Mutex<Option<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
    /// Держатель потока движка; не join-ится в `disconnect()` (неблокирующий стоп).
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

#[uniffi::export]
impl TunnelClient {
    /// Создаёт клиент и проверяет конфигурацию; соединение устанавливается
    /// после `connect()`. Метод не блокирует.
    #[uniffi::constructor]
    pub fn new(config: TunnelConfig) -> Result<Self, CoreError> {
        let config = normalize_config(config);
        validate_config(&config)?;
        let (shared, packet_in_rx) = EngineShared::new(config);
        Ok(Self {
            shared,
            packet_in_rx: Mutex::new(Some(packet_in_rx)),
            worker: Mutex::new(None),
        })
    }

    /// Запускает фоновый движок (переподключения, keepalive, data plane).
    /// Идемпотентно: повторный вызов на живом движке — no-op.
    /// После постоянной ошибки движок не поднимается — создайте новый клиент.
    pub fn connect(&self) -> Result<(), CoreError> {
        let mut worker = self
            .worker
            .lock()
            .map_err(|_| CoreError::Internal("worker-мьютекс отравлен".to_owned()))?;
        if worker.is_some() {
            return Ok(());
        }
        let packet_in_rx = self
            .packet_in_rx
            .lock()
            .map_err(|_| CoreError::Internal("packet-мьютекс отравлен".to_owned()))?
            .take()
            .ok_or_else(|| {
                CoreError::Internal(
                    "движок уже отработал полный цикл; создайте новый TunnelClient".to_owned(),
                )
            })?;

        let shared = Arc::clone(&self.shared);
        let handle = std::thread::Builder::new()
            .name("tunnel-core".to_owned())
            .spawn(move || {
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        tracing::error!(%err, "не удалось создать tokio-рантайм");
                        shared.finish_stop();
                        return;
                    }
                };
                runtime.block_on(run(shared, packet_in_rx));
            })
            .map_err(|err| {
                CoreError::Internal(format!("не удалось запустить поток движка: {err}"))
            })?;
        *worker = Some(handle);
        Ok(())
    }

    /// Корректно останавливает движок. Не блокирует: поток движка завершится
    /// сам, увидев команду остановки (подключение, сессия, ретрай). Идемпотентно.
    pub fn disconnect(&self) {
        self.shared.request_stop();
        // Держатель потока не join-им, чтобы disconnect() не блокировал
        // FFI-поток на время дрейна сессии; поток умирает по wait_stopping.
        if let Ok(mut worker) = self.worker.lock() {
            let _ = worker.take();
        }
    }

    /// Регистрирует коллбэк смены статуса (`None` — снять).
    ///
    /// Коллбэк вызывается из внутренних потоков ядра; он должен быть быстрым
    /// и не вызывать методы SDK внутри себя. После регистрации сразу придёт
    /// текущий статус — партнёру не нужно отдельно запрашивать состояние.
    pub fn set_status_callback(&self, callback: Option<Box<dyn ConnectionStatusCallback>>) {
        self.shared.set_callback(callback);
    }

    /// Снимок телеметрии: трафик и последний пинг (с момента создания клиента).
    pub fn get_telemetry(&self) -> Telemetry {
        let snapshot = self.shared.metrics.snapshot();
        let ping = self.shared.last_ping_ms.load(Ordering::Relaxed);
        Telemetry {
            bytes_sent: snapshot.bytes_sent,
            bytes_received: snapshot.bytes_received,
            ping_ms: if ping == 0 {
                None
            } else {
                Some(ping.min(u32::MAX as u64) as u32)
            },
        }
    }

    /// Отправляет сырой IP-пакет от платформенного TUN в туннель.
    ///
    /// Неблокирующий. Возвращает `false`, если очередь переполнена —
    /// пакет выбрасывается (семантика UDP; TCP-потоки внутри туннеля
    /// ретранслируют сами).
    pub fn send_packet(&self, packet: Vec<u8>) -> bool {
        if packet.is_empty() {
            return false;
        }
        self.shared.packet_in_tx.try_send(packet).is_ok()
    }

    /// Выкачивает пакет из туннеля для записи в платформенный TUN.
    ///
    /// Блокирует поток до `timeout_ms`; `None` — тайм-аут или движок закрыл
    /// поток. Вызывать из выделенного фонового потока; параллельные вызовы
    /// сериализуются (консьюмер по контракту один).
    pub fn recv_packet(&self, timeout_ms: u32) -> Option<Vec<u8>> {
        let rx = self.shared.packet_out_rx.lock().ok()?;
        rx.recv_timeout(Duration::from_millis(u64::from(timeout_ms)))
            .ok()
    }

    /// Подсказка о смене сети (Wi-Fi ↔ cellular): активное QUIC-соединение
    /// закрывается, движок немедленно переподключается на новом интерфейсе.
    pub fn on_network_changed(&self) {
        self.shared.force_reconnect();
    }
}

/// Методы для Rust-тестов: в FFI-контракт не входят (партнёру достаточно
/// `ConnectionStatus` и `get_telemetry`).
impl TunnelClient {
    /// Текущее внутреннее состояние движка.
    pub fn state(&self) -> TunnelState {
        self.shared.state_rx.borrow().clone()
    }

    /// MTU, согласованный сервером в текущей сессии (`Welcome.mtu`).
    pub fn negotiated_mtu(&self) -> Option<u16> {
        match self.shared.state_rx.borrow().clone() {
            TunnelState::Connected { mtu, .. } => Some(mtu),
            _ => None,
        }
    }

    /// Виртуальный адрес клиента в текущей сессии (`Welcome.vip`).
    pub fn negotiated_vip(&self) -> Option<String> {
        match self.shared.state_rx.borrow().clone() {
            TunnelState::Connected { vip, .. } => Some(vip),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    // В тестах допустимы unwrap/expect: падение теста — это и есть сигнал.
    use super::*;

    fn config() -> TunnelConfig {
        TunnelConfig {
            server_host: "127.0.0.1".to_owned(),
            server_name: "localhost".to_owned(),
            server_port: 443,
            auth_token: "token".to_owned(),
            client_id: "test".to_owned(),
            pinned_server_cert_der: vec![0x30],
            connect_timeout_ms: 1000,
            min_backoff_ms: 50,
            max_backoff_ms: 200,
            keepalive_interval_secs: 0,
        }
    }

    #[test]
    fn config_validation() {
        assert!(validate_config(&config()).is_ok());

        let mut bad = config();
        bad.auth_token = String::new();
        assert!(matches!(validate_config(&bad), Err(CoreError::InvalidConfig(_))));

        let mut bad = config();
        bad.max_backoff_ms = 10;
        bad.min_backoff_ms = 100;
        assert!(matches!(validate_config(&bad), Err(CoreError::InvalidConfig(_))));

        let mut bad = config();
        bad.pinned_server_cert_der = Vec::new();
        assert!(matches!(validate_config(&bad), Err(CoreError::InvalidConfig(_))));

        let mut bad = config();
        bad.connect_timeout_ms = 0;
        assert!(matches!(validate_config(&bad), Err(CoreError::InvalidConfig(_))));
    }

    #[test]
    fn normalize_fills_optional_fields() {
        let mut cfg = config();
        cfg.server_name = "  ".to_owned();
        cfg.client_id = String::new();
        let cfg = normalize_config(cfg);
        assert_eq!(cfg.server_name, "127.0.0.1", "server_name → server_host");
        assert_eq!(cfg.client_id, "sdk-client");
    }

    #[test]
    fn telemetry_snapshot_converts() {
        let client = TunnelClient::new(config()).expect("клиент");
        let telemetry = client.get_telemetry();
        assert_eq!(telemetry.bytes_sent, 0);
        assert_eq!(telemetry.bytes_received, 0);
        assert_eq!(telemetry.ping_ms, None, "пинг не измерялся");

        client.shared.last_ping_ms.store(42, Ordering::Relaxed);
        assert_eq!(client.get_telemetry().ping_ms, Some(42));

        // RTT меньше миллисекунды в коде хранится как 0 → телеметрия скрывает.
        client.shared.last_ping_ms.store(0, Ordering::Relaxed);
        assert_eq!(client.get_telemetry().ping_ms, None);
    }

    #[test]
    fn empty_packet_is_rejected_without_queue() {
        let client = TunnelClient::new(config()).expect("клиент");
        assert!(!client.send_packet(Vec::new()));
    }

    /// Тестовый коллбэк: собирает статусы в общий для теста буфер.
    struct Collector {
        events: Arc<std::sync::Mutex<Vec<ConnectionStatus>>>,
    }
    impl ConnectionStatusCallback for Collector {
        fn on_status_change(&self, status: ConnectionStatus) {
            self.events.lock().unwrap().push(status);
        }
    }

    #[test]
    fn set_callback_repeats_current_status_then_dedupes() {
        let client = TunnelClient::new(config()).expect("клиент");
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        client.set_status_callback(Some(Box::new(Collector {
            events: Arc::clone(&events),
        })));

        // Коллбэку сразу отдаётся текущий статус — отдельно опрашивать не нужно.
        assert_eq!(*events.lock().unwrap(), vec![ConnectionStatus::Disconnected]);

        // disconnect() до connect(): переходы в те же статусы не дублируются.
        client.disconnect();
        assert_eq!(*events.lock().unwrap(), vec![ConnectionStatus::Disconnected]);
    }
}
