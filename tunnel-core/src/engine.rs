//! Движок ядра: цикл сессий, экспоненциальные переподключения, координация
//! остановки и смены сети.
//!
//! Движок живёт в выделенном фоновом потоке (однопоточный tokio-рантайм —
//! экономно для мобильных устройств). FFI-объект [`crate::ffi::TunnelClient`]
//! общается с ним через общее [`EngineShared`] (канал состояния + очереди
//! пакетов), не владея асинхронными типами напрямую.
//!
//! Каждый статус, видимый партнёру через коллбэк, вычисляется здесь
//! ([`EngineShared::notify_status`]): `Connected` → `Reconnecting` →
//! `Disconnected` без дубликатов, см. док в `ffi`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc as std_mpsc};

use tokio::sync::{mpsc, watch};

use tunnel_proto::Metrics;

use crate::backoff::Backoff;
use crate::ffi::{ConnectionStatus, ConnectionStatusCallback, TunnelConfig, TunnelState};
use crate::session::{SessionOutcome, run_session};

/// Длина очередей пакетов (оба направления). При переполнении входной очереди
/// `send_packet` возвращает платформе `false`; выходная очередь дропает пакет
/// и увеличивает счётчик `packets_dropped` — семантика UDP, а не затор.
const PACKET_QUEUE_LEN: usize = 256;

/// Состояние, разделяемое между FFI-объектом и потоком движка.
pub(crate) struct EngineShared {
    pub(crate) config: TunnelConfig,
    state_tx: watch::Sender<TunnelState>,
    pub(crate) state_rx: watch::Receiver<TunnelState>,
    /// Платформа → туннель (tokio, ограниченная очередь).
    pub(crate) packet_in_tx: mpsc::Sender<Vec<u8>>,
    /// Туннель → платформа (std sync_channel; FFI выкачивает с тайм-аутом).
    /// Receiver обёрнут в Mutex: std-тип не Sync, а параллельные recv-вызовы
    /// и так сериализуются по смыслу (один консьюмер).
    pub(crate) packet_out_tx: std_mpsc::SyncSender<Vec<u8>>,
    pub(crate) packet_out_rx: Mutex<std_mpsc::Receiver<Vec<u8>>>,
    /// Телеметрия: атомарные счётчики, снимок копируется в FFI по запросу.
    pub(crate) metrics: Arc<Metrics>,
    /// RTT последнего ping/pong, мс; 0 — ещё не измерялся в этой сессии.
    pub(crate) last_ping_ms: AtomicU64,
    /// Активное QUIC-соединение — для форс-закрытия при смене сети.
    active_conn: Mutex<Option<quinn::Connection>>,
    /// Партнёрский коллбэк статуса (uniffi callback-interface).
    callback: Mutex<Option<Box<dyn ConnectionStatusCallback>>>,
    /// Последний отправленный в коллбэк статус — для дедупликации уведомлений.
    last_status: Mutex<Option<ConnectionStatus>>,
    /// Была ли хотя бы одна успешная сессия: «Connecting после неё» —
    /// это `Reconnecting`, а не `Disconnected`.
    ever_connected: AtomicBool,
}

impl EngineShared {
    /// Собирает каналы и метрики. Приёмник входных пакетов возвращается
    /// отдельно: его забирает поток движка в `TunnelClient::connect`.
    pub(crate) fn new(config: TunnelConfig) -> (Arc<Self>, mpsc::Receiver<Vec<u8>>) {
        let (state_tx, state_rx) = watch::channel(TunnelState::Disconnected);
        let (packet_in_tx, packet_in_rx) = mpsc::channel(PACKET_QUEUE_LEN);
        let (packet_out_tx, packet_out_rx) = std_mpsc::sync_channel(PACKET_QUEUE_LEN);
        let shared = Arc::new(Self {
            config,
            state_tx,
            state_rx,
            packet_in_tx,
            packet_out_tx,
            packet_out_rx: Mutex::new(packet_out_rx),
            metrics: Arc::new(Metrics::default()),
            last_ping_ms: AtomicU64::new(0),
            active_conn: Mutex::new(None),
            callback: Mutex::new(None),
            last_status: Mutex::new(None),
            ever_connected: AtomicBool::new(false),
        });
        (shared, packet_in_rx)
    }

    /// Публикует новое состояние для FFI-наблюдателей и партнёрского коллбэка.
    pub(crate) fn set_state(&self, state: TunnelState) {
        self.state_tx.send_replace(state);
        self.notify_status();
    }

    /// Регистрирует партнёрский коллбэк (`None` — снять).
    /// После регистрации коллбэк сразу получает текущий статус.
    pub(crate) fn set_callback(&self, callback: Option<Box<dyn ConnectionStatusCallback>>) {
        if let Ok(mut slot) = self.callback.lock() {
            *slot = callback;
        }
        if let Ok(mut last) = self.last_status.lock() {
            // Принудительно повторить текущий статус новому коллбэку.
            *last = None;
        }
        self.notify_status();
    }

    /// Считает статус по внутреннему состоянию и уведомляет коллбэк
    /// только при реальной смене (без дубликатов при каждом ретрае).
    fn notify_status(&self) {
        let state = self.state_rx.borrow().clone();
        if matches!(state, TunnelState::Connected { .. }) {
            self.ever_connected.store(true, Ordering::Relaxed);
        }
        let status = match &state {
            TunnelState::Connected { mtu, vip } => ConnectionStatus::Connected {
                mtu: *mtu,
                vip: vip.clone(),
            },
            // Корректная остановка или постоянная ошибка — соединения нет.
            TunnelState::Stopping | TunnelState::Stopped => ConnectionStatus::Disconnected,
            // Попытка подключения/backoff: до первой успешной сессии это
            // просто «нет соединения», после — восстановление.
            TunnelState::Connecting | TunnelState::Disconnected => {
                if self.ever_connected.load(Ordering::Relaxed) {
                    ConnectionStatus::Reconnecting
                } else {
                    ConnectionStatus::Disconnected
                }
            }
        };

        let Ok(mut last) = self.last_status.lock() else {
            return;
        };
        if *last == Some(status.clone()) {
            return;
        }
        *last = Some(status.clone());
        drop(last);

        // Коллбэк под мьютексом: повторный вход set_status_callback из
        // коллбэка невозможен — контракт требует быстрого, нереентерабельного
        // обработчика (см. док `ConnectionStatusCallback`).
        if let Ok(slot) = self.callback.lock() {
            if let Some(callback) = slot.as_ref() {
                callback.on_status_change(status);
            }
        }
    }

    /// Сбрасывает пинг (новая сессия — старые измерения недействительны).
    pub(crate) fn reset_ping(&self) {
        self.last_ping_ms.store(0, Ordering::Relaxed);
    }

    /// Запоминает активное QUIC-соединение (или очищает слот).
    pub(crate) fn set_active_conn(&self, conn: Option<quinn::Connection>) {
        if let Ok(mut slot) = self.active_conn.lock() {
            *slot = conn;
        }
    }

    /// Подсказка о смене сети: активное QUIC-соединение немедленно закрывается,
    /// движок выходит из сессии и подключается заново (уже на новом интерфейсе).
    pub(crate) fn force_reconnect(&self) {
        let conn = match self.active_conn.lock() {
            Ok(mut slot) => slot.take(),
            Err(_) => return,
        };
        if let Some(conn) = conn {
            tracing::info!("смена сети: закрываю активное QUIC-соединение");
            conn.close(quinn::VarInt::from_u32(0), b"network-changed");
        }
    }

    /// Корректная остановка: идемпотентно, `Stopped` не перезаписывает.
    pub(crate) fn request_stop(&self) {
        let changed = self.state_tx.send_if_modified(|state| {
            if matches!(state, TunnelState::Stopped) {
                false
            } else {
                *state = TunnelState::Stopping;
                true
            }
        });
        if changed {
            self.notify_status();
        }
    }

    /// Финальное состояние после завершения цикла движка.
    pub(crate) fn finish_stop(&self) {
        let changed = self.state_tx.send_if_modified(|state| {
            if matches!(state, TunnelState::Stopped) {
                false
            } else {
                *state = TunnelState::Stopped;
                true
            }
        });
        if changed {
            self.notify_status();
        }
    }
}

/// Ждёт команду остановки (Stopping/Stopped) на клоне watch-канала.
pub(crate) async fn wait_stopping(stop_rx: &mut watch::Receiver<TunnelState>) {
    loop {
        if matches!(*stop_rx.borrow(), TunnelState::Stopping | TunnelState::Stopped) {
            return;
        }
        // Канал живёт столько же, сколько FFI-объект: ошибка означает
        // закрытие отправителя — трактуем как остановку.
        if stop_rx.changed().await.is_err() {
            return;
        }
    }
}

/// Главная петля движка: попытка сессии → разбор исхода → backoff → ретрай.
/// Завершается по `request_stop()` (`Shutdown`) или постоянной ошибке.
pub(crate) async fn run(shared: Arc<EngineShared>, mut packet_in_rx: mpsc::Receiver<Vec<u8>>) {
    let mut backoff = Backoff::from_config(&shared.config);
    shared.set_state(TunnelState::Connecting);

    loop {
        let outcome = run_session(&shared, &mut packet_in_rx).await;
        let mut stop_rx = shared.state_rx.clone();
        match outcome {
            // `disconnect()` или drop FFI-объекта — выходим из цикла.
            SessionOutcome::Shutdown => {
                shared.set_active_conn(None);
                break;
            }
            SessionOutcome::Closed { cause, established } => {
                // Постоянные ошибки (токен, версия, конфиг) не лечатся ретраями.
                if cause.is_permanent() {
                    tracing::warn!(%cause, "постоянная ошибка: движок остановлен");
                    shared.set_active_conn(None);
                    shared.set_state(TunnelState::Stopped);
                    return;
                }
                shared.set_active_conn(None);
                if established {
                    // Сессия была рабочей: ретраим быстро, считаем reconnect.
                    tracing::info!(%cause, "сессия оборвалась: переподключаюсь");
                    shared.metrics.record_reconnect();
                    backoff.reset();
                } else {
                    tracing::info!(%cause, "попытка не удалась: backoff");
                }
                shared.set_state(TunnelState::Disconnected);
                let delay = backoff.next();
                tokio::select! {
                    biased;
                    _ = wait_stopping(&mut stop_rx) => break,
                    _ = tokio::time::sleep(delay) => shared.set_state(TunnelState::Connecting),
                }
            }
        }
    }

    shared.finish_stop();
}

#[cfg(test)]
mod tests {
    // В тестах допустимы unwrap/expect: падение теста — это и есть сигнал.
    use super::*;
    use std::time::Duration;

    fn sample_config() -> TunnelConfig {
        TunnelConfig {
            server_host: "127.0.0.1".to_owned(),
            server_name: "localhost".to_owned(),
            server_port: 4433,
            auth_token: "sample-token".to_owned(),
            client_id: "engine-test".to_owned(),
            pinned_server_cert_der: vec![0x30],
            connect_timeout_ms: 1000,
            min_backoff_ms: 50,
            max_backoff_ms: 200,
            keepalive_interval_secs: 0,
        }
    }

    #[test]
    fn packet_queues_are_bounded() {
        let (shared, mut packet_in_rx) = EngineShared::new(sample_config());
        // Входная очередь: PACKET_QUEUE_LEN пакетов помещается, следующий — нет.
        let packet = vec![0x45, 0x00];
        for _ in 0..PACKET_QUEUE_LEN {
            assert!(shared.packet_in_tx.try_send(packet.clone()).is_ok());
        }
        assert!(
            shared.packet_in_tx.try_send(packet).is_err(),
            "очередь входа обязана быть ограниченной"
        );
        // Выходная очередь: приёмник забирает всё обратно.
        assert!(shared.packet_out_tx.try_send(vec![0x60]).is_ok());
        let drained = shared.packet_out_rx.lock().unwrap().recv().unwrap();
        assert_eq!(drained, vec![0x60]);
        let _ = packet_in_rx.try_recv();
    }

    #[tokio::test]
    async fn force_reconnect_without_active_conn_is_noop() {
        let (shared, _rx) = EngineShared::new(sample_config());
        // Не должно паниковать при пустом слоте соединения.
        shared.force_reconnect();
    }

    /// Тестовый коллбэк: собирает статусы в общий буфер.
    struct Collector {
        events: Arc<Mutex<Vec<ConnectionStatus>>>,
    }
    impl ConnectionStatusCallback for Collector {
        fn on_status_change(&self, status: ConnectionStatus) {
            self.events.lock().unwrap().push(status);
        }
    }

    #[test]
    fn status_callback_full_lifecycle() {
        let (shared, _rx) = EngineShared::new(sample_config());
        let events = Arc::new(Mutex::new(Vec::new()));
        shared.set_callback(Some(Box::new(Collector { events: Arc::clone(&events) })));

        // Регистрация повторяет текущий статус: до connect() это Disconnected.
        assert_eq!(*events.lock().unwrap(), vec![ConnectionStatus::Disconnected]);

        // Первая попытка подключения: без «восстановления» — Reconnecting
        // имеет смысл только после успешной сессии.
        shared.set_state(TunnelState::Connecting);
        assert_eq!(*events.lock().unwrap(), vec![ConnectionStatus::Disconnected]);

        shared.set_state(TunnelState::Connected {
            mtu: 1280,
            vip: "10.66.0.2".to_owned(),
        });
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                ConnectionStatus::Disconnected,
                ConnectionStatus::Connected {
                    mtu: 1280,
                    vip: "10.66.0.2".to_owned(),
                },
            ]
        );

        // Разрыв сессии и ретрай-цикл: один Reconnecting без дубликатов.
        shared.set_state(TunnelState::Connecting);
        shared.set_state(TunnelState::Disconnected);
        shared.set_state(TunnelState::Connecting);
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                ConnectionStatus::Disconnected,
                ConnectionStatus::Connected {
                    mtu: 1280,
                    vip: "10.66.0.2".to_owned(),
                },
                ConnectionStatus::Reconnecting,
            ]
        );

        // Корректная остановка → Disconnected; финал Stopped не дублирует.
        shared.request_stop();
        shared.finish_stop();
        assert_eq!(
            *events.lock().unwrap(),
            vec![
                ConnectionStatus::Disconnected,
                ConnectionStatus::Connected {
                    mtu: 1280,
                    vip: "10.66.0.2".to_owned(),
                },
                ConnectionStatus::Reconnecting,
                ConnectionStatus::Disconnected,
            ]
        );
    }

    #[tokio::test]
    async fn wait_stopping_fires_on_request() {
        let (shared, _rx) = EngineShared::new(sample_config());
        let mut stop_rx = shared.state_rx.clone();
        tokio::select! {
            _ = wait_stopping(&mut stop_rx) => panic!("без команды остановки не должен завершиться"),
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
        shared.request_stop();
        tokio::select! {
            _ = wait_stopping(&mut stop_rx) => {} // команда увидена
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                panic!("wait_stopping не увидел request_stop")
            }
        }
    }
}
