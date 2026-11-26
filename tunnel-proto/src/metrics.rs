//! Счётчики телеметрии: атомарные, без блокировок, общий для клиента и
//! сервера. Снимок ([`MetricsSnapshot`]) копируется по запросу — FFI-слой
//! клиентского ядра отдаёт его платформе как «трафик за жизнь клиента».

use std::sync::atomic::{AtomicU64, Ordering};

/// Атомарные счётчики туннеля (один экземпляр на клиента/сервер).
#[derive(Debug, Default)]
pub struct Metrics {
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    datagrams_sent: AtomicU64,
    datagrams_received: AtomicU64,
    packets_dropped: AtomicU64,
    sessions_established: AtomicU64,
    reconnects: AtomicU64,
}

impl Metrics {
    /// Учтёт `n` отправленных байт payload.
    pub fn record_bytes_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    /// Учтёт `n` принятых байт payload.
    pub fn record_bytes_received(&self, n: u64) {
        self.bytes_received.fetch_add(n, Ordering::Relaxed);
    }

    /// Учтёт отправленную дейтаграмму data plane.
    pub fn record_datagram_sent(&self) {
        self.datagrams_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Учтёт принятую дейтаграмму data plane.
    pub fn record_datagram_received(&self) {
        self.datagrams_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Учтёт сброшенные пакеты (переполнение очереди, неизвестный кадр).
    pub fn record_packets_dropped(&self, n: u64) {
        self.packets_dropped.fetch_add(n, Ordering::Relaxed);
    }

    /// Учтёт установленную сессию (после `Welcome`).
    pub fn record_session_established(&self) {
        self.sessions_established.fetch_add(1, Ordering::Relaxed);
    }

    /// Учтёт переподключение после разрыва установленной сессии.
    pub fn record_reconnect(&self) {
        self.reconnects.fetch_add(1, Ordering::Relaxed);
    }

    /// Снимок: согласованность между полями не гарантируется (атомики
    /// читаются независимо), для операционной телеметрии этого достаточно.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        MetricsSnapshot {
            bytes_sent: load(&self.bytes_sent),
            bytes_received: load(&self.bytes_received),
            datagrams_sent: load(&self.datagrams_sent),
            datagrams_received: load(&self.datagrams_received),
            packets_dropped: load(&self.packets_dropped),
            sessions_established: load(&self.sessions_established),
            reconnects: load(&self.reconnects),
        }
    }
}

/// Снимок счётчиков на момент вызова.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MetricsSnapshot {
    /// Отправлено байт payload через туннель.
    pub bytes_sent: u64,
    /// Принято байт payload из туннеля.
    pub bytes_received: u64,
    /// Отправлено дейтаграмм data plane.
    pub datagrams_sent: u64,
    /// Принято дейтаграмм data plane.
    pub datagrams_received: u64,
    /// Сброшено пакетов (переполнение очереди, мусорные кадры).
    pub packets_dropped: u64,
    /// Установлено сессий (рукопожатий, завершившихся `Welcome`).
    pub sessions_established: u64,
    /// Восстановлений после разрыва установленной сессии.
    pub reconnects: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_accumulate_and_snapshot() {
        let metrics = Metrics::default();
        let snap = metrics.snapshot();
        assert_eq!(snap, MetricsSnapshot::default(), "новые счётчики нулевые");

        metrics.record_bytes_sent(100);
        metrics.record_bytes_received(50);
        metrics.record_datagram_sent();
        metrics.record_datagram_sent();
        metrics.record_datagram_received();
        metrics.record_packets_dropped(3);
        metrics.record_session_established();
        metrics.record_reconnect();

        let snap = metrics.snapshot();
        assert_eq!(snap.bytes_sent, 100);
        assert_eq!(snap.bytes_received, 50);
        assert_eq!(snap.datagrams_sent, 2);
        assert_eq!(snap.datagrams_received, 1);
        assert_eq!(snap.packets_dropped, 3);
        assert_eq!(snap.sessions_established, 1);
        assert_eq!(snap.reconnects, 1);
    }

    #[test]
    fn snapshot_is_a_copy_not_a_view() {
        let metrics = Metrics::default();
        let snap = metrics.snapshot();
        metrics.record_bytes_sent(10);
        assert_eq!(snap.bytes_sent, 0, "снимок не изменяется задним числом");
        assert_eq!(metrics.snapshot().bytes_sent, 10);
    }

    #[test]
    fn byte_counts_are_additive() {
        let metrics = Metrics::default();
        for n in [1u64, 22, 1280] {
            metrics.record_bytes_sent(n);
            metrics.record_bytes_received(n);
        }
        let snap = metrics.snapshot();
        assert_eq!(snap.bytes_sent, 1303);
        assert_eq!(snap.bytes_received, 1303);
    }

    #[test]
    fn sessions_and_reconnects_are_independent() {
        let metrics = Metrics::default();
        metrics.record_session_established();
        metrics.record_session_established();
        metrics.record_reconnect();
        let snap = metrics.snapshot();
        assert_eq!(snap.sessions_established, 2);
        assert_eq!(snap.reconnects, 1);
    }
}
