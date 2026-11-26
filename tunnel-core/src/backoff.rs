//! Экспоненциальный backoff с джиттером: пауза между ретраями подключения.
//!
//! Политика: первая задержка — `min_backoff_ms`, каждая следующая удваивается
//! до `max_backoff_ms`; к результату добавляется случайный джиттер ±20%, чтобы
//! флот клиентов после перезапуска сервера не атаковал его синхронной волной
//! (thundering herd). После успешной сессии счётчик сбрасывается: разрыв через
//! секунду работы — не повод ждать 30 секунд до первого ретрая.

use std::time::Duration;

use crate::ffi::TunnelConfig;

/// Экспоненциальная задержка с джиттером.
pub(crate) struct Backoff {
    min: Duration,
    max: Duration,
    /// База без джиттера: растёт x2 при каждом `next`, сбрасывается `reset`.
    base: Duration,
    /// Псевдослучайное состояние (xorshift) — детерминируемо в тестах.
    seed: u64,
}

impl Backoff {
    /// Собирает backoff из конфигурации клиента (мс → Duration).
    pub(crate) fn from_config(config: &TunnelConfig) -> Self {
        Self::new(config.min_backoff_ms, config.max_backoff_ms)
    }

    pub(crate) fn new(min_ms: u32, max_ms: u32) -> Self {
        let min = Duration::from_millis(u64::from(min_ms.max(1)));
        let max = Duration::from_millis(u64::from(max_ms.max(min_ms)));
        Self {
            min,
            max,
            base: min,
            seed: 0x9E37_79B9_7F4A_7C15, // фиксированный «золотой» семпл
        }
    }

    /// Следующий xorshift-шаг: псевдослучайный [0..1) без внешних крейтов.
    fn jitter_unit(&mut self) -> f64 {
        // xorshift64*: хватает для джиттера, детерминируемо для тестов.
        self.seed ^= self.seed >> 12;
        self.seed ^= self.seed << 25;
        self.seed ^= self.seed >> 27;
        (self.seed >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Следующая задержка: base * 2^i, с джиттером ±20%, с потолком `max`.
    pub(crate) fn next(&mut self) -> Duration {
        let jittered = (self.base.as_millis() as f64) * (0.8 + 0.4 * self.jitter_unit());
        let millis = jittered.clamp(
            self.min.as_millis() as f64,
            self.max.as_millis() as f64,
        );
        // База растёт только до max: последующие next() остаются у потолка
        // (с новым джиттером каждый раз).
        self.base = (self.base * 2).min(self.max);
        Duration::from_millis(millis as u64)
    }

    /// Сброс после успешной сессии: следующая задержка снова минимальная.
    pub(crate) fn reset(&mut self) {
        self.base = self.min;
    }

    /// Текущая база (без джиттера) — для тестов.
    #[cfg(test)]
    pub(crate) fn base(&self) -> Duration {
        self.base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_delay_is_near_min() {
        let mut backoff = Backoff::new(500, 30_000);
        let delay = backoff.next();
        assert!(
            delay >= Duration::from_millis(400) && delay <= Duration::from_millis(600),
            "первая задержка около 500мс ±20%: {delay:?}"
        );
    }

    #[test]
    fn grows_exponentially_up_to_max() {
        let mut backoff = Backoff::new(100, 1600);
        let mut bases = Vec::new();
        for _ in 0..8 {
            backoff.next();
            bases.push(backoff.base());
        }
        // База удваивается до потолка 1600мс и дальше не растёт.
        assert_eq!(bases, vec![
            Duration::from_millis(200),
            Duration::from_millis(400),
            Duration::from_millis(800),
            Duration::from_millis(1600),
            Duration::from_millis(1600),
            Duration::from_millis(1600),
            Duration::from_millis(1600),
            Duration::from_millis(1600),
        ]);
    }

    #[test]
    fn jitter_stays_within_bounds() {
        // Джиттер ±20% применяется к ТЕКУЩЕЙ базе; проверяем его на
        // минимальной базе — reset перед каждым шагом держит base = min.
        let mut backoff = Backoff::new(500, 30_000);
        for _ in 0..20 {
            backoff.reset();
            let delay = backoff.next();
            assert!(
                delay >= Duration::from_millis(400) && delay <= Duration::from_millis(600),
                "джиттер выскочил за ±20% от min-базы: {delay:?}"
            );
        }
    }

    #[test]
    fn reset_returns_to_min() {
        let mut backoff = Backoff::new(500, 30_000);
        for _ in 0..4 {
            backoff.next();
        }
        assert!(backoff.base() > Duration::from_millis(500), "база выросла");
        backoff.reset();
        assert_eq!(backoff.base(), Duration::from_millis(500));
        let delay = backoff.next();
        assert!(
            delay <= Duration::from_millis(600),
            "после reset задержка снова у минимума: {delay:?}"
        );
    }

    #[test]
    fn max_is_never_exceeded_even_with_tiny_min() {
        let mut backoff = Backoff::new(1, 8);
        for _ in 0..20 {
            let delay = backoff.next();
            assert!(delay <= Duration::from_millis(9), "потолок 8мс +джиттер: {delay:?}");
        }
    }
}
