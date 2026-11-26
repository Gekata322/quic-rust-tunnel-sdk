//! Ошибки клиентского ядра (`tunnel-core`).
//!
//! `CoreError` одновременно является библиотечной ошибкой (`thiserror`) и
//! FFI-ошибкой (`uniffi::Error`): партнёрский код на Kotlin/Swift видит
//! типизированные варианты с сообщением, а Rust-код отличает временные
//! сбои (нужно переподключаться) от постоянных (переподключаться бессмысленно).

use thiserror::Error;

/// Ошибки клиентского ядра туннеля.
#[derive(Debug, Error, uniffi::Error)]
pub enum CoreError {
    /// Конфигурация недействительна (пустой хост/токен, неверные задержки).
    #[error("конфигурация некорректна: {0}")]
    InvalidConfig(String),
    /// Закреплённый сертификат сервера не удалось разобрать.
    #[error("закреплённый сертификат сервера недействителен: {0}")]
    InvalidServerCert(String),
    /// Сервер отклонил авторизацию (токен неизвестен или заблокирован).
    #[error("авторизация отклонена: {0}")]
    AuthRejected(String),
    /// Версия протокола не поддерживается сервером — нужно обновить SDK.
    #[error("версия протокола не поддерживается: {0}")]
    ProtocolMismatch(String),
    /// Сервер перегружен / пул виртуальных IP исчерпан — ретрай уместен.
    #[error("сервер временно недоступен: {0}")]
    ServerBusy(String),
    /// Ошибка ввода-вывода ОС (UDP-сокет, поток движка и т.п.).
    #[error("ошибка ввода-вывода: {0}")]
    Io(String),
    /// QUIC-соединение не установлено (сеть недоступна, сервер молчит).
    #[error("не удалось подключиться: {0}")]
    ConnectFailed(String),
    /// Превышен тайм-аут подключения или рукопожатия.
    #[error("тайм-аут: {0}")]
    TimedOut(String),
    /// Установленная сессия оборвалась (сеть, сервер закрыл соединение).
    #[error("сессия прервана: {0}")]
    SessionClosed(String),
    /// Ошибка внутри ядра: соберите логи `tracing` и зарегистрируйте баг.
    #[error("внутренняя ошибка: {0}")]
    Internal(String),
}

impl CoreError {
    /// Ошибки, при которых переподключение бесполезно: движок переводит
    /// клиента в `Stopped` вместо бесконечных ретраев.
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            Self::InvalidConfig(_)
                | Self::InvalidServerCert(_)
                | Self::AuthRejected(_)
                | Self::ProtocolMismatch(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanent_errors_are_flagged() {
        assert!(CoreError::AuthRejected("токен не найден".into()).is_permanent());
        assert!(CoreError::ProtocolMismatch("v99".into()).is_permanent());
        assert!(CoreError::InvalidConfig("пустой хост".into()).is_permanent());
        assert!(CoreError::InvalidServerCert("битый DER".into()).is_permanent());
    }

    #[test]
    fn transient_errors_are_retryable() {
        assert!(!CoreError::ServerBusy("пул исчерпан".into()).is_permanent());
        assert!(!CoreError::ConnectFailed("сеть недоступна".into()).is_permanent());
        assert!(!CoreError::TimedOut("8с".into()).is_permanent());
        assert!(!CoreError::SessionClosed("QUIC closed".into()).is_permanent());
        assert!(!CoreError::Io("EBADF".into()).is_permanent());
        assert!(!CoreError::Internal("bug".into()).is_permanent());
    }

    #[test]
    fn error_messages_are_human_readable() {
        let err = CoreError::AuthRejected("токен заблокирован".to_owned());
        assert_eq!(err.to_string(), "авторизация отклонена: токен заблокирован");
    }
}
