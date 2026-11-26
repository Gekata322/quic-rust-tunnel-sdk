//! Конфигурация сервера: источник токенов, параметры подсети/MTU/TUN.
//!
//! Заполняется из CLI (см. `main.rs`) или напрямую из кода (интеграционные
//! тесты используют `TokensSource::Inline`). Загрузка токенов — через
//! `tunnel_proto::auth::TokenStore`.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use tunnel_proto::auth::TokenStore;

/// Ошибки конфигурации сервера.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Файл токенов не читается или бит.
    #[error("файл токенов «{0}»: {1}")]
    TokensFile(String, #[source] std::io::Error),
    /// Переменная TUNNEL_TOKENS не задана при `TokensSource::Env`.
    #[error("переменная TUNNEL_TOKENS не задана (или пуста)")]
    TokensEnvMissing,
    /// Конфигурация недействительна.
    #[error("конфигурация некорректна: {0}")]
    Invalid(String),
}

/// Откуда сервер берёт B2B-токены партнёров.
#[derive(Debug, Clone)]
pub enum TokensSource {
    /// Готовые пары `(client_id, token)` — тесты и встраивание.
    Inline(Vec<(String, String)>),
    /// Файл `"client_id:token"` построчно (`#` — комментарии).
    File(PathBuf),
    /// Переменная окружения `TUNNEL_TOKENS` (`"a:t1,b:t2"`).
    Env,
}

/// Полная конфигурация сервера.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// UDP-адрес слушателя QUIC (обычно `0.0.0.0:443`).
    pub listen: SocketAddr,
    /// Подсеть виртуальных адресов, CIDR с байтовой маской (`10.66.0.0/24`).
    pub pool: String,
    /// MTU виртуального интерфейса клиентов (обычно 1280).
    pub mtu: u16,
    /// Период прикладного ping, передаваемый клиентам в `Welcome`, сек.
    pub keepalive_interval_secs: u32,
    /// DNS-серверы, рекомендуемые клиентам (роадмап: DHCP-опции туннеля).
    pub dns_servers: Vec<IpAddr>,
    /// Имя TUN-интерфейса; `None` — loopback-режим (эхо на адрес сервера).
    pub tun_name: Option<String>,
    /// Имя сервера для SAN сертификата и SNI (должно совпадать с ожиданием
    /// клиентов в `TunnelConfig::server_name`).
    pub server_name: String,
    /// Источник токенов.
    pub tokens: TokensSource,
}

impl ServerConfig {
    /// Загружает токены из настроенного источника.
    pub fn load_tokens(&self) -> Result<TokenStore, ConfigError> {
        match &self.tokens {
            TokensSource::Inline(pairs) => Ok(TokenStore::from_pairs(pairs.clone())),
            TokensSource::File(path) => {
                TokenStore::from_file(path).map_err(|err| {
                    ConfigError::TokensFile(path.display().to_string(), err)
                })
            }
            TokensSource::Env => {
                TokenStore::from_env().ok_or(ConfigError::TokensEnvMissing)
            }
        }
    }

    /// Ранние и понятные ошибки вместо молчаливых проблем в рантайме.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server_name.trim().is_empty() {
            return Err(ConfigError::Invalid("server_name пуст — SAN сертификата не собрать".to_owned()));
        }
        if self.mtu == 0 {
            return Err(ConfigError::Invalid("mtu равен нулю".to_owned()));
        }
        if self.mtu < 1280 {
            return Err(ConfigError::Invalid(format!(
                "mtu {mtu} меньше минимума QUIC (1280) — фрагментация гарантирована",
                mtu = self.mtu
            )));
        }
        // Порт 0 легален: ОС выдаёт эфемерный (тесты, динамический деплой).
        // Подсеть валидирует IpPool при старте состояния сервера.
        Ok(())
    }

    /// Loopback-режим: без TUN — эхо пакетов на адрес сервера (для CI и
    /// проверки клиентов без привилегий).
    pub fn is_loopback(&self) -> bool {
        self.tun_name.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ServerConfig {
        ServerConfig {
            listen: "127.0.0.1:0".parse().expect("адрес"),
            pool: "10.66.0.0/24".to_owned(),
            mtu: 1280,
            keepalive_interval_secs: 1,
            dns_servers: vec![],
            tun_name: None,
            server_name: "localhost".to_owned(),
            tokens: TokensSource::Inline(vec![("c".to_owned(), "t".to_owned())]),
        }
    }

    #[test]
    fn inline_tokens_load() {
        let config = base();
        let store = config.load_tokens().expect("инлайн-токены");
        assert_eq!(store.len(), 1);
        assert!(store.verify("c", "t"));
    }

    #[test]
    fn file_tokens_load() {
        let dir = std::env::temp_dir().join(format!("tunnel-server-tokens-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let path = dir.join("tokens.txt");
        std::fs::write(&path, "# партнёр\npartner: tok-123\n").expect("файл токенов");
        let mut config = base();
        config.tokens = TokensSource::File(path.clone());
        let store = config.load_tokens().expect("файл токенов");
        assert!(store.verify("partner", "tok-123"));
        std::fs::remove_dir_all(&dir).expect("чистка tmp");
    }

    #[test]
    fn missing_tokens_file_is_clear_error() {
        let mut config = base();
        config.tokens = TokensSource::File(PathBuf::from("/nonexistent/tokens.txt"));
        assert!(matches!(config.load_tokens(), Err(ConfigError::TokensFile(_, _))));
    }

    #[test]
    fn validation_rules() {
        let config = base();
        assert!(config.validate().is_ok());
        assert!(config.is_loopback());

        let mut bad = base();
        bad.mtu = 0;
        assert!(matches!(bad.validate(), Err(ConfigError::Invalid(_))));
        let mut bad = base();
        bad.mtu = 1200;
        assert!(matches!(bad.validate(), Err(ConfigError::Invalid(_))));
        let mut bad = base();
        bad.server_name = String::new();
        assert!(matches!(bad.validate(), Err(ConfigError::Invalid(_))));
        let mut ok = base();
        ok.listen = "127.0.0.1:0".parse().expect("эфемерный порт");
        assert!(ok.validate().is_ok(), "порт 0 — валидный эфемерный слушатель");
    }

    #[test]
    fn loopback_detection() {
        let mut config = base();
        config.tun_name = Some("tunnel0".to_owned());
        assert!(!config.is_loopback());
    }
}
