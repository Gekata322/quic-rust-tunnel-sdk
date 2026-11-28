//! Server configuration: token source, subnet/MTU/TUN parameters.
//!
//! Populated from the CLI (see `main.rs`) or directly from code (integration
//! tests use `TokensSource::Inline`). Token loading goes through
//! `tunnel_proto::auth::TokenStore`.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use tunnel_proto::auth::TokenStore;

/// Server configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The token file is unreadable or malformed.
    #[error("token file {0:?}: {1}")]
    TokensFile(String, #[source] std::io::Error),
    /// The TUNNEL_TOKENS variable is missing for `TokensSource::Env`.
    #[error("the TUNNEL_TOKENS variable is not set (or empty)")]
    TokensEnvMissing,
    /// The configuration is invalid.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

/// Where the server takes the partner B2B tokens from.
#[derive(Debug, Clone)]
pub enum TokensSource {
    /// Ready `(client_id, token)` pairs — tests and embedding.
    Inline(Vec<(String, String)>),
    /// A file with one `"client_id:token"` pair per line (`#` — comments).
    File(PathBuf),
    /// The `TUNNEL_TOKENS` environment variable (`"a:t1,b:t2"`).
    Env,
}

/// HTTP admin API configuration (see [`crate::admin`]).
#[derive(Debug, Clone)]
pub struct AdminConfig {
    /// Bind address of the API. Keep it on a private interface — the default
    /// and documented value is `127.0.0.1:8080` (the API is not for clients).
    pub listen: SocketAddr,
    /// Shared secret required in `X-Admin-Key` on every request.
    pub key: String,
}

/// Full server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// UDP address of the QUIC listener (usually `0.0.0.0:443`).
    pub listen: SocketAddr,
    /// Virtual address subnet, a CIDR with a byte-aligned mask (`10.66.0.0/24`).
    pub pool: String,
    /// MTU of the clients' virtual interface (usually 1280).
    pub mtu: u16,
    /// Application ping period sent to clients in `Welcome`, sec.
    pub keepalive_interval_secs: u32,
    /// DNS servers recommended to clients (roadmap: tunnel DHCP options).
    pub dns_servers: Vec<IpAddr>,
    /// TUN interface name; `None` — loopback mode (echo to the server address).
    pub tun_name: Option<String>,
    /// Server name for the certificate SAN and SNI (must match what clients
    /// expect in `TunnelConfig::server_name`).
    pub server_name: String,
    /// Token source.
    pub tokens: TokensSource,
    /// HTTP admin API; `None` — the API is disabled (the default).
    pub admin: Option<AdminConfig>,
}

impl ServerConfig {
    /// Loads tokens from the configured source.
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

    /// Early and clear errors instead of silent runtime problems.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server_name.trim().is_empty() {
            return Err(ConfigError::Invalid("server_name is empty — cannot build the certificate SAN".to_owned()));
        }
        if self.mtu == 0 {
            return Err(ConfigError::Invalid("mtu is zero".to_owned()));
        }
        if self.mtu < 1280 {
            return Err(ConfigError::Invalid(format!(
                "mtu {mtu} is below the QUIC minimum (1280) — fragmentation is guaranteed",
                mtu = self.mtu
            )));
        }
        if let Some(admin) = &self.admin {
            if admin.key.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "admin.key is empty — the admin API would be unprotected".to_owned(),
                ));
            }
        }
        // Port 0 is legal: the OS issues an ephemeral one (tests, dynamic deploys).
        // The subnet is validated by IpPool at server state startup.
        Ok(())
    }

    /// Loopback mode: without TUN — packets are echoed to the server address
    /// (for CI and client checks without privileges).
    pub fn is_loopback(&self) -> bool {
        self.tun_name.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ServerConfig {
        ServerConfig {
            listen: "127.0.0.1:0".parse().expect("address"),
            pool: "10.66.0.0/24".to_owned(),
            mtu: 1280,
            keepalive_interval_secs: 1,
            dns_servers: vec![],
            tun_name: None,
            server_name: "localhost".to_owned(),
            tokens: TokensSource::Inline(vec![("c".to_owned(), "t".to_owned())]),
            admin: None,
        }
    }

    #[test]
    fn file_tokens_load() {
        let dir = std::env::temp_dir().join(format!("tunnel-server-tokens-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let path = dir.join("tokens.txt");
        std::fs::write(&path, "# partner\npartner: tok-123\n").expect("token file");
        let mut config = base();
        config.tokens = TokensSource::File(path.clone());
        let store = config.load_tokens().expect("token file");
        assert!(store.verify("partner", "tok-123"));
        std::fs::remove_dir_all(&dir).expect("tmp cleanup");
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
        ok.listen = "127.0.0.1:0".parse().expect("ephemeral port");
        assert!(ok.validate().is_ok(), "port 0 is a valid ephemeral listener");
    }

    #[test]
    fn admin_key_must_not_be_empty() {
        let mut ok = base();
        ok.admin = Some(AdminConfig {
            listen: "127.0.0.1:8080".parse().expect("address"),
            key: "secret".to_owned(),
        });
        assert!(ok.validate().is_ok());

        let mut bad = base();
        bad.admin = Some(AdminConfig {
            listen: "127.0.0.1:8080".parse().expect("address"),
            key: "   ".to_owned(),
        });
        assert!(matches!(bad.validate(), Err(ConfigError::Invalid(_))));
    }
}
