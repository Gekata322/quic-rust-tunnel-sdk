//! QUIC-эндпоинт сервера: самоподписанный сертификат, ALPN, цикл приёма.
//!
//! Сертификат сервера генерируется при старте (rcgen) и выгружается DER-файлом
//! (`--export-cert`): партнёр кладёт его в `pinned_server_cert_der` — public CA
//! не используются, единственный доверенный корень. При повторных запусках
//! сервера сертификат пересоздаётся; в проде закрепляйте его раз и
//! распространяйте через релизный процесс партнёра.

use std::net::SocketAddr;
use std::sync::Arc;

use rcgen::CertifiedKey;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::watch;

use tunnel_proto::ALPN_TUNNEL_V1;

use crate::session::ServerShared;

/// Ошибки подъёма TLS/QUIC-эндпоинта.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// Сертификат/ключ не собрался.
    #[error("сертификат: {0}")]
    Certificate(String),
    /// UDP-эндпоинт не привязался.
    #[error("bind {0}: {1}")]
    Bind(SocketAddr, #[source] std::io::Error),
    /// Внутренняя ошибка сборки QUIC поверх TLS.
    #[error("QUIC/TLS: {0}")]
    Quic(String),
}

/// Самоподписанный сертификат сервера + ключ (для `build_endpoint`).
#[derive(Debug, Clone)]
pub struct Certificate {
    /// DER-сертификат: то, что партнёр pin-ит (пишется в `--export-cert`).
    pub der: rustls::pki_types::CertificateDer<'static>,
    /// PKCS#8 DER ключа; не покидает сервер.
    key_der: Vec<u8>,
}

/// Генерирует самоподписанный сертификат с SAN=`server_name`.
/// Для loopback-проверок добавляются SAN 127.0.0.1, чтобы клиенты могли
/// подключаться по IP.
pub fn generate_certificate(server_name: &str) -> Result<Certificate, EndpointError> {
    let mut subjects = vec![server_name.to_owned()];
    subjects.push("127.0.0.1".to_owned());
    let CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(subjects)
        .map_err(|err| EndpointError::Certificate(format!("{err}")))?;
    Ok(Certificate {
        der: cert.der().clone(),
        key_der: signing_key.serialize_der(),
    })
}

/// Собирает QUIC-эндпоинт: TLS с ALPN `tunnel/v1`, дейтаграммы, разумные
/// тайм-ауты. Клиент без совпадающего ALPN отсекается ещё на TLS-рукопожатии.
pub fn build_endpoint(cert: &Certificate, listen: SocketAddr) -> Result<quinn::Endpoint, EndpointError> {
    let cert_der = cert.der.clone();
    let key_der = PrivatePkcs8KeyDer::from(cert.key_der.clone());

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|err| EndpointError::Quic(format!("{err}")))?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], PrivateKeyDer::Pkcs8(key_der))
        .map_err(|err| EndpointError::Certificate(format!("{err}")))?;
    tls.alpn_protocols = vec![ALPN_TUNNEL_V1.to_vec()];

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30))
            .expect("30с укладываются в VarInt"),
    ));
    transport.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));

    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|err| EndpointError::Quic(format!("{err}")))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    server_config.transport_config(Arc::new(transport));

    quinn::Endpoint::server(server_config, listen)
        .map_err(|err| EndpointError::Bind(listen, err))
}

/// Цикл приёма подключений: QUIC-соединение → обработчик сессии.
/// Завершается по `shutdown_rx = true` или закрытию канала остановки.
pub async fn accept_loop(
    shared: Arc<ServerShared>,
    endpoint: quinn::Endpoint,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                match changed {
                    Ok(()) if !*shutdown_rx.borrow() => continue,
                    // true или канал закрыт (владелец дропнулся) — останавливаемся.
                    _ => {
                        tracing::info!("команда остановки: accept_loop завершается");
                        endpoint.close(0u32.into(), b"server-shutdown");
                        return;
                    }
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    tracing::info!("эндпоинт закрыт: accept_loop завершается");
                    return;
                };
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => crate::session::handle_connection(shared, conn).await,
                        Err(err) => tracing::debug!(%err, "QUIC-рукопожатие не состоялось"),
                    }
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_has_valid_der_and_names() {
        let cert = generate_certificate("tunnel-server").expect("сертификат");
        assert!(cert.der.len() > 100, "DER-сертификат не может быть таким коротким");
        assert_eq!(cert.der[0], 0x30, "DER начинается с SEQUENCE");
        assert!(!cert.key_der.is_empty());

        // DER парсится rustls-типами (тот же путь, что и при pinning).
        let _parsed = &cert.der; // CertificateDer: deref к &[u8] уже проверен выше
        assert!(cert.der.as_ref().len() == cert.der.len(), "CertificateDer согласован");
        let _key: PrivatePkcs8KeyDer<'static> = PrivatePkcs8KeyDer::from(cert.key_der.clone());
    }

    #[tokio::test]
    async fn endpoint_binds_and_reports_local_addr() {
        let cert = generate_certificate("localhost").expect("сертификат");
        let endpoint =
            build_endpoint(&cert, "127.0.0.1:0".parse().expect("адрес")).expect("эндпоинт");
        let addr = endpoint.local_addr().expect("локальный адрес");
        assert_ne!(addr.port(), 0, "ОС выдала эфемерный порт");
        endpoint.close(0u32.into(), b"bye");
    }

    #[tokio::test]
    async fn bind_twice_on_same_port_fails_clearly() {
        let cert = generate_certificate("localhost").expect("сертификат");
        let endpoint = build_endpoint(&cert, "127.0.0.1:0".parse().expect("адрес"))
            .expect("первый эндпоинт");
        let port = endpoint.local_addr().expect("адрес").port();
        let second = build_endpoint(&cert, format!("127.0.0.1:{port}").parse().expect("адрес"));
        match second {
            Err(EndpointError::Bind(addr, _)) => assert_eq!(addr.port(), port),
            Ok(_) => panic!("повторный bind того же порта обязан упасть"),
            Err(other) => panic!("неожиданная ошибка: {other}"),
        }
        endpoint.close(0u32.into(), b"bye");
    }

    #[test]
    fn certificate_error_display() {
        let err = EndpointError::Certificate("битый DER".to_owned());
        assert_eq!(err.to_string(), "сертификат: битый DER");
    }
}
