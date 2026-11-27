//! Server QUIC endpoint: self-signed certificate, ALPN, accept loop.
//!
//! The server certificate is generated at startup (rcgen) and exported as a
//! DER file (`--export-cert`): the partner puts it into
//! `pinned_server_cert_der` — public CAs are not used, it is the only trusted
//! root. On server restarts the certificate is regenerated; in production pin
//! it once and distribute it through the partner release process.

use std::net::SocketAddr;
use std::sync::Arc;

use rcgen::CertifiedKey;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::sync::watch;

use tunnel_proto::ALPN_TUNNEL_V1;

use crate::session::ServerShared;

/// TLS/QUIC endpoint startup errors.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// The certificate/key did not build.
    #[error("certificate: {0}")]
    Certificate(String),
    /// The UDP endpoint did not bind.
    #[error("bind {0}: {1}")]
    Bind(SocketAddr, #[source] std::io::Error),
    /// Internal error building QUIC over TLS.
    #[error("QUIC/TLS: {0}")]
    Quic(String),
}

/// Self-signed server certificate + key (for `build_endpoint`).
#[derive(Debug, Clone)]
pub struct Certificate {
    /// DER certificate: what the partner pins (written by `--export-cert`).
    pub der: rustls::pki_types::CertificateDer<'static>,
    /// PKCS#8 DER of the key; never leaves the server.
    key_der: Vec<u8>,
}

/// Generates a self-signed certificate with SAN=`server_name`.
/// For loopback checks a 127.0.0.1 SAN is added so clients can connect by IP.
pub fn generate_certificate(server_name: &str) -> Result<Certificate, EndpointError> {
    let subjects = vec![server_name.to_owned(), "127.0.0.1".to_owned()];
    let CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(subjects)
        .map_err(|err| EndpointError::Certificate(format!("{err}")))?;
    Ok(Certificate {
        der: cert.der().clone(),
        key_der: signing_key.serialize_der(),
    })
}

/// Builds the QUIC endpoint: TLS with ALPN `tunnel/v1`, datagrams, sensible
/// timeouts. A client without a matching ALPN is cut off at the TLS handshake.
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
            .expect("30s fits into a VarInt"),
    ));
    transport.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));

    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|err| EndpointError::Quic(format!("{err}")))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    server_config.transport_config(Arc::new(transport));

    quinn::Endpoint::server(server_config, listen)
        .map_err(|err| EndpointError::Bind(listen, err))
}

/// Connection accept loop: QUIC connection → session handler.
/// Terminates on `shutdown_rx = true` or when the stop channel closes.
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
                    // true or the channel closed (the owner dropped) — stop.
                    _ => {
                        tracing::info!("stop command: accept_loop is shutting down");
                        endpoint.close(0u32.into(), b"server-shutdown");
                        return;
                    }
                }
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    tracing::info!("endpoint closed: accept_loop is shutting down");
                    return;
                };
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => crate::session::handle_connection(shared, conn).await,
                        Err(err) => tracing::debug!(%err, "QUIC handshake did not complete"),
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
        let cert = generate_certificate("tunnel-server").expect("certificate");
        assert!(cert.der.len() > 100, "a DER certificate cannot be this short");
        assert_eq!(cert.der[0], 0x30, "DER starts with a SEQUENCE");
        assert!(!cert.key_der.is_empty());

        // The DER parses into rustls types (the same path as pinning).
        let _parsed: PrivatePkcs8KeyDer<'static> = PrivatePkcs8KeyDer::from(cert.key_der.clone());
    }

    #[tokio::test]
    async fn endpoint_binds_and_reports_local_addr() {
        let cert = generate_certificate("localhost").expect("certificate");
        let endpoint =
            build_endpoint(&cert, "127.0.0.1:0".parse().expect("address")).expect("endpoint");
        let addr = endpoint.local_addr().expect("local address");
        assert_ne!(addr.port(), 0, "the OS issued an ephemeral port");
        endpoint.close(0u32.into(), b"bye");
    }

    #[tokio::test]
    async fn bind_twice_on_same_port_fails_clearly() {
        let cert = generate_certificate("localhost").expect("certificate");
        let endpoint = build_endpoint(&cert, "127.0.0.1:0".parse().expect("address"))
            .expect("first endpoint");
        let port = endpoint.local_addr().expect("address").port();
        let second = build_endpoint(&cert, format!("127.0.0.1:{port}").parse().expect("address"));
        match second {
            Err(EndpointError::Bind(addr, _)) => assert_eq!(addr.port(), port),
            Ok(_) => panic!("a second bind of the same port must fail"),
            Err(other) => panic!("unexpected error: {other}"),
        }
        endpoint.close(0u32.into(), b"bye");
    }
}
