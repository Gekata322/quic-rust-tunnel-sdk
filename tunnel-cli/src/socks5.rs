//! SOCKS5 front-end (RFC 1928): the CONNECT command, no authentication.
//!
//! Local applications connect to the listener; after the handshake each
//! request becomes a [`Session`] on the userspace stack ([`crate::stack`]).
//! The listener is meant for the loopback interface — there is no
//! authentication, so binding it to a public interface would be a
//! configuration error.
//!
//! Protocol scope: version 5, method `00` (NO AUTHENTICATION REQUIRED),
//! command `01` (CONNECT), address types IPv4 and domains. Domain names are
//! resolved locally with the system resolver (the first IPv4 address) —
//! DNS does not traverse the tunnel in this version.

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::stack::{Session, Stack};

/// SOCKS protocol version served by this proxy.
const VERSION: u8 = 5;
/// Authentication method: no authentication required (RFC 1928 §3).
const METHOD_NONE: u8 = 0x00;
/// The client must pick a method this proxy understands.
const METHOD_UNACCEPTABLE: u8 = 0xFF;
/// Command: CONNECT.
const COMMAND_CONNECT: u8 = 0x01;
/// Address type: IPv4.
const ATYP_IPV4: u8 = 0x01;
/// Address type: domain name.
const ATYP_DOMAIN: u8 = 0x03;
/// Address type: IPv6.
const ATYP_IPV6: u8 = 0x04;

/// Reply codes (RFC 1928 §6).
mod reply {
    pub const SUCCESS: u8 = 0x00;
    pub const NETWORK_UNREACHABLE: u8 = 0x03;
    pub const HOST_UNREACHABLE: u8 = 0x04;
    pub const CONNECTION_REFUSED: u8 = 0x05;
    pub const COMMAND_NOT_SUPPORTED: u8 = 0x07;
    pub const ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
}

/// Deadline for a CONNECT to reach the established state through the tunnel.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A parsed CONNECT target: an IP literal or a domain name (resolved later).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum TargetHost {
    Ip(Ipv4Addr),
    Domain(String),
}

/// A parsed CONNECT request.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Target {
    pub(crate) host: TargetHost,
    pub(crate) port: u16,
}

/// Handshake failures; the reply (when any) has already been sent.
#[derive(Debug, thiserror::Error)]
pub(crate) enum NegotiationError {
    #[error("the client disconnected mid-handshake")]
    Disconnected,
    #[error("not a SOCKS5 client (version {0})")]
    BadVersion(u8),
    #[error("the client offered no authentication methods")]
    NoMethods,
    #[error("no acceptable authentication method")]
    NoAcceptableMethod,
    #[error("command {0} is not supported (CONNECT only)")]
    UnsupportedCommand(u8),
    #[error("address type {0} is not supported (IPv4 and domains only)")]
    UnsupportedAddressType(u8),
}

/// Performs the greeting and reads the CONNECT request.
///
/// Protocol-level problems are answered with the proper reply code and
/// returned as an error; the caller just drops the stream. The success
/// reply is sent later, when the tunnel session is established.
pub(crate) async fn negotiate<S>(stream: &mut S) -> Result<Target, NegotiationError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Greeting: VER NMETHODS METHODS...
    let mut header = [0u8; 2];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| NegotiationError::Disconnected)?;
    let (version, nmethods) = (header[0], header[1]);
    if version != VERSION {
        return Err(NegotiationError::BadVersion(version));
    }
    if nmethods == 0 {
        return Err(NegotiationError::NoMethods);
    }
    let mut methods = vec![0u8; usize::from(nmethods)];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|_| NegotiationError::Disconnected)?;
    if !methods.contains(&METHOD_NONE) {
        let _ = stream.write_all(&[VERSION, METHOD_UNACCEPTABLE]).await;
        return Err(NegotiationError::NoAcceptableMethod);
    }
    stream
        .write_all(&[VERSION, METHOD_NONE])
        .await
        .map_err(|_| NegotiationError::Disconnected)?;

    // Request: VER CMD RSV ATYP ADDR PORT.
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|_| NegotiationError::Disconnected)?;
    let [version, command, _reserved, atyp] = head;
    if version != VERSION {
        return Err(NegotiationError::BadVersion(version));
    }
    if command != COMMAND_CONNECT {
        send_reply(stream, reply::COMMAND_NOT_SUPPORTED, &bind_address_with_port(0))
            .await
            .map_err(|_| NegotiationError::Disconnected)?;
        return Err(NegotiationError::UnsupportedCommand(command));
    }

    let host = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream
                .read_exact(&mut octets)
                .await
                .map_err(|_| NegotiationError::Disconnected)?;
            TargetHost::Ip(Ipv4Addr::from(octets))
        }
        ATYP_DOMAIN => {
            let mut length = [0u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .map_err(|_| NegotiationError::Disconnected)?;
            let mut name = vec![0u8; usize::from(length[0])];
            stream
                .read_exact(&mut name)
                .await
                .map_err(|_| NegotiationError::Disconnected)?;
            // A DNS name is ASCII; anything else cannot be resolved anyway.
            TargetHost::Domain(String::from_utf8_lossy(&name).into_owned())
        }
        ATYP_IPV6 => {
            send_reply(stream, reply::ADDRESS_TYPE_NOT_SUPPORTED, &bind_address_with_port(0))
                .await
                .map_err(|_| NegotiationError::Disconnected)?;
            return Err(NegotiationError::UnsupportedAddressType(ATYP_IPV6));
        }
        other => {
            send_reply(stream, reply::ADDRESS_TYPE_NOT_SUPPORTED, &bind_address_with_port(0))
                .await
                .map_err(|_| NegotiationError::Disconnected)?;
            return Err(NegotiationError::UnsupportedAddressType(other));
        }
    };
    let mut port_bytes = [0u8; 2];
    stream
        .read_exact(&mut port_bytes)
        .await
        .map_err(|_| NegotiationError::Disconnected)?;
    let port = u16::from_be_bytes(port_bytes);
    Ok(Target { host, port })
}

/// `BND.ADDR`/`BND.PORT` fields of a reply (IPv4 address + port).
fn bind_address(addr: Ipv4Addr, port: u16) -> [u8; 6] {
    let mut bind = [0u8; 6];
    bind[..4].copy_from_slice(&addr.octets());
    bind[4..].copy_from_slice(&port.to_be_bytes());
    bind
}

/// Writes a full SOCKS5 reply frame.
async fn send_reply<S>(stream: &mut S, code: u8, bind: &[u8; 6]) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut frame = [0u8; 10];
    frame[0] = VERSION;
    frame[1] = code;
    frame[3] = ATYP_IPV4;
    frame[4..10].copy_from_slice(bind);
    stream.write_all(&frame).await
}

/// Resolves a domain through the system resolver, taking the first IPv4
/// address. DNS does not traverse the tunnel in this version.
async fn resolve_domain(name: &str, port: u16) -> std::io::Result<Ipv4Addr> {
    let mut addresses = tokio::net::lookup_host((name, port)).await?;
    addresses
        .find_map(|address| match address {
            std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
            std::net::SocketAddr::V6(_) => None,
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                format!("no IPv4 address for {name}"),
            )
        })
}

/// Accepts SOCKS5 clients until `shutdown` fires; every connection is
/// handled in its own task. `connected` mirrors the tunnel state: while the
/// tunnel is down, CONNECT requests are rejected without touching the stack.
pub async fn serve(
    listener: TcpListener,
    stack: Stack,
    connected: watch::Receiver<bool>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            result = listener.accept() => result,
            _ = shutdown.changed() => return,
        };
        match accepted {
            Ok((stream, peer)) => {
                tracing::debug!(%peer, "SOCKS5 client connected");
                let stack = stack.clone();
                let connected = connected.clone();
                tokio::spawn(handle_connection(stream, stack, connected));
            }
            Err(err) => {
                tracing::warn!(%err, "SOCKS5 accept failed");
            }
        }
    }
}

/// The full per-connection path: handshake → resolve → tunnel session →
/// byte pump.
async fn handle_connection(
    mut stream: TcpStream,
    stack: Stack,
    connected: watch::Receiver<bool>,
) {
    let target = match negotiate(&mut stream).await {
        Ok(target) => target,
        Err(err) => {
            tracing::debug!(%err, "SOCKS5 handshake failed");
            return;
        }
    };
    let destination = match &target.host {
        TargetHost::Ip(ip) => *ip,
        TargetHost::Domain(name) => match resolve_domain(name, target.port).await {
            Ok(ip) => ip,
            Err(err) => {
                tracing::debug!(host = %name, %err, "resolution failed");
                let _ = send_reply(&mut stream, reply::HOST_UNREACHABLE, &bind_address_with_port(0)).await;
                return;
            }
        },
    };

    if !*connected.borrow() {
        tracing::debug!(%destination, "rejected: the tunnel is down");
        let _ = send_reply(&mut stream, reply::NETWORK_UNREACHABLE, &bind_address_with_port(0)).await;
        return;
    }

    let session = match tokio::time::timeout(CONNECT_TIMEOUT, stack.connect(destination, target.port))
        .await
    {
        Ok(Ok(session)) => session,
        Ok(Err(err)) => {
            tracing::debug!(%destination, port = target.port, %err, "tunnel connect failed");
            let _ = send_reply(&mut stream, reply::CONNECTION_REFUSED, &bind_address_with_port(0)).await;
            return;
        }
        Err(_deadline) => {
            tracing::debug!(%destination, port = target.port, "tunnel connect timed out");
            let _ = send_reply(&mut stream, reply::CONNECTION_REFUSED, &bind_address_with_port(0)).await;
            return;
        }
    };
    tracing::debug!(
        session = session.id(),
        from = %destination,
        port = target.port,
        local_port = session.local_port(),
        "CONNECT established"
    );
    // BND.ADDR is the client's tunnel-side address (0.0.0.0 + the local
    // port here — clients ignore it, curl and browsers included).
    if send_reply(&mut stream, reply::SUCCESS, &bind_address_with_port(session.local_port()))
        .await
        .is_err()
    {
        return;
    }

    pump(stream, session).await;
}

/// The success reply with the local port of the tunnel session.
fn bind_address_with_port(port: u16) -> [u8; 6] {
    bind_address(Ipv4Addr::UNSPECIFIED, port)
}

/// Moves bytes both ways between the SOCKS5 client and the tunnel session.
///
/// Half-close is honored: a client-side EOF sends a FIN into the tunnel and
/// the remote data keeps flowing until the remote finishes.
async fn pump(mut stream: TcpStream, mut session: Session) {
    let (mut reader, mut writer) = stream.split();
    let mut buffer = vec![0u8; 16 * 1024];
    let mut client_eof = false;
    loop {
        tokio::select! {
            biased;
            // Remote → client.
            chunk = session.recv() => match chunk {
                Some(data) => {
                    if writer.write_all(&data).await.is_err() {
                        return;
                    }
                }
                // The remote finished: propagate the close to the client.
                None => {
                    let _ = writer.shutdown().await;
                    return;
                }
            },
            // Client → remote (until the client closes its write side).
            read = reader.read(&mut buffer), if !client_eof => match read {
                Ok(0) => {
                    client_eof = true;
                    session.send_half_close();
                }
                Ok(n) => {
                    if session.send(buffer[..n].to_vec()).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    use tokio::task::JoinHandle;

    /// Drives the client side of a handshake over a duplex pipe.
    struct Harness {
        client: tokio::io::DuplexStream,
        /// The negotiate() task; resolve it after dropping `client`.
        result: JoinHandle<Result<Target, NegotiationError>>,
    }

    /// Writes `requests` into the client side; the proxy consumes them
    /// concurrently (duplex buffers, so the order is safe).
    async fn open_handshake(requests: &[&[u8]]) -> Harness {
        let (proxy_side, mut client) = duplex(1024);
        let mut proxy = proxy_side;
        let result = tokio::spawn(async move { negotiate(&mut proxy).await });
        for request in requests {
            client.write_all(request).await.expect("test request");
            // Let the proxy consume before the next write.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Harness { client, result }
    }

    #[tokio::test]
    async fn happy_path_with_an_ipv4_target() {
        let mut harness = open_handshake(&[
            &[VERSION, 1, METHOD_NONE],
            &[VERSION, COMMAND_CONNECT, 0, ATYP_IPV4, 10, 66, 0, 7, 0x1F, 0x90],
        ])
        .await;
        let mut method = [0u8; 2];
        harness.client.read_exact(&mut method).await.expect("method reply");
        drop(harness.client); // EOF: the proxy must finish on its own
        let target = harness.result.await.expect("negotiate task").expect("parsed target");
        assert_eq!(
            target,
            Target {
                host: TargetHost::Ip(Ipv4Addr::new(10, 66, 0, 7)),
                port: 8080,
            }
        );
    }

    #[tokio::test]
    async fn happy_path_with_a_domain_target() {
        let mut request = vec![VERSION, COMMAND_CONNECT, 0, ATYP_DOMAIN, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443u16.to_be_bytes());
        let mut harness = open_handshake(&[&[VERSION, 1, METHOD_NONE], &request]).await;
        let mut method = [0u8; 2];
        harness.client.read_exact(&mut method).await.expect("method reply");
        drop(harness.client);
        let target = harness.result.await.expect("negotiate task").expect("parsed target");
        assert_eq!(
            target,
            Target {
                host: TargetHost::Domain("example.com".to_owned()),
                port: 443,
            }
        );
    }

    #[tokio::test]
    async fn no_common_method_is_rejected_with_ff() {
        let mut harness = open_handshake(&[&[VERSION, 1, 0x02]]).await;
        let mut method = [0u8; 2];
        harness.client.read_exact(&mut method).await.expect("method reply");
        drop(harness.client);
        let result = harness.result.await.expect("negotiate task");
        assert!(matches!(result, Err(NegotiationError::NoAcceptableMethod)));
    }

    #[tokio::test]
    async fn bind_command_gets_reply_seven() {
        let mut harness = open_handshake(&[
            &[VERSION, 1, METHOD_NONE],
            &[VERSION, 0x02, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 80],
        ])
        .await;
        let mut method = [0u8; 2];
        harness.client.read_exact(&mut method).await.expect("method reply");
        let mut reply = [0u8; 10];
        harness.client.read_exact(&mut reply).await.expect("reply");
        assert_eq!(reply[1], reply::COMMAND_NOT_SUPPORTED);
        drop(harness.client);
        let result = harness.result.await.expect("negotiate task");
        assert!(matches!(result, Err(NegotiationError::UnsupportedCommand(0x02))));
    }

    #[tokio::test]
    async fn ipv6_target_gets_reply_eight() {
        let mut harness = open_handshake(&[
            &[VERSION, 1, METHOD_NONE],
            &[
                VERSION, COMMAND_CONNECT, 0, ATYP_IPV6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 1, 0, 80,
            ],
        ])
        .await;
        let mut method = [0u8; 2];
        harness.client.read_exact(&mut method).await.expect("method reply");
        let mut reply = [0u8; 10];
        harness.client.read_exact(&mut reply).await.expect("reply");
        assert_eq!(reply[1], reply::ADDRESS_TYPE_NOT_SUPPORTED);
        drop(harness.client);
        let result = harness.result.await.expect("negotiate task");
        assert!(matches!(
            result,
            Err(NegotiationError::UnsupportedAddressType(ATYP_IPV6))
        ));
    }

    #[tokio::test]
    async fn wrong_version_fails_without_reply() {
        let harness = open_handshake(&[&[4, 1, 0]]).await;
        drop(harness.client);
        let result = harness.result.await.expect("negotiate task");
        assert!(matches!(result, Err(NegotiationError::BadVersion(4))));
    }

    #[tokio::test]
    async fn empty_method_list_fails() {
        let harness = open_handshake(&[&[VERSION, 0]]).await;
        drop(harness.client);
        let result = harness.result.await.expect("negotiate task");
        assert!(matches!(result, Err(NegotiationError::NoMethods)));
    }

    #[tokio::test]
    async fn truncated_request_fails_with_eof() {
        let mut harness = open_handshake(&[&[VERSION, 1, METHOD_NONE], &[VERSION, COMMAND_CONNECT]])
            .await;
        let mut method = [0u8; 2];
        harness.client.read_exact(&mut method).await.expect("method reply");
        drop(harness.client); // EOF in the middle of the request
        let result = harness.result.await.expect("negotiate task");
        assert!(matches!(result, Err(NegotiationError::Disconnected)));
    }

    #[test]
    fn bind_address_layout() {
        let bind = bind_address(Ipv4Addr::new(10, 66, 0, 2), 49152);
        assert_eq!(bind, [10, 66, 0, 2, 0xC0, 0x00]);
        assert_eq!(bind_address_with_port(80), [0, 0, 0, 0, 0, 80]);
    }

    #[tokio::test]
    async fn domain_resolution_returns_an_ipv4() {
        // "localhost" resolves everywhere; the resolver must yield IPv4,
        // not the (often first) ::1 answer.
        let ip = resolve_domain("localhost", 80).await.expect("localhost resolves");
        assert!(!ip.is_unspecified());
    }
}
