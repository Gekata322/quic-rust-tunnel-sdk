//! `tunnel-cli` entry point: a SOCKS5 proxy over the QUIC tunnel.
//!
//! Typical usage:
//!
//! ```text
//! tunnel-cli --server tunnel.example.com:4433 --cert tunnel-root.der --token b2b-live-a1b2c3d4
//! curl --socks5-hostname 127.0.0.1:1080 http://example.test/
//! ```
//!
//! The binary needs no root and no TUN device: local applications connect
//! to the SOCKS5 listener on the loopback interface, the userspace TCP
//! stack (`tunnel_cli::stack`) turns their streams into tunnel packets.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::sync::watch;
use tunnel_cli::socks5;
use tunnel_cli::stack::Stack;
use tunnel_cli::stats;
use tunnel_core::ffi::TunnelState;
use tunnel_core::{ConnectionStatus, ConnectionStatusCallback, TunnelClient, TunnelConfig};

/// Deadline for the first successful handshake after `connect()`.
const FIRST_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// Command-line arguments of the proxy.
#[derive(Debug, Parser)]
#[command(
    name = "tunnel-cli",
    version,
    about = "SOCKS5 proxy over the QUIC tunnel — no root, no TUN device"
)]
struct Args {
    /// Tunnel server address, host:port (UDP/QUIC).
    #[arg(long, value_name = "HOST:PORT")]
    server: String,
    /// Pinned server certificate (DER), as exported by
    /// `tunnel-server --export-cert`.
    #[arg(long, value_name = "FILE")]
    cert: PathBuf,
    /// B2B authentication token issued by the server operator.
    #[arg(long, value_name = "TOKEN", env = "TUNNEL_TOKEN", hide_env_values = true)]
    token: String,
    /// Client identifier for the server logs and the IPAM accounting.
    #[arg(long, value_name = "ID", default_value = "tunnel-cli")]
    client_id: String,
    /// SOCKS5 listener address. Keep it on the loopback interface: the
    /// listener has no authentication.
    #[arg(long, value_name = "IP:PORT", default_value = "127.0.0.1:1080")]
    socks: SocketAddr,
    /// Seconds between status lines (0 disables the periodic report).
    #[arg(long, value_name = "SEC", default_value_t = 5)]
    stats_secs: u64,
}

fn main() {
    // Logs: RUST_LOG controls verbosity (default — info).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    if let Err(err) = runtime.block_on(run(args)) {
        eprintln!("Error: {err}");
        std::process::exit(1);
    }
}

/// Full startup: config → engine → first session → SOCKS5 → stats → Ctrl-C.
async fn run(args: Args) -> Result<(), String> {
    let cert_der = std::fs::read(&args.cert)
        .map_err(|err| format!("cannot read the certificate {}: {err}", args.cert.display()))?;
    let (host, port) = parse_server(&args.server)?;

    // The gate for the SOCKS5 listener: while the tunnel is down, CONNECT
    // requests are rejected without touching the stack. The status callback
    // keeps it in sync (watch sends are cheap and safe from any thread).
    let (connected_tx, connected_rx) = watch::channel(false);
    let client = Arc::new(TunnelClient::new(TunnelConfig {
        server_host: host.clone(),
        server_name: String::new(), // the core falls back to server_host
        server_port: port,
        auth_token: args.token,
        client_id: args.client_id.clone(),
        pinned_server_cert_der: cert_der,
        connect_timeout_ms: 8000,
        min_backoff_ms: 500,
        max_backoff_ms: 30_000,
        keepalive_interval_secs: 0,
    })
    .map_err(|err| err.to_string())?);
    client.set_status_callback(Some(Box::new(StatusLog {
        connected: connected_tx,
    })));
    client.connect().map_err(|err| err.to_string())?;
    tracing::info!(server = %args.server, client = %args.client_id, "connecting to the tunnel server...");

    // The stack needs the VIP and the MTU of the first session.
    let vip = wait_for_first_session(&client).await?;
    let stack = Stack::spawn(Arc::clone(&client)).map_err(|err| err.to_string())?;
    tracing::info!(vip = %vip, socks = %args.socks, "tunnel is up; the SOCKS5 listener is opening");

    let listener = tokio::net::TcpListener::bind(args.socks)
        .await
        .map_err(|err| format!("cannot bind the SOCKS5 listener {}: {err}", args.socks))?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(socks5::serve(
        listener,
        stack.clone(),
        connected_rx,
        shutdown_rx.clone(),
    ));
    if args.stats_secs > 0 {
        stats::spawn(
            Arc::clone(&client),
            stack,
            Duration::from_secs(args.stats_secs),
            shutdown_rx,
        );
    }

    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("Ctrl-C: stopping the tunnel and the proxy");
    let _ = shutdown_tx.send(true);
    client.disconnect();
    // Give the goodbye lines (status callback, CONNECTION_CLOSE drain) a moment.
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(())
}

/// Waits for the first `Connected` state; permanent errors (a rejected
/// token, a wrong certificate) are reported immediately.
async fn wait_for_first_session(client: &TunnelClient) -> Result<Ipv4Addr, String> {
    let deadline = tokio::time::Instant::now() + FIRST_SESSION_TIMEOUT;
    loop {
        match client.state() {
            TunnelState::Connected { vip, .. } => {
                return vip
                    .parse()
                    .map_err(|_| format!("the server issued an unparseable address: {vip}"));
            }
            TunnelState::Stopped => {
                return Err(
                    "the tunnel stopped permanently (rejected token or wrong certificate); \
                     see the log lines above"
                        .to_owned(),
                );
            }
            _ => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return Err("the tunnel did not come up in time; check the server address, \
                        the certificate and the token"
                .to_owned());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// `host:port` → `(host, port)`. Host may be a name or an IP.
fn parse_server(server: &str) -> Result<(String, u16), String> {
    let (host, port) = server
        .rsplit_once(':')
        .ok_or_else(|| format!("--server expects host:port, got {server:?}"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("--server: {port:?} is not a port"))?;
    if host.is_empty() {
        return Err(format!("--server: the host is empty in {server:?}"));
    }
    Ok((host.to_owned(), port))
}

/// Logs status transitions and keeps the SOCKS5 gate in sync.
struct StatusLog {
    connected: watch::Sender<bool>,
}

impl ConnectionStatusCallback for StatusLog {
    fn on_status_change(&self, status: ConnectionStatus) {
        let _ = self.connected.send(matches!(status, ConnectionStatus::Connected { .. }));
        match status {
            ConnectionStatus::Connected { mtu, vip } => {
                tracing::info!(vip = %vip, mtu, "tunnel connected");
            }
            ConnectionStatus::Reconnecting => tracing::info!("tunnel reconnecting"),
            ConnectionStatus::Disconnected => tracing::info!("tunnel disconnected"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_addresses_parse() {
        assert_eq!(
            parse_server("tunnel.example.com:4433").expect("host:port"),
            ("tunnel.example.com".to_owned(), 4433)
        );
        assert_eq!(
            parse_server("127.0.0.1:443").expect("ip:port"),
            ("127.0.0.1".to_owned(), 443)
        );
        // IPv6 literal with the last colon as the port separator.
        assert_eq!(
            parse_server("[::1]:4433").expect("bracketed v6"),
            ("[::1]".to_owned(), 4433)
        );
    }

    #[test]
    fn server_addresses_fail_loudly() {
        assert!(parse_server("no-port-here").is_err());
        assert!(parse_server(":4433").is_err(), "empty host");
        assert!(parse_server("host:not-a-port").is_err());
        assert!(parse_server("host:").is_err());
    }

    #[test]
    fn cli_defaults_are_sensible() {
        let args = Args::parse_from([
            "tunnel-cli",
            "--server", "srv:4433",
            "--cert", "server.der",
            "--token", "t",
        ]);
        assert_eq!(args.socks.to_string(), "127.0.0.1:1080");
        assert_eq!(args.client_id, "tunnel-cli");
        assert_eq!(args.stats_secs, 5);
    }

    #[test]
    fn cli_accepts_inline_values_and_env() {
        let args = Args::parse_from([
            "tunnel-cli",
            "--server=srv:4433",
            "--cert=server.der",
            "--token=t",
            "--client-id=partner-x",
            "--socks=127.0.0.1:2080",
            "--stats-secs=0",
        ]);
        assert_eq!(args.client_id, "partner-x");
        assert_eq!(args.socks.to_string(), "127.0.0.1:2080");
        assert_eq!(args.stats_secs, 0, "0 disables the periodic report");
    }
}
