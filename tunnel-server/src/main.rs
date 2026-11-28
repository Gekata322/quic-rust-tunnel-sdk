//! B2B tunnel server: CLI, endpoint/TUN startup, the client accept loop.
//!
//! Modes:
//! - **production** (`--tun tunnel0`): client packets go into the TUN and
//!   outside (NAT is configured by separate rules — the server prints them
//!   with actual values right after startup);
//! - **loopback** (no `--tun`, the default): packets are echoed to the server
//!   address — client and CI checks without CAP_NET_ADMIN.
//!
//! Tokens: `--tokens tokens.txt` (file) or `--env-tokens` (TUNNEL_TOKENS).

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::watch;
use tunnel_proto::auth::TokenStore;
use tunnel_server::config::{AdminConfig, ServerConfig, TokensSource};
use tunnel_server::endpoint::{accept_loop, build_endpoint, generate_certificate};
use tunnel_server::session::ServerShared;
use tunnel_server::tun::TunDevice;

/// Parsed CLI: configuration + certificate export path.
struct Cli {
    config: ServerConfig,
    export_cert: Option<PathBuf>,
}

/// Server startup errors: typed context instead of hand-formatted strings.
#[derive(Debug, thiserror::Error)]
enum RunError {
    /// Runtime creation failed.
    #[error("tokio runtime: {0}")]
    Runtime(#[source] std::io::Error),
    /// Configuration or token loading failed.
    #[error("configuration: {0}")]
    Config(#[from] tunnel_server::config::ConfigError),
    /// Certificate or endpoint startup failed.
    #[error("{0}")]
    Endpoint(#[from] tunnel_server::endpoint::EndpointError),
    /// The TUN interface could not be opened.
    #[error("TUN interface: {0}")]
    Tun(#[source] std::io::Error),
    /// Server state startup failed (address pool).
    #[error("{0}")]
    State(#[from] tunnel_server::session::ServerError),
    /// No tokens loaded — the server would reject everyone.
    #[error("no tokens loaded: the server would reject every client (see --tokens/--env-tokens)")]
    NoTokens,
    /// The admin HTTP listener did not bind.
    #[error("admin API: {0}")]
    Admin(#[from] tunnel_server::admin::AdminError),
    /// Certificate DER export failed.
    #[error("exporting the certificate to {0}: {1}")]
    CertExport(PathBuf, #[source] std::io::Error),
}

fn main() {
    // Logs: RUST_LOG controls verbosity (default — info).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    match parse_cli(&args) {
        Ok(Some(cli)) => {
            if let Err(err) = run(cli) {
                eprintln!("Error: {err}");
                std::process::exit(1);
            }
        }
        // --help was printed; exit successfully.
        Ok(None) => {}
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    }
}

/// Full server startup: config → certificate → endpoint → TUN → accept_loop.
fn run(cli: Cli) -> Result<(), RunError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(RunError::Runtime)?;
    runtime.block_on(async_run(cli))
}

async fn async_run(cli: Cli) -> Result<(), RunError> {
    let config = cli.config;
    config.validate()?;
    let tokens: TokenStore = config.load_tokens()?;
    if tokens.is_empty() {
        return Err(RunError::NoTokens);
    }

    let cert = generate_certificate(&config.server_name)?;
    if let Some(path) = &cli.export_cert {
        std::fs::write(path, &cert.der).map_err(|err| RunError::CertExport(path.clone(), err))?;
        tracing::info!(path = %path.display(), "DER certificate exported for client pinning");
    }

    let endpoint = build_endpoint(&cert, config.listen)?;
    tracing::info!(
        local_addr = %endpoint.local_addr().expect("bound"),
        server_name = %config.server_name,
        "QUIC endpoint is up"
    );

    let tun = match &config.tun_name {
        Some(name) => {
            let tun = TunDevice::open(name).map_err(RunError::Tun)?;
            tracing::info!(name = tun.name(), "TUN interface is up");
            // The address and routes are set up by the operator (see the hint below).
            Some(tun)
        }
        None => {
            tracing::info!("loopback mode: echo only to the server address, no TUN is created");
            None
        }
    };

    let shared = ServerShared::new(&config, tokens.clone(), tun)?;
    tracing::info!(
        server_vip = %shared.server_vip,
        pool = %config.pool,
        mtu = config.mtu,
        tokens = tokens.len(),
        "server is ready to accept clients"
    );
    if let (Some(name), dns) = (&config.tun_name, &config.dns_servers) {
        // Routing hint: actual values — copy and run.
        println!("# Route clients to the outside (run as root):");
        println!("sysctl -w net.ipv4.ip_forward=1");
        println!("ip addr add {}/24 dev {}", shared.server_vip, name);
        println!("ip link set {} up", name);
        println!("iptables -t nat -A POSTROUTING -s {} ! -o {} -j MASQUERADE", config.pool, name);
        println!("iptables -A FORWARD -i {} -j ACCEPT", name);
        println!("iptables -A FORWARD -o {} -j ACCEPT", name);
        if !dns.is_empty() {
            println!("# DNS servers recommended to clients: {}", join_dns(dns));
        }
    }

    shared.spawn_tun_reader();
    shared.spawn_idle_reaper();
    tracing::info!(
        idle_timeout_secs = tunnel_server::reaper::IDLE_SESSION_TIMEOUT.as_secs(),
        scan_interval_secs = tunnel_server::reaper::REAP_INTERVAL.as_secs(),
        "idle-session reaper is running"
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("Ctrl-C received: shutting down gracefully");
            let _ = shutdown_tx.send(true);
        }
    });

    // The admin API stops with the same shutdown signal as the accept loop.
    if let Some(admin) = &config.admin {
        let bound =
            tunnel_server::admin::spawn_admin_server(Arc::clone(&shared), admin, shutdown_rx.clone())
                .await?;
        tracing::info!(addr = %bound, "admin HTTP API is up");
    }

    accept_loop(shared, endpoint, shutdown_rx).await;
    tracing::info!("server stopped");
    Ok(())
}

fn join_dns(servers: &[IpAddr]) -> String {
    servers
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Parses the CLI: `--flag value` or `--flag=value`; `--help` prints usage.
/// Returns `Ok(None)` when `--help` was printed (the caller exits with code 0);
/// `Err` — a parse error. Never exits the process itself, so it stays testable.
fn parse_cli(args: &[String]) -> Result<Option<Cli>, String> {
    let mut config = ServerConfig {
        listen: "0.0.0.0:443".parse().expect("default listener"),
        pool: "10.66.0.0/24".to_owned(),
        mtu: 1280,
        keepalive_interval_secs: 15,
        dns_servers: Vec::new(),
        tun_name: None,
        server_name: "tunnel-server".to_owned(),
        tokens: TokensSource::Env,
        admin: None,
    };
    let mut export_cert = None;
    let mut admin_listen: Option<std::net::SocketAddr> = None;
    let mut admin_key: Option<String> = None;

    let usage = "usage:
  tunnel-server --listen 0.0.0.0:443 --tokens tokens.txt \\\n      --tun tunnel0 --pool 10.66.0.0/24 --mtu 1280 \\\n      --server-name tunnel.example.com --export-cert tunnel-root.der
  tunnel-server --listen 127.0.0.1:4433 --env-tokens   # loopback mode
  tunnel-server --env-tokens --admin-listen 127.0.0.1:8080 --admin-key SECRET

flags:
  --listen <ip:port>        QUIC UDP address (default 0.0.0.0:443)
  --tokens <file>           token file: one \"client_id:token[:mbps]\" per line
                            (the optional suffix caps the client, e.g. a:b:10mbps)
  --env-tokens              read TUNNEL_TOKENS (\"a:t1,b:t2:5mbps\")
  --tun <name>              production mode: TUN interface (needs CAP_NET_ADMIN)
  --pool <cidr>             virtual address subnet (default 10.66.0.0/24)
  --mtu <n>                 client MTU (default 1280)
  --keepalive <sec>         application ping period (default 15)
  --dns <a,b,c>             DNS servers recommended to clients
  --server-name <name>      certificate SAN / SNI (default tunnel-server)
  --export-cert <file>      export the DER certificate for client pinning
  --admin-listen <ip:port>  HTTP admin API bind address (default 127.0.0.1:8080;
                            requires --admin-key, keep it off public interfaces)
  --admin-key <secret>      X-Admin-Key required on every admin request
  -h, --help                this help";

    let mut index = 1;
    while index < args.len() {
        let arg = args[index].as_str();
        let (flag, inline_value) = match arg.split_once('=') {
            Some((flag, value)) => (flag, Some(value)),
            None => (arg, None),
        };
        let next_value = |flag: &str| -> Result<String, String> {
            match inline_value {
                Some(value) => Ok(value.to_owned()),
                None => args
                    .get(index + 1)
                    .cloned()
                    .ok_or_else(|| format!("{flag}: a value is expected\n\n{usage}")),
            }
        };
        match flag {
            "-h" | "--help" => {
                println!("{usage}");
                return Ok(None);
            }
            "--listen" => {
                config.listen = next_value(flag)?
                    .parse()
                    .map_err(|_| format!("--listen: expected ip:port, got {:?}", args.get(index + 1)))?;
            }
            "--tokens" => {
                config.tokens = TokensSource::File(PathBuf::from(next_value(flag)?));
            }
            "--env-tokens" => {
                config.tokens = TokensSource::Env;
            }
            "--tun" => {
                config.tun_name = Some(next_value(flag)?);
            }
            "--pool" => {
                config.pool = next_value(flag)?;
            }
            "--mtu" => {
                config.mtu = next_value(flag)?
                    .parse()
                    .map_err(|_| format!("--mtu: expected a number, got {:?}", args.get(index + 1)))?;
            }
            "--keepalive" => {
                config.keepalive_interval_secs = next_value(flag)?
                    .parse()
                    .map_err(|_| format!("--keepalive: expected seconds, got {:?}", args.get(index + 1)))?;
            }
            "--dns" => {
                config.dns_servers = next_value(flag)?
                    .split(',')
                    .filter(|part| !part.trim().is_empty())
                    .map(|part| {
                        part.trim()
                            .parse::<IpAddr>()
                            .map_err(|_| format!("--dns: {part:?} is not an IP address"))
                    })
                    .collect::<Result<_, _>>()?;
            }
            "--server-name" => {
                config.server_name = next_value(flag)?;
            }
            "--export-cert" => {
                export_cert = Some(PathBuf::from(next_value(flag)?));
            }
            "--admin-listen" => {
                admin_listen = Some(next_value(flag)?
                    .parse()
                    .map_err(|_| format!("--admin-listen: expected ip:port, got {:?}", args.get(index + 1)))?);
            }
            "--admin-key" => {
                admin_key = Some(next_value(flag)?);
            }
            other => {
                return Err(format!("unknown flag {other:?}\n\n{usage}"));
            }
        }
        // Skip the value if it was a separate argument.
        if inline_value.is_none() && !matches!(flag, "--env-tokens") {
            index += 1;
        }
        index += 1;
    }

    // The admin API is enabled only with both parts: a listener without a
    // key would be an unprotected admin surface, a key without a listener is
    // a silent misconfiguration.
    config.admin = match (admin_listen, admin_key) {
        (Some(listen), Some(key)) => Some(AdminConfig { listen, key }),
        (Some(_), None) => return Err("--admin-listen requires --admin-key: an admin API without a key would be unprotected".to_owned()),
        (None, Some(_)) => return Err("--admin-key requires --admin-listen".to_owned()),
        (None, None) => None,
    };

    Ok(Some(Cli { config, export_cert }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        std::iter::once("tunnel-server".to_owned())
            .chain(parts.iter().map(|part| part.to_string()))
            .collect()
    }

    #[test]
    fn defaults_match_documented_behavior() {
        let cli = parse_cli(&argv(&["--env-tokens"])).expect("parse").expect("not help");
        assert_eq!(cli.config.listen.to_string(), "0.0.0.0:443");
        assert_eq!(cli.config.pool, "10.66.0.0/24");
        assert_eq!(cli.config.mtu, 1280);
        assert_eq!(cli.config.keepalive_interval_secs, 15);
        assert_eq!(cli.config.server_name, "tunnel-server");
        assert!(cli.config.tun_name.is_none());
        assert!(cli.config.is_loopback());
        assert!(cli.export_cert.is_none());
        assert!(cli.config.admin.is_none(), "the admin API is off by default");
    }

    #[test]
    fn full_production_flags() {
        let cli = parse_cli(&argv(&[
            "--listen=0.0.0.0:4433", // inline `--flag=value` syntax
            "--tokens", "tokens.txt",
            "--tun", "tunnel0",
            "--pool", "10.66.0.0/24",
            "--mtu", "1280",
            "--server-name", "tunnel.example.com",
            "--export-cert", "tunnel-root.der",
            "--keepalive", "20",
            "--dns", "8.8.8.8,1.1.1.1, 2606:4700:4700::1111 ",
        ])).expect("parse").expect("not help");
        assert_eq!(cli.config.listen.to_string(), "0.0.0.0:4433");
        assert_eq!(cli.config.tun_name.as_deref(), Some("tunnel0"));
        assert_eq!(cli.config.server_name, "tunnel.example.com");
        assert_eq!(cli.config.keepalive_interval_secs, 20);
        assert_eq!(cli.config.dns_servers.len(), 3, "v4, v4 and v6 DNS are parsed");
        assert_eq!(cli.export_cert.as_deref(), Some(PathBuf::from("tunnel-root.der").as_path()));
        assert!(matches!(cli.config.tokens, TokensSource::File(_)));
    }

    #[test]
    fn admin_flags_enable_the_api_only_as_a_pair() {
        let cli = parse_cli(&argv(&[
            "--env-tokens",
            "--admin-listen=127.0.0.1:8080", // inline syntax works too
            "--admin-key", "operator-secret",
        ])).expect("parse").expect("not help");
        let admin = cli.config.admin.expect("the API is enabled");
        assert_eq!(admin.listen.to_string(), "127.0.0.1:8080");
        assert_eq!(admin.key, "operator-secret");

        // Half-configured admin flags are rejected: a keyless admin API is
        // an unprotected admin surface, a keyless-listener key is a typo.
        let only_listen = parse_cli(&argv(&["--env-tokens", "--admin-listen", "127.0.0.1:8080"]));
        assert!(only_listen.is_err(), "listen without a key");
        let only_key = parse_cli(&argv(&["--env-tokens", "--admin-key", "s"]));
        assert!(only_key.is_err(), "key without a listener");
        let bad_addr = parse_cli(&argv(&["--env-tokens", "--admin-listen", "nope", "--admin-key", "s"]));
        assert!(bad_addr.is_err());
    }

    #[test]
    fn unknown_flag_and_missing_value_fail() {
        assert!(parse_cli(&argv(&["--nope"])).is_err());
        assert!(parse_cli(&argv(&["--listen"])).is_err(), "no value");
        assert!(parse_cli(&argv(&["--mtu", "abc"])).is_err());
        assert!(parse_cli(&argv(&["--dns", "not-an-ip"])).is_err());
    }

    #[test]
    fn help_is_detected_without_exiting() {
        // --help must be a regular return value, not process::exit: otherwise
        // it kills the whole test binary and cannot be covered by tests.
        assert!(parse_cli(&argv(&["--help"])).is_ok());
        assert!(parse_cli(&argv(&["-h"])).is_ok());
    }
}
