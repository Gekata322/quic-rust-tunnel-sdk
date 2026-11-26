//! Сервер B2B-туннеля: CLI, подъём эндпоинта/TUN, цикл приёма клиентов.
//!
//! Режимы:
//! - **боевой** (`--tun tunnel0`): пакеты клиентов идут в TUN и наружу
//!   (NAT настраивается отдельными правилами — сервер печатает их с
//!   фактическими значениями сразу после старта);
//! - **loopback** (без `--tun`, дефолт): эхо пакетов на адрес сервера —
//!   проверка клиентов и CI без CAP_NET_ADMIN.
//!
//! Токены: `--tokens tokens.txt` (файл) или `--env-tokens` (TUNNEL_TOKENS).

use std::net::IpAddr;
use std::path::PathBuf;

use tokio::sync::watch;
use tunnel_proto::auth::TokenStore;
use tunnel_server::config::{ServerConfig, TokensSource};
use tunnel_server::endpoint::{accept_loop, build_endpoint, generate_certificate};
use tunnel_server::session::ServerShared;
use tunnel_server::tun::TunDevice;

/// Разобранный CLI: конфигурация + путь выгрузки сертификата.
struct Cli {
    config: ServerConfig,
    export_cert: Option<PathBuf>,
}

fn main() {
    // Логи: RUST_LOG управляет детализацией (дефолт — info).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let cli = match parse_cli(&args) {
        Ok(cli) => cli,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };

    if let Err(err) = run(cli) {
        eprintln!("Ошибка: {err}");
        std::process::exit(1);
    }
}

/// Полный запуск сервера: конфиг → сертификат → эндпоинт → TUN → accept_loop.
fn run(cli: Cli) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("tokio-рантайм: {err}"))?;
    runtime.block_on(async_run(cli))
}

async fn async_run(cli: Cli) -> Result<(), String> {
    let config = cli.config;
    config
        .validate()
        .map_err(|err| format!("конфигурация: {err}"))?;
    let tokens: TokenStore = config
        .load_tokens()
        .map_err(|err| format!("токены: {err}"))?;
    if tokens.is_empty() {
        return Err("ни одного токена не загружено: сервер никого не пустит \
             (см. --tokens/--env-tokens)"
            .to_owned());
    }

    let cert = generate_certificate(&config.server_name)
        .map_err(|err| format!("{err}"))?;
    if let Some(path) = &cli.export_cert {
        std::fs::write(path, &cert.der)
            .map_err(|err| format!("выгрузка сертификата в {}: {err}", path.display()))?;
        tracing::info!(path = %path.display(), "DER-сертификат для pinning экспортирован");
    }

    let endpoint = build_endpoint(&cert, config.listen).map_err(|err| err.to_string())?;
    tracing::info!(
        local_addr = %endpoint.local_addr().expect("привязан"),
        server_name = %config.server_name,
        "QUIC-эндпоинт поднят"
    );

    let tun = match &config.tun_name {
        Some(name) => {
            let tun = TunDevice::open(name).map_err(|err| err.to_string())?;
            tracing::info!(name = tun.name(), "TUN-интерфейс поднят");
            // Адрес и маршруты выставляет оператор (см. подсказку ниже).
            Some(tun)
        }
        None => {
            tracing::info!("loopback-режим: эхо только на адрес сервера, TUN не создаётся");
            None
        }
    };

    let shared = ServerShared::new(&config, tokens.clone(), tun)
        .map_err(|err| format!("{err}"))?;
    tracing::info!(
        server_vip = %shared.server_vip,
        pool = %config.pool,
        mtu = config.mtu,
        tokens = tokens.len(),
        "сервер готов принимать клиентов"
    );
    if let (Some(name), dns) = (&config.tun_name, &config.dns_servers) {
        // Подсказка маршрутизации: фактические значения — копируй и выполняй.
        println!("# Маршрутизация клиентов наружу (выполни с root):");
        println!("sysctl -w net.ipv4.ip_forward=1");
        println!("ip addr add {}/24 dev {}", shared.server_vip, name);
        println!("ip link set {} up", name);
        println!("iptables -t nat -A POSTROUTING -s {} ! -o {} -j MASQUERADE", config.pool, name);
        println!("iptables -A FORWARD -i {} -j ACCEPT", name);
        println!("iptables -A FORWARD -o {} -j ACCEPT", name);
        if !dns.is_empty() {
            println!("# Рекомендуемые клиентам DNS: {}", join_dns(dns));
        }
    }

    shared.spawn_tun_reader();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("получен Ctrl-C: корректная остановка");
            let _ = shutdown_tx.send(true);
        }
    });

    accept_loop(shared, endpoint, shutdown_rx).await;
    tracing::info!("сервер остановлен");
    Ok(())
}

fn join_dns(servers: &[IpAddr]) -> String {
    servers
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Парсит CLI: `--флаг значение` или `--флаг=значение`; `--help` — usage.
fn parse_cli(args: &[String]) -> Result<Cli, String> {
    let mut config = ServerConfig {
        listen: "0.0.0.0:443".parse().expect("дефолтный слушатель"),
        pool: "10.66.0.0/24".to_owned(),
        mtu: 1280,
        keepalive_interval_secs: 15,
        dns_servers: Vec::new(),
        tun_name: None,
        server_name: "tunnel-server".to_owned(),
        tokens: TokensSource::Env,
    };
    let mut export_cert = None;

    let usage = "использование:
  tunnel-server --listen 0.0.0.0:443 --tokens tokens.txt \\
      --tun tunnel0 --pool 10.66.0.0/24 --mtu 1280 \\
      --server-name tunnel.example.com --export-cert tunnel-root.der
  tunnel-server --listen 127.0.0.1:4433 --env-tokens   # loopback-режим

флаги:
  --listen <ip:port>        UDP-адрес QUIC (дефолт 0.0.0.0:443)
  --tokens <файл>           файл токенов: «client_id:token» построчно
  --env-tokens              читать TUNNEL_TOKENS («a:t1,b:t2»)
  --tun <имя>               боевой режим: TUN-интерфейс (нужен CAP_NET_ADMIN)
  --pool <cidr>             подсеть виртуальных адресов (дефолт 10.66.0.0/24)
  --mtu <n>                 MTU клиентов (дефолт 1280)
  --keepalive <сек>         период прикладного ping (дефолт 15)
  --dns <a,b,c>             DNS-серверы, рекомендуемые клиентам
  --server-name <имя>       SAN сертификата / SNI (дефолт tunnel-server)
  --export-cert <файл>      выгрузить DER-сертификат для pinning клиента
  -h, --help                эта справка";

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
                    .ok_or_else(|| format!("{flag}: ожидается значение\n\n{usage}")),
            }
        };
        match flag {
            "-h" | "--help" => {
                println!("{usage}");
                std::process::exit(0);
            }
            "--listen" => {
                config.listen = next_value(flag)?
                    .parse()
                    .map_err(|_| format!("--listen: ожидался ip:port, получено «{}»", args[index + 1]))?;
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
                    .map_err(|_| format!("--mtu: ожидалось число, получено «{}»", args[index + 1]))?;
            }
            "--keepalive" => {
                config.keepalive_interval_secs = next_value(flag)?
                    .parse()
                    .map_err(|_| format!("--keepalive: ожидалось число секунд, получено «{}»", args[index + 1]))?;
            }
            "--dns" => {
                config.dns_servers = next_value(flag)?
                    .split(',')
                    .filter(|part| !part.trim().is_empty())
                    .map(|part| {
                        part.trim()
                            .parse::<IpAddr>()
                            .map_err(|_| format!("--dns: «{part}» не IP-адрес"))
                    })
                    .collect::<Result<_, _>>()?;
            }
            "--server-name" => {
                config.server_name = next_value(flag)?;
            }
            "--export-cert" => {
                export_cert = Some(PathBuf::from(next_value(flag)?));
            }
            other => {
                return Err(format!("неизвестный флаг «{other}»\n\n{usage}"));
            }
        }
        // Пропускаем значение, если оно было отдельным аргументом.
        if inline_value.is_none() && !matches!(flag, "-h" | "--help" | "--env-tokens") {
            index += 1;
        }
        index += 1;
    }

    Ok(Cli { config, export_cert })
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
        let cli = parse_cli(&argv(&["--env-tokens"])).expect("парсинг");
        assert_eq!(cli.config.listen.to_string(), "0.0.0.0:443");
        assert_eq!(cli.config.pool, "10.66.0.0/24");
        assert_eq!(cli.config.mtu, 1280);
        assert_eq!(cli.config.keepalive_interval_secs, 15);
        assert_eq!(cli.config.server_name, "tunnel-server");
        assert!(cli.config.tun_name.is_none());
        assert!(cli.config.is_loopback());
        assert!(cli.export_cert.is_none());
    }

    #[test]
    fn full_production_flags() {
        let cli = parse_cli(&argv(&[
            "--listen", "0.0.0.0:4433",
            "--tokens", "tokens.txt",
            "--tun", "tunnel0",
            "--pool", "10.66.0.0/24",
            "--mtu", "1280",
            "--server-name", "tunnel.example.com",
            "--export-cert", "tunnel-root.der",
            "--keepalive", "20",
            "--dns", "8.8.8.8,1.1.1.1",
        ])).expect("парсинг");
        assert_eq!(cli.config.listen.to_string(), "0.0.0.0:4433");
        assert_eq!(cli.config.tun_name.as_deref(), Some("tunnel0"));
        assert_eq!(cli.config.server_name, "tunnel.example.com");
        assert_eq!(cli.config.keepalive_interval_secs, 20);
        assert_eq!(cli.config.dns_servers.len(), 2);
        assert_eq!(cli.export_cert.as_deref(), Some(PathBuf::from("tunnel-root.der").as_path()));
        assert!(matches!(cli.config.tokens, TokensSource::File(_)));
    }

    #[test]
    fn inline_value_syntax_supported() {
        let cli = parse_cli(&argv(&["--listen=127.0.0.1:9999", "--env-tokens"]))
            .expect("парсинг");
        assert_eq!(cli.config.listen.to_string(), "127.0.0.1:9999");
    }

    #[test]
    fn unknown_flag_and_missing_value_fail() {
        assert!(parse_cli(&argv(&["--nope"])).is_err());
        assert!(parse_cli(&argv(&["--listen"])).is_err(), "без значения");
        assert!(parse_cli(&argv(&["--mtu", "abc"])).is_err());
        assert!(parse_cli(&argv(&["--dns", "не-ip"])).is_err());
    }

    #[test]
    fn tokens_source_switches() {
        let cli = parse_cli(&argv(&["--env-tokens"])).expect("парсинг");
        assert!(matches!(cli.config.tokens, TokensSource::Env));
        let cli = parse_cli(&argv(&["--tokens", "t.txt"])).expect("парсинг");
        assert!(matches!(cli.config.tokens, TokensSource::File(_)));
    }

    #[test]
    fn help_exits_before_parse_errors() {
        // --help обрабатывается немедленно: ошибки остальных флагов не важны.
        let cli = parse_cli(&argv(&["--help"]));
        assert!(cli.is_err(), "после exit(0) сюда не дойти — сигнал не-ошибки скрыт exit'ом");
    }

    #[test]
    fn dns_list_is_parsed() {
        let cli = parse_cli(&argv(&["--dns", "8.8.8.8,1.1.1.1, 2606:4700:4700::1111 ", "--env-tokens"]))
            .expect("парсинг");
        assert_eq!(cli.config.dns_servers.len(), 3);
    }
}
