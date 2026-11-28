//! Periodic reporting: connection status, RTT, throughput, live sessions.
//!
//! One line per interval on the `info` level — enough to see that the
//! tunnel is alive and what it is doing, without per-connection noise.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tunnel_core::ffi::TunnelState;
use tunnel_core::TunnelClient;

use crate::stack::Stack;

/// Prints a status line every `interval` until `shutdown` fires.
pub fn spawn(
    client: Arc<TunnelClient>,
    stack: Stack,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut previous = client.get_telemetry();
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = shutdown.changed() => return,
            }
            let now = client.get_telemetry();
            let down = now.bytes_received.saturating_sub(previous.bytes_received);
            let up = now.bytes_sent.saturating_sub(previous.bytes_sent);
            tracing::info!(
                status = %describe(&client.state()),
                ping = ?now.ping_ms.map(|ms| format!("{ms} ms")),
                down = %format_rate(down, interval),
                up = %format_rate(up, interval),
                totals = %format!("down {} / up {}", format_size(now.bytes_received as f64), format_size(now.bytes_sent as f64)),
                sessions = stack.live_sessions(),
                "tunnel stats"
            );
            previous = now;
        }
    })
}

/// A compact one-string status for the report line.
pub(crate) fn describe(state: &TunnelState) -> String {
    match state {
        TunnelState::Connected { mtu, vip } => format!("connected vip={vip} mtu={mtu}"),
        TunnelState::Connecting => "connecting".to_owned(),
        TunnelState::Disconnected => "disconnected".to_owned(),
        TunnelState::Stopping => "stopping".to_owned(),
        TunnelState::Stopped => "stopped".to_owned(),
    }
}

/// Human-readable size: `1234` → `"1.2 KiB"`.
pub fn format_size(bytes: f64) -> String {
    const KIB: f64 = 1024.0;
    if bytes < KIB {
        format!("{bytes:.0} B")
    } else if bytes < KIB * KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{:.1} MiB", bytes / (KIB * KIB))
    }
}

/// Human-readable rate over `period`: bytes transferred in a tick → per second.
pub fn format_rate(bytes: u64, period: Duration) -> String {
    if period.is_zero() {
        return "n/a".to_owned();
    }
    let per_second = bytes as f64 / period.as_secs_f64();
    format!("{}/s", format_size(per_second))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_core::Telemetry;

    #[test]
    fn sizes_format_with_binary_prefixes() {
        assert_eq!(format_size(0.0), "0 B");
        assert_eq!(format_size(999.0), "999 B");
        assert_eq!(format_size(1023.0), "1023 B");
        assert_eq!(format_size(1024.0), "1.0 KiB");
        assert_eq!(format_size(1536.0), "1.5 KiB");
        assert_eq!(format_size(1024.0 * 1024.0), "1.0 MiB");
        assert_eq!(format_size(2.5 * 1024.0 * 1024.0), "2.5 MiB");
    }

    #[test]
    fn rates_format_per_second() {
        assert_eq!(format_rate(0, Duration::from_secs(1)), "0 B/s");
        assert_eq!(format_rate(2048, Duration::from_secs(2)), "1.0 KiB/s");
        assert_eq!(format_rate(1024, Duration::from_millis(500)), "2.0 KiB/s");
        assert_eq!(format_rate(1, Duration::ZERO), "n/a", "zero interval is guarded");
    }

    #[test]
    fn states_describe_compactly() {
        assert_eq!(
            describe(&TunnelState::Connected {
                mtu: 1280,
                vip: "10.66.0.2".to_owned()
            }),
            "connected vip=10.66.0.2 mtu=1280"
        );
        assert_eq!(describe(&TunnelState::Connecting), "connecting");
        assert_eq!(describe(&TunnelState::Stopped), "stopped");
    }

    #[test]
    fn telemetry_deltas_drive_the_report() {
        // The report is the difference between two snapshots.
        let previous = Telemetry {
            bytes_sent: 100,
            bytes_received: 200,
            ping_ms: Some(5),
        };
        let now = Telemetry {
            bytes_sent: 1124,
            bytes_received: 200,
            ping_ms: Some(7),
        };
        let up = now.bytes_sent - previous.bytes_sent;
        let down = now.bytes_received.saturating_sub(previous.bytes_received);
        assert_eq!(up, 1024);
        assert_eq!(down, 0);
        assert_eq!(format_rate(up, Duration::from_secs(1)), "1.0 KiB/s");
    }
}
