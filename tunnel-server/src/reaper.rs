//! Idle-session reaper: protects the address pool from vanished clients.
//!
//! A client that lost its network without closing the QUIC connection
//! (laptop sleep, dead Wi-Fi, NAT teardown) still holds its virtual address.
//! The QUIC idle timeout only helps while the session task keeps polling the
//! connection; a task stuck in a blocking write would keep the address
//! forever. The reaper scans the tracked sessions on a timer and force-closes
//! the ones that produced no inbound traffic (control or data) for
//! [`IDLE_SESSION_TIMEOUT`]: the QUIC connection is closed, the routing entry
//! is removed and the virtual address returns to the pool. The session task's
//! own cleanup is idempotent, so its later exit is a harmless no-op.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::session::ServerShared;

/// A session silent for longer than this is force-closed and its address is
/// returned to the pool.
pub const IDLE_SESSION_TIMEOUT: Duration = Duration::from_secs(45);
/// How often the reaper scans for idle sessions.
pub const REAP_INTERVAL: Duration = Duration::from_secs(5);

/// What the reaper needs to identify and kill a stale session.
pub(crate) struct TrackedSession {
    pub(crate) client_id: String,
    /// The live QUIC connection: closing it unblocks the session task.
    pub(crate) conn: quinn::Connection,
    /// The session's own outbound channel — the routing table removes an
    /// entry only when it belongs to exactly this channel.
    pub(crate) outbound_tx: mpsc::Sender<Vec<u8>>,
    /// Last inbound activity (a control message or a datagram).
    pub(crate) last_activity: Instant,
}

/// Registry of live sessions with their last inbound activity.
#[derive(Default)]
pub struct SessionTracker {
    sessions: Mutex<HashMap<Ipv4Addr, TrackedSession>>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a session with `last_activity = now`. Re-registering the same
    /// address (a fast-reconnecting client) replaces the stale entry.
    pub(crate) fn register(
        &self,
        vip: Ipv4Addr,
        client_id: &str,
        conn: quinn::Connection,
        outbound_tx: mpsc::Sender<Vec<u8>>,
    ) {
        self.sessions.lock().expect("tracker mutex").insert(
            vip,
            TrackedSession {
                client_id: client_id.to_owned(),
                conn,
                outbound_tx,
                last_activity: Instant::now(),
            },
        );
    }

    /// Marks inbound activity for a session.
    pub(crate) fn touch(&self, vip: Ipv4Addr) {
        if let Some(session) = self.sessions.lock().expect("tracker mutex").get_mut(&vip) {
            session.last_activity = Instant::now();
        }
    }

    /// Removes the entry; the session task calls it on every exit path.
    pub(crate) fn remove(&self, vip: Ipv4Addr) -> bool {
        self.sessions
            .lock()
            .expect("tracker mutex")
            .remove(&vip)
            .is_some()
    }

    /// Removes and returns the sessions that were silent for longer than
    /// `idle_timeout`. The caller performs the actual cleanup.
    pub(crate) fn take_idle(&self, idle_timeout: Duration) -> Vec<(Ipv4Addr, TrackedSession)> {
        let mut sessions = self.sessions.lock().expect("tracker mutex");
        let stale: Vec<Ipv4Addr> = sessions
            .iter()
            .filter(|(_, session)| session.last_activity.elapsed() > idle_timeout)
            .map(|(vip, _)| *vip)
            .collect();
        stale
            .into_iter()
            .filter_map(|vip| sessions.remove(&vip).map(|session| (vip, session)))
            .collect()
    }

    /// Number of tracked sessions (diagnostics).
    pub fn tracked(&self) -> usize {
        self.sessions.lock().expect("tracker mutex").len()
    }
}

/// Spawns the reaper loop with the production timeouts
/// ([`IDLE_SESSION_TIMEOUT`], [`REAP_INTERVAL`]).
pub fn spawn_idle_reaper(shared: &Arc<ServerShared>) {
    spawn_idle_reaper_with(shared, IDLE_SESSION_TIMEOUT, REAP_INTERVAL);
}

/// Spawns the reaper loop with explicit timeouts (tests use shortened ones).
pub fn spawn_idle_reaper_with(
    shared: &Arc<ServerShared>,
    idle_timeout: Duration,
    interval: Duration,
) {
    let shared = Arc::clone(shared);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            shared.reap_idle_sessions(idle_timeout);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::{build_endpoint, generate_certificate};

    fn vip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 66, 0, last)
    }

    /// A real QUIC connection over localhost: the tracker stores live
    /// connections, so the tests need one.
    async fn live_conn() -> (quinn::Connection, quinn::Endpoint) {
        let cert = generate_certificate("localhost").expect("certificate");
        let server = build_endpoint(&cert, "127.0.0.1:0".parse().expect("bind address"))
            .expect("server endpoint");
        let addr = server.local_addr().expect("local address");

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der.clone()).expect("pinned certificate");
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![tunnel_proto::ALPN_TUNNEL_V1.to_vec()];
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("QUIC over TLS");
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().expect("bind address"))
            .expect("client endpoint");
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));

        let connect = client.connect(addr, "localhost").expect("connect started");
        let (conn, _server_conn) =
            tokio::join!(async { connect.await.expect("handshake") }, async {
                server
                    .accept()
                    .await
                    .expect("incoming connection")
                    .await
                    .expect("handshake")
            });
        (conn, client)
    }

    #[tokio::test]
    async fn take_idle_returns_only_stale_sessions() {
        let (conn, endpoint) = live_conn().await;
        let tracker = SessionTracker::new();
        let (tx, _rx) = mpsc::channel(8);
        tracker.register(vip(2), "client-a", conn, tx);

        // A fresh session is not stale even for a tiny timeout.
        assert!(tracker.take_idle(Duration::from_millis(1)).is_empty());

        tokio::time::sleep(Duration::from_millis(10)).await;
        let taken = tracker.take_idle(Duration::from_millis(5));
        assert_eq!(taken.len(), 1, "the silent session is taken");
        assert_eq!(taken[0].0, vip(2));
        assert_eq!(taken[0].1.client_id, "client-a");
        assert!(
            tracker.take_idle(Duration::from_millis(5)).is_empty(),
            "taken exactly once — gone from the registry"
        );
        drop(endpoint);
    }

    #[tokio::test]
    async fn touch_keeps_a_session_not_stale() {
        let (conn, endpoint) = live_conn().await;
        let tracker = SessionTracker::new();
        let (tx, _rx) = mpsc::channel(8);
        tracker.register(vip(3), "client-b", conn, tx);

        tokio::time::sleep(Duration::from_millis(10)).await;
        tracker.touch(vip(3));
        assert!(
            tracker.take_idle(Duration::from_millis(5)).is_empty(),
            "a touched session is fresh again"
        );

        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(
            tracker.take_idle(Duration::from_millis(5)).len(),
            1,
            "the session goes stale again after the touch"
        );
        drop(endpoint);
    }

    #[tokio::test]
    async fn remove_is_idempotent_and_reregistration_replaces() {
        let (conn, endpoint) = live_conn().await;
        let tracker = SessionTracker::new();
        let (tx, _rx) = mpsc::channel(8);
        tracker.register(vip(4), "client-c", conn.clone(), tx.clone());
        assert_eq!(tracker.tracked(), 1);

        assert!(tracker.remove(vip(4)));
        assert!(!tracker.remove(vip(4)), "removing twice is a no-op");
        assert_eq!(tracker.tracked(), 0);

        // A reconnecting client replaces the entry with a fresh one.
        tracker.register(vip(4), "client-c2", conn, tx);
        assert_eq!(tracker.tracked(), 1);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let taken = tracker.take_idle(Duration::from_millis(5));
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].1.client_id, "client-c2");
        drop(endpoint);
    }
}
