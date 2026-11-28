//! HTTP admin API (axum): token management and live server statistics.
//!
//! Endpoints (every request must carry `X-Admin-Key` matching
//! [`crate::config::AdminConfig::key`]; the comparison is constant time):
//! - `POST /tokens` — add a token or replace an existing one (upsert):
//!   `{"client_id": "...", "token": "...", "rate_limit_mbps": 10}` (the
//!   limit field is optional); `201` on create, `200` on replace, `400` on
//!   validation errors. The secret is never echoed back;
//! - `DELETE /tokens/{client_id}` — hot revocation: the entry is removed and
//!   every live session of the client is force-closed, its virtual addresses
//!   return to the pool; `404` for an unknown client;
//! - `GET /stats` — counters, pool state and the live session list.
//!
//! The API binds to a private interface (`127.0.0.1` by default) and is
//! meant for operators, not clients: keep it off the public network or put
//! an authenticating proxy in front. Token changes are in-memory only —
//! the token file is never rewritten (see [`crate::registry`]).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use tunnel_proto::auth::{TokenEntry, const_time_eq};
use tunnel_proto::MetricsSnapshot;

use crate::config::AdminConfig;
use crate::session::ServerShared;

/// Largest accepted `client_id`/`token` length: enough headroom for real
/// identifiers, still bounded so one request cannot bloat the registry.
const MAX_FIELD_LEN: usize = 512;

/// Admin API startup errors.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// The HTTP listener did not bind.
    #[error("bind {0}: {1}")]
    Bind(SocketAddr, #[source] std::io::Error),
}

/// State shared by all handlers.
#[derive(Clone)]
struct AdminState {
    shared: Arc<ServerShared>,
    admin_key: Arc<str>,
    started: Instant,
}

/// Binds the admin HTTP server and spawns it. Returns the actual bound
/// address (`:0` → an ephemeral port, tests and dynamic deploys). The server
/// stops on `shutdown_rx = true` or when every sender is dropped.
pub async fn spawn_admin_server(
    shared: Arc<ServerShared>,
    admin: &AdminConfig,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<SocketAddr, AdminError> {
    let state = AdminState {
        shared,
        admin_key: Arc::from(admin.key.as_str()),
        started: Instant::now(),
    };
    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(admin.listen)
        .await
        .map_err(|err| AdminError::Bind(admin.listen, err))?;
    let bound = listener
        .local_addr()
        .map_err(|err| AdminError::Bind(admin.listen, err))?;
    tokio::spawn(async move {
        let stop = stop_when_shutdown(shutdown_rx);
        if let Err(err) = axum::serve(listener, router).with_graceful_shutdown(stop).await {
            tracing::error!(%err, "admin HTTP server failed");
        }
    });
    tracing::info!(addr = %bound, "admin HTTP API is up");
    Ok(bound)
}

/// Resolves when the shutdown flag is set or the sender side is dropped.
async fn stop_when_shutdown(mut shutdown_rx: watch::Receiver<bool>) {
    loop {
        if *shutdown_rx.borrow() {
            return;
        }
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

/// Builds the router: the auth middleware covers every route, there is no
/// anonymous endpoint.
fn build_router(state: AdminState) -> Router {
    Router::new()
        .route("/tokens", post(create_token))
        .route("/tokens/{client_id}", delete(revoke_token))
        .route("/stats", get(stats))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_admin_key,
        ))
        .with_state(state)
}

/// Gate for every request: `X-Admin-Key` must match the configured key.
/// Missing and wrong keys answer identically, so the API does not reveal
/// whether a header was expected at all.
async fn require_admin_key(
    State(state): State<AdminState>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let authorized = headers
        .get("X-Admin-Key")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|provided| const_time_eq(provided.as_bytes(), state.admin_key.as_bytes()));
    if authorized {
        next.run(request).await
    } else {
        error_response(
            StatusCode::UNAUTHORIZED,
            "missing or invalid X-Admin-Key header",
        )
    }
}

/// Request body of `POST /tokens`.
#[derive(Debug, Deserialize)]
struct CreateTokenRequest {
    client_id: String,
    token: String,
    /// Optional data-plane cap for this client, Mbps.
    rate_limit_mbps: Option<u32>,
}

/// Response of `POST /tokens` (the secret is never echoed back).
#[derive(Debug, Serialize)]
struct CreateTokenResponse {
    client_id: String,
    rate_limit_mbps: Option<u32>,
    /// `true` — a new client was created; `false` — an existing one replaced.
    created: bool,
}

/// Response of `DELETE /tokens/{client_id}`.
#[derive(Debug, Serialize)]
struct RevokeResponse {
    client_id: String,
    revoked: bool,
    /// Live sessions that were force-closed by the revocation.
    sessions_killed: usize,
}

/// One live session in `GET /stats`.
#[derive(Debug, Serialize)]
struct SessionView {
    client_id: String,
    /// Assigned virtual address.
    vip: String,
    /// Seconds since the last inbound control message or datagram.
    idle_secs: u64,
}

/// Counter snapshot for `GET /stats` (a serde mirror of the wire metrics).
#[derive(Debug, Serialize)]
struct MetricsView {
    bytes_sent: u64,
    bytes_received: u64,
    datagrams_sent: u64,
    datagrams_received: u64,
    packets_dropped: u64,
    rate_limited: u64,
    sessions_established: u64,
    reconnects: u64,
}

impl From<MetricsSnapshot> for MetricsView {
    fn from(snap: MetricsSnapshot) -> Self {
        Self {
            bytes_sent: snap.bytes_sent,
            bytes_received: snap.bytes_received,
            datagrams_sent: snap.datagrams_sent,
            datagrams_received: snap.datagrams_received,
            packets_dropped: snap.packets_dropped,
            rate_limited: snap.rate_limited,
            sessions_established: snap.sessions_established,
            reconnects: snap.reconnects,
        }
    }
}

/// Response of `GET /stats`.
#[derive(Debug, Serialize)]
struct StatsResponse {
    /// Server uptime, seconds.
    uptime_secs: u64,
    /// `"loopback"` (echo mode) or `"tun"` (production mode).
    mode: &'static str,
    /// Live routing entries.
    active_clients: usize,
    /// Pool addresses currently issued.
    allocated_addresses: usize,
    /// Pool capacity for clients.
    pool_capacity: usize,
    /// Number of stored token entries.
    tokens: usize,
    metrics: MetricsView,
    /// Live sessions with their idle times.
    sessions: Vec<SessionView>,
}

/// JSON error body shared by all error answers.
#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(ErrorBody { error: message.into() })).into_response()
}

/// Adds a token or replaces the entry of the same `client_id` (upsert).
/// Live sessions of a replaced client are untouched — revocation is a
/// separate `DELETE` call.
async fn create_token(
    State(state): State<AdminState>,
    Json(request): Json<CreateTokenRequest>,
) -> Response {
    let client_id = request.client_id.trim();
    let token = request.token.trim();
    if client_id.is_empty() || token.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "client_id and token must be non-empty");
    }
    if client_id.len() > MAX_FIELD_LEN || token.len() > MAX_FIELD_LEN {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!("client_id and token must be at most {MAX_FIELD_LEN} characters"),
        );
    }
    if request.rate_limit_mbps == Some(0) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "rate_limit_mbps must be positive — to block a client, revoke the token instead",
        );
    }
    let entry = TokenEntry {
        client_id: client_id.to_owned(),
        token: token.to_owned(),
        rate_limit_mbps: request.rate_limit_mbps,
    };
    let created = !state.shared.tokens().upsert(entry);
    let status = if created { StatusCode::CREATED } else { StatusCode::OK };
    (
        status,
        Json(CreateTokenResponse {
            client_id: client_id.to_owned(),
            rate_limit_mbps: request.rate_limit_mbps,
            created,
        }),
    )
        .into_response()
}

/// Hot revocation: the token entry is removed (future handshakes are
/// rejected) and every live session of the client is force-closed — the
/// addresses return to the pool immediately.
async fn revoke_token(State(state): State<AdminState>, Path(client_id): Path<String>) -> Response {
    if state.shared.tokens().remove(&client_id).is_none() {
        return error_response(
            StatusCode::NOT_FOUND,
            format!("unknown client_id {client_id:?}"),
        );
    }
    let sessions_killed = state.shared.revoke_client_sessions(&client_id);
    (
        StatusCode::OK,
        Json(RevokeResponse {
            client_id,
            revoked: true,
            sessions_killed,
        }),
    )
        .into_response()
}

/// Live server statistics: counters, pool state, sessions.
async fn stats(State(state): State<AdminState>) -> Json<StatsResponse> {
    let shared = &state.shared;
    Json(StatsResponse {
        uptime_secs: state.started.elapsed().as_secs(),
        mode: if shared.is_loopback() { "loopback" } else { "tun" },
        active_clients: shared.active_clients(),
        allocated_addresses: shared.allocated_addresses(),
        pool_capacity: shared.pool_capacity(),
        tokens: shared.tokens().len(),
        metrics: MetricsView::from(shared.metrics.snapshot()),
        sessions: shared
            .session_infos()
            .into_iter()
            .map(|info| SessionView {
                client_id: info.client_id,
                vip: info.vip.to_string(),
                idle_secs: info.idle.as_secs(),
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::config::{ServerConfig, TokensSource};

    fn test_state() -> AdminState {
        let config = ServerConfig {
            listen: "127.0.0.1:0".parse().expect("address"),
            pool: "10.66.0.0/24".to_owned(),
            mtu: 1280,
            keepalive_interval_secs: 15,
            dns_servers: vec![],
            tun_name: None,
            server_name: "localhost".to_owned(),
            tokens: TokensSource::Inline(vec![("c".to_owned(), "t".to_owned())]),
            admin: None,
        };
        let tokens = config.load_tokens().expect("tokens");
        let shared = ServerShared::new(&config, tokens, None).expect("server state");
        AdminState {
            shared,
            admin_key: Arc::from("test-key"),
            started: Instant::now(),
        }
    }

    async fn call(
        app: Router,
        method: &str,
        uri: &str,
        key: Option<&str>,
        body: Option<String>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(key) = key {
            builder = builder.header("X-Admin-Key", key);
        }
        if body.is_some() {
            builder = builder.header("Content-Type", "application/json");
        }
        let request = builder
            .body(Body::from(body.unwrap_or_default()))
            .expect("request");
        let response = app.oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = BodyExt::collect(response.into_body())
            .await
            .expect("body")
            .to_bytes();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            // Rejected request bodies answer with plain text, not JSON —
            // keep the helper total and let the test assert on the status.
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    #[tokio::test]
    async fn stats_requires_the_admin_key() {
        let state = test_state();
        let app = build_router(state.clone());

        for key in [None, Some("wrong-key")] {
            let (status, body) = call(app.clone(), "GET", "/stats", key, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "key: {key:?}");
            assert_eq!(body["error"], "missing or invalid X-Admin-Key header");
        }

        let (status, body) = call(app, "GET", "/stats", Some("test-key"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["mode"], "loopback");
        assert_eq!(body["active_clients"], 0);
        assert_eq!(body["allocated_addresses"], 0);
        assert_eq!(body["pool_capacity"], 253);
        assert_eq!(body["tokens"], 1);
        assert_eq!(body["metrics"]["sessions_established"], 0);
        assert_eq!(body["sessions"], serde_json::Value::Array(Vec::new()));
    }

    #[tokio::test]
    async fn create_token_validates_and_upserts() {
        let state = test_state();
        let app = build_router(state.clone());

        // Without the key nothing is created.
        let (status, _) = call(
            app.clone(),
            "POST",
            "/tokens",
            None,
            Some(r#"{"client_id":"new","token":"tok"}"#.to_owned()),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!state.shared.tokens().verify("new", "tok"));

        // Validation errors.
        for bad_body in [
            r#"{"client_id":"  ","token":"tok"}"#,
            r#"{"client_id":"new","token":"  "}"#,
            r#"{"client_id":"new","token":"tok","rate_limit_mbps":0}"#,
        ] {
            let (status, body) = call(
                app.clone(),
                "POST",
                "/tokens",
                Some("test-key"),
                Some(bad_body.to_owned()),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "body: {bad_body}");
            assert!(body["error"].is_string(), "an error message is returned");
        }
        let oversized = format!(
            r#"{{"client_id":"{}","token":"tok"}}"#,
            "x".repeat(MAX_FIELD_LEN + 1)
        );
        let (status, _) = call(
            app.clone(),
            "POST",
            "/tokens",
            Some("test-key"),
            Some(oversized),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "oversized client_id");

        // A garbage body is a client error, not a panic.
        let (status, _) = call(
            app.clone(),
            "POST",
            "/tokens",
            Some("test-key"),
            Some("not-json".to_owned()),
        )
        .await;
        assert!(status.is_client_error(), "malformed JSON: {status}");

        // Create: 201, the token verifies immediately.
        let (status, body) = call(
            app.clone(),
            "POST",
            "/tokens",
            Some("test-key"),
            Some(r#"{"client_id":"new","token":"tok","rate_limit_mbps":2}"#.to_owned()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["created"], true);
        assert_eq!(body["client_id"], "new");
        assert_eq!(body["rate_limit_mbps"], 2);
        assert!(state.shared.tokens().verify("new", "tok"));
        assert_eq!(state.shared.tokens().limit_of("new"), Some(2));

        // Replace: 200, the old secret stops verifying, the cap is updated.
        let (status, body) = call(
            app,
            "POST",
            "/tokens",
            Some("test-key"),
            Some(r#"{"client_id":"new","token":"tok2"}"#.to_owned()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["created"], false);
        assert!(!state.shared.tokens().verify("new", "tok"), "old secret gone");
        assert!(state.shared.tokens().verify("new", "tok2"));
        assert_eq!(state.shared.tokens().limit_of("new"), None);
    }

    #[tokio::test]
    async fn delete_revokes_and_reports_unknown_clients() {
        let state = test_state();
        let app = build_router(state.clone());

        let (status, _) = call(app.clone(), "DELETE", "/tokens/ghost", Some("test-key"), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        state.shared.tokens().upsert(TokenEntry {
            client_id: "guest".to_owned(),
            token: "guest-token".to_owned(),
            rate_limit_mbps: None,
        });
        // No live session yet: the revocation kills nothing but still removes.
        let (status, body) =
            call(app.clone(), "DELETE", "/tokens/guest", Some("test-key"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["revoked"], true);
        assert_eq!(body["sessions_killed"], 0);
        assert!(
            !state.shared.tokens().verify("guest", "guest-token"),
            "the token must stop verifying right after the revocation"
        );
        let (status, _) = call(app, "DELETE", "/tokens/guest", Some("test-key"), None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "already revoked");
    }
}
