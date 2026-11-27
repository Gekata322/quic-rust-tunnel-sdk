//! Client core errors (`tunnel-core`).
//!
//! `CoreError` is both a library error (`thiserror`) and an FFI error
//! (`uniffi::Error`): partner code in Kotlin/Swift sees typed variants with
//! messages, while Rust code distinguishes transient failures (reconnect) from
//! permanent ones (retrying is pointless).

use thiserror::Error;

/// Client tunnel core errors.
#[derive(Debug, Error, uniffi::Error)]
pub enum CoreError {
    /// The configuration is invalid (empty host/token, bad delays).
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    /// The pinned server certificate could not be parsed.
    #[error("invalid pinned server certificate: {0}")]
    InvalidServerCert(String),
    /// The server rejected authentication (token unknown or revoked).
    #[error("authentication rejected: {0}")]
    AuthRejected(String),
    /// The protocol version is not supported by the server — update the SDK.
    #[error("protocol version not supported: {0}")]
    ProtocolMismatch(String),
    /// The server is overloaded / the virtual IP pool is exhausted — retry is reasonable.
    #[error("server temporarily unavailable: {0}")]
    ServerBusy(String),
    /// OS I/O failure (UDP socket, engine thread, ...).
    #[error("I/O error: {0}")]
    Io(String),
    /// The QUIC connection was not established (network down, server silent).
    #[error("failed to connect: {0}")]
    ConnectFailed(String),
    /// Connection or handshake timed out.
    #[error("timed out: {0}")]
    TimedOut(String),
    /// An established session dropped (network, server closed the connection).
    #[error("session closed: {0}")]
    SessionClosed(String),
    /// Core bug: collect `tracing` logs and file a bug report.
    #[error("internal error: {0}")]
    Internal(String),
}

impl CoreError {
    /// Errors for which reconnecting is useless: the engine moves the client
    /// to `Stopped` instead of retrying forever.
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            Self::InvalidConfig(_)
                | Self::InvalidServerCert(_)
                | Self::AuthRejected(_)
                | Self::ProtocolMismatch(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permanent_and_transient_errors_are_classified() {
        assert!(CoreError::AuthRejected("token not found".into()).is_permanent());
        assert!(CoreError::ProtocolMismatch("v99".into()).is_permanent());
        assert!(CoreError::InvalidConfig("empty host".into()).is_permanent());
        assert!(CoreError::InvalidServerCert("bad DER".into()).is_permanent());

        assert!(!CoreError::ServerBusy("pool exhausted".into()).is_permanent());
        assert!(!CoreError::ConnectFailed("network down".into()).is_permanent());
        assert!(!CoreError::TimedOut("8s".into()).is_permanent());
        assert!(!CoreError::SessionClosed("QUIC closed".into()).is_permanent());
        assert!(!CoreError::Io("EBADF".into()).is_permanent());
        assert!(!CoreError::Internal("bug".into()).is_permanent());
    }
}
