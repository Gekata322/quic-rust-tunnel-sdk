//! Errors of the CLI components.

/// Errors of the userspace TCP stack ([`crate::stack`]).
#[derive(Debug, thiserror::Error)]
pub enum StackError {
    /// The tunnel is not (yet) established — the stack needs the VIP and MTU
    /// from the server `Welcome` before the first session.
    #[error("the tunnel is not established")]
    NotConnected,
    /// The remote refused the connection or it timed out.
    #[error("connection refused or timed out")]
    ConnectFailed,
    /// The requested local TCP port cannot be allocated.
    #[error("local port is unavailable")]
    PortUnavailable,
    /// The stack thread could not be started.
    #[error("failed to start the stack thread")]
    ThreadSpawn,
    /// The stack stopped (the tunnel client was dropped or stopped).
    #[error("the stack is shutting down")]
    Shutdown,
}
