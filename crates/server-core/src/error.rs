//! Error type for `server-core`.

/// Errors returned by `server-core`.
///
/// Messages never contain secrets and never reveal whether an account exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A client message or stored value could not be parsed.
    #[error("malformed message")]
    MalformedMessage,

    /// Authentication failed.
    #[error("authentication failed")]
    Authentication,

    /// The server's secret configuration is missing or invalid.
    #[error("invalid server configuration")]
    InvalidConfiguration,

    /// A write does not extend the current state; re-read and retry.
    #[error("conflict with a concurrent change")]
    Conflict,

    /// The request is not allowed in the current state.
    #[error("not allowed")]
    NotAllowed,

    /// A waiting period has not yet passed.
    #[error("waiting period not over")]
    TooEarly,
}

impl From<vault_core::Error> for Error {
    fn from(e: vault_core::Error) -> Self {
        match e {
            vault_core::Error::MalformedMessage => Self::MalformedMessage,
            _ => Self::Authentication,
        }
    }
}

/// Result type used throughout `server-core`.
pub type Result<T> = core::result::Result<T, Error>;
