/// Why a client flow failed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientError {
    /// The email address, password or Secret Key is wrong. The server
    /// cannot tell which, and neither can the client.
    #[error("wrong email address, password or Secret Key")]
    WrongCredentials,

    /// The session has expired or was ended; sign in again.
    #[error("not signed in")]
    SignedOut,

    /// Too many attempts; try again after this many seconds, if known.
    #[error("too many attempts")]
    RateLimited(Option<u64>),

    /// The server refused the request with this status and error code.
    #[error("server error {status}: {code}")]
    Server {
        /// HTTP status.
        status: u16,
        /// The `error` code from the body (spec section 12.3).
        code: String,
    },

    /// The server's answer was malformed or failed a check. Treat this as a
    /// possible attack, not a network glitch.
    #[error("invalid answer from the server")]
    InvalidResponse,

    /// The app asked for a change the vault format does not allow, such as
    /// deleting a vault's details or saving an ordinary item in their place.
    #[error("not allowed for this item")]
    NotAllowed,

    /// The vault holds items saved by a newer version of the app, and this
    /// change needs every item: update the app first.
    #[error("update the app to make this change")]
    NeedsUpdate,

    /// A cryptographic check failed, or input was invalid.
    #[error(transparent)]
    Crypto(#[from] vault_core::Error),
}

/// Result type for client flows.
pub type Result<T> = core::result::Result<T, ClientError>;
