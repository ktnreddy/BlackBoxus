use serde::Serialize;
use serde::de::DeserializeOwned;
use vault_core::AccountId;
use vault_core::login::SessionToken;
use wire::ErrorResponse;

use crate::{ClientError, Result};

/// Largest response body a client accepts (twice the request limit).
const MAX_RESPONSE_BYTES: usize = 2 << 20;

/// HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`
    Get,
    /// `POST`
    Post,
    /// `PUT`
    Put,
}

impl Method {
    /// The method's name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }
}

/// A request for the app to send, to the server origin plus [`Request::path`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// HTTP method.
    pub method: Method,
    /// Path and query, starting with `/v1/`.
    pub path: String,
    /// JSON body, if any. Send with `Content-Type: application/json`.
    pub body: Option<String>,
    /// Value for the `Authorization` header, if the request needs a session.
    /// Never log it.
    pub authorization: Option<String>,
}

impl Request {
    pub(crate) fn get(path: String, session: Option<&Session>) -> Self {
        Self {
            method: Method::Get,
            path,
            body: None,
            authorization: session.map(Session::authorization),
        }
    }

    pub(crate) fn json<T: Serialize>(
        method: Method,
        path: String,
        body: &T,
        session: Option<&Session>,
    ) -> Result<Self> {
        Ok(Self {
            method,
            path,
            body: Some(serde_json::to_string(body).map_err(|_| ClientError::InvalidResponse)?),
            authorization: session.map(Session::authorization),
        })
    }
}

/// What the server answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// HTTP status.
    pub status: u16,
    /// The `Retry-After` header in seconds, if present.
    pub retry_after: Option<u64>,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// Parses a successful answer, or turns an error answer into a
    /// [`ClientError`].
    pub(crate) fn parse<T: DeserializeOwned>(&self) -> Result<T> {
        if self.body.len() > MAX_RESPONSE_BYTES {
            return Err(ClientError::InvalidResponse);
        }
        if self.status == 200 {
            return serde_json::from_slice(&self.body).map_err(|_| ClientError::InvalidResponse);
        }
        let code = serde_json::from_slice::<ErrorResponse>(&self.body)
            .map(|e| e.error)
            .unwrap_or_default();
        Err(match (self.status, code.as_str()) {
            (429, _) => ClientError::RateLimited(self.retry_after),
            (401, _) => ClientError::SignedOut,
            _ => ClientError::Server {
                status: self.status,
                code,
            },
        })
    }

    /// Checks a successful answer whose body does not matter.
    pub(crate) fn ok(&self) -> Result<()> {
        self.parse::<serde::de::IgnoredAny>().map(|_| ())
    }
}

/// A signed-in session (spec section 4.6). Keep it in memory only, or in
/// the platform's secure storage.
#[derive(Debug)]
pub struct Session {
    token: SessionToken,
    account_id: AccountId,
}

impl Session {
    pub(crate) const fn new(token: SessionToken, account_id: AccountId) -> Self {
        Self { token, account_id }
    }

    /// Restores a session whose token was kept in secure local storage, so
    /// a device-key unlock can sync without the master password (spec
    /// section 10.4). The server still decides whether it has expired.
    #[must_use]
    pub const fn restore(token: SessionToken, account_id: AccountId) -> Self {
        Self { token, account_id }
    }

    /// The session token, to keep in secure local storage. Never log it.
    #[must_use]
    pub const fn token(&self) -> &SessionToken {
        &self.token
    }

    /// The signed-in account.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// The `Authorization` header value.
    #[must_use]
    pub fn authorization(&self) -> String {
        format!("Bearer {}", wire::b64(self.token.as_bytes()))
    }

    /// `POST /v1/logout`.
    #[must_use]
    pub fn logout_request(&self) -> Request {
        Request {
            method: Method::Post,
            path: "/v1/logout".into(),
            body: None,
            authorization: Some(self.authorization()),
        }
    }
}

/// Decodes a base64url field of a server answer.
pub(crate) fn field(text: &str, max_len: usize) -> Result<Vec<u8>> {
    wire::unb64(text, max_len).ok_or(ClientError::InvalidResponse)
}

/// Decodes a fixed-length base64url field of a server answer.
pub(crate) fn field_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    wire::unb64_array(text).ok_or(ClientError::InvalidResponse)
}
