//! The HTTP side of the server API (spec section 12) that does not depend on
//! Cloudflare: routing, JSON bodies, base64url and hex encoding, errors,
//! headers and rate limit keys. Everything here is tested natively.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vault_core::{AccountId, KdfParams};

/// Largest request body, in bytes (spec section 12.2).
pub const MAX_BODY_BYTES: usize = server_core::api::MAX_REQUEST_BYTES;

/// Headers sent with every response (spec section 12.2).
pub const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("Strict-Transport-Security", "max-age=63072000"),
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    (
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'",
    ),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Type", "application/json"),
];

/// A request the server knows how to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// `POST /v1/prelogin`
    Prelogin,
    /// `POST /v1/register/start`
    RegisterStart,
    /// `POST /v1/register/finish`
    RegisterFinish,
    /// `POST /v1/login/start`
    LoginStart,
    /// `POST /v1/login/finish`
    LoginFinish,
    /// `POST /v1/logout`
    Logout,
    /// `GET /v1/keyset`
    KeySet,
    /// `GET /v1/accounts/{id}/keys`
    AccountKeys(AccountId),
    /// `PUT /v1/enrolment/{session_id}`
    EnrolmentPut([u8; 16]),
    /// `GET /v1/enrolment/{session_id}`
    EnrolmentGet([u8; 16]),
    /// An endpoint of spec section 12 that this version does not serve yet.
    NotImplemented,
}

/// Endpoints of spec section 12 that this version does not serve yet.
const PLANNED: &[(&str, &str)] = &[
    ("PUT", "/v1/keyset/wrapped"),
    ("DELETE", "/v1/keyset/wrapped"),
    ("POST", "/v1/password"),
    ("POST", "/v1/recovery/start"),
    ("POST", "/v1/recovery/finish"),
    ("PUT", "/v1/recovery"),
    ("GET", "/v1/accounts/self/leaves"),
    ("POST", "/v1/shares"),
    ("GET", "/v1/shares"),
    ("PUT", "/v1/emergency"),
];

/// Finds the route for a method and path.
///
/// # Errors
///
/// Returns [`ApiError::NotFound`] for anything else, including IDs that are
/// not canonical base64url of the right length.
pub fn route(method: &str, path: &str) -> Result<Route, ApiError> {
    let fixed = match (method, path) {
        ("POST", "/v1/prelogin") => Some(Route::Prelogin),
        ("POST", "/v1/register/start") => Some(Route::RegisterStart),
        ("POST", "/v1/register/finish") => Some(Route::RegisterFinish),
        ("POST", "/v1/login/start") => Some(Route::LoginStart),
        ("POST", "/v1/login/finish") => Some(Route::LoginFinish),
        ("POST", "/v1/logout") => Some(Route::Logout),
        ("GET", "/v1/keyset") => Some(Route::KeySet),
        _ => None,
    };
    if let Some(r) = fixed {
        return Ok(r);
    }
    if PLANNED.contains(&(method, path)) {
        return Ok(Route::NotImplemented);
    }
    let parts: Vec<&str> = path.split('/').collect();
    match (method, parts.as_slice()) {
        ("GET", ["", "v1", "accounts", id, "keys"]) => {
            Ok(Route::AccountKeys(AccountId::from_bytes(path_id(id)?)))
        }
        ("PUT", ["", "v1", "enrolment", id]) => Ok(Route::EnrolmentPut(path_id(id)?)),
        ("GET", ["", "v1", "enrolment", id]) => Ok(Route::EnrolmentGet(path_id(id)?)),
        (
            "POST" | "GET",
            ["", "v1", "vaults", _, "log" | "items"]
            | ["", "v1", "emergency", _]
            | ["", "v1", "emergency", _, "request" | "deny"],
        ) => Ok(Route::NotImplemented),
        _ => Err(ApiError::NotFound),
    }
}

/// An error answer (spec section 12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    /// From the request handlers.
    Core(server_core::Error),
    /// Too many requests; retry after this many seconds.
    RateLimited(u64),
    /// No such endpoint.
    NotFound,
    /// Specified but not served by this version.
    NotImplemented,
    /// Storage failed.
    Storage,
}

impl From<server_core::Error> for ApiError {
    fn from(e: server_core::Error) -> Self {
        Self::Core(e)
    }
}

impl ApiError {
    /// HTTP status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        use server_core::Error as E;
        match self {
            Self::Core(E::Authentication) => 401,
            Self::Core(E::NotAllowed | E::TooEarly) => 403,
            Self::Core(E::Conflict) => 409,
            Self::Core(E::InvalidConfiguration) | Self::Storage => 500,
            Self::RateLimited(_) => 429,
            Self::NotFound => 404,
            Self::NotImplemented => 501,
            // Malformed requests, and any variant added later.
            Self::Core(_) => 400,
        }
    }

    /// The `error` code in the response body.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        use server_core::Error as E;
        match self {
            Self::Core(E::Authentication) => "unauthenticated",
            Self::Core(E::NotAllowed) => "not_allowed",
            Self::Core(E::TooEarly) => "too_early",
            Self::Core(E::Conflict) => "conflict",
            Self::Core(E::InvalidConfiguration) | Self::Storage => "server_error",
            Self::RateLimited(_) => "rate_limited",
            Self::NotFound => "not_found",
            Self::NotImplemented => "not_implemented",
            Self::Core(_) => "malformed",
        }
    }

    /// The JSON response body.
    #[must_use]
    pub fn body(&self) -> String {
        format!("{{\"error\":\"{}\"}}", self.code())
    }
}

const MALFORMED: ApiError = ApiError::Core(server_core::Error::MalformedMessage);

/// Parses a JSON request body, rejecting unknown fields and oversized bodies.
///
/// # Errors
///
/// Returns a `malformed` error.
pub fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(MALFORMED);
    }
    serde_json::from_slice(body).map_err(|_| MALFORMED)
}

/// Encodes bytes as base64url without padding.
#[must_use]
pub fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Decodes canonical base64url without padding, rejecting anything longer
/// than `max_len` bytes.
///
/// # Errors
///
/// Returns a `malformed` error for padding, other alphabets, non-zero
/// trailing bits or excess length.
pub fn unb64(text: &str, max_len: usize) -> Result<Vec<u8>, ApiError> {
    // Four characters carry three bytes; reject before decoding anything big.
    if text.len() > max_len.saturating_mul(4).div_ceil(3) {
        return Err(MALFORMED);
    }
    let bytes = Base64UrlUnpadded::decode_vec(text).map_err(|_| MALFORMED)?;
    if bytes.len() > max_len {
        return Err(MALFORMED);
    }
    Ok(bytes)
}

/// Decodes canonical base64url of exactly `N` bytes.
///
/// # Errors
///
/// Returns a `malformed` error.
pub fn unb64_array<const N: usize>(text: &str) -> Result<[u8; N], ApiError> {
    unb64(text, N)?.try_into().map_err(|_| MALFORMED)
}

/// Lower-case hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(
        String::with_capacity(bytes.len().saturating_mul(2)),
        |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        },
    )
}

/// Parses a 16-byte ID in a path (canonical base64url, 22 characters).
///
/// # Errors
///
/// Returns [`ApiError::NotFound`].
pub fn path_id(text: &str) -> Result<[u8; 16], ApiError> {
    unb64_array(text).map_err(|_| ApiError::NotFound)
}

/// Extracts the session token from an `Authorization: Bearer` header.
///
/// # Errors
///
/// Returns `unauthenticated` if the header is missing or malformed.
pub fn bearer_token(header: Option<&str>) -> Result<Vec<u8>, ApiError> {
    let unauthenticated = ApiError::Core(server_core::Error::Authentication);
    let value = header.ok_or(unauthenticated)?;
    let token = value.strip_prefix("Bearer ").ok_or(unauthenticated)?;
    unb64(token, vault_core::login::SESSION_TOKEN_LEN).map_err(|_| unauthenticated)
}

/// Parses the optional `seen` query parameter of a key lookup.
///
/// # Errors
///
/// Returns a `malformed` error for anything but a single decimal number.
pub fn parse_seen(query: Option<&str>) -> Result<Option<u64>, ApiError> {
    let Some(q) = query.filter(|q| !q.is_empty()) else {
        return Ok(None);
    };
    let value = q.strip_prefix("seen=").ok_or(MALFORMED)?;
    if value.is_empty() || value.len() > 19 || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(MALFORMED);
    }
    value.parse().map(Some).map_err(|_| MALFORMED)
}

/// A rate limit (spec section 12.5): at most `max` requests per window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    /// Short name, part of the storage key.
    pub name: &'static str,
    /// Requests allowed per window.
    pub max: u32,
    /// Window length in milliseconds.
    pub window_ms: u64,
}

const MINUTES_15: u64 = 15 * 60_000;

/// `prelogin` and `login/start`, per email address.
pub const LOGIN_PER_ADDRESS: Limit = Limit {
    name: "login-addr",
    max: 10,
    window_ms: MINUTES_15,
};
/// `prelogin`, `login/start` and registration, per client IP address.
pub const LOGIN_PER_IP: Limit = Limit {
    name: "login-ip",
    max: 100,
    window_ms: MINUTES_15,
};
/// Failed `login/finish`, per email address; reaching it locks the address.
pub const LOGIN_FAILURES: Limit = Limit {
    name: "login-fail",
    max: 5,
    window_ms: MINUTES_15,
};
/// Enrolment downloads, per client IP address.
pub const ENROLMENT_PER_IP: Limit = Limit {
    name: "enrol-ip",
    max: 20,
    window_ms: MINUTES_15,
};
/// Everything else, per session.
pub const PER_SESSION: Limit = Limit {
    name: "session",
    max: 600,
    window_ms: MINUTES_15,
};

impl Limit {
    /// Storage key for this limit and subject. The subject (an email
    /// address, IP address or session hash) is stored only as a hash.
    #[must_use]
    pub fn key(&self, subject: &[u8]) -> String {
        let digest = Sha256::new()
            .chain_update(self.name.as_bytes())
            .chain_update([0])
            .chain_update(subject)
            .finalize();
        format!(
            "{}:{}",
            self.name,
            hex(digest.get(..16).unwrap_or_default())
        )
    }

    /// Seconds until a window that started at `window_start_ms` ends.
    #[must_use]
    pub const fn retry_after(&self, window_start_ms: u64, now_ms: u64) -> u64 {
        window_start_ms
            .saturating_add(self.window_ms)
            .saturating_sub(now_ms)
            .div_ceil(1000)
    }
}

/// Argon2id parameters as sent in JSON.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KdfJson {
    /// Memory in KiB.
    pub m: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl From<KdfParams> for KdfJson {
    fn from(k: KdfParams) -> Self {
        Self {
            m: k.memory_kib,
            t: k.iterations,
            p: k.parallelism,
        }
    }
}

impl From<KdfJson> for KdfParams {
    fn from(k: KdfJson) -> Self {
        Self {
            memory_kib: k.m,
            iterations: k.t,
            parallelism: k.p,
        }
    }
}

/// `POST /v1/prelogin`
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreloginRequest {
    /// Email address.
    pub email: String,
}

/// Answer to `POST /v1/prelogin`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreloginResponse {
    /// Argon2id salt.
    pub salt: String,
    /// Argon2id parameters.
    pub kdf: KdfJson,
}

/// `POST /v1/register/start`
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterStartRequest {
    /// Email address.
    pub email: String,
    /// OPAQUE registration request.
    pub request: String,
}

/// Answer to `POST /v1/register/start`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterStartResponse {
    /// OPAQUE registration response.
    pub response: String,
}

/// `POST /v1/register/finish`
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterFinishRequest {
    /// Email address.
    pub email: String,
    /// Argon2id salt.
    pub salt: String,
    /// Argon2id parameters.
    pub kdf: KdfJson,
    /// OPAQUE registration upload.
    pub upload: String,
    /// Signed public key bundle.
    pub signed_bundle: String,
    /// Key set wrapped with method 1.
    pub wrapped_key_set: String,
}

/// Answer to `POST /v1/register/finish`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterFinishResponse {
    /// The new account's ID, lower-case hex.
    pub account_id: String,
}

/// `POST /v1/login/start`
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginStartRequest {
    /// Email address.
    pub email: String,
    /// OPAQUE `KE1`.
    pub ke1: String,
}

/// Answer to `POST /v1/login/start`.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// ID to send back with `KE3`.
    pub login_id: String,
    /// OPAQUE `KE2`.
    pub ke2: String,
}

/// `POST /v1/login/finish`
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginFinishRequest {
    /// From `login/start`.
    pub login_id: String,
    /// OPAQUE `KE3`.
    pub ke3: String,
}

/// One wrapped copy of the key set.
#[derive(Debug, Serialize, Deserialize)]
pub struct WrappedJson {
    /// Unlock method (spec section 5.4).
    pub method: u8,
    /// The wrapped key set.
    pub data: String,
}

/// Answer to `GET /v1/keyset`.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeySetResponse {
    /// Current key set version.
    pub key_set_version: u32,
    /// Wrapped copies stored on the server.
    pub wrapped: Vec<WrappedJson>,
}

/// Answer to `GET /v1/accounts/{id}/keys`.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyLookupJson {
    /// Signed public key bundle.
    pub signed_bundle: String,
    /// Its log leaf.
    pub leaf: String,
    /// The leaf's index.
    pub leaf_index: u64,
    /// Inclusion proof.
    pub inclusion_proof: Vec<String>,
    /// Signed tree head.
    pub signed_tree_head: String,
    /// Consistency proof from `seen`.
    pub consistency_proof: Vec<String>,
}

impl From<server_core::api::KeyLookupResponse> for KeyLookupJson {
    fn from(r: server_core::api::KeyLookupResponse) -> Self {
        Self {
            signed_bundle: b64(&r.signed_bundle),
            leaf: b64(&r.leaf),
            leaf_index: r.leaf_index,
            inclusion_proof: r.inclusion_proof.iter().map(|h| b64(h)).collect(),
            signed_tree_head: b64(&r.signed_tree_head),
            consistency_proof: r.consistency_proof.iter().map(|h| b64(h)).collect(),
        }
    }
}

/// `PUT /v1/enrolment/{session_id}`
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolmentPutRequest {
    /// The encrypted transfer.
    pub sealed: String,
}

/// Answer to `GET /v1/enrolment/{session_id}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct EnrolmentGetResponse {
    /// The encrypted transfer.
    pub sealed: String,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    #[test]
    fn routes() {
        let bytes: [u8; 16] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let id = b64(&bytes);
        assert_eq!(route("POST", "/v1/prelogin"), Ok(Route::Prelogin));
        assert_eq!(route("POST", "/v1/login/finish"), Ok(Route::LoginFinish));
        assert_eq!(route("GET", "/v1/keyset"), Ok(Route::KeySet));
        assert_eq!(
            route("GET", &format!("/v1/accounts/{id}/keys")),
            Ok(Route::AccountKeys(AccountId::from_bytes(bytes)))
        );
        assert_eq!(
            route("PUT", &format!("/v1/enrolment/{id}")),
            Ok(Route::EnrolmentPut(bytes))
        );
        assert_eq!(
            route("GET", &format!("/v1/enrolment/{id}")),
            Ok(Route::EnrolmentGet(bytes))
        );
        assert_eq!(route("POST", "/v1/shares"), Ok(Route::NotImplemented));
        assert_eq!(
            route("POST", &format!("/v1/vaults/{id}/log")),
            Ok(Route::NotImplemented)
        );
        for (m, p) in [
            ("GET", "/v1/prelogin"),
            ("POST", "/v1/prelogin/"),
            ("POST", "/v2/prelogin"),
            ("GET", "/"),
            ("GET", "/v1/accounts/AAECAwQFBgcICQoLDA0ODw==/keys"),
            ("GET", "/v1/accounts/AAECAwQFBgcICQoLDA0ODx/keys"),
            ("GET", "/v1/accounts/AAEC/keys"),
            ("GET", "/v1/enrolment/AAECAwQFBgcICQoLDA0ODwAA"),
            ("DELETE", "/v1/enrolment/AAECAwQFBgcICQoLDA0ODw"),
        ] {
            assert_eq!(route(m, p), Err(ApiError::NotFound), "{m} {p}");
        }
    }

    #[test]
    fn errors_map_to_spec_codes() {
        use server_core::Error as E;
        let cases = [
            (ApiError::Core(E::MalformedMessage), 400, "malformed"),
            (ApiError::Core(E::Authentication), 401, "unauthenticated"),
            (ApiError::Core(E::NotAllowed), 403, "not_allowed"),
            (ApiError::Core(E::TooEarly), 403, "too_early"),
            (ApiError::Core(E::Conflict), 409, "conflict"),
            (ApiError::RateLimited(5), 429, "rate_limited"),
            (ApiError::NotFound, 404, "not_found"),
            (ApiError::NotImplemented, 501, "not_implemented"),
            (ApiError::Storage, 500, "server_error"),
        ];
        for (e, status, code) in cases {
            assert_eq!((e.status(), e.code()), (status, code));
            assert_eq!(e.body(), format!("{{\"error\":\"{code}\"}}"));
        }
    }

    #[test]
    fn base64url_is_strict() {
        assert_eq!(b64(b"\xfb\xff"), "-_8");
        assert_eq!(unb64("-_8", 10).unwrap(), b"\xfb\xff");
        assert!(unb64("-_8=", 10).is_err(), "padding");
        assert!(unb64("+/8", 10).is_err(), "standard alphabet");
        assert!(unb64("-_9", 10).is_err(), "non-zero trailing bits");
        assert!(unb64("AAAA", 2).is_err(), "too long");
        assert!(unb64(&"A".repeat(10_000), 16).is_err());
        assert_eq!(unb64_array::<2>("-_8").unwrap(), [0xfb, 0xff]);
        assert!(unb64_array::<3>("-_8").is_err());
    }

    #[test]
    fn hex_is_lower_case() {
        assert_eq!(hex(&[0x0f, 0xa0]), "0fa0");
    }

    #[test]
    fn bearer_tokens() {
        let token = [7_u8; 32];
        let header = format!("Bearer {}", b64(&token));
        assert_eq!(bearer_token(Some(&header)).unwrap(), token);
        let unauthenticated = Err(ApiError::Core(server_core::Error::Authentication));
        assert_eq!(bearer_token(None), unauthenticated);
        assert_eq!(bearer_token(Some(&b64(&token))), unauthenticated);
        assert_eq!(bearer_token(Some("Bearer !!!")), unauthenticated);
        assert_eq!(
            bearer_token(Some(&format!("Bearer {}", b64(&[7; 33])))),
            unauthenticated
        );
    }

    #[test]
    fn seen_parameter() {
        assert_eq!(parse_seen(None), Ok(None));
        assert_eq!(parse_seen(Some("")), Ok(None));
        assert_eq!(parse_seen(Some("seen=42")), Ok(Some(42)));
        for bad in [
            "seen=",
            "seen=-1",
            "seen=1e3",
            "x=1",
            "seen=1&x=2",
            "seen=99999999999999999999",
        ] {
            assert!(parse_seen(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn json_bodies_are_strict() {
        let ok: PreloginRequest = parse_json(br#"{"email":"a@b.c"}"#).unwrap();
        assert_eq!(ok.email, "a@b.c");
        assert!(parse_json::<PreloginRequest>(br#"{"email":"a@b.c","x":1}"#).is_err());
        assert!(parse_json::<PreloginRequest>(br"{}").is_err());
        assert!(parse_json::<PreloginRequest>(b"not json").is_err());
        assert!(parse_json::<PreloginRequest>(&vec![b' '; MAX_BODY_BYTES + 1]).is_err());
        assert!(parse_json::<RegisterFinishRequest>(
            br#"{"email":"","salt":"","kdf":{"m":1,"t":1,"p":1,"q":1},"upload":"","signed_bundle":"","wrapped_key_set":""}"#
        )
        .is_err());
    }

    #[test]
    fn rate_limit_keys_hide_the_subject() {
        let key = LOGIN_PER_ADDRESS.key(b"alice@example.com");
        assert!(key.starts_with("login-addr:"));
        assert_eq!(key.len(), "login-addr:".len() + 32);
        assert!(!key.contains("alice"));
        assert_ne!(key, LOGIN_FAILURES.key(b"alice@example.com"));
        assert_eq!(LOGIN_PER_ADDRESS.retry_after(0, 1), 900);
        assert_eq!(LOGIN_PER_ADDRESS.retry_after(0, 900_000), 0);
    }
}
