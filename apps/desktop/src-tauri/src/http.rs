//! Sends `client-core` requests to the server over HTTPS.

use std::io::Read;
use std::time::Duration;

use client_core::{Method, Request, Response};

use crate::error::AppError;

/// The server's origin. It is also the server identity bound into every
/// login, so it never changes at run time.
pub const ORIGIN: &str = "https://api.blackboxus.workers.dev";

/// Largest answer read from the server.
const MAX_BODY: u64 = 4 << 20;

/// Sends one request and returns the server's answer.
pub trait Transport {
    /// Sends `request` and returns the answer, whatever its status.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Offline`] if the server cannot be reached.
    fn send(&self, request: &Request) -> Result<Response, AppError>;
}

/// The real transport.
#[derive(Debug)]
pub struct Https {
    agent: ureq::Agent,
    base: String,
}

impl Https {
    /// A transport to [`ORIGIN`].
    ///
    /// Debug builds can be pointed at a local test server with
    /// `BLACKBOXUS_API_URL=http://127.0.0.1:8787`; release builds ignore it.
    pub fn new() -> Self {
        let base = if cfg!(debug_assertions) {
            std::env::var("BLACKBOXUS_API_URL").unwrap_or_else(|_| ORIGIN.into())
        } else {
            ORIGIN.into()
        };
        let local = base.starts_with("http://127.0.0.1:") || base.starts_with("http://localhost:");
        let agent = ureq::Agent::config_builder()
            .https_only(!local)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(30)))
            .timeout_connect(Some(Duration::from_secs(10)))
            .user_agent(concat!("BlackBoxus-Desktop/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Self { agent, base }
    }
}

impl Default for Https {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for Https {
    fn send(&self, request: &Request) -> Result<Response, AppError> {
        let url = format!("{}{}", self.base, request.path);
        let result = match (request.method, &request.body) {
            (Method::Get, _) => {
                let mut r = self.agent.get(&url);
                if let Some(auth) = &request.authorization {
                    r = r.header("Authorization", auth);
                }
                r.call()
            }
            (method, body) => {
                let mut r = match method {
                    Method::Put => self.agent.put(&url),
                    _ => self.agent.post(&url),
                };
                if let Some(auth) = &request.authorization {
                    r = r.header("Authorization", auth);
                }
                match body {
                    Some(json) => r
                        .header("Content-Type", "application/json")
                        .send(json.as_bytes()),
                    None => r.send_empty(),
                }
            }
        };
        let mut answer = result.map_err(|_| AppError::Offline)?;
        let status = answer.status().as_u16();
        let retry_after = answer
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse().ok());
        let mut body = Vec::new();
        answer
            .body_mut()
            .as_reader()
            .take(MAX_BODY)
            .read_to_end(&mut body)
            .map_err(|_| AppError::Offline)?;
        Ok(Response {
            status,
            retry_after,
            body,
        })
    }
}
