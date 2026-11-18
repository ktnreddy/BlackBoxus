//! "Something changed" notifications (spec section 12.12).
//!
//! Each account has a Durable Object holding the open WebSocket connections
//! of its devices, accepted with the hibernation API so idle connections
//! cost nothing. When a vault changes, a share arrives or an emergency
//! request is made, the Worker asks the objects of the accounts concerned
//! to send a short hint such as `{"t":"vault","id":"…"}`. Hints carry no
//! secrets and nothing the account could not already read: devices only
//! sync sooner, and check everything as usual.
//!
//! Connections are tagged with a hash of the session token they were
//! opened with, closed at once when that session signs out or its password
//! changes, and closed after an hour in any case, so a device reconnects
//! (and is authenticated again) at least hourly.

use serde::{Deserialize, Serialize};
use vault_core::AccountId;
use worker::{
    Date, DurableObject, Env, Headers, Method, Request, RequestInit, Response, Result, State,
    WebSocket, WebSocketIncomingMessage, WebSocketPair, durable_object,
};

use crate::http::b64;

/// The binding in `wrangler.toml`.
const BINDING: &str = "NOTIFIER";

/// How long a connection lasts before the device must reconnect.
const MAX_CONNECTION_MS: u64 = 3_600_000;

/// Close code for a connection whose session ended or expired.
const CLOSE_SIGNED_OUT: u16 = 4001;

/// Tag for connections from emergency (read-only) sessions.
const READ_ONLY_TAG: &str = "ro";

/// One account's open connections.
#[durable_object]
pub struct Notifier {
    state: State,
}

#[derive(Serialize, Deserialize)]
struct CloseRequest {
    /// Close only the connection opened with this session.
    only: Option<String>,
    /// Keep the connection opened with this session.
    keep: Option<String>,
    /// Close only connections from emergency sessions.
    read_only: bool,
}

impl Notifier {
    fn expired(ws: &WebSocket, now: u64) -> bool {
        ws.deserialize_attachment::<u64>()
            .ok()
            .flatten()
            .is_none_or(|at| now.saturating_sub(at) >= MAX_CONNECTION_MS)
    }
}

impl DurableObject for Notifier {
    fn new(state: State, _env: Env) -> Self {
        Self { state }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let now = Date::now().as_millis();
        match (req.method(), req.path().as_str()) {
            (Method::Get, "/connect") => {
                let tag = req.headers().get("X-Session-Tag")?.unwrap_or_default();
                let read_only = req.headers().get("X-Read-Only")?.as_deref() == Some("1");
                let pair = WebSocketPair::new()?;
                let kind = if read_only { READ_ONLY_TAG } else { "rw" };
                self.state
                    .accept_websocket_with_tags(&pair.server, &[tag.as_str(), kind]);
                pair.server.serialize_attachment(now)?;
                Response::from_websocket(pair.client)
            }
            (Method::Post, "/notify") => {
                let message = req.text().await?;
                for ws in self.state.get_websockets() {
                    if Self::expired(&ws, now) {
                        let _ = ws.close(Some(CLOSE_SIGNED_OUT), Some("expired"));
                    } else {
                        let _ = ws.send_with_str(&message);
                    }
                }
                Response::empty()
            }
            (Method::Post, "/close") => {
                let close: CloseRequest = req.json().await?;
                for ws in self.state.get_websockets() {
                    let tags = self.state.get_tags(&ws);
                    let kept = close
                        .keep
                        .as_ref()
                        .is_some_and(|keep| tags.iter().any(|t| t == keep));
                    let chosen = (!close.read_only || tags.iter().any(|t| t == READ_ONLY_TAG))
                        && close
                            .only
                            .as_ref()
                            .is_none_or(|only| tags.iter().any(|t| t == only));
                    if chosen && !kept {
                        let _ = ws.close(Some(CLOSE_SIGNED_OUT), Some("signed out"));
                    }
                }
                Response::empty()
            }
            _ => Response::error("not found", 404),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        _message: WebSocketIncomingMessage,
    ) -> Result<()> {
        // Devices have nothing to say; anything sent is a keepalive.
        if Self::expired(&ws, Date::now().as_millis()) {
            let _ = ws.close(Some(CLOSE_SIGNED_OUT), Some("expired"));
        }
        Ok(())
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, _error: worker::Error) -> Result<()> {
        Ok(())
    }
}

fn stub(env: &Env, account: &AccountId) -> Result<worker::Stub> {
    env.durable_object(BINDING)?
        .id_from_name(&b64(account.as_bytes()))?
        .get_stub()
}

async fn post(env: &Env, account: &AccountId, path: &str, body: String) -> Result<()> {
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(body.into()));
    let req = Request::new_with_init(&format!("https://notifier{path}"), &init)?;
    stub(env, account)?
        .fetch_with_request(req)
        .await
        .map(|_| ())
}

/// Hands an authenticated WebSocket upgrade to the account's object.
///
/// # Errors
///
/// Returns an error if the Durable Object cannot be reached.
pub async fn connect(
    env: &Env,
    account: &AccountId,
    session_tag: &str,
    read_only: bool,
) -> Result<Response> {
    let headers = Headers::new();
    headers.set("Upgrade", "websocket")?;
    headers.set("X-Session-Tag", session_tag)?;
    headers.set("X-Read-Only", if read_only { "1" } else { "0" })?;
    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    let req = Request::new_with_init("https://notifier/connect", &init)?;
    stub(env, account)?.fetch_with_request(req).await
}

/// Sends a hint to each account's devices. Best effort: a hint that is lost
/// only means a device syncs later, as it would without notifications.
pub async fn send(env: &Env, accounts: &[AccountId], message: &str) {
    for account in accounts {
        let _ = post(env, account, "/notify", message.to_owned()).await;
    }
}

/// Which of an account's connections to close.
#[derive(Debug, Clone, Copy)]
pub enum Close<'a> {
    /// The one opened with this session.
    Only(&'a str),
    /// All but the one opened with this session.
    AllBut(&'a str),
    /// Those of emergency sessions.
    ReadOnly,
}

/// Closes some of an account's connections. Best effort, since every
/// connection ends within an hour anyway.
pub async fn close(env: &Env, account: &AccountId, which: Close<'_>) {
    let request = match which {
        Close::Only(tag) => CloseRequest {
            only: Some(tag.to_owned()),
            keep: None,
            read_only: false,
        },
        Close::AllBut(tag) => CloseRequest {
            only: None,
            keep: Some(tag.to_owned()),
            read_only: false,
        },
        Close::ReadOnly => CloseRequest {
            only: None,
            keep: None,
            read_only: true,
        },
    };
    let body = serde_json::to_string(&request).unwrap_or_default();
    let _ = post(env, account, "/close", body).await;
}

/// The tag a connection is opened with: a hash of its session token, as
/// sessions are stored.
#[must_use]
pub fn session_tag(token_hash: &[u8]) -> String {
    b64(token_hash)
}
