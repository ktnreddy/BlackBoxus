//! Listening for "something changed" hints from the server (spec section
//! 12.12), so the app syncs as soon as another device or a member of a
//! shared vault makes a change.
//!
//! A background thread keeps one WebSocket connection open with the
//! session's token. A hint only names what changed; the window then syncs,
//! which fetches and verifies everything as usual, so a forged or missing
//! hint changes nothing but timing. The connection is dropped when the app
//! locks, and replaced at least hourly, since the server closes it then.

use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tungstenite::client::IntoClientRequest;
use tungstenite::protocol::WebSocketConfig;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

/// Largest hint accepted.
const MAX_MESSAGE: usize = 4096;

/// How long a read waits before checking whether to stop.
const POLL: Duration = Duration::from_secs(2);

/// How often an idle connection is kept alive.
const KEEPALIVE: Duration = Duration::from_secs(240);

/// Longest wait between connection attempts.
const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// What changed, as the window is told.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Hint {
    /// A vault changed.
    Vault {
        /// The vault, as the window names vaults.
        id: String,
    },
    /// A vault was shared with this account.
    Shares,
    /// A trusted contact request changed.
    Emergency,
}

#[derive(Deserialize)]
struct HintJson {
    t: String,
    id: Option<String>,
}

/// Reads a hint from the server. Anything else is ignored.
fn parse(text: &str) -> Option<Hint> {
    if text.len() > MAX_MESSAGE {
        return None;
    }
    let json: HintJson = serde_json::from_str(text).ok()?;
    match (json.t.as_str(), json.id) {
        ("vault", Some(id)) => {
            // A vault ID is 16 bytes in base64url: 22 characters.
            wire::unb64_array::<16>(&id).map(|_| Hint::Vault { id })
        }
        ("shares", _) => Some(Hint::Shares),
        ("emergency", _) => Some(Hint::Emergency),
        _ => None,
    }
}

/// The address to connect to, from the server's base URL.
fn notifications_url(base: &str) -> Option<String> {
    let rest = base
        .strip_prefix("https://")
        .map(|r| format!("wss://{r}"))
        .or_else(|| base.strip_prefix("http://").map(|r| format!("ws://{r}")))?;
    Some(format!("{}/v1/notifications", rest.trim_end_matches('/')))
}

/// A running listener. Dropping it stops the thread.
pub struct Live {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl core::fmt::Debug for Live {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Live").finish_non_exhaustive()
    }
}

impl Live {
    /// Starts listening with `authorization` (the session's `Bearer`
    /// header), sending each hint to the window as a `server-hint` event.
    #[must_use]
    pub fn start(app: AppHandle, base: &str, authorization: String) -> Option<Self> {
        let url = notifications_url(base)?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("server-hints".into())
            .spawn(move || run(&app, &url, &authorization, &flag))
            .ok()?;
        Some(Self {
            stop,
            thread: Some(thread),
        })
    }

    /// Whether the thread has given up (its session was refused).
    #[must_use]
    pub fn finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // The thread notices within one poll; there is no need to wait.
        drop(self.thread.take());
    }
}

/// What ended a connection.
enum Ended {
    /// Stop was asked for.
    Stopped,
    /// The session is no longer accepted: give up until the next unlock.
    Refused,
    /// Anything else: try again later.
    Lost,
}

fn run(app: &AppHandle, url: &str, authorization: &str, stop: &AtomicBool) {
    let mut backoff = Duration::from_secs(5);
    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        match listen(app, url, authorization, stop) {
            Ended::Stopped | Ended::Refused => return,
            Ended::Lost => {}
        }
        // A connection that lasted a while was healthy: reconnect promptly.
        if started.elapsed() > Duration::from_secs(60) {
            backoff = Duration::from_secs(5);
        }
        let waiting = Instant::now();
        while waiting.elapsed() < backoff {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(POLL.min(backoff.saturating_sub(waiting.elapsed())));
        }
        backoff = backoff.saturating_mul(2).min(MAX_BACKOFF);
    }
}

fn set_timeout(ws: &WebSocket<MaybeTlsStream<TcpStream>>) {
    let tcp = match ws.get_ref() {
        MaybeTlsStream::Plain(s) => s,
        MaybeTlsStream::Rustls(s) => s.get_ref(),
        _ => return,
    };
    let _ = tcp.set_read_timeout(Some(POLL));
}

fn listen(app: &AppHandle, url: &str, authorization: &str, stop: &AtomicBool) -> Ended {
    let Ok(mut request) = url.into_client_request() else {
        return Ended::Refused;
    };
    let Ok(value) = authorization.parse() else {
        return Ended::Refused;
    };
    request.headers_mut().insert("Authorization", value);
    if let Ok(agent) = concat!("BlackBoxus-Desktop/", env!("CARGO_PKG_VERSION")).parse() {
        request.headers_mut().insert("User-Agent", agent);
    }
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE));
    let mut ws = match tungstenite::client::connect_with_config(request, Some(config), 0) {
        Ok((ws, _)) => ws,
        Err(tungstenite::Error::Http(response))
            if matches!(response.status().as_u16(), 401 | 403) =>
        {
            return Ended::Refused;
        }
        Err(_) => return Ended::Lost,
    };
    set_timeout(&ws);
    let mut last_sent = Instant::now();
    loop {
        if stop.load(Ordering::Relaxed) {
            let _ = ws.close(None);
            let _ = ws.flush();
            return Ended::Stopped;
        }
        match ws.read() {
            Ok(Message::Text(text)) => {
                if let Some(hint) = parse(text.as_str()) {
                    let _ = app.emit("server-hint", hint);
                }
            }
            Ok(Message::Close(_)) => return Ended::Lost,
            Ok(_) => {}
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Ended::Lost,
        }
        if last_sent.elapsed() > KEEPALIVE {
            if ws.send(Message::Ping(Vec::new().into())).is_err() {
                return Ended::Lost;
            }
            last_sent = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_are_read_strictly() {
        let id = wire::b64(&[7; 16]);
        assert_eq!(
            parse(&format!(r#"{{"t":"vault","id":"{id}"}}"#)),
            Some(Hint::Vault { id })
        );
        assert_eq!(parse(r#"{"t":"shares"}"#), Some(Hint::Shares));
        assert_eq!(parse(r#"{"t":"emergency"}"#), Some(Hint::Emergency));
        assert_eq!(parse(r#"{"t":"vault","id":"not an id"}"#), None);
        assert_eq!(parse(r#"{"t":"vault"}"#), None);
        assert_eq!(parse(r#"{"t":"other"}"#), None);
        assert_eq!(parse("not json"), None);
        assert_eq!(parse(&"x".repeat(MAX_MESSAGE + 1)), None);
    }

    #[test]
    fn the_address_follows_the_server() {
        assert_eq!(
            notifications_url("https://api.blackboxus.workers.dev").as_deref(),
            Some("wss://api.blackboxus.workers.dev/v1/notifications")
        );
        assert_eq!(
            notifications_url("http://127.0.0.1:8787/").as_deref(),
            Some("ws://127.0.0.1:8787/v1/notifications")
        );
        assert_eq!(notifications_url("ftp://x"), None);
    }
}
