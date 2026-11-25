//! The bridge to the browser extension (spec section 14).
//!
//! The browser starts this app's own executable as its native messaging
//! host ([`host`]), which relays messages over a local socket to the
//! running app. The app answers only extensions the user paired, only while
//! unlocked, and only with logins that match the page. The extension never
//! holds keys or a copy of the vault.

pub mod host;
pub mod matching;
pub mod protocol;
mod register;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, mpsc};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::{AppHandle, Emitter, Manager};
use vault_core::{FieldKind, ItemType};
use zeroize::Zeroizing;

use crate::error::AppError;
use crate::state::AppState;
use protocol::{Direction, Incoming, Outgoing, Request};

pub use register::{register, unregister};

/// The name extensions connect to (spec section 14.2).
pub const HOST_NAME: &str = "com.blackboxus.desktop";

/// How long the app waits for the user to approve a pairing.
const PAIRING_TIMEOUT: Duration = Duration::from_secs(120);

/// Most logins listed for one page.
const MAX_LOGINS: usize = 50;

/// The local socket the host relays to: a named pipe on Windows, open only
/// to the signed-in Windows user, or a file in the user's runtime directory
/// elsewhere.
pub fn socket_name() -> String {
    #[cfg(debug_assertions)]
    if let Ok(name) = std::env::var("BLACKBOXUS_BROWSER_SOCKET") {
        return name;
    }
    #[cfg(windows)]
    {
        // Per user, so one user cannot squat on another's name.
        let user: String = std::env::var("USERNAME")
            .unwrap_or_default()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect();
        format!("blackboxus-browser-{user}")
    }
    #[cfg(not(windows))]
    {
        let dir = std::env::var_os("XDG_RUNTIME_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        dir.join("blackboxus-browser.sock")
            .to_string_lossy()
            .into_owned()
    }
}

/// A paired browser, as stored.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPairing {
    id: String,
    browser: String,
    created_ms: u64,
    key: Zeroizing<String>,
}

/// A paired browser, as listed in Settings.
#[derive(Debug, Clone, Serialize)]
pub struct PairingView {
    /// Pairing ID, base64url.
    pub id: String,
    /// The browser's name.
    pub browser: String,
    /// When it was paired, Unix milliseconds.
    pub created_ms: u64,
}

/// A pairing waiting for the user, shown in the window.
#[derive(Debug, Clone, Serialize)]
pub struct PairingRequest {
    /// The browser's name.
    pub browser: String,
    /// The code the extension shows too.
    pub code: String,
}

struct Pending {
    request: PairingRequest,
    answer: mpsc::Sender<bool>,
}

/// The bridge's state, managed by Tauri next to [`AppState`].
#[derive(Default)]
pub struct Bridge {
    enabled: AtomicBool,
    listening: AtomicBool,
    pending: Mutex<Option<Pending>>,
    /// Serialises changes to the stored pairings.
    store: Mutex<()>,
}

impl Bridge {
    fn pending(&self) -> MutexGuard<'_, Option<Pending>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Turns the bridge on or off. Turning it on registers the host with
    /// the browsers and starts listening; turning it off unregisters it and
    /// forgets every paired browser.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Storage`] if registering or forgetting fails.
    pub fn set_enabled(&self, app: &AppHandle, enabled: bool) -> Result<(), AppError> {
        if enabled {
            register(app)?;
            self.enabled.store(true, Ordering::SeqCst);
            self.listen(app);
        } else {
            self.enabled.store(false, Ordering::SeqCst);
            unregister(app)?;
            self.forget_all()?;
            if let Some(p) = self.pending().take() {
                let _ = p.answer.send(false);
            }
        }
        Ok(())
    }

    /// Whether the bridge is on.
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    fn listen(&self, app: &AppHandle) {
        if self.listening.swap(true, Ordering::SeqCst) {
            return;
        }
        let app = app.clone();
        std::thread::spawn(move || {
            if listener::run(&app).is_err() {
                // Another copy of the app owns the socket, or it could not
                // be made; try again the next time the bridge is turned on.
                app.state::<Self>().listening.store(false, Ordering::SeqCst);
            }
        });
    }

    /// The pairing waiting for the user, if any.
    pub fn pending_request(&self) -> Option<PairingRequest> {
        self.pending().as_ref().map(|p| p.request.clone())
    }

    /// The user's answer to the waiting pairing.
    pub fn answer(&self, allow: bool) {
        if let Some(p) = self.pending().take() {
            let _ = p.answer.send(allow);
        }
    }

    fn load(&self) -> Vec<StoredPairing> {
        crate::storage::load_browser_pairings()
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    }

    fn save(&self, pairings: &[StoredPairing]) -> Result<(), AppError> {
        let json = Zeroizing::new(serde_json::to_string(pairings).map_err(|_| AppError::Storage)?);
        crate::storage::save_browser_pairings(&json)
    }

    /// The paired browsers.
    pub fn pairings(&self) -> Vec<PairingView> {
        self.load()
            .into_iter()
            .map(|p| PairingView {
                id: p.id,
                browser: p.browser,
                created_ms: p.created_ms,
            })
            .collect()
    }

    /// Forgets one paired browser.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Storage`] if the change cannot be saved.
    pub fn forget(&self, id: &str) -> Result<(), AppError> {
        let _guard = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut all = self.load();
        all.retain(|p| p.id != id);
        self.save(&all)
    }

    /// Forgets every paired browser.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Storage`] if the change cannot be saved.
    pub fn forget_all(&self) -> Result<(), AppError> {
        let _guard = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::storage::delete_browser_pairings()
    }

    fn key_for(&self, id: &str) -> Option<Zeroizing<[u8; 32]>> {
        let stored = self.load().into_iter().find(|p| p.id == id)?;
        let bytes = Zeroizing::new(wire::unb64(&stored.key, 32)?);
        let mut key = Zeroizing::new([0_u8; 32]);
        key.copy_from_slice(bytes.get(..32)?);
        Some(key)
    }

    fn remember(&self, id: &str, browser: &str, key: &[u8; 32]) -> Result<(), AppError> {
        let _guard = self
            .store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut all = self.load();
        all.retain(|p| p.id != id);
        all.push(StoredPairing {
            id: id.to_owned(),
            browser: browser.to_owned(),
            created_ms: crate::state::now_ms(),
            key: Zeroizing::new(wire::b64(key)),
        });
        self.save(&all)
    }
}

mod listener {
    use std::io::{BufReader, Write};

    use interprocess::local_socket::prelude::*;
    use interprocess::local_socket::{ListenerOptions, Stream};
    use tauri::{AppHandle, Manager};

    use super::protocol::{MAX_MESSAGE_BYTES, MAX_REPLY_BYTES, read_frame, write_frame};
    use super::{Bridge, socket_name};

    /// Accepts connections from the host until the app exits.
    pub(super) fn run(app: &AppHandle) -> std::io::Result<()> {
        let listener = create()?;
        for conn in listener.incoming().filter_map(Result::ok) {
            let app = app.clone();
            std::thread::spawn(move || serve(&app, conn));
        }
        Ok(())
    }

    #[cfg(windows)]
    fn create() -> std::io::Result<LocalSocketListener> {
        use interprocess::local_socket::GenericNamespaced;
        use interprocess::os::windows::local_socket::ListenerOptionsExt;
        use interprocess::os::windows::security_descriptor::SecurityDescriptor;
        // Only the pipe's owner (this Windows user) and the system may
        // open it. Remote clients are refused by the pipe itself.
        let sddl = widestring::U16CString::from_str("D:P(A;;GA;;;OW)(A;;GA;;;SY)")
            .map_err(|_| std::io::ErrorKind::InvalidInput)?;
        ListenerOptions::new()
            .name(socket_name().to_ns_name::<GenericNamespaced>()?)
            .security_descriptor(SecurityDescriptor::deserialize(&sddl)?)
            .create_sync()
    }

    #[cfg(not(windows))]
    fn create() -> std::io::Result<LocalSocketListener> {
        use interprocess::local_socket::GenericFilePath;
        use std::os::unix::fs::PermissionsExt;
        let path = socket_name();
        let listener = ListenerOptions::new()
            .name(path.as_str().to_fs_name::<GenericFilePath>()?)
            .try_overwrite(true)
            .create_sync()?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }

    type LocalSocketListener = interprocess::local_socket::Listener;

    fn serve(app: &AppHandle, conn: Stream) {
        let mut reader = BufReader::new(&conn);
        let mut writer = &conn;
        let bridge = app.state::<Bridge>();
        while let Ok(Some(frame)) = read_frame(&mut reader, MAX_MESSAGE_BYTES) {
            let mut send = |message: &super::Outgoing| {
                serde_json::to_vec(message)
                    .ok()
                    .is_some_and(|bytes| write_frame(&mut writer, &bytes, MAX_REPLY_BYTES).is_ok())
            };
            if !super::handle(app, &bridge, &frame, &mut send) {
                break;
            }
        }
        let _ = writer.flush();
    }
}

/// Handles one message, sending the answers with `send`. Returns `false`
/// to close the connection.
fn handle(
    app: &AppHandle,
    bridge: &Bridge,
    frame: &[u8],
    send: &mut dyn FnMut(&Outgoing) -> bool,
) -> bool {
    if !bridge.enabled() {
        send(&Outgoing::Error { code: "disabled" });
        return false;
    }
    let Ok(message) = serde_json::from_slice::<Incoming>(frame) else {
        send(&Outgoing::Error { code: "malformed" });
        return false;
    };
    match message {
        Incoming::Pair { id, key, browser } => pair(app, bridge, &id, &key, &browser, send),
        Incoming::Req { id, n, c } => {
            let reply = request(app, bridge, &id, &n, &c);
            send(&reply)
        }
    }
}

fn pair(
    app: &AppHandle,
    bridge: &Bridge,
    id: &str,
    key: &str,
    browser: &str,
    send: &mut dyn FnMut(&Outgoing) -> bool,
) -> bool {
    let browser: String = browser
        .chars()
        .filter(|c| !c.is_control())
        .take(40)
        .collect();
    let (Some(id_bytes), Some(key_bytes)) = (wire::unb64(id, 16), wire::unb64(key, 65)) else {
        send(&Outgoing::Error { code: "malformed" });
        return false;
    };
    let Ok(pairing) = protocol::pair(&id_bytes, &key_bytes) else {
        send(&Outgoing::Error { code: "malformed" });
        return false;
    };
    let (answer, decision) = mpsc::channel();
    {
        let mut pending = bridge.pending();
        if pending.is_some() {
            drop(pending);
            send(&Outgoing::Error { code: "busy" });
            return false;
        }
        *pending = Some(Pending {
            request: PairingRequest {
                browser: browser.clone(),
                code: pairing.code.clone(),
            },
            answer,
        });
    }
    if !send(&Outgoing::Pair {
        key: wire::b64(&pairing.app_key),
    }) {
        bridge.pending().take();
        return false;
    }
    // Ask the user in the window, bringing it forward.
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
    let _ = app.emit("browser-pairing", bridge.pending_request());
    let allowed = decision.recv_timeout(PAIRING_TIMEOUT).unwrap_or(false);
    bridge.pending().take();
    let _ = app.emit("browser-pairing", None::<PairingRequest>);
    if allowed && bridge.remember(id, &browser, &pairing.key).is_ok() {
        send(&Outgoing::Paired)
    } else {
        send(&Outgoing::Error { code: "denied" });
        false
    }
}

fn request(app: &AppHandle, bridge: &Bridge, id: &str, n: &str, c: &str) -> Outgoing {
    let Some(key) = bridge.key_for(id) else {
        return Outgoing::Error { code: "unpaired" };
    };
    let Some(id_bytes) = wire::unb64(id, 16) else {
        return Outgoing::Error { code: "malformed" };
    };
    let (Some(nonce), Some(sealed)) = (
        wire::unb64(n, 12),
        wire::unb64(c, protocol::MAX_MESSAGE_BYTES),
    ) else {
        return Outgoing::Error { code: "malformed" };
    };
    let Ok(plain) = protocol::open(&key, &id_bytes, Direction::Request, &nonce, &sealed) else {
        return Outgoing::Error { code: "unpaired" };
    };
    let answer = match serde_json::from_slice::<Request>(&plain) {
        Ok(r) => answer(&app.state::<AppState>(), &r),
        Err(_) => json!({ "error": "malformed" }),
    };
    let Ok(bytes) = serde_json::to_vec(&answer).map(Zeroizing::new) else {
        return Outgoing::Error { code: "malformed" };
    };
    match protocol::seal(&key, &id_bytes, Direction::Response, &bytes) {
        Ok((n, c)) => Outgoing::Res {
            n: wire::b64(&n),
            c: wire::b64(&c),
        },
        Err(_) => Outgoing::Error { code: "malformed" },
    }
}

fn first(item: &vault_core::Item, kind: FieldKind) -> Option<&str> {
    item.fields
        .iter()
        .find(|f| f.kind == kind && !f.value.is_empty())
        .map(|f| f.value.as_str())
}

/// Answers a request with what the vaults hold. Nothing is answered while
/// locked.
fn answer(state: &AppState, request: &Request) -> serde_json::Value {
    let status = state.status();
    match request {
        Request::Status => json!({
            "unlocked": status.account.is_some() && !status.locked,
            "account": status.account.is_some(),
        }),
        Request::Logins { url } => state
            .read_session(|s| {
                let mut logins = Vec::new();
                for vault in s.vaults.summaries(&s.unlocked) {
                    let Some(id) =
                        wire::unb64_array(&vault.id).map(vault_core::VaultId::from_bytes)
                    else {
                        continue;
                    };
                    for (item_id, item) in s.vaults.items(&id).unwrap_or_default() {
                        if !login_matches(&item, url) {
                            continue;
                        }
                        logins.push(json!({
                            "vault": vault.id,
                            "vault_name": vault.name,
                            "item": wire::b64(item_id.as_bytes()),
                            "title": first(&item, FieldKind::Title).unwrap_or(""),
                            "username": first(&item, FieldKind::Username).unwrap_or(""),
                        }));
                    }
                }
                logins.sort_by_cached_key(|l| l["title"].as_str().unwrap_or("").to_lowercase());
                logins.truncate(MAX_LOGINS);
                Ok(json!({ "logins": logins }))
            })
            .unwrap_or_else(|_| json!({ "error": "locked" })),
        Request::Fill { url, vault, item } => {
            let (Some(vault), Some(item_id)) = (
                wire::unb64_array(vault).map(vault_core::VaultId::from_bytes),
                wire::unb64_array(item).map(vault_core::ItemId::from_bytes),
            ) else {
                return json!({ "error": "not_found" });
            };
            let Some(origin) = matching::fillable_origin(url) else {
                return json!({ "error": "no_match" });
            };
            state
                .read_session(|s| {
                    let Ok(found) = s.vaults.item(&vault, &item_id) else {
                        return Ok(json!({ "error": "not_found" }));
                    };
                    // Checked again here: the extension's word is not enough.
                    if !login_matches(&found, url) {
                        return Ok(json!({ "error": "no_match" }));
                    }
                    let totp = first(&found, FieldKind::TotpSecret)
                        .and_then(|secret| crate::totp::Totp::parse(secret).ok())
                        .and_then(|t| t.code_at(crate::state::now_ms() / 1000).ok())
                        .map(|c| c.code.to_string());
                    Ok(json!({
                        "origin": origin,
                        "username": first(&found, FieldKind::Username).unwrap_or(""),
                        "password": first(&found, FieldKind::Password).unwrap_or(""),
                        "totp": totp,
                    }))
                })
                .unwrap_or_else(|_| json!({ "error": "locked" }))
        }
    }
}

/// Whether a login has an address that matches the page.
fn login_matches(item: &vault_core::Item, page: &str) -> bool {
    item.item_type == ItemType::Login
        && item
            .fields
            .iter()
            .filter(|f| f.kind == FieldKind::Url)
            .any(|f| matching::matches(&f.value, page))
}
