//! Filling logins into other apps on Android, through Android's autofill
//! framework.
//!
//! The autofill service and its picker are plain Android code (in
//! `gen/android`). They hold no vault data: they ask this side, which has
//! the unlocked vaults, through a small Tauri plugin. Rust waits for the
//! next question (`next`), answers it (`answer`) and waits again, so no
//! native entry points are needed and nothing is answered while the app
//! is closed or locked.
//!
//! What is offered follows the browser extension's rules (spec section
//! 14.5): in a browser, only logins saved for the same site; in other
//! apps, nothing is matched automatically and the person picks a login
//! themselves, after being shown which app is asking.

// Built on desktops only for its tests.
#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vault_core::{FieldKind, Item, ItemType};

use crate::state::AppState;

// The browser extension's site matching. Phones have no extension, so the
// file is included directly there.
#[cfg(not(target_os = "android"))]
use crate::browser::matching;
#[cfg(target_os = "android")]
#[allow(dead_code)]
#[path = "browser/matching.rs"]
mod matching;

/// The most logins one answer lists.
const MAX_LOGINS: usize = 500;

/// A question from the autofill picker.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Ask {
    /// The logins to offer. `page` is the web page being filled
    /// (`https://example.com`), or `None` in an app that is not a browser.
    Logins { page: Option<String> },
    /// The username and password of one login the person picked.
    Fill {
        vault: String,
        item: String,
        page: Option<String>,
    },
}

/// A question with the number its answer goes back under.
#[derive(Debug, Deserialize)]
struct Question {
    id: u64,
    #[serde(flatten)]
    ask: Ask,
}

#[derive(Serialize)]
struct Answer {
    id: u64,
    body: String,
}

/// The first non-empty field of a kind.
fn first(item: &Item, kind: FieldKind) -> Option<&str> {
    item.fields
        .iter()
        .find(|f| f.kind == kind && !f.value.is_empty())
        .map(|f| f.value.as_str())
}

/// Whether a login may be offered: on a web page, only when one of its
/// addresses is the same site; in other apps, any login, picked by hand.
fn offered(item: &Item, page: Option<&str>) -> bool {
    item.item_type == ItemType::Login
        && match page {
            None => true,
            Some(page) => item
                .fields
                .iter()
                .filter(|f| f.kind == FieldKind::Url)
                .any(|f| matching::matches(&f.value, page)),
        }
}

/// Answers one question from what the vaults hold.
fn answer(state: &AppState, ask: &Ask) -> Value {
    let status = state.status();
    if status.account.is_none() || status.locked {
        return json!({ "error": "locked" });
    }
    let answered = state.with_session(|s| {
        Ok(match ask {
            Ask::Logins { page } => {
                let mut logins = Vec::new();
                for vault in s.vaults.summaries(&s.unlocked) {
                    let Some(id) =
                        wire::unb64_array(&vault.id).map(vault_core::VaultId::from_bytes)
                    else {
                        continue;
                    };
                    for (item_id, item) in s.vaults.items(&id).unwrap_or_default() {
                        if !offered(&item, page.as_deref())
                            || first(&item, FieldKind::Password).is_none()
                        {
                            continue;
                        }
                        logins.push(json!({
                            "vault": vault.id,
                            "vault_name": vault.name,
                            "item": wire::b64(item_id.as_bytes()),
                            "title": first(&item, FieldKind::Title).unwrap_or("Untitled"),
                            "username": first(&item, FieldKind::Username).unwrap_or(""),
                        }));
                    }
                }
                logins.sort_by_cached_key(|l| l["title"].as_str().unwrap_or("").to_lowercase());
                logins.truncate(MAX_LOGINS);
                json!({ "logins": logins })
            }
            Ask::Fill { vault, item, page } => {
                let (Some(vault), Some(item_id)) = (
                    wire::unb64_array(vault).map(vault_core::VaultId::from_bytes),
                    wire::unb64_array(item).map(vault_core::ItemId::from_bytes),
                ) else {
                    return Ok(json!({ "error": "not_found" }));
                };
                let Ok(found) = s.vaults.item(&vault, &item_id) else {
                    return Ok(json!({ "error": "not_found" }));
                };
                // Checked again here: the picker's word is not enough.
                if !offered(&found, page.as_deref()) {
                    return Ok(json!({ "error": "no_match" }));
                }
                json!({
                    "username": first(&found, FieldKind::Username).unwrap_or(""),
                    "password": first(&found, FieldKind::Password).unwrap_or(""),
                })
            }
        })
    });
    answered.unwrap_or_else(|_| json!({ "error": "locked" }))
}

#[cfg(target_os = "android")]
pub use android::{enabled, init, open_settings};

#[cfg(target_os = "android")]
mod android {
    use std::time::Duration;

    use tauri::plugin::{Builder, PluginHandle, TauriPlugin};
    use tauri::{AppHandle, Manager, Wry};

    use super::{Answer, Question, answer};
    use crate::state::AppState;

    /// The plugin's handle, for the settings commands.
    struct Bridge(PluginHandle<Wry>);

    #[derive(serde::Deserialize)]
    struct Status {
        enabled: bool,
    }

    /// Whether BlackBoxus is the phone's autofill service.
    pub fn enabled(app: &AppHandle) -> bool {
        app.try_state::<Bridge>()
            .and_then(|b| b.0.run_mobile_plugin::<Status>("status", ()).ok())
            .is_some_and(|s| s.enabled)
    }

    /// Opens the phone's setting for choosing the autofill service.
    pub fn open_settings(app: &AppHandle) {
        if let Some(bridge) = app.try_state::<Bridge>() {
            // Best effort: some phones have no such setting.
            let _: Result<serde_json::Value, _> = bridge.0.run_mobile_plugin("openSettings", ());
        }
    }

    /// Registers the autofill bridge and starts answering its questions.
    pub fn init() -> TauriPlugin<Wry> {
        Builder::new("autofill")
            .setup(|app, api| {
                let handle =
                    api.register_android_plugin("io.github.ktnreddy.blackboxus", "AutofillPlugin")?;
                app.manage(Bridge(handle.clone()));
                let app = app.clone();
                std::thread::Builder::new()
                    .name("autofill".into())
                    .spawn(move || serve(&app, &handle))?;
                Ok(())
            })
            .build()
    }

    /// Waits for each question and answers it, for as long as the app runs.
    fn serve(app: &AppHandle, handle: &PluginHandle<Wry>) {
        loop {
            match handle.run_mobile_plugin::<Question>("next", ()) {
                Ok(question) => {
                    let body = answer(&app.state::<AppState>(), &question.ask).to_string();
                    let sent: Result<serde_json::Value, _> = handle.run_mobile_plugin(
                        "answer",
                        Answer {
                            id: question.id,
                            body,
                        },
                    );
                    if sent.is_err() {
                        std::thread::sleep(Duration::from_millis(200));
                    }
                }
                // The Android side is not ready yet, or a malformed question.
                Err(_) => std::thread::sleep(Duration::from_secs(1)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::Field;

    fn login(url: &str, password: &str) -> Item {
        Item {
            item_type: ItemType::Login,
            created_ms: 0,
            modified_ms: 0,
            fields: vec![
                Field::new(FieldKind::Title, "Example"),
                Field::new(FieldKind::Url, url),
                Field::new(FieldKind::Password, password),
            ],
        }
    }

    #[test]
    fn web_pages_get_only_their_own_sites_logins() {
        let item = login("https://accounts.example.com/login", "pw");
        assert!(offered(&item, Some("https://www.example.com")));
        assert!(!offered(&item, Some("https://example.org")));
        assert!(!offered(&item, Some("https://example.com.evil.net")));
        // A login saved for https is never offered to an http page.
        assert!(!offered(&item, Some("http://www.example.com")));
        // Other apps pick by hand.
        assert!(offered(&item, None));
    }

    #[test]
    fn only_logins_are_offered() {
        let mut note = login("https://example.com", "pw");
        note.item_type = ItemType::SecureNote;
        assert!(!offered(&note, None));
    }

    #[test]
    fn questions_are_read() -> Result<(), serde_json::Error> {
        let q: Question = serde_json::from_str(r#"{"id":4,"kind":"logins","page":null}"#)?;
        assert_eq!(q.id, 4);
        assert!(matches!(q.ask, Ask::Logins { page: None }));
        let q: Question = serde_json::from_str(
            r#"{"id":5,"kind":"fill","vault":"v","item":"i","page":"https://a.com"}"#,
        )?;
        assert!(matches!(q.ask, Ask::Fill { .. }));
        Ok(())
    }
}
