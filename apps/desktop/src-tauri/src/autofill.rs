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

use crate::error::AppError;
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
    /// Saves what the person just typed into another app's sign-in form,
    /// after they chose "Save" in Android's prompt and confirmed it here.
    /// A login for the same site (or with the same title, in apps) and the
    /// same username gets the new password; otherwise a new login is made
    /// in the first vault this account owns.
    Save {
        title: String,
        username: String,
        password: zeroize::Zeroizing<String>,
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

/// Whether `item` is the saved login for what is being saved: the same
/// site (or, in apps, the same title) and the same username.
fn same_login(item: &Item, title: &str, username: &str, page: Option<&str>) -> bool {
    item.item_type == ItemType::Login
        && first(item, FieldKind::Username).unwrap_or("") == username
        && match page {
            Some(page) => item
                .fields
                .iter()
                .any(|f| f.kind == FieldKind::Url && matching::matches(&f.value, page)),
            None => first(item, FieldKind::Title).is_some_and(|t| t.eq_ignore_ascii_case(title)),
        }
}

/// The login to save, as an item: a new one, or `existing` with the new
/// password in place of its first one.
fn login_to_save(
    existing: Option<Item>,
    title: &str,
    username: &str,
    password: &str,
    page: Option<&str>,
    now: u64,
) -> Item {
    if let Some(mut item) = existing {
        if let Some(field) = item
            .fields
            .iter_mut()
            .find(|f| f.kind == FieldKind::Password)
        {
            field.value = zeroize::Zeroizing::new(password.to_owned());
        } else {
            item.fields
                .push(vault_core::Field::new(FieldKind::Password, password));
        }
        item.modified_ms = now;
        return item;
    }
    let title = if title.trim().is_empty() {
        "Login"
    } else {
        title.trim()
    };
    let mut fields = vec![vault_core::Field::new(FieldKind::Title, title)];
    if !username.is_empty() {
        fields.push(vault_core::Field::new(FieldKind::Username, username));
    }
    fields.push(vault_core::Field::new(FieldKind::Password, password));
    if let Some(page) = page {
        fields.push(vault_core::Field::new(FieldKind::Url, page));
    }
    Item {
        item_type: ItemType::Login,
        created_ms: now,
        modified_ms: now,
        fields,
    }
}

/// Saves a login typed into another app: see [`Ask::Save`].
fn save(
    state: &AppState,
    title: &str,
    username: &str,
    password: &str,
    page: Option<&str>,
) -> Value {
    if password.is_empty() || password.len() > 4096 || title.len() > 512 || username.len() > 4096 {
        return json!({ "error": "invalid" });
    }
    let offline = state.is_offline();
    let now = crate::state::now_ms();
    let saved = state.with_session(|s| {
        let summaries = s.vaults.summaries(&s.unlocked);
        // An existing login for this, in any vault this account may change.
        let mut target = None;
        for vault in summaries.iter().filter(|v| v.writable) {
            let Some(id) = wire::unb64_array(&vault.id).map(vault_core::VaultId::from_bytes) else {
                continue;
            };
            if let Some((item_id, item)) = s
                .vaults
                .items(&id)
                .unwrap_or_default()
                .into_iter()
                .find(|(_, item)| same_login(item, title, username, page))
            {
                target = Some((vault.name.clone(), id, Some(item_id), Some(item)));
                break;
            }
        }
        let (vault_name, id, item_id, existing) = match target {
            Some(found) => found,
            None => {
                let vault = summaries
                    .iter()
                    .find(|v| v.owner && v.writable)
                    .ok_or(AppError::ReadOnly)?;
                let id = wire::unb64_array(&vault.id)
                    .map(vault_core::VaultId::from_bytes)
                    .ok_or(AppError::NotFound)?;
                (vault.name.clone(), id, None, None)
            }
        };
        let updated = existing.is_some();
        let item = login_to_save(existing, title, username, password, page, now);
        if offline {
            s.vaults.put_offline(&s.unlocked, id, item_id, &item)?;
        } else {
            match s
                .vaults
                .put(&state.transport, &s.unlocked, id, item_id, &item)
            {
                Err(AppError::Offline) => {
                    s.vaults.put_offline(&s.unlocked, id, item_id, &item)?;
                }
                other => {
                    other?;
                }
            }
        }
        Ok(json!({ "saved": true, "updated": updated, "vault_name": vault_name }))
    });
    saved.unwrap_or_else(|e| match e {
        AppError::Locked => json!({ "error": "locked" }),
        e => json!({ "error": "failed", "message": e.to_string() }),
    })
}

/// Answers one question from what the vaults hold.
fn answer(state: &AppState, ask: &Ask) -> Value {
    let status = state.status();
    if status.account.is_none() || status.locked {
        return json!({ "error": "locked" });
    }
    if let Ask::Save {
        title,
        username,
        password,
        page,
    } = ask
    {
        return save(state, title, username, password, page.as_deref());
    }
    let answered = state.read_session(|s| {
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
            Ask::Save { .. } => json!({ "error": "invalid" }),
        })
    });
    answered.unwrap_or_else(|_| json!({ "error": "locked" }))
}

#[cfg(target_os = "android")]
pub use android::{init, open_settings, status};

/// The phone's autofill service, as Settings shows it.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct AutofillStatus {
    /// Whether BlackBoxus is the phone's autofill service.
    pub enabled: bool,
    /// The last time Android asked about a form: when, which app, and
    /// what came of it. Kept only on the phone.
    #[serde(default)]
    pub last: Option<serde_json::Value>,
    /// Whether Chrome lets autofill services fill its pages: `None` when
    /// Chrome isn't installed or too old to say.
    #[serde(default)]
    pub chrome: Option<bool>,
}

#[cfg(target_os = "android")]
mod android {
    use std::time::Duration;

    use tauri::plugin::{Builder, PluginHandle, TauriPlugin};
    use tauri::{AppHandle, Manager, Wry};

    use super::{Answer, Question, answer};
    use crate::state::AppState;

    /// The plugin's handle, for the settings commands.
    struct Bridge(PluginHandle<Wry>);

    /// Whether BlackBoxus is the phone's autofill service, and what
    /// happened the last time Android asked it about a form.
    pub fn status(app: &AppHandle) -> super::AutofillStatus {
        app.try_state::<Bridge>()
            .and_then(|b| {
                b.0.run_mobile_plugin::<super::AutofillStatus>("status", ())
                    .ok()
            })
            .unwrap_or_default()
    }

    /// Opens the phone's setting for choosing the autofill service, or
    /// Chrome's.
    pub fn open_settings(app: &AppHandle, chrome: bool) {
        if let Some(bridge) = app.try_state::<Bridge>() {
            // Best effort: some phones have no such setting.
            let command = if chrome {
                "openChromeSettings"
            } else {
                "openSettings"
            };
            let _: Result<serde_json::Value, _> = bridge.0.run_mobile_plugin(command, ());
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

    #[test]
    fn saving_updates_the_same_login_or_makes_a_new_one() {
        let mut saved = login("https://example.com", "old");
        saved.fields.push(Field::new(FieldKind::Username, "alex"));
        // Same site and username: the password is replaced, nothing else.
        assert!(same_login(&saved, "x", "alex", Some("https://example.com")));
        let updated = login_to_save(Some(saved.clone()), "x", "alex", "new", None, 7);
        assert_eq!(first(&updated, FieldKind::Password), Some("new"));
        assert_eq!(first(&updated, FieldKind::Title), Some("Example"));
        assert_eq!(updated.modified_ms, 7);
        // Another username or another site is another login.
        assert!(!same_login(&saved, "x", "sam", Some("https://example.com")));
        assert!(!same_login(
            &saved,
            "x",
            "alex",
            Some("https://example.org")
        ));
        // In apps, logins are told apart by title.
        assert!(same_login(&saved, "example", "alex", None));
        let fresh = login_to_save(None, "  Bank app ", "", "pw", None, 9);
        assert_eq!(first(&fresh, FieldKind::Title), Some("Bank app"));
        assert_eq!(first(&fresh, FieldKind::Username), None);
        assert_eq!(first(&fresh, FieldKind::Url), None);
        assert_eq!(fresh.created_ms, 9);
    }
}
