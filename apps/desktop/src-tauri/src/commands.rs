//! The commands the window can call. Each is also listed in `build.rs`
//! and allowed in `capabilities/main.json`; anything else is refused.
//!
//! Secrets arrive as [`Zeroizing`] strings, so the Rust copy is wiped as
//! soon as a command returns.

use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use vault_core::{ClientIdentity, ItemId, SecretKey, ServerIdentity, VaultId};
use zeroize::Zeroizing;

use crate::breach;
use crate::error::AppError;
use crate::flows;
use crate::generator::{self, Generated, Options};
use crate::http::ORIGIN;
use crate::items::{self, ItemInput, ItemSummary, ItemView};
use crate::state::{AppState, AppStatus};
use crate::storage::AccountRecord;
use crate::strength::{self, Rating};
use crate::vaults::{Keep, LookedUp, MemberView, PendingView, VaultSummary};

/// The Emergency Kit, shown once after sign-up.
#[derive(Debug, Serialize)]
pub(crate) struct KitView {
    email: String,
    server: String,
    secret_key: Zeroizing<String>,
    /// A recovery key just created, shown only this once.
    recovery_key: Option<Zeroizing<String>>,
}

/// What [`create_account`] returns.
#[derive(Debug, Serialize)]
pub(crate) struct Created {
    status: AppStatus,
    kit: KitView,
}

fn server() -> Result<ServerIdentity, AppError> {
    ServerIdentity::new(ORIGIN).map_err(|_| AppError::Internal)
}

/// Runs `job` on a worker thread with the app state, so slow key
/// derivation does not freeze the window.
async fn blocking<T: Send + 'static>(
    app: AppHandle,
    job: impl FnOnce(&AppState) -> Result<T, AppError> + Send + 'static,
) -> Result<T, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let _busy = state.begin()?;
        job(&state)
    })
    .await
    .map_err(|_| AppError::Internal)?
}

/// Reports whether there is an account and whether it is locked.
#[tauri::command]
pub(crate) fn app_status(state: State<'_, AppState>) -> AppStatus {
    state.status()
}

/// Rates a new master password for the strength meter.
#[tauri::command]
pub(crate) fn rate_password(password: Zeroizing<String>, email: String) -> Rating {
    let words: Vec<&str> = email.split(['@', '.', '_', '-', '+']).collect();
    strength::rate(&password, &words)
}

/// Checks a new master password is typed the same twice, is long and
/// strong enough, and has not appeared in a known data breach. If the
/// breach check can't run (offline, or the service is down), the password
/// is still accepted: the length and strength rules above already applied.
fn check_new_password(email: &str, password: &str, confirm: &str) -> Result<(), AppError> {
    if password != confirm {
        return Err(AppError::PasswordsDiffer);
    }
    let words: Vec<&str> = email.split(['@', '.', '_', '-', '+']).collect();
    let rating = strength::rate(password, &words);
    if rating.chars < rating.min_chars {
        return Err(AppError::PasswordTooShort(rating.min_chars));
    }
    if !rating.acceptable {
        return Err(AppError::WeakPassword);
    }
    if let breach::Outcome::Breached(_) = breach::check(password) {
        return Err(AppError::BreachedPassword);
    }
    Ok(())
}

fn account_id_of(record: &AccountRecord) -> Result<vault_core::AccountId, AppError> {
    wire::unb64_array(&record.account_id)
        .map(vault_core::AccountId::from_bytes)
        .ok_or(AppError::Storage)
}

/// Creates an account, stores its Secret Key on this computer, signs in
/// and returns the Emergency Kit.
#[tauri::command]
pub(crate) async fn create_account(
    app: AppHandle,
    email: String,
    password: Zeroizing<String>,
    confirm: Zeroizing<String>,
) -> Result<Created, AppError> {
    blocking(app, move |state| {
        if state.account().is_some() {
            return Err(AppError::AccountExists);
        }
        check_new_password(&email, &password, &confirm)?;
        let server = server()?;
        let (unlocked, offline, secret_key, kit) =
            flows::create_account(&state.transport, &server, &email, &password)?;
        let identity = ClientIdentity::new(&email)?;
        let record = AccountRecord::new(&identity, unlocked.session.account_id(), ORIGIN);
        state.storage.save_account(&record, &secret_key)?;
        state.storage.save_offline(&offline)?;
        state.set_account(record, unlocked)?;
        Ok(Created {
            status: state.status(),
            kit: KitView {
                email: kit.email,
                server: kit.server,
                secret_key: kit.secret_key,
                recovery_key: None,
            },
        })
    })
    .await
}

/// Signs in to an existing account on this computer with the Secret Key
/// from the Emergency Kit.
#[tauri::command]
pub(crate) async fn sign_in(
    app: AppHandle,
    email: String,
    secret_key: Zeroizing<String>,
    password: Zeroizing<String>,
) -> Result<AppStatus, AppError> {
    blocking(app, move |state| {
        if state.account().is_some() {
            return Err(AppError::AccountExists);
        }
        if password.is_empty() {
            return Err(AppError::EmptyPassword);
        }
        let identity = ClientIdentity::new(&email)?;
        let secret_key = SecretKey::parse(&secret_key)?;
        let (unlocked, offline) =
            flows::sign_in(&state.transport, &server()?, &email, &secret_key, &password)?;
        let record = AccountRecord::new(&identity, unlocked.session.account_id(), ORIGIN);
        state.storage.save_account(&record, &secret_key)?;
        state.storage.save_offline(&offline)?;
        state.set_account(record, unlocked)?;
        Ok(state.status())
    })
    .await
}

/// Unlocks the vaults with the master password.
#[tauri::command]
pub(crate) async fn unlock(
    app: AppHandle,
    password: Zeroizing<String>,
) -> Result<AppStatus, AppError> {
    blocking(app, move |state| {
        if password.is_empty() {
            return Err(AppError::EmptyPassword);
        }
        let record = state.account().ok_or(AppError::NoAccount)?;
        let secret_key = state.storage.secret_key(&record)?;
        let online = flows::sign_in(
            &state.transport,
            &server()?,
            &record.email,
            &secret_key,
            &password,
        );
        let unlocked = match online {
            Ok((unlocked, offline)) => {
                if wire::b64(unlocked.session.account_id().as_bytes()) != record.account_id {
                    return Err(AppError::Tampered);
                }
                state.storage.save_offline(&offline)?;
                state
                    .device
                    .password_used(&unlocked, crate::state::now_ms())?;
                unlocked
            }
            // No connection: unlock from the copy kept on this computer,
            // read-only until the next sync reaches the server.
            Err(AppError::Offline) => {
                let saved = state.storage.load_offline()?.ok_or(AppError::Offline)?;
                let opened = saved.unlock(&password, &secret_key).map_err(|e| match e {
                    client_core::ClientError::WrongCredentials => AppError::WrongPassword,
                    other => other.into(),
                })?;
                if wire::b64(opened.account_id.as_bytes()) != record.account_id {
                    return Err(AppError::Tampered);
                }
                client_core::login::Unlocked {
                    // No session: every request would fail, and none is
                    // made while offline.
                    session: client_core::Session::restore(
                        vault_core::login::SessionToken::from_bytes([0; 32]),
                        opened.account_id,
                    ),
                    key_set: opened.key_set,
                    key_set_version: opened.key_set_version,
                }
            }
            // Only the password can be wrong: the email and Secret Key
            // were stored when this computer was set up.
            Err(AppError::WrongCredentials) => return Err(AppError::WrongPassword),
            Err(other) => return Err(other),
        };
        state.set_unlocked(unlocked)?;
        Ok(state.status())
    })
    .await
}

/// Locks the vaults.
#[tauri::command]
pub(crate) fn lock(state: State<'_, AppState>) -> AppStatus {
    state.lock();
    state.status()
}

fn vault_id(text: &str) -> Result<VaultId, AppError> {
    wire::unb64_array(text)
        .map(VaultId::from_bytes)
        .ok_or(AppError::NotFound)
}

fn item_id(text: &str) -> Result<ItemId, AppError> {
    wire::unb64_array(text)
        .map(ItemId::from_bytes)
        .ok_or(AppError::NotFound)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

/// What [`sync_vaults`] returns.
#[derive(Debug, Serialize)]
pub(crate) struct Synced {
    vaults: Vec<VaultSummary>,
    /// The server could not be reached: these are this computer's copies.
    offline: bool,
    /// The key log records keys for this account that it did not publish
    /// (spec section 9.5).
    unknown_keys: bool,
    /// The trusted contact has asked for access (spec section 11.5).
    emergency_request: Option<crate::trusted::GrantView>,
    /// Changes made offline, still to be sent.
    waiting: usize,
    /// Items changed both here and elsewhere, for the user to settle.
    conflicts: usize,
}

/// Syncs every vault with the server and lists them. Without a connection,
/// lists this computer's copies instead, read-only.
///
/// The sync works on its own copy of the vaults, so the app stays usable
/// while it talks to the server: reading, copying and locking don't wait.
/// Changes wait for it to finish (see [`AppState::with_session`]).
#[tauri::command]
pub(crate) async fn sync_vaults(app: AppHandle) -> Result<Synced, AppError> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let state = handle.state::<AppState>();
        let _gate = state.sync_gate();
        let (id, unlocked, mut synced) =
            state.read_session(|s| Ok((s.id, s.unlocked.clone(), s.vaults.for_sync())))?;
        let offline = match synced.sync(&state.transport, &unlocked) {
            Ok(()) => false,
            Err(AppError::Offline) => {
                synced.load_local(&unlocked);
                true
            }
            Err(e) => return Err(e),
        };
        let unknown_keys = if offline {
            false
        } else {
            match synced.check_own_keys(&state.transport, &unlocked, now_ms()) {
                // A lost connection only postpones the check.
                Err(AppError::Offline) => false,
                other => other?,
            }
        };
        // A pending request from the trusted contact is shown on every
        // sync, so the owner can deny it in time (spec section 11.6).
        let emergency_request = if offline {
            None
        } else {
            match crate::trusted::emergency_status(&state.transport, &unlocked) {
                Ok(status) => crate::trusted::EmergencyView::from(&status)
                    .contact
                    .filter(|c| c.stage == "requested"),
                Err(AppError::Offline) => None,
                Err(e) => return Err(e),
            }
        };
        state.set_offline(offline);
        state.read_session(|s| {
            // Locked meanwhile, and perhaps unlocked again: the synced copy
            // belongs to a session that has ended.
            if s.id != id {
                return Err(AppError::Locked);
            }
            s.vaults.replace_with(synced);
            // Listen for changes while online, starting again after the
            // server refused an expired session and a new one was made.
            if !offline && s.live.as_ref().is_none_or(crate::live::Live::finished) {
                s.live = crate::live::Live::start(
                    app.clone(),
                    state.transport.base(),
                    s.unlocked.session.authorization(),
                );
            }
            let pending = s.vaults.pending(&s.unlocked)?;
            Ok(Synced {
                vaults: s.vaults.summaries(&s.unlocked),
                offline,
                unknown_keys,
                emergency_request,
                waiting: pending.waiting,
                conflicts: pending.conflicts.len(),
            })
        })
    })
    .await
    .map_err(|_| AppError::Internal)?
}

/// The vaults as this device has them, straight away and without the
/// server, so the screens can show them while the first sync runs.
#[tauri::command]
pub(crate) fn local_vaults(state: State<'_, AppState>) -> Result<Synced, AppError> {
    let offline = state.is_offline();
    state.read_session(|s| {
        if s.vaults.is_empty() {
            s.vaults.load_local(&s.unlocked);
        }
        let pending = s.vaults.pending(&s.unlocked)?;
        Ok(Synced {
            vaults: s.vaults.summaries(&s.unlocked),
            offline,
            unknown_keys: false,
            emergency_request: None,
            waiting: pending.waiting,
            conflicts: pending.conflicts.len(),
        })
    })
}

/// The vaults to read: the account's own, or with `owner`, those of the
/// account opened as its trusted contact.
fn vaults_of<'a>(
    s: &'a mut crate::state::Session,
    owner: Option<&str>,
) -> Result<&'a mut crate::vaults::Vaults, AppError> {
    match owner {
        None => Ok(&mut s.vaults),
        Some(owner) => {
            let owner = crate::sharing_id::decode(owner)?;
            s.emergency
                .as_mut()
                .filter(|e| e.owner == owner)
                .map(|e| &mut e.vaults)
                .ok_or(AppError::EmergencyUnavailable)
        }
    }
}

/// Lists a vault's items, sorted by title. Carries no secrets.
#[tauri::command]
pub(crate) fn list_items(
    state: State<'_, AppState>,
    vault: String,
    owner: Option<String>,
) -> Result<Vec<ItemSummary>, AppError> {
    let id = vault_id(&vault)?;
    state.read_session(|s| {
        let vaults = vaults_of(s, owner.as_deref())?;
        let mut list: Vec<ItemSummary> = vaults
            .items(&id)?
            .iter()
            .map(|(item_id, item)| {
                let mut summary = items::summary(item_id, item);
                summary.pending = vaults.pending_kind(&id, item_id);
                summary
            })
            .collect();
        list.sort_by_key(|i| i.title.to_lowercase());
        Ok(list)
    })
}

/// One item, with concealed values left out.
#[tauri::command]
pub(crate) fn get_item(
    state: State<'_, AppState>,
    vault: String,
    item: String,
    owner: Option<String>,
) -> Result<ItemView, AppError> {
    let (id, item_id) = (vault_id(&vault)?, item_id(&item)?);
    state.read_session(|s| {
        Ok(items::view(
            &item_id,
            &vaults_of(s, owner.as_deref())?.item(&id, &item_id)?,
        ))
    })
}

/// The value of one concealed field, when the user asks to see it.
#[tauri::command]
pub(crate) fn reveal_field(
    state: State<'_, AppState>,
    vault: String,
    item: String,
    index: usize,
    owner: Option<String>,
) -> Result<Zeroizing<String>, AppError> {
    let (id, item_id) = (vault_id(&vault)?, item_id(&item)?);
    state.read_session(|s| {
        let item = vaults_of(s, owner.as_deref())?.item(&id, &item_id)?;
        Ok(items::field_at(&item, index)?.value.clone())
    })
}

/// Copies one field to the clipboard from here, so concealed values never
/// pass through the window. Cleared after 30 seconds.
#[tauri::command]
pub(crate) fn copy_field(
    state: State<'_, AppState>,
    vault: String,
    item: String,
    index: usize,
    owner: Option<String>,
) -> Result<(), AppError> {
    let (id, item_id) = (vault_id(&vault)?, item_id(&item)?);
    let value = state.read_session(|s| {
        let item = vaults_of(s, owner.as_deref())?.item(&id, &item_id)?;
        Ok(items::field_at(&item, index)?.value.clone())
    })?;
    state.clipboard.copy(value)
}

/// Adds an item (no `item`) or saves changes to one. Returns its ID.
/// Offline, the change is kept on this device and sent once online.
#[tauri::command]
pub(crate) async fn save_item(
    app: AppHandle,
    vault: String,
    item: Option<String>,
    input: ItemInput,
) -> Result<String, AppError> {
    let id = vault_id(&vault)?;
    let existing = item.as_deref().map(item_id).transpose()?;
    blocking(app, move |state| {
        let offline = state.is_offline();
        let saved = state.with_session(|s| {
            let created_ms = match &existing {
                Some(item_id) => s.vaults.item(&id, item_id)?.created_ms,
                None => now_ms(),
            };
            let built = items::build(&input, created_ms, now_ms())?;
            if offline {
                return s.vaults.put_offline(&s.unlocked, id, existing, &built);
            }
            match s
                .vaults
                .put(&state.transport, &s.unlocked, id, existing, &built)
            {
                // The connection dropped: keep it here instead.
                Err(AppError::Offline) => s.vaults.put_offline(&s.unlocked, id, existing, &built),
                other => other,
            }
        });
        Ok(wire::b64(saved?.as_bytes()))
    })
    .await
}

/// Deletes an item. Offline, the deletion is kept and sent once online.
#[tauri::command]
pub(crate) async fn delete_item(
    app: AppHandle,
    vault: String,
    item: String,
) -> Result<(), AppError> {
    let (id, item_id) = (vault_id(&vault)?, item_id(&item)?);
    blocking(app, move |state| {
        let offline = state.is_offline();
        state.with_session(|s| {
            if offline {
                return s.vaults.delete_offline(&s.unlocked, id, &item_id);
            }
            match s.vaults.delete(&state.transport, &s.unlocked, id, &item_id) {
                Err(AppError::Offline) => s.vaults.delete_offline(&s.unlocked, id, &item_id),
                other => other,
            }
        })
    })
    .await
}

/// Changes made offline that are waiting, and conflicts to settle.
#[tauri::command]
pub(crate) fn pending_changes(state: State<'_, AppState>) -> Result<PendingView, AppError> {
    state.read_session(|s| s.vaults.pending(&s.unlocked))
}

/// One field of either version of a conflict, to compare them.
#[tauri::command]
pub(crate) fn conflict_field(
    state: State<'_, AppState>,
    vault: String,
    item: String,
    mine: bool,
    index: usize,
) -> Result<Zeroizing<String>, AppError> {
    let (id, item_id) = (vault_id(&vault)?, item_id(&item)?);
    state.read_session(|s| {
        s.vaults
            .conflict_field(&s.unlocked, &id, &item_id, mine, index)
    })
}

/// Settles a conflict by keeping one version, or both.
#[tauri::command]
pub(crate) async fn resolve_conflict(
    app: AppHandle,
    vault: String,
    item: String,
    keep: Keep,
) -> Result<(), AppError> {
    let (id, item_id) = (vault_id(&vault)?, item_id(&item)?);
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|s| {
            s.vaults
                .resolve(&state.transport, &s.unlocked, id, item_id, keep)
        })
    })
    .await
}

/// Scans a QR code with the camera (phones only) and returns its text,
/// such as an otpauth:// link with a one-time code secret.
#[tauri::command]
pub(crate) async fn scan_code(app: AppHandle) -> Result<String, AppError> {
    #[cfg(mobile)]
    {
        let handle = app.clone();
        tauri::async_runtime::spawn_blocking(move || {
            // The camera permission and the camera itself pause the app.
            let state = handle.state::<AppState>();
            let _screen = state.away.system_screen();
            crate::scanner::scan(&handle)
        })
        .await
        .map_err(|_| AppError::Internal)?
    }
    #[cfg(not(mobile))]
    {
        let _ = app;
        Err(AppError::CameraDenied)
    }
}

/// Stops a scan in progress.
#[tauri::command]
pub(crate) fn cancel_scan(app: AppHandle) {
    #[cfg(mobile)]
    crate::scanner::cancel(&app);
    #[cfg(not(mobile))]
    let _ = app;
}

/// Whether BlackBoxus fills logins in other apps: `None` where there is no
/// such thing (desktops), otherwise whether it is the phone's autofill
/// service.
#[tauri::command]
pub(crate) async fn autofill_status(app: AppHandle) -> Option<serde_json::Value> {
    #[cfg(target_os = "android")]
    {
        let handle = app.clone();
        tauri::async_runtime::spawn_blocking(move || crate::autofill::status(&handle))
            .await
            .ok()
            .and_then(|s| serde_json::to_value(s).ok())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        None
    }
}

/// Opens the phone's setting for choosing the autofill service, or with
/// `chrome`, Chrome's setting for letting it be used there.
#[tauri::command]
pub(crate) async fn autofill_settings(app: AppHandle, chrome: Option<bool>) {
    #[cfg(target_os = "android")]
    {
        let handle = app.clone();
        let chrome = chrome.unwrap_or(false);
        let _ = tauri::async_runtime::spawn_blocking(move || {
            crate::autofill::open_settings(&handle, chrome);
        })
        .await;
    }
    #[cfg(not(target_os = "android"))]
    let _ = (app, chrome);
}

/// Generates a random password.
#[tauri::command]
pub(crate) fn generate_password(options: Options) -> Result<Generated, AppError> {
    generator::generate(&options)
}

/// This account's sharing ID, for others to share vaults with it.
#[tauri::command]
pub(crate) fn my_sharing_id(state: State<'_, AppState>) -> Result<String, AppError> {
    state.read_session(|s| Ok(crate::sharing_id::encode(s.unlocked.session.account_id())))
}

/// The members of a vault.
#[tauri::command]
pub(crate) fn vault_members(
    state: State<'_, AppState>,
    vault: String,
) -> Result<Vec<MemberView>, AppError> {
    let id = vault_id(&vault)?;
    state.read_session(|s| s.vaults.members(&id, &s.unlocked))
}

/// Looks someone up by sharing ID and returns the safety number.
#[tauri::command]
pub(crate) async fn look_up_member(
    app: AppHandle,
    vault: String,
    sharing_id: String,
) -> Result<LookedUp, AppError> {
    let id = vault_id(&vault)?;
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|s| {
            s.vaults
                .look_up(&state.transport, &s.unlocked, id, &sharing_id)
        })
    })
    .await
}

/// Shares a vault with the person just looked up.
#[tauri::command]
pub(crate) async fn share_vault(
    app: AppHandle,
    vault: String,
    sharing_id: String,
    role: String,
) -> Result<Vec<MemberView>, AppError> {
    let id = vault_id(&vault)?;
    let role = match role.as_str() {
        "editor" | "viewer" => role_from(&role)?,
        _ => return Err(AppError::Internal),
    };
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|s| {
            s.vaults
                .share(&state.transport, &s.unlocked, id, &sharing_id, role)?;
            s.vaults.members(&id, &s.unlocked)
        })
    })
    .await
}

/// The safety number with a member, to compare with them.
#[tauri::command]
pub(crate) async fn compare_safety_number(
    app: AppHandle,
    sharing_id: String,
) -> Result<LookedUp, AppError> {
    blocking(app, move |state| {
        state.with_session(|s| s.vaults.compare(&state.transport, &s.unlocked, &sharing_id))
    })
    .await
}

/// Copies text the window already shows, such as a newly generated
/// password, with the same protections as copying a field.
#[tauri::command]
pub(crate) fn copy_text(
    state: State<'_, AppState>,
    text: Zeroizing<String>,
) -> Result<(), AppError> {
    state.clipboard.copy(text)
}

/// What [`import_choose_file`] returns.
#[derive(Debug, Serialize)]
pub(crate) struct ImportChosen {
    file_name: String,
    preview: crate::import::Preview,
    /// Whether the app can delete the file afterwards. Files picked on a
    /// phone come through the system's document picker, which only lets
    /// the app read them.
    can_delete: bool,
    /// A BlackBoxus export: give its password to [`import_open_export`].
    needs_password: bool,
}

/// Opens the chosen BlackBoxus export with its password, so its items
/// can be imported like any other file's.
#[tauri::command]
pub(crate) async fn import_open_export(
    app: AppHandle,
    password: Zeroizing<String>,
) -> Result<crate::import::Preview, AppError> {
    blocking(app, move |state| {
        let sealed = state.with_session(|s| {
            let pending = s.pending_import.as_ref().ok_or(AppError::NotFound)?;
            pending.sealed.clone().ok_or(AppError::NotFound)
        })?;
        let password = vault_core::MasterPassword::new(&password).map_err(AppError::from)?;
        let vaults = vault_core::export::open_export(&password, &sealed).map_err(|e| match e {
            vault_core::Error::Decryption => AppError::WrongExportPassword,
            vault_core::Error::NewerItemFormat => AppError::NeedsUpdate,
            _ => AppError::ImportUnreadable,
        })?;
        let (items, preview) = crate::export::preview(&vaults);
        state.with_session(|s| {
            let pending = s.pending_import.as_mut().ok_or(AppError::NotFound)?;
            pending.items = items;
            pending.preview = preview.clone();
            pending.sealed = None;
            Ok(())
        })?;
        Ok(preview)
    })
    .await
}

/// What to export, with the master password typed again.
#[derive(serde::Deserialize)]
pub(crate) struct ExportRequest {
    /// `encrypted` or `csv`.
    format: String,
    /// The master password, to confirm it's the account's owner.
    master: Zeroizing<String>,
    /// The export password, twice, for an encrypted export.
    password: Option<Zeroizing<String>>,
    confirm: Option<Zeroizing<String>>,
    /// Today's date where the person is, `YYYY-MM-DD`, for the file name.
    day: String,
}

/// An export that was saved.
#[derive(Serialize)]
pub(crate) struct ExportDone {
    vaults: usize,
    items: usize,
    /// Items left out because they need a newer version of the app.
    left_out: usize,
}

/// Exports every vault this account can read to a file the person picks:
/// encrypted with an export password (spec section 6.9), or as plain CSV.
/// Returns `None` if they cancelled choosing where to save it.
#[tauri::command]
pub(crate) async fn export_vaults(
    app: AppHandle,
    request: ExportRequest,
) -> Result<Option<ExportDone>, AppError> {
    let encrypted = match request.format.as_str() {
        "encrypted" => true,
        "csv" => false,
        _ => return Err(AppError::InvalidSetting),
    };
    let day = request.day.clone();
    let (bytes, done) = blocking(app.clone(), move |state| {
        if request.master.is_empty() {
            return Err(AppError::EmptyPassword);
        }
        // The master password, checked on this device, so it works offline.
        let record = state.account().ok_or(AppError::NoAccount)?;
        let secret_key = state.storage.secret_key(&record)?;
        let saved = state.storage.load_offline()?.ok_or(AppError::Storage)?;
        let opened = saved
            .unlock(&request.master, &secret_key)
            .map_err(|e| match e {
                client_core::ClientError::WrongCredentials => AppError::WrongPassword,
                other => other.into(),
            })?;
        if wire::b64(opened.account_id.as_bytes()) != record.account_id {
            return Err(AppError::Tampered);
        }
        let export_password = if encrypted {
            let (Some(password), Some(confirm)) = (&request.password, &request.confirm) else {
                return Err(AppError::EmptyPassword);
            };
            check_new_password(&record.email, password, confirm)?;
            Some(
                vault_core::MasterPassword::new_for_account_creation(password)
                    .map_err(AppError::from)?,
            )
        } else {
            None
        };
        let (vaults, left_out) = state.read_session(|s| {
            let mut vaults = Vec::new();
            let mut left_out = 0_usize;
            for summary in s.vaults.summaries(&s.unlocked) {
                let id = vault_id(&summary.id)?;
                left_out = left_out.saturating_add(summary.newer);
                vaults.push(vault_core::export::ExportedVault {
                    name: summary.name,
                    items: s
                        .vaults
                        .items(&id)?
                        .into_iter()
                        .map(|(_, item)| item)
                        .collect(),
                });
            }
            Ok((vaults, left_out))
        })?;
        let done = ExportDone {
            vaults: vaults.len(),
            items: vaults.iter().map(|v| v.items.len()).sum(),
            left_out,
        };
        let bytes = match &export_password {
            Some(password) => Zeroizing::new(
                vault_core::export::seal_export(password, &vaults, &vault_core::KdfParams::DEFAULT)
                    .map_err(AppError::from)?,
            ),
            None => crate::export::csv(&vaults)?,
        };
        Ok((bytes, done))
    })
    .await?;

    let day: String = day
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '-')
        .take(10)
        .collect();
    let name = if encrypted {
        format!("BlackBoxus export {day}.bbx")
    } else {
        format!("BlackBoxus export {day} UNENCRYPTED.csv")
    };
    let picker = app.clone();
    let chosen = tauri::async_runtime::spawn_blocking(move || {
        use tauri_plugin_dialog::DialogExt;
        let state = picker.state::<AppState>();
        let _screen = state.away.system_screen();
        let dialog = picker
            .dialog()
            .file()
            .set_title("Save the export")
            .set_file_name(&name);
        #[cfg(desktop)]
        let dialog = if encrypted {
            dialog.add_filter("BlackBoxus export", &["bbx"])
        } else {
            dialog.add_filter("CSV", &["csv"])
        };
        dialog.blocking_save_file()
    })
    .await
    .map_err(|_| AppError::Internal)?;
    let Some(chosen) = chosen else {
        return Ok(None);
    };
    write_chosen(&app, chosen, &bytes)?;
    Ok(Some(done))
}

#[cfg(desktop)]
fn write_chosen(
    _app: &AppHandle,
    chosen: tauri_plugin_dialog::FilePath,
    bytes: &[u8],
) -> Result<(), AppError> {
    let path = chosen.into_path().map_err(|_| AppError::Storage)?;
    std::fs::write(path, bytes).map_err(|_| AppError::Storage)
}

#[cfg(mobile)]
fn write_chosen(
    app: &AppHandle,
    chosen: tauri_plugin_dialog::FilePath,
    bytes: &[u8],
) -> Result<(), AppError> {
    use std::io::Write as _;
    use tauri_plugin_fs::{FsExt, OpenOptions};
    let mut file = app
        .fs()
        .open(
            chosen,
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .clone(),
        )
        .map_err(|_| AppError::Storage)?;
    file.write_all(bytes).map_err(|_| AppError::Storage)
}

/// A chosen export, read in full.
struct ExportFile {
    name: String,
    bytes: Zeroizing<Vec<u8>>,
    /// Where it is on disk, if the app may delete it.
    path: Option<std::path::PathBuf>,
}

/// Reads at most one byte more than the import limit, so a larger file is
/// refused without reading all of it.
fn read_capped(reader: impl std::io::Read) -> Result<Zeroizing<Vec<u8>>, AppError> {
    use std::io::Read as _;
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(crate::import::MAX_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| AppError::ImportUnreadable)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > crate::import::MAX_FILE_BYTES {
        return Err(AppError::ImportTooLarge);
    }
    Ok(bytes)
}

#[cfg(desktop)]
fn read_export(
    _app: &AppHandle,
    chosen: tauri_plugin_dialog::FilePath,
) -> Result<Option<ExportFile>, AppError> {
    let Ok(path) = chosen.into_path() else {
        return Ok(None);
    };
    let file = std::fs::File::open(&path).map_err(|_| AppError::ImportUnreadable)?;
    let bytes = read_capped(file)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(Some(ExportFile {
        name,
        bytes,
        path: Some(path),
    }))
}

#[cfg(mobile)]
fn read_export(
    app: &AppHandle,
    chosen: tauri_plugin_dialog::FilePath,
) -> Result<Option<ExportFile>, AppError> {
    use tauri_plugin_fs::{FsExt, OpenOptions};
    let file = app
        .fs()
        .open(chosen, OpenOptions::new().read(true).clone())
        .map_err(|_| AppError::ImportUnreadable)?;
    let bytes = read_capped(file)?;
    Ok(Some(ExportFile {
        name: "The export file".to_owned(),
        bytes,
        path: None,
    }))
}

/// Opens the system file picker, reads the chosen CSV export here in Rust
/// and keeps its items until the user confirms. Returns `None` if the user
/// cancelled the picker.
#[tauri::command]
pub(crate) async fn import_choose_file(app: AppHandle) -> Result<Option<ImportChosen>, AppError> {
    use tauri_plugin_dialog::DialogExt;
    let picker = app.clone();
    let chosen = tauri::async_runtime::spawn_blocking(move || {
        // The system's file picker pauses the app.
        let state = picker.state::<AppState>();
        let _screen = state.away.system_screen();
        let dialog = picker.dialog().file().set_title("Choose a password export");
        // Android matches by file type, and exports are labelled
        // inconsistently there, so phones show every file.
        #[cfg(desktop)]
        let dialog = dialog
            .add_filter("Password exports", &["bbx", "csv"])
            .add_filter("All files", &["*"]);
        dialog.blocking_pick_file()
    })
    .await
    .map_err(|_| AppError::Internal)?;
    let Some(chosen) = chosen else {
        return Ok(None);
    };
    let reader = app.clone();
    blocking(app, move |state| {
        let Some(file) = read_export(&reader, chosen)? else {
            return Ok(None);
        };
        let can_delete = file.path.is_some();
        // A BlackBoxus export: its password is asked for next.
        if vault_core::export::is_export(&file.bytes) {
            let (_, preview) = crate::export::preview(&[]);
            state.with_session(|s| {
                s.pending_import = Some(crate::importer::PendingImport {
                    path: file.path,
                    items: Vec::new(),
                    preview: preview.clone(),
                    sealed: Some(file.bytes),
                });
                Ok(())
            })?;
            return Ok(Some(ImportChosen {
                file_name: file.name,
                preview,
                can_delete,
                needs_password: true,
            }));
        }
        let parsed = crate::import::parse(&file.bytes, now_ms())?;
        let preview = parsed.preview.clone();
        state.with_session(|s| {
            s.pending_import = Some(crate::importer::PendingImport {
                path: file.path,
                items: parsed.items,
                preview: parsed.preview,
                sealed: None,
            });
            Ok(())
        })?;
        Ok(Some(ImportChosen {
            file_name: file.name,
            preview,
            can_delete,
            needs_password: false,
        }))
    })
    .await
}

/// Starts importing the chosen file into a vault.
#[tauri::command]
pub(crate) fn import_start(
    app: AppHandle,
    state: State<'_, AppState>,
    vault: String,
) -> Result<(), AppError> {
    let id = vault_id(&vault)?;
    state.require_online()?;
    let items = state.with_session(|s| {
        let existing: Vec<vault_core::Item> = s
            .vaults
            .items(&id)?
            .into_iter()
            .map(|(_, item)| item)
            .collect();
        let pending = s.pending_import.as_mut().ok_or(AppError::NotFound)?;
        if pending.items.is_empty() {
            return Err(AppError::NotFound);
        }
        // Items exactly like ones already in the vault are left out.
        let skip = crate::import::already_there(&pending.items, &existing);
        let items: Vec<vault_core::Item> = std::mem::take(&mut pending.items)
            .into_iter()
            .zip(skip)
            .filter_map(|(item, skip)| (!skip).then_some(item))
            .collect();
        Ok(items)
    })?;
    if items.is_empty() {
        return Err(AppError::NothingNew);
    }
    state.import.start(items.len())?;
    crate::importer::spawn(app, id, items);
    Ok(())
}

/// How many of the chosen file's items are already in `vault`, exactly,
/// and would be left out.
#[tauri::command]
pub(crate) fn import_duplicates(
    state: State<'_, AppState>,
    vault: String,
) -> Result<usize, AppError> {
    let id = vault_id(&vault)?;
    state.read_session(|s| {
        let existing: Vec<vault_core::Item> = s
            .vaults
            .items(&id)?
            .into_iter()
            .map(|(_, item)| item)
            .collect();
        let pending = s.pending_import.as_ref().ok_or(AppError::NotFound)?;
        Ok(crate::import::already_there(&pending.items, &existing)
            .into_iter()
            .filter(|&skip| skip)
            .count())
    })
}

/// How the import is going.
#[tauri::command]
pub(crate) fn import_progress(state: State<'_, AppState>) -> crate::importer::Progress {
    state.import.get()
}

/// Forgets the chosen file. With `delete_file`, also deletes it, since it
/// holds passwords in plain text.
#[tauri::command]
pub(crate) fn import_finish(state: State<'_, AppState>, delete_file: bool) -> Result<(), AppError> {
    let pending = state.with_session(|s| Ok(s.pending_import.take()))?;
    if let (true, Some(path)) = (delete_file, pending.and_then(|p| p.path)) {
        std::fs::remove_file(path).map_err(|_| AppError::Storage)?;
    }
    Ok(())
}

fn account_of(state: &AppState) -> Result<vault_core::AccountId, AppError> {
    let record = state.account().ok_or(AppError::NoAccount)?;
    wire::unb64_array(&record.account_id)
        .map(vault_core::AccountId::from_bytes)
        .ok_or(AppError::Storage)
}

/// Turns on unlocking with Windows Hello. Windows asks the user to verify.
#[tauri::command]
pub(crate) async fn hello_enable(app: AppHandle) -> Result<AppStatus, AppError> {
    blocking(app, move |state| {
        // An offline unlock has no session to keep for Hello unlocks.
        state.require_online()?;
        // The prompt can take a while: the rest of the app keeps working,
        // and the prompt pausing the app doesn't count as leaving it.
        let unlocked = state.read_session(|s| Ok(s.unlocked.clone()))?;
        let _screen = state.away.system_screen();
        state.device.enable(&unlocked, crate::state::now_ms())?;
        Ok(state.status())
    })
    .await
}

/// Turns off unlocking with Windows Hello and deletes its key.
#[tauri::command]
pub(crate) fn hello_disable(state: State<'_, AppState>) -> Result<AppStatus, AppError> {
    state.device.disable(&account_of(&state)?)?;
    Ok(state.status())
}

/// Unlocks with Windows Hello. Windows asks the user to verify.
#[tauri::command]
pub(crate) async fn unlock_with_hello(app: AppHandle) -> Result<AppStatus, AppError> {
    blocking(app, move |state| {
        let account = account_of(state)?;
        let unlocked = {
            let _screen = state.away.system_screen();
            state.device.unlock(&account, crate::state::now_ms())?
        };
        state.set_unlocked(unlocked)?;
        Ok(state.status())
    })
    .await
}

/// Opens an item's website in the browser. Only http and https links open.
#[tauri::command]
pub(crate) fn open_website(
    app: AppHandle,
    state: State<'_, AppState>,
    vault: String,
    item: String,
) -> Result<(), AppError> {
    use tauri_plugin_opener::OpenerExt;
    let (id, item_id) = (vault_id(&vault)?, item_id(&item)?);
    let url = state
        .read_session(|s| Ok(items::website(&s.vaults.item(&id, &item_id)?)))?
        .ok_or(AppError::NotFound)?;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|_| AppError::Internal)
}

/// Checks the saved passwords for the Security tab: weak, reused and, if
/// asked, leaked. The passwords stay here; the window gets the findings.
#[tauri::command]
pub(crate) async fn password_health(
    app: AppHandle,
    check_leaks: bool,
) -> Result<crate::health::Health, AppError> {
    tauri::async_runtime::spawn_blocking(move || {
        crate::health::run(&app.state::<AppState>(), check_leaks)
    })
    .await
    .map_err(|_| AppError::Internal)?
}

/// The current one-time code from an item's code secret.
#[tauri::command]
pub(crate) fn totp_code(
    state: State<'_, AppState>,
    vault: String,
    item: String,
    index: usize,
    owner: Option<String>,
) -> Result<crate::totp::Code, AppError> {
    let (id, item_id) = (vault_id(&vault)?, item_id(&item)?);
    let totp = state.read_session(|s| {
        let item = vaults_of(s, owner.as_deref())?.item(&id, &item_id)?;
        crate::totp::Totp::parse(&items::field_at(&item, index)?.value)
    })?;
    totp.code_at(now_ms() / 1000)
}

/// This computer's settings.
#[tauri::command]
pub(crate) fn get_settings(state: State<'_, AppState>) -> crate::storage::Settings {
    state.storage.settings()
}

/// Changes this computer's settings.
#[tauri::command]
pub(crate) fn set_settings(
    state: State<'_, AppState>,
    settings: crate::storage::Settings,
) -> Result<crate::storage::Settings, AppError> {
    if !crate::storage::AUTO_LOCK_CHOICES.contains(&settings.auto_lock_minutes) {
        return Err(AppError::InvalidSetting);
    }
    // The browser bridge is changed only by `set_browser_integration`.
    let settings = crate::storage::Settings {
        browser_integration: state.storage.settings().browser_integration,
        ..settings
    };
    state.storage.save_settings(&settings)?;
    Ok(settings)
}

/// The Emergency Kit, shown again after the master password is entered.
/// The password is checked on this computer against the offline unlock
/// record, so this works offline too.
#[tauri::command]
pub(crate) async fn show_emergency_kit(
    app: AppHandle,
    password: Zeroizing<String>,
) -> Result<KitView, AppError> {
    blocking(app, move |state| {
        state.with_session(|_| Ok(()))?;
        let record = state.account().ok_or(AppError::NoAccount)?;
        let secret_key = state.storage.secret_key(&record)?;
        let offline = state.storage.load_offline()?.ok_or(AppError::Storage)?;
        offline
            .unlock(&password, &secret_key)
            .map_err(|e| match e {
                client_core::ClientError::WrongCredentials => AppError::WrongPassword,
                other => other.into(),
            })?;
        Ok(KitView {
            email: record.email,
            server: record.server,
            secret_key: secret_key.to_display_string(),
            recovery_key: None,
        })
    })
    .await
}

/// Signs out and removes the account from this computer: its Secret Key,
/// vault copies, offline record and Windows Hello unlock. The account and
/// its vaults stay on the server.
#[tauri::command]
pub(crate) async fn sign_out(app: AppHandle) -> Result<AppStatus, AppError> {
    let handle = app.clone();
    blocking(app, move |state| {
        let record = state.account().ok_or(AppError::NoAccount)?;
        // Best effort: end the session on the server too.
        if state.status().offline {
            // No session to end.
        } else if let Ok(request) = state.with_session(|s| Ok(s.unlocked.session.logout_request()))
        {
            let _ = crate::http::Transport::send(&state.transport, &request);
        }
        if let Some(account) = wire::unb64_array(&record.account_id) {
            state
                .device
                .disable(&vault_core::AccountId::from_bytes(account))?;
        }
        state.storage.remove_account(&record)?;
        // Paired browsers belonged to that account's use of this computer.
        let _ = app_bridge_forget(&handle);
        state.forget_account();
        Ok(state.status())
    })
    .await
}

fn role_from(text: &str) -> Result<vault_core::log::Role, AppError> {
    match text {
        "owner" => Ok(vault_core::log::Role::Owner),
        "editor" => Ok(vault_core::log::Role::Editor),
        "viewer" => Ok(vault_core::log::Role::Viewer),
        _ => Err(AppError::Internal),
    }
}

/// Changes a member's role.
#[tauri::command]
pub(crate) async fn change_member_role(
    app: AppHandle,
    vault: String,
    sharing_id: String,
    role: String,
) -> Result<Vec<MemberView>, AppError> {
    let id = vault_id(&vault)?;
    let role = role_from(&role)?;
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|s| {
            s.vaults
                .change_role(&state.transport, &s.unlocked, id, &sharing_id, role)?;
            s.vaults.members(&id, &s.unlocked)
        })
    })
    .await
}

/// Removes a member and replaces the vault key.
#[tauri::command]
pub(crate) async fn remove_member(
    app: AppHandle,
    vault: String,
    sharing_id: String,
) -> Result<Vec<MemberView>, AppError> {
    let id = vault_id(&vault)?;
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|s| {
            s.vaults
                .remove_member(&state.transport, &s.unlocked, id, &sharing_id)?;
            s.vaults.members(&id, &s.unlocked)
        })
    })
    .await
}

/// Leaves a vault shared with this account.
#[tauri::command]
pub(crate) async fn leave_vault(app: AppHandle, vault: String) -> Result<(), AppError> {
    let id = vault_id(&vault)?;
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|s| s.vaults.leave(&state.transport, &s.unlocked, id))
    })
    .await
}

/// Whether the account has a recovery key. Needs a connection.
#[tauri::command]
pub(crate) async fn recovery_key_status(app: AppHandle) -> Result<bool, AppError> {
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|s| flows::recovery_key_set(&state.transport, &s.unlocked))
    })
    .await
}

/// Creates a recovery key, replacing any earlier one, after the master
/// password is entered. Returns a new Emergency Kit holding it, shown once.
#[tauri::command]
pub(crate) async fn create_recovery_key(
    app: AppHandle,
    password: Zeroizing<String>,
) -> Result<KitView, AppError> {
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|_| Ok(()))?;
        if password.is_empty() {
            return Err(AppError::EmptyPassword);
        }
        let record = state.account().ok_or(AppError::NoAccount)?;
        let secret_key = state.storage.secret_key(&record)?;
        let key = flows::set_recovery_key(
            &state.transport,
            &server()?,
            &record.email,
            &secret_key,
            &password,
            &account_id_of(&record)?,
        )?;
        Ok(KitView {
            email: record.email,
            server: record.server,
            secret_key: secret_key.to_display_string(),
            recovery_key: Some(key.to_display_string()),
        })
    })
    .await
}

/// Removes the recovery key, after the master password is entered.
#[tauri::command]
pub(crate) async fn remove_recovery_key(
    app: AppHandle,
    password: Zeroizing<String>,
) -> Result<(), AppError> {
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|_| Ok(()))?;
        if password.is_empty() {
            return Err(AppError::EmptyPassword);
        }
        let record = state.account().ok_or(AppError::NoAccount)?;
        let secret_key = state.storage.secret_key(&record)?;
        flows::delete_recovery_key(
            &state.transport,
            &server()?,
            &record.email,
            &secret_key,
            &password,
            &account_id_of(&record)?,
        )
    })
    .await
}

/// Changes the master password after the current one is entered. The
/// account carries on with the session used for the change, since the
/// server ends every other one; the offline unlock record and the Windows
/// Hello session are replaced too.
#[tauri::command]
pub(crate) async fn change_password(
    app: AppHandle,
    current: Zeroizing<String>,
    password: Zeroizing<String>,
    confirm: Zeroizing<String>,
) -> Result<(), AppError> {
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|_| Ok(()))?;
        if current.is_empty() {
            return Err(AppError::EmptyPassword);
        }
        let record = state.account().ok_or(AppError::NoAccount)?;
        if *password == *current {
            return Err(AppError::SamePassword);
        }
        check_new_password(&record.email, &password, &confirm)?;
        let secret_key = state.storage.secret_key(&record)?;
        let (unlocked, offline) = flows::change_password(
            &state.transport,
            &server()?,
            &record.email,
            &secret_key,
            &current,
            &password,
            &account_id_of(&record)?,
        )?;
        state.storage.save_offline(&offline)?;
        state
            .device
            .password_used(&unlocked, crate::state::now_ms())?;
        state.with_session(|s| {
            s.unlocked = std::sync::Arc::new(unlocked);
            Ok(())
        })
    })
    .await
}

/// Trusted contacts: the one this account named, and people who named it.
#[tauri::command]
pub(crate) async fn emergency_status(
    app: AppHandle,
) -> Result<crate::trusted::EmergencyView, AppError> {
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|s| {
            let status = crate::trusted::emergency_status(&state.transport, &s.unlocked)?;
            Ok(crate::trusted::EmergencyView::from(&status))
        })
    })
    .await
}

/// Looks someone up to be the trusted contact, for comparing the safety
/// number.
#[tauri::command]
pub(crate) async fn look_up_contact(
    app: AppHandle,
    sharing_id: String,
) -> Result<LookedUp, AppError> {
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|s| {
            s.vaults
                .look_up_contact(&state.transport, &s.unlocked, &sharing_id)
        })
    })
    .await
}

/// Names the person just looked up as the trusted contact, after the
/// master password is entered.
#[tauri::command]
pub(crate) async fn set_trusted_contact(
    app: AppHandle,
    sharing_id: String,
    wait_days: u16,
    password: Zeroizing<String>,
) -> Result<crate::trusted::EmergencyView, AppError> {
    blocking(app, move |state| {
        state.require_online()?;
        if password.is_empty() {
            return Err(AppError::EmptyPassword);
        }
        if !(1..=90).contains(&wait_days) {
            return Err(AppError::EmergencyUnavailable);
        }
        let record = state.account().ok_or(AppError::NoAccount)?;
        let secret_key = state.storage.secret_key(&record)?;
        let contact = state.with_session(|s| s.vaults.take_contact(&sharing_id))?;
        flows::set_trusted_contact(
            &state.transport,
            &server()?,
            &record.email,
            &secret_key,
            &password,
            &account_id_of(&record)?,
            &contact,
            wait_days,
        )?;
        state.with_session(|s| {
            let status = crate::trusted::emergency_status(&state.transport, &s.unlocked)?;
            Ok(crate::trusted::EmergencyView::from(&status))
        })
    })
    .await
}

/// Removes the trusted contact, ending any access they were given.
#[tauri::command]
pub(crate) async fn remove_trusted_contact(
    app: AppHandle,
) -> Result<crate::trusted::EmergencyView, AppError> {
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|s| {
            crate::trusted::remove_contact(&state.transport, &s.unlocked)?;
            let status = crate::trusted::emergency_status(&state.transport, &s.unlocked)?;
            Ok(crate::trusted::EmergencyView::from(&status))
        })
    })
    .await
}

/// Denies the trusted contact's pending request.
#[tauri::command]
pub(crate) async fn deny_emergency(
    app: AppHandle,
    sharing_id: String,
) -> Result<crate::trusted::EmergencyView, AppError> {
    blocking(app, move |state| {
        state.require_online()?;
        let contact = crate::sharing_id::decode(&sharing_id)?;
        state.with_session(|s| {
            crate::trusted::deny(&state.transport, &s.unlocked, &contact)?;
            let status = crate::trusted::emergency_status(&state.transport, &s.unlocked)?;
            Ok(crate::trusted::EmergencyView::from(&status))
        })
    })
    .await
}

/// Asks for access to the account of someone who named this account as
/// their trusted contact.
#[tauri::command]
pub(crate) async fn request_emergency(
    app: AppHandle,
    sharing_id: String,
) -> Result<crate::trusted::EmergencyView, AppError> {
    blocking(app, move |state| {
        state.require_online()?;
        let owner = crate::sharing_id::decode(&sharing_id)?;
        state.with_session(|s| {
            crate::trusted::request(&state.transport, &s.unlocked, &owner)?;
            let status = crate::trusted::emergency_status(&state.transport, &s.unlocked)?;
            Ok(crate::trusted::EmergencyView::from(&status))
        })
    })
    .await
}

/// Opens, read-only, the account of someone who named this account as
/// their trusted contact, once the waiting period is over. Returns their
/// vaults.
#[tauri::command]
pub(crate) async fn open_emergency(
    app: AppHandle,
    sharing_id: String,
) -> Result<Vec<VaultSummary>, AppError> {
    blocking(app, move |state| {
        state.require_online()?;
        let owner = crate::sharing_id::decode(&sharing_id)?;
        let dir = state.emergency_dir();
        let log_key = crate::vaults::log_key()?;
        state.with_session(|s| {
            s.emergency = None;
            let access = crate::trusted::open(
                &state.transport,
                &s.unlocked,
                &mut s.vaults,
                &owner,
                &dir,
                log_key,
            )?;
            let mut list = access.vaults.summaries(&access.unlocked);
            for v in &mut list {
                v.writable = false;
            }
            s.emergency = Some(access);
            Ok(list)
        })
    })
    .await
}

/// Closes an account opened as its trusted contact, ending the read-only
/// session and deleting its vault copies from this computer.
#[tauri::command]
pub(crate) async fn close_emergency(app: AppHandle) -> Result<(), AppError> {
    blocking(app, move |state| {
        let closed = state.with_session(|s| Ok(s.emergency.take()))?;
        if let Some(access) = closed {
            // Best effort: the session expires within a day anyway.
            let _ = crate::http::Transport::send(
                &state.transport,
                &access.unlocked.session.logout_request(),
            );
        }
        state.remove_emergency_copies();
        Ok(())
    })
    .await
}

/// Sets a new master password with the recovery key, signs in, and makes a
/// new recovery key, because the old one has been typed here. Works with
/// no account on this computer, or for the account already set up on it,
/// whose Secret Key is then kept. Returns a new Emergency Kit to save.
#[tauri::command]
pub(crate) async fn recover_account(
    app: AppHandle,
    email: String,
    recovery_key: Zeroizing<String>,
    password: Zeroizing<String>,
    confirm: Zeroizing<String>,
) -> Result<Created, AppError> {
    blocking(app, move |state| {
        let identity = ClientIdentity::new(&email)?;
        let existing = state.account();
        if existing
            .as_ref()
            .is_some_and(|r| r.email != identity.as_str())
        {
            return Err(AppError::AccountExists);
        }
        check_new_password(&email, &password, &confirm)?;
        let kept = existing
            .as_ref()
            .and_then(|r| state.storage.secret_key(r).ok());
        let server = server()?;
        let account = flows::recover(
            &state.transport,
            &server,
            &email,
            &recovery_key,
            &password,
            kept,
        )?;
        let (unlocked, offline) = flows::sign_in(
            &state.transport,
            &server,
            &email,
            &account.secret_key,
            &password,
        )?;
        if unlocked.session.account_id() != &account.account_id {
            return Err(AppError::Tampered);
        }
        // The old key was typed on this computer, so replace it at once,
        // while the session is fresh.
        let (key, request) = client_core::recovery::new_recovery_key(&unlocked, identity.as_str())?;
        client_core::vaults::written(&crate::http::Transport::send(&state.transport, &request)?)?;

        // Windows Hello unlock held the old session, which has ended.
        state.device.disable(&account.account_id)?;
        let record = AccountRecord::new(&identity, &account.account_id, ORIGIN);
        state.storage.save_account(&record, &account.secret_key)?;
        state.storage.save_offline(&offline)?;
        state.set_account(record, unlocked)?;
        let kit = account.emergency_kit();
        Ok(Created {
            status: state.status(),
            kit: KitView {
                email: kit.email,
                server: kit.server,
                secret_key: kit.secret_key,
                recovery_key: Some(key.to_display_string()),
            },
        })
    })
    .await
}

/// What [`create_vault`] returns.
#[derive(Debug, Serialize)]
pub(crate) struct NewVault {
    id: String,
    vaults: Vec<VaultSummary>,
}

/// Creates a vault with a name. Needs a connection.
#[tauri::command]
pub(crate) async fn create_vault(app: AppHandle, name: String) -> Result<NewVault, AppError> {
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|s| {
            let id = s.vaults.create(&state.transport, &s.unlocked, &name)?;
            Ok(NewVault {
                id: wire::b64(id.as_bytes()),
                vaults: s.vaults.summaries(&s.unlocked),
            })
        })
    })
    .await
}

/// Renames a vault. Needs a connection.
#[tauri::command]
pub(crate) async fn rename_vault(
    app: AppHandle,
    vault: String,
    name: String,
) -> Result<Vec<VaultSummary>, AppError> {
    let id = vault_id(&vault)?;
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|s| {
            s.vaults.rename(&state.transport, &s.unlocked, id, &name)?;
            Ok(s.vaults.summaries(&s.unlocked))
        })
    })
    .await
}

fn app_bridge_forget(app: &AppHandle) -> Result<(), AppError> {
    app.state::<crate::browser::Bridge>().forget_all()
}

/// The browser bridge, for Settings.
#[derive(Debug, Serialize)]
pub(crate) struct BrowserStatus {
    enabled: bool,
    pairings: Vec<crate::browser::PairingView>,
    pending: Option<crate::browser::PairingRequest>,
}

fn browser_view(app: &AppHandle) -> BrowserStatus {
    let bridge = app.state::<crate::browser::Bridge>();
    BrowserStatus {
        enabled: bridge.enabled(),
        pairings: bridge.pairings(),
        pending: bridge.pending_request(),
    }
}

/// Whether the browser extension may ask for logins, and which browsers
/// are paired.
#[tauri::command]
pub(crate) fn browser_status(app: AppHandle) -> BrowserStatus {
    browser_view(&app)
}

/// Turns the browser bridge on or off. Off forgets every paired browser.
#[tauri::command]
pub(crate) async fn set_browser_integration(
    app: AppHandle,
    enabled: bool,
) -> Result<BrowserStatus, AppError> {
    let handle = app.clone();
    blocking(app, move |state| {
        handle
            .state::<crate::browser::Bridge>()
            .set_enabled(&handle, enabled)?;
        let settings = crate::storage::Settings {
            browser_integration: enabled,
            ..state.storage.settings()
        };
        state.storage.save_settings(&settings)?;
        Ok(browser_view(&handle))
    })
    .await
}

/// The user's answer to a browser asking to pair.
#[tauri::command]
pub(crate) fn answer_browser_pairing(app: AppHandle, allow: bool) {
    app.state::<crate::browser::Bridge>().answer(allow);
}

/// Forgets one paired browser.
#[tauri::command]
pub(crate) fn forget_browser(app: AppHandle, id: String) -> Result<BrowserStatus, AppError> {
    app.state::<crate::browser::Bridge>().forget(&id)?;
    Ok(browser_view(&app))
}
