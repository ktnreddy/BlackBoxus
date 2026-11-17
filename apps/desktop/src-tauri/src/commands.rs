//! The commands the window can call. Each is also listed in `build.rs`
//! and allowed in `capabilities/main.json`; anything else is refused.
//!
//! Secrets arrive as [`Zeroizing`] strings, so the Rust copy is wiped as
//! soon as a command returns.

use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use vault_core::{ClientIdentity, ItemId, SecretKey, ServerIdentity, VaultId};
use zeroize::Zeroizing;

use crate::error::AppError;
use crate::flows;
use crate::generator::{self, Generated, Options};
use crate::http::ORIGIN;
use crate::items::{self, ItemInput, ItemSummary, ItemView};
use crate::state::{AppState, AppStatus};
use crate::storage::AccountRecord;
use crate::strength::{self, Rating};
use crate::vaults::{LookedUp, MemberView, VaultSummary};

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

/// Checks a new master password is typed the same twice and is long and
/// strong enough.
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
}

/// Syncs every vault with the server and lists them. Without a connection,
/// lists this computer's copies instead, read-only.
#[tauri::command]
pub(crate) async fn sync_vaults(app: AppHandle) -> Result<Synced, AppError> {
    blocking(app, move |state| {
        let offline =
            state.with_session(|s| match s.vaults.sync(&state.transport, &s.unlocked) {
                Ok(()) => Ok(false),
                Err(AppError::Offline) => {
                    s.vaults.load_local(&s.unlocked);
                    Ok(true)
                }
                Err(e) => Err(e),
            })?;
        state.set_offline(offline);
        state.with_session(|s| {
            let unknown_keys = if offline {
                false
            } else {
                match s
                    .vaults
                    .check_own_keys(&state.transport, &s.unlocked, now_ms())
                {
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
                match crate::trusted::emergency_status(&state.transport, &s.unlocked) {
                    Ok(status) => crate::trusted::EmergencyView::from(&status)
                        .contact
                        .filter(|c| c.stage == "requested"),
                    Err(AppError::Offline) => None,
                    Err(e) => return Err(e),
                }
            };
            Ok(Synced {
                vaults: s.vaults.summaries(&s.unlocked),
                offline,
                unknown_keys,
                emergency_request,
            })
        })
    })
    .await
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
    state.with_session(|s| {
        let mut list: Vec<ItemSummary> = vaults_of(s, owner.as_deref())?
            .items(&id)?
            .iter()
            .map(|(item_id, item)| items::summary(item_id, item))
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
    state.with_session(|s| {
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
    state.with_session(|s| {
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
    let value = state.with_session(|s| {
        let item = vaults_of(s, owner.as_deref())?.item(&id, &item_id)?;
        Ok(items::field_at(&item, index)?.value.clone())
    })?;
    state.clipboard.copy(value)
}

/// Adds an item (no `item`) or saves changes to one. Returns its ID.
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
        state.require_online()?;
        state.with_session(|s| {
            let created_ms = match &existing {
                Some(item_id) => s.vaults.item(&id, item_id)?.created_ms,
                None => now_ms(),
            };
            let built = items::build(&input, created_ms, now_ms())?;
            let saved = s
                .vaults
                .put(&state.transport, &s.unlocked, id, existing, &built)?;
            Ok(wire::b64(saved.as_bytes()))
        })
    })
    .await
}

/// Deletes an item.
#[tauri::command]
pub(crate) async fn delete_item(
    app: AppHandle,
    vault: String,
    item: String,
) -> Result<(), AppError> {
    let (id, item_id) = (vault_id(&vault)?, item_id(&item)?);
    blocking(app, move |state| {
        state.require_online()?;
        state.with_session(|s| s.vaults.delete(&state.transport, &s.unlocked, id, &item_id))
    })
    .await
}

/// Generates a random password.
#[tauri::command]
pub(crate) fn generate_password(options: Options) -> Result<Generated, AppError> {
    generator::generate(&options)
}

/// This account's sharing ID, for others to share vaults with it.
#[tauri::command]
pub(crate) fn my_sharing_id(state: State<'_, AppState>) -> Result<String, AppError> {
    state.with_session(|s| Ok(crate::sharing_id::encode(s.unlocked.session.account_id())))
}

/// The members of a vault.
#[tauri::command]
pub(crate) fn vault_members(
    state: State<'_, AppState>,
    vault: String,
) -> Result<Vec<MemberView>, AppError> {
    let id = vault_id(&vault)?;
    state.with_session(|s| s.vaults.members(&id, &s.unlocked))
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
}

/// Opens the system file picker, reads the chosen CSV export here in Rust
/// and keeps its items until the user confirms. Returns `None` if the user
/// cancelled the picker.
#[tauri::command]
pub(crate) async fn import_choose_file(app: AppHandle) -> Result<Option<ImportChosen>, AppError> {
    use tauri_plugin_dialog::DialogExt;
    let picker = app.clone();
    let chosen = tauri::async_runtime::spawn_blocking(move || {
        picker
            .dialog()
            .file()
            .set_title("Choose a password export")
            .add_filter("CSV export", &["csv"])
            .blocking_pick_file()
    })
    .await
    .map_err(|_| AppError::Internal)?;
    let Some(path) = chosen.and_then(|f| f.into_path().ok()) else {
        return Ok(None);
    };
    blocking(app, move |state| {
        let size = std::fs::metadata(&path)
            .map_err(|_| AppError::ImportUnreadable)?
            .len();
        if size > crate::import::MAX_FILE_BYTES {
            return Err(AppError::ImportTooLarge);
        }
        let bytes = Zeroizing::new(std::fs::read(&path).map_err(|_| AppError::ImportUnreadable)?);
        let parsed = crate::import::parse(&bytes, now_ms())?;
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let preview = parsed.preview.clone();
        state.with_session(|s| {
            s.pending_import = Some(crate::importer::PendingImport {
                path,
                items: parsed.items,
                preview: parsed.preview,
            });
            Ok(())
        })?;
        Ok(Some(ImportChosen { file_name, preview }))
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
        let pending = s.pending_import.as_mut().ok_or(AppError::NotFound)?;
        Ok(std::mem::take(&mut pending.items))
    })?;
    if items.is_empty() {
        return Err(AppError::NotFound);
    }
    state.import.start(items.len())?;
    crate::importer::spawn(app, id, items);
    Ok(())
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
    if let (true, Some(p)) = (delete_file, pending) {
        std::fs::remove_file(&p.path).map_err(|_| AppError::Storage)?;
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
        state.with_session(|s| state.device.enable(&s.unlocked, crate::state::now_ms()))?;
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
        let unlocked = state.device.unlock(&account, crate::state::now_ms())?;
        state.set_unlocked(unlocked)?;
        Ok(state.status())
    })
    .await
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
    let totp = state.with_session(|s| {
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
        check_new_password(&record.email, &password, &confirm)?;
        if *password == *current {
            return Err(AppError::SamePassword);
        }
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
            s.unlocked = unlocked;
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
