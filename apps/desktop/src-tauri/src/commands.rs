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
        if *password != *confirm {
            return Err(AppError::PasswordsDiffer);
        }
        let words: Vec<&str> = email.split(['@', '.', '_', '-', '+']).collect();
        let rating = strength::rate(&password, &words);
        if rating.chars < rating.min_chars {
            return Err(AppError::PasswordTooShort(rating.min_chars));
        }
        if !rating.acceptable {
            return Err(AppError::WeakPassword);
        }
        let server = server()?;
        let (unlocked, secret_key, kit) =
            flows::create_account(&state.transport, &server, &email, &password)?;
        let identity = ClientIdentity::new(&email)?;
        let record = AccountRecord::new(&identity, unlocked.session.account_id(), ORIGIN);
        state.storage.save_account(&record, &secret_key)?;
        state.set_account(record, unlocked)?;
        Ok(Created {
            status: state.status(),
            kit: KitView {
                email: kit.email,
                server: kit.server,
                secret_key: kit.secret_key,
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
        let unlocked =
            flows::sign_in(&state.transport, &server()?, &email, &secret_key, &password)?;
        let record = AccountRecord::new(&identity, unlocked.session.account_id(), ORIGIN);
        state.storage.save_account(&record, &secret_key)?;
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
        let unlocked = flows::sign_in(
            &state.transport,
            &server()?,
            &record.email,
            &secret_key,
            &password,
        )
        .map_err(|e| match e {
            // Only the password can be wrong: the email and Secret Key
            // were stored when this computer was set up.
            AppError::WrongCredentials => AppError::WrongPassword,
            other => other,
        })?;
        if wire::b64(unlocked.session.account_id().as_bytes()) != record.account_id {
            return Err(AppError::Tampered);
        }
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

/// Syncs every vault with the server and lists them.
#[tauri::command]
pub(crate) async fn sync_vaults(app: AppHandle) -> Result<Vec<VaultSummary>, AppError> {
    blocking(app, move |state| {
        state.with_session(|s| {
            s.vaults.sync(&state.transport, &s.unlocked)?;
            Ok(s.vaults.summaries(&s.unlocked))
        })
    })
    .await
}

/// Lists a vault's items, sorted by title. Carries no secrets.
#[tauri::command]
pub(crate) fn list_items(
    state: State<'_, AppState>,
    vault: String,
) -> Result<Vec<ItemSummary>, AppError> {
    let id = vault_id(&vault)?;
    state.with_session(|s| {
        let mut list: Vec<ItemSummary> = s
            .vaults
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
) -> Result<ItemView, AppError> {
    let (id, item_id) = (vault_id(&vault)?, item_id(&item)?);
    state.with_session(|s| Ok(items::view(&item_id, &s.vaults.item(&id, &item_id)?)))
}

/// The value of one concealed field, when the user asks to see it.
#[tauri::command]
pub(crate) fn reveal_field(
    state: State<'_, AppState>,
    vault: String,
    item: String,
    index: usize,
) -> Result<Zeroizing<String>, AppError> {
    let (id, item_id) = (vault_id(&vault)?, item_id(&item)?);
    state.with_session(|s| {
        let item = s.vaults.item(&id, &item_id)?;
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
) -> Result<(), AppError> {
    let (id, item_id) = (vault_id(&vault)?, item_id(&item)?);
    let value = state.with_session(|s| {
        let item = s.vaults.item(&id, &item_id)?;
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
        "editor" => vault_core::log::Role::Editor,
        "viewer" => vault_core::log::Role::Viewer,
        _ => return Err(AppError::Internal),
    };
    blocking(app, move |state| {
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
