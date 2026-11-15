//! The commands the window can call. Each is also listed in `build.rs`
//! and allowed in `capabilities/main.json`; anything else is refused.
//!
//! Secrets arrive as [`Zeroizing`] strings, so the Rust copy is wiped as
//! soon as a command returns.

use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use vault_core::{ClientIdentity, SecretKey, ServerIdentity};
use zeroize::Zeroizing;

use crate::error::AppError;
use crate::flows;
use crate::http::ORIGIN;
use crate::state::{AppState, AppStatus};
use crate::storage::AccountRecord;
use crate::strength::{self, Rating};

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
        state.set_account(record, unlocked);
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
        state.set_account(record, unlocked);
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
        state.set_unlocked(unlocked);
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
