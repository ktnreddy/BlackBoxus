//! What the app holds in memory while it runs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use client_core::login::Unlocked;
use serde::Serialize;

use crate::clipboard::SecretClipboard;
use crate::device_unlock::{DeviceUnlock, HelloStatus};
use crate::error::AppError;
use crate::http::{Https, ORIGIN};
use crate::importer::{ImportStatus, PendingImport};
use crate::storage::{AccountRecord, Storage};
use crate::vaults::{VaultFiles, Vaults, log_key};

/// An unlocked account: its session, key set and vaults. Dropping it
/// erases the keys and decrypted vault keys.
pub struct Session {
    /// The signed-in session and key set.
    pub unlocked: Unlocked,
    /// The account's vaults.
    pub vaults: Vaults,
    /// A file chosen for import, until imported or cancelled.
    pub pending_import: Option<PendingImport>,
    /// Another account opened as its trusted contact, read-only.
    pub emergency: Option<crate::trusted::EmergencyAccess>,
    /// The connection listening for the server's hints.
    pub live: Option<crate::live::Live>,
}

/// The account set up on this computer, as shown in the window.
#[derive(Debug, Clone, Serialize)]
pub struct AccountView {
    /// The account's email address.
    pub email: String,
}

/// What the window is told about the app.
#[derive(Debug, Clone, Serialize)]
pub struct AppStatus {
    /// The app's version.
    pub version: &'static str,
    /// The server, without `https://`.
    pub server: &'static str,
    /// The account on this computer, if one has been set up.
    pub account: Option<AccountView>,
    /// Whether the vaults are locked.
    pub locked: bool,
    /// Whether the vaults are shown read-only from this computer's copy.
    pub offline: bool,
    /// Windows Hello unlock.
    pub hello: HelloStatus,
}

#[derive(Default)]
struct Inner {
    account: Option<AccountRecord>,
    /// The session while unlocked.
    session: Option<Session>,
    /// The vaults are shown from this computer's copy because the server
    /// could not be reached; they are read-only until a sync succeeds.
    offline: bool,
}

/// Shared app state. Keys live here, never in the window.
pub struct AppState {
    inner: Mutex<Inner>,
    busy: AtomicBool,
    /// Where the account record and Secret Key are kept.
    pub storage: Storage,
    /// How requests reach the server.
    pub transport: Https,
    /// Copies secrets and clears them again.
    pub clipboard: SecretClipboard,
    /// Progress of the running import.
    pub import: ImportStatus,
    /// Windows Hello unlock.
    pub device: DeviceUnlock,
}

impl core::fmt::Debug for AppState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}

/// Held while an account flow runs, so two cannot overlap.
#[derive(Debug)]
pub struct BusyGuard<'a>(&'a AtomicBool);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl AppState {
    /// State for an app keeping its files in `storage`. A damaged account
    /// record is treated as no account, so the user can sign in again.
    pub fn new(storage: Storage, transport: Https, device: DeviceUnlock) -> Self {
        let account = storage.load_account().ok().flatten();
        Self {
            inner: Mutex::new(Inner {
                account,
                session: None,
                offline: false,
            }),
            busy: AtomicBool::new(false),
            storage,
            transport,
            clipboard: SecretClipboard::default(),
            import: ImportStatus::default(),
            device,
        }
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        // A panic while holding the lock cannot leave this state half
        // written, so a poisoned lock is safe to keep using.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Marks an account flow as running.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Busy`] if one already is.
    pub fn begin(&self) -> Result<BusyGuard<'_>, AppError> {
        self.busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| BusyGuard(&self.busy))
            .map_err(|_| AppError::Busy)
    }

    /// The status to show in the window.
    pub fn status(&self) -> AppStatus {
        let inner = self.inner();
        let account_id = inner
            .account
            .as_ref()
            .and_then(|a| wire::unb64_array(&a.account_id))
            .map(vault_core::AccountId::from_bytes);
        AppStatus {
            version: env!("CARGO_PKG_VERSION"),
            server: ORIGIN.trim_start_matches("https://"),
            account: inner.account.as_ref().map(|a| AccountView {
                email: a.email.clone(),
            }),
            locked: inner.session.is_none(),
            offline: inner.offline,
            hello: self.device.status(account_id.as_ref(), now_ms()),
        }
    }

    /// The account record, if there is one.
    pub fn account(&self) -> Option<AccountRecord> {
        self.inner().account.clone()
    }

    fn session_for(&self, unlocked: Unlocked) -> Result<Session, AppError> {
        Ok(Session {
            unlocked,
            vaults: Vaults::new(VaultFiles::new(self.storage.vault_dir()), log_key()?),
            pending_import: None,
            emergency: None,
            live: None,
        })
    }

    /// Records a newly set-up account and unlocks it.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotConfigured`] if this build has no log key.
    pub fn set_account(&self, account: AccountRecord, unlocked: Unlocked) -> Result<(), AppError> {
        let session = self.session_for(unlocked)?;
        let mut inner = self.inner();
        inner.account = Some(account);
        inner.session = Some(session);
        Ok(())
    }

    /// Unlocks with a signed-in session.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotConfigured`] if this build has no log key.
    pub fn set_unlocked(&self, unlocked: Unlocked) -> Result<(), AppError> {
        let session = self.session_for(unlocked)?;
        let mut inner = self.inner();
        inner.session = Some(session);
        inner.offline = false;
        Ok(())
    }

    /// Records whether the last sync reached the server.
    pub fn set_offline(&self, offline: bool) {
        self.inner().offline = offline;
    }

    /// Fails with [`AppError::ReadOnlyOffline`] while offline, before any
    /// change is attempted.
    ///
    /// # Errors
    ///
    /// As described.
    pub fn require_online(&self) -> Result<(), AppError> {
        if self.inner().offline {
            Err(AppError::ReadOnlyOffline)
        } else {
            Ok(())
        }
    }

    /// Runs `f` with the unlocked session.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Locked`] if the vaults are locked, or `f`'s error.
    pub fn with_session<T>(
        &self,
        f: impl FnOnce(&mut Session) -> Result<T, AppError>,
    ) -> Result<T, AppError> {
        let mut inner = self.inner();
        let session = inner.session.as_mut().ok_or(AppError::Locked)?;
        f(session)
    }

    /// Forgets the account after it was removed from this computer.
    pub fn forget_account(&self) {
        let session = {
            let mut inner = self.inner();
            inner.offline = false;
            inner.account = None;
            inner.session.take()
        };
        drop(session);
        self.clipboard.clear_now();
    }

    /// Locks the vaults, erasing the keys from memory and any secret left
    /// on the clipboard.
    pub fn lock(&self) {
        let session = {
            let mut inner = self.inner();
            inner.offline = false;
            inner.session.take()
        };
        drop(session);
        self.clipboard.clear_now();
        self.remove_emergency_copies();
    }

    /// Where the vaults of an account opened as a trusted contact are kept
    /// while open.
    pub fn emergency_dir(&self) -> std::path::PathBuf {
        self.storage.vault_dir().join("emergency")
    }

    /// Deletes the copies of another account's vaults opened as its
    /// trusted contact. They are sealed with that account's keys, but
    /// there is no reason to keep them once closed.
    pub fn remove_emergency_copies(&self) {
        let _ = std::fs::remove_dir_all(self.emergency_dir());
    }
}

/// The time, Unix milliseconds.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}
