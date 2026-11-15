//! What the app holds in memory while it runs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use client_core::login::Unlocked;
use serde::Serialize;

use crate::error::AppError;
use crate::http::{Https, ORIGIN};
use crate::storage::{AccountRecord, Storage};

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
}

#[derive(Default)]
struct Inner {
    account: Option<AccountRecord>,
    /// The signed-in session and key set while unlocked. Dropping it
    /// erases the keys.
    unlocked: Option<Unlocked>,
}

/// Shared app state. Keys live here, never in the window.
pub struct AppState {
    inner: Mutex<Inner>,
    busy: AtomicBool,
    /// Where the account record and Secret Key are kept.
    pub storage: Storage,
    /// How requests reach the server.
    pub transport: Https,
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
    pub fn new(storage: Storage, transport: Https) -> Self {
        let account = storage.load_account().ok().flatten();
        Self {
            inner: Mutex::new(Inner {
                account,
                unlocked: None,
            }),
            busy: AtomicBool::new(false),
            storage,
            transport,
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
        AppStatus {
            version: env!("CARGO_PKG_VERSION"),
            server: ORIGIN.trim_start_matches("https://"),
            account: inner.account.as_ref().map(|a| AccountView {
                email: a.email.clone(),
            }),
            locked: inner.unlocked.is_none(),
        }
    }

    /// The account record, if there is one.
    pub fn account(&self) -> Option<AccountRecord> {
        self.inner().account.clone()
    }

    /// Records a newly set-up account and unlocks it.
    pub fn set_account(&self, account: AccountRecord, unlocked: Unlocked) {
        let mut inner = self.inner();
        inner.account = Some(account);
        inner.unlocked = Some(unlocked);
    }

    /// Unlocks with a signed-in session.
    pub fn set_unlocked(&self, unlocked: Unlocked) {
        self.inner().unlocked = Some(unlocked);
    }

    /// Locks the vaults, erasing the keys from memory.
    pub fn lock(&self) {
        let unlocked = self.inner().unlocked.take();
        drop(unlocked);
    }
}
