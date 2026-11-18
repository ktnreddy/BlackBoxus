//! Copies secrets to the phone's clipboard and clears them again.
//!
//! Copies are marked sensitive, so Android shows dots instead of the text
//! in its clipboard preview. After [`CLEAR_AFTER`], or when the vaults are
//! locked, the clipboard is cleared unless it visibly holds something the
//! user copied since. Android only lets apps read the clipboard while in
//! the foreground; when it can't be read, it is cleared anyway, since a
//! leftover secret is worse than a lost copy.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use tauri::{AppHandle, Wry};
use tauri_plugin_clipboard_manager::ClipboardExt;
use zeroize::Zeroizing;

use crate::error::AppError;

/// How long a copied secret stays on the clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(30);

/// The app, set once at start so the clipboard plugin can be reached.
static APP: OnceLock<AppHandle<Wry>> = OnceLock::new();

/// Gives the clipboard the running app. Called once, at start.
pub fn attach(app: AppHandle<Wry>) {
    // A second call keeps the first handle, which is the same app.
    let _ = APP.set(app);
}

fn clear_if_ours(last: &mut Option<Zeroizing<String>>) {
    let Some(secret) = last.take() else {
        return;
    };
    let Some(app) = APP.get() else {
        return;
    };
    let clipboard = app.clipboard();
    let replaced = clipboard
        .read_text()
        .map(|t| Zeroizing::new(t) != secret)
        .unwrap_or(false);
    if !replaced {
        // Best effort: nothing more can be done if this fails.
        let _ = clipboard.clear();
    }
}

/// The app's clipboard for secrets.
#[derive(Default)]
pub struct SecretClipboard {
    last: Arc<Mutex<Option<Zeroizing<String>>>>,
    generation: Arc<AtomicU64>,
}

impl core::fmt::Debug for SecretClipboard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretClipboard").finish_non_exhaustive()
    }
}

impl SecretClipboard {
    /// Copies `secret` and schedules clearing it.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Clipboard`] if the clipboard is unavailable.
    pub fn copy(&self, secret: Zeroizing<String>) -> Result<(), AppError> {
        let app = APP.get().ok_or(AppError::Clipboard)?;
        {
            let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
            app.clipboard()
                .write_secret(secret.as_str())
                .map_err(|_| AppError::Clipboard)?;
            *last = Some(secret);
        }
        let generation = self
            .generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        let last = Arc::clone(&self.last);
        let current = Arc::clone(&self.generation);
        std::thread::spawn(move || {
            std::thread::sleep(CLEAR_AFTER);
            // A newer copy has its own timer.
            if current.load(Ordering::Acquire) == generation {
                clear_if_ours(&mut last.lock().unwrap_or_else(PoisonError::into_inner));
            }
        });
        Ok(())
    }

    /// Clears the last secret copied now, if it is still on the clipboard.
    pub fn clear_now(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        clear_if_ours(&mut self.last.lock().unwrap_or_else(PoisonError::into_inner));
    }
}
