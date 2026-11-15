//! Copies secrets to the clipboard and clears them again.
//!
//! On Windows the copy is marked so it stays out of clipboard history
//! (Win+V) and is not synced to other devices. After [`CLEAR_AFTER`], or
//! when the vaults are locked, the clipboard is cleared if it still holds
//! what was copied, so anything the user copied since is left alone.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::error::AppError;

/// How long a copied secret stays on the clipboard.
pub const CLEAR_AFTER: Duration = Duration::from_secs(30);

#[derive(Default)]
struct Inner {
    /// Kept for the app's lifetime: on Linux, copied text is only
    /// available while the clipboard object that set it exists.
    clipboard: Option<arboard::Clipboard>,
    /// The secret last copied, until it is cleared.
    last: Option<Zeroizing<String>>,
}

impl Inner {
    fn clear_if_ours(&mut self) {
        let Some(secret) = self.last.take() else {
            return;
        };
        if let Some(clipboard) = self.clipboard.as_mut() {
            let still_ours = clipboard
                .get_text()
                .map(|t| Zeroizing::new(t) == secret)
                .unwrap_or(false);
            if still_ours {
                // Best effort: nothing more can be done if this fails.
                let _ = clipboard.clear();
            }
        }
    }
}

/// The app's clipboard for secrets.
#[derive(Default)]
pub struct SecretClipboard {
    inner: Arc<Mutex<Inner>>,
    generation: Arc<AtomicU64>,
}

impl core::fmt::Debug for SecretClipboard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecretClipboard").finish_non_exhaustive()
    }
}

fn set(clipboard: &mut arboard::Clipboard, text: &str) -> Result<(), arboard::Error> {
    #[cfg(windows)]
    {
        use arboard::SetExtWindows;
        clipboard
            .set()
            .exclude_from_history()
            .exclude_from_cloud()
            .text(text)
    }
    #[cfg(not(windows))]
    {
        clipboard.set_text(text)
    }
}

impl SecretClipboard {
    /// Copies `secret` and schedules clearing it.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Clipboard`] if the clipboard is unavailable.
    pub fn copy(&self, secret: Zeroizing<String>) -> Result<(), AppError> {
        {
            let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
            if inner.clipboard.is_none() {
                inner.clipboard = Some(arboard::Clipboard::new().map_err(|_| AppError::Clipboard)?);
            }
            let clipboard = inner.clipboard.as_mut().ok_or(AppError::Clipboard)?;
            set(clipboard, &secret).map_err(|_| AppError::Clipboard)?;
            inner.last = Some(secret);
        }
        let generation = self
            .generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        let inner = Arc::clone(&self.inner);
        let current = Arc::clone(&self.generation);
        std::thread::spawn(move || {
            std::thread::sleep(CLEAR_AFTER);
            // A newer copy has its own timer.
            if current.load(Ordering::Acquire) == generation {
                inner
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clear_if_ours();
            }
        });
        Ok(())
    }

    /// Clears the last secret copied now, if it is still on the clipboard.
    pub fn clear_now(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear_if_ours();
    }
}
