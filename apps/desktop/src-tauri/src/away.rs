//! Locking when the app leaves the screen, on phones.
//!
//! The window can't be trusted to notice: Android's web view doesn't
//! reliably report being hidden, and a backgrounded app's timers stop. So
//! the Rust side watches the app itself: Android's `onPause` and
//! `onResume` (iOS: resign active, enter foreground).
//!
//! - "Lock after: straight away" erases the keys as the app leaves the
//!   screen.
//! - Any other time is checked when the app comes back: away that long,
//!   it locks before anything is shown.
//!
//! Some system screens pause the app without the person leaving it: the
//! fingerprint prompt, the camera permission, the file picker. While the
//! app itself has one open ([`SystemScreen`]), leaving doesn't count.

#![cfg_attr(desktop, allow(dead_code))]

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use tauri::{AppHandle, Emitter, Manager};

use crate::state::{AppState, now_ms};

/// What the window is told when the vaults were locked by leaving the app.
pub const LOCKED_EVENT: &str = "locked-away";
/// What the window is told when the app comes back, still unlocked.
pub const BACK_EVENT: &str = "app-back";

/// When the app left the screen, and how many system screens the app
/// itself has open.
#[derive(Default)]
pub struct Away {
    since: Mutex<Option<u64>>,
    system_screens: AtomicU32,
}

/// Marks a system screen the app opens itself, for as long as it lives.
pub struct SystemScreen<'a>(&'a Away);

impl Drop for SystemScreen<'_> {
    fn drop(&mut self) {
        self.0.system_screens.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Away {
    /// The app is about to show a system screen over itself.
    pub fn system_screen(&self) -> SystemScreen<'_> {
        self.system_screens.fetch_add(1, Ordering::AcqRel);
        SystemScreen(self)
    }

    fn since(&self) -> std::sync::MutexGuard<'_, Option<u64>> {
        self.since
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Whether being away `away_ms` locks, with "Lock after" set to
/// `minutes`: straight away (0) locks as soon as the app leaves.
fn locks_after(minutes: u32, away_ms: u64) -> bool {
    away_ms >= u64::from(minutes).saturating_mul(60_000)
}

/// The app left the screen.
pub fn left(app: &AppHandle) {
    let state = app.state::<AppState>();
    let away = &state.away;
    if away.system_screens.load(Ordering::Acquire) > 0 {
        return;
    }
    *away.since() = Some(now_ms());
    if state.storage.settings().auto_lock_minutes == 0 {
        lock(app, &state);
    }
}

/// The app is back on the screen.
pub fn back(app: &AppHandle) {
    let state = app.state::<AppState>();
    let Some(since) = state.away.since().take() else {
        return;
    };
    let minutes = state.storage.settings().auto_lock_minutes;
    if locks_after(minutes, now_ms().saturating_sub(since)) {
        lock(app, &state);
    } else {
        let _ = app.emit(BACK_EVENT, ());
    }
}

fn lock(app: &AppHandle, state: &AppState) {
    if !state.status().locked {
        state.lock();
        let _ = app.emit(LOCKED_EVENT, ());
    }
}

#[cfg(test)]
mod tests {
    use super::locks_after;

    #[test]
    fn straight_away_locks_on_leaving_and_others_after_their_time() {
        assert!(locks_after(0, 0));
        assert!(!locks_after(1, 59_999));
        assert!(locks_after(1, 60_000));
        assert!(!locks_after(15, 10 * 60_000));
        assert!(locks_after(15, 16 * 60_000));
    }
}
