//! Runs an import in the background, a batch at a time, so the window
//! stays usable and shows progress. Pauses when the server's request limit
//! is reached and carries on when it allows.

use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use client_core::ClientError;
use client_core::vaults::written;
use serde::Serialize;
use tauri::{AppHandle, Manager};
use vault_core::{Item, VaultId};

use crate::error::AppError;
use crate::http::Transport;
use crate::import::Preview;
use crate::state::AppState;

/// Items written per batch before the vault is synced and verified again.
const BATCH: usize = 50;
/// Longest wait for the server's request limit.
const MAX_WAIT: Duration = Duration::from_secs(16 * 60);

/// A file chosen for import and waiting for the user to confirm.
pub struct PendingImport {
    /// Where the file is, so the user can have it deleted afterwards.
    pub path: PathBuf,
    /// Its items.
    pub items: Vec<Item>,
    /// What was shown.
    pub preview: Preview,
}

impl core::fmt::Debug for PendingImport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingImport")
            .field("preview", &self.preview)
            .finish_non_exhaustive()
    }
}

/// How an import is going, polled by the window.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Progress {
    /// Whether an import is running.
    pub running: bool,
    /// Items saved so far.
    pub done: usize,
    /// Items in the file.
    pub total: usize,
    /// Seconds until the server allows more, while waiting for its limit.
    pub waiting_seconds: Option<u64>,
    /// Why the import stopped early, if it did.
    pub error: Option<String>,
    /// Whether the import finished.
    pub finished: bool,
}

/// Shared import progress.
#[derive(Debug, Default)]
pub struct ImportStatus(Mutex<Progress>);

impl ImportStatus {
    /// The current progress.
    pub fn get(&self) -> Progress {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn update(&self, f: impl FnOnce(&mut Progress)) {
        f(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner));
    }

    /// Marks an import as started.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::ImportRunning`] if one already is.
    pub fn start(&self, total: usize) -> Result<(), AppError> {
        let mut p = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if p.running {
            return Err(AppError::ImportRunning);
        }
        *p = Progress {
            running: true,
            total,
            ..Progress::default()
        };
        Ok(())
    }
}

/// Imports `items` into `vault` on a background thread.
pub fn spawn(app: AppHandle, vault: VaultId, items: Vec<Item>) {
    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        let result = run(&state, vault, &items);
        state.import.update(|p| {
            p.running = false;
            p.waiting_seconds = None;
            match result {
                Ok(()) => p.finished = true,
                Err(e) => p.error = Some(e.to_string()),
            }
        });
    });
}

fn run(state: &AppState, vault: VaultId, items: &[Item]) -> Result<(), AppError> {
    let mut done = 0_usize;
    let mut stalled = 0_u32;
    while let Some(rest) = items.get(done..).filter(|r| !r.is_empty()) {
        let batch = rest.get(..BATCH.min(rest.len())).unwrap_or(rest);
        // Locking the vaults ends the session, and with it the import.
        let before = done;
        let requests =
            state.with_session(|s| s.vaults.new_items_batch(&s.unlocked, &vault, batch))?;
        'batch: for request in &requests {
            loop {
                match written(&state.transport.send(request)?) {
                    Ok(()) => break,
                    Err(ClientError::RateLimited(after)) => {
                        let wait = Duration::from_secs(after.unwrap_or(60)).min(MAX_WAIT);
                        state
                            .import
                            .update(|p| p.waiting_seconds = Some(wait.as_secs()));
                        std::thread::sleep(wait);
                        state.import.update(|p| p.waiting_seconds = None);
                    }
                    // Another device wrote first: the rest of this batch no
                    // longer fits the log. Sync and build them again.
                    Err(ClientError::Server { status: 409, .. }) => break 'batch,
                    Err(e) => return Err(e.into()),
                }
            }
            done = done.saturating_add(1);
            state.import.update(|p| p.done = done);
        }
        state.with_session(|s| s.vaults.sync_vault(&state.transport, &s.unlocked, vault))?;
        stalled = if done == before {
            stalled.saturating_add(1)
        } else {
            0
        };
        if stalled >= 5 {
            return Err(AppError::Server);
        }
    }
    Ok(())
}
