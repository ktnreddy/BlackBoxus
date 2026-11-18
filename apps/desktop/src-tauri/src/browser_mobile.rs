//! The browser bridge on phones, where there is none.
//!
//! Phone browsers have no native messaging, so the extension cannot reach
//! the app. This keeps the same shape as the desktop bridge so the
//! commands compile unchanged: it is always off, lists no browsers and
//! refuses to be turned on.

use serde::Serialize;
use tauri::AppHandle;

use crate::error::AppError;

/// A paired browser. There are never any on phones.
#[derive(Debug, Clone, Serialize)]
pub enum PairingView {}

/// A pairing waiting for the user. There are never any on phones.
#[derive(Debug, Clone, Serialize)]
pub enum PairingRequest {}

/// The bridge, always off.
#[derive(Debug, Default)]
pub struct Bridge {
    /// Made with `default()`, like the desktop bridge.
    _private: (),
}

impl Bridge {
    /// Turning the bridge off succeeds; turning it on is refused.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::InvalidSetting`] when asked to turn it on.
    pub fn set_enabled(&self, _app: &AppHandle, enabled: bool) -> Result<(), AppError> {
        if enabled {
            Err(AppError::InvalidSetting)
        } else {
            Ok(())
        }
    }

    /// Always off.
    pub fn enabled(&self) -> bool {
        false
    }

    /// Never a pairing waiting.
    pub fn pending_request(&self) -> Option<PairingRequest> {
        None
    }

    /// Nothing to answer.
    pub fn answer(&self, _allow: bool) {}

    /// No paired browsers.
    pub fn pairings(&self) -> Vec<PairingView> {
        Vec::new()
    }

    /// Nothing to forget.
    ///
    /// # Errors
    ///
    /// Never fails.
    pub fn forget(&self, _id: &str) -> Result<(), AppError> {
        Ok(())
    }

    /// Nothing to forget.
    ///
    /// # Errors
    ///
    /// Never fails.
    pub fn forget_all(&self) -> Result<(), AppError> {
        Ok(())
    }
}
