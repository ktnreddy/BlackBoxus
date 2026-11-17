//! Telling browsers where the native messaging host is (spec section
//! 14.2): a manifest naming this executable and the extensions allowed to
//! start it, and, on Windows, a registry value per browser pointing to the
//! manifest. Everything is per user; nothing needs administrator rights.

use std::path::PathBuf;

use serde_json::json;
use tauri::{AppHandle, Manager};

use super::HOST_NAME;
use crate::error::AppError;

/// The extensions allowed to use the host: the ID that the key in
/// `apps/extension/manifest.json` gives. A store listing adds its own ID
/// here.
pub const EXTENSION_IDS: &[&str] = &["mnddjkdakjkomjkjebabnkkdpglecjol"];

/// Where each Chromium browser looks for hosts in the registry.
#[cfg(windows)]
const REGISTRY_KEYS: &[&str] = &[
    r"Software\Google\Chrome\NativeMessagingHosts",
    r"Software\Microsoft\Edge\NativeMessagingHosts",
    r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
    r"Software\Chromium\NativeMessagingHosts",
];

fn manifest_path(app: &AppHandle) -> Result<PathBuf, AppError> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|_| AppError::Storage)?
        .join(format!("{HOST_NAME}.json")))
}

/// This executable. On Linux a running program whose file was replaced (by
/// an update) is reported as "… (deleted)"; the new file is at the plain
/// path.
fn executable() -> Result<PathBuf, AppError> {
    let exe = std::env::current_exe().map_err(|_| AppError::Storage)?;
    Ok(exe
        .to_str()
        .and_then(|s| s.strip_suffix(" (deleted)"))
        .map_or(exe.clone(), PathBuf::from))
}

fn manifest() -> Result<Vec<u8>, AppError> {
    let exe = executable()?;
    let origins: Vec<String> = EXTENSION_IDS
        .iter()
        .map(|id| format!("chrome-extension://{id}/"))
        .collect();
    serde_json::to_vec_pretty(&json!({
        "name": HOST_NAME,
        "description": "BlackBoxus",
        "path": exe,
        "type": "stdio",
        "allowed_origins": origins,
    }))
    .map_err(|_| AppError::Storage)
}

/// Writes the manifest and registers it with each browser. Run again at
/// every start, since an update can move the executable.
///
/// # Errors
///
/// Returns [`AppError::Storage`] if any of it cannot be written.
pub fn register(app: &AppHandle) -> Result<(), AppError> {
    let path = manifest_path(app)?;
    let dir = path.parent().ok_or(AppError::Storage)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(AppError::Storage)?;
    crate::storage::write_atomically(dir, name, &manifest()?)?;
    #[cfg(windows)]
    for key in REGISTRY_KEYS {
        windows_registry::CURRENT_USER
            .create(format!(r"{key}\{HOST_NAME}"))
            .and_then(|k| k.set_string("", path.to_string_lossy()))
            .map_err(|_| AppError::Storage)?;
    }
    #[cfg(not(windows))]
    for dir in unix_dirs() {
        crate::storage::write_atomically(&dir, name, &manifest()?)?;
    }
    Ok(())
}

/// Removes the registration and the manifest.
///
/// # Errors
///
/// Returns [`AppError::Storage`] if the manifest cannot be removed.
pub fn unregister(app: &AppHandle) -> Result<(), AppError> {
    #[cfg(windows)]
    for key in REGISTRY_KEYS {
        // Absent already is fine.
        let _ = windows_registry::CURRENT_USER.remove_tree(format!(r"{key}\{HOST_NAME}"));
    }
    #[cfg(not(windows))]
    for dir in unix_dirs() {
        let _ = std::fs::remove_file(dir.join(format!("{HOST_NAME}.json")));
    }
    match std::fs::remove_file(manifest_path(app)?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(AppError::Storage),
    }
}

/// Where Chrome and Chromium look for hosts on Linux, for development.
#[cfg(not(windows))]
fn unix_dirs() -> Vec<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(dir) = std::env::var_os("BLACKBOXUS_NATIVE_HOST_DIR") {
        return vec![PathBuf::from(dir)];
    }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    ["google-chrome", "chromium"]
        .iter()
        .map(|b| home.join(".config").join(b).join("NativeMessagingHosts"))
        .collect()
}
