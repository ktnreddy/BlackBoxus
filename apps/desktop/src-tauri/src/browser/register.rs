//! Telling browsers where the native messaging host is (spec section
//! 14.2): a manifest naming this executable and the extensions allowed to
//! start it, and, on Windows, a registry value per browser pointing to the
//! manifest. Chromium browsers and Firefox each get their own manifest,
//! since they list allowed extensions differently. Everything is per user;
//! nothing needs administrator rights.

use std::path::PathBuf;

use serde_json::json;
use tauri::{AppHandle, Manager};

use super::HOST_NAME;
use crate::error::AppError;

/// The extensions allowed to use the host: the ID that the key in
/// `apps/extension/manifest.json` gives. A store listing adds its own ID
/// here.
pub const EXTENSION_IDS: &[&str] = &["mnddjkdakjkomjkjebabnkkdpglecjol"];

/// The Firefox add-on IDs allowed to use the host: the ID that
/// `apps/extension/build.mjs` declares.
pub const FIREFOX_IDS: &[&str] = &["{7ee1ca63-9148-4233-a256-ff54b5fbbdc9}"];

/// Where each Chromium browser looks for hosts in the registry.
#[cfg(windows)]
const REGISTRY_KEYS: &[&str] = &[
    r"Software\Google\Chrome\NativeMessagingHosts",
    r"Software\Microsoft\Edge\NativeMessagingHosts",
    r"Software\BraveSoftware\Brave-Browser\NativeMessagingHosts",
    r"Software\Chromium\NativeMessagingHosts",
];

/// Where Firefox looks for hosts in the registry.
#[cfg(windows)]
const FIREFOX_REGISTRY_KEY: &str = r"Software\Mozilla\NativeMessagingHosts";

/// The two kinds of browser, whose manifests differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Chromium,
    Firefox,
}

impl Family {
    /// The name of the app's own copy of the manifest, which the Windows
    /// registry points to.
    fn file_name(self) -> String {
        match self {
            Self::Chromium => format!("{HOST_NAME}.json"),
            Self::Firefox => format!("{HOST_NAME}.firefox.json"),
        }
    }
}

fn manifest_path(app: &AppHandle, family: Family) -> Result<PathBuf, AppError> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|_| AppError::Storage)?
        .join(family.file_name()))
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

fn manifest(family: Family) -> Result<Vec<u8>, AppError> {
    let exe = executable()?;
    let value = match family {
        Family::Chromium => {
            let origins: Vec<String> = EXTENSION_IDS
                .iter()
                .map(|id| format!("chrome-extension://{id}/"))
                .collect();
            json!({
                "name": HOST_NAME,
                "description": "BlackBoxus",
                "path": exe,
                "type": "stdio",
                "allowed_origins": origins,
            })
        }
        Family::Firefox => json!({
            "name": HOST_NAME,
            "description": "BlackBoxus",
            "path": exe,
            "type": "stdio",
            "allowed_extensions": FIREFOX_IDS,
        }),
    };
    serde_json::to_vec_pretty(&value).map_err(|_| AppError::Storage)
}

/// Writes the manifest and registers it with each browser. Run again at
/// every start, since an update can move the executable.
///
/// # Errors
///
/// Returns [`AppError::Storage`] if any of it cannot be written.
pub fn register(app: &AppHandle) -> Result<(), AppError> {
    for family in [Family::Chromium, Family::Firefox] {
        let path = manifest_path(app, family)?;
        let dir = path.parent().ok_or(AppError::Storage)?;
        crate::storage::write_atomically(dir, &family.file_name(), &manifest(family)?)?;
        #[cfg(windows)]
        for key in registry_keys(family) {
            windows_registry::CURRENT_USER
                .create(format!(r"{key}\{HOST_NAME}"))
                .and_then(|k| k.set_string("", path.to_string_lossy()))
                .map_err(|_| AppError::Storage)?;
        }
        #[cfg(not(windows))]
        for dir in unix_dirs(family) {
            // These folders hold one file per host, named after it.
            crate::storage::write_atomically(
                &dir,
                &format!("{HOST_NAME}.json"),
                &manifest(family)?,
            )?;
        }
    }
    Ok(())
}

#[cfg(windows)]
const fn registry_keys(family: Family) -> &'static [&'static str] {
    match family {
        Family::Chromium => REGISTRY_KEYS,
        Family::Firefox => core::slice::from_ref(&FIREFOX_REGISTRY_KEY),
    }
}

/// Removes the registration and the manifest.
///
/// # Errors
///
/// Returns [`AppError::Storage`] if the manifest cannot be removed.
pub fn unregister(app: &AppHandle) -> Result<(), AppError> {
    for family in [Family::Chromium, Family::Firefox] {
        #[cfg(windows)]
        for key in registry_keys(family) {
            // Absent already is fine.
            let _ = windows_registry::CURRENT_USER.remove_tree(format!(r"{key}\{HOST_NAME}"));
        }
        #[cfg(not(windows))]
        for dir in unix_dirs(family) {
            let _ = std::fs::remove_file(dir.join(format!("{HOST_NAME}.json")));
        }
        match std::fs::remove_file(manifest_path(app, family)?) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(AppError::Storage),
        }
    }
    Ok(())
}

/// Where browsers look for hosts on Linux, for development.
#[cfg(not(windows))]
fn unix_dirs(family: Family) -> Vec<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(dir) = std::env::var_os("BLACKBOXUS_NATIVE_HOST_DIR") {
        let dir = PathBuf::from(dir);
        return vec![match family {
            Family::Chromium => dir,
            Family::Firefox => dir.join("firefox"),
        }];
    }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    match family {
        Family::Chromium => ["google-chrome", "chromium"]
            .iter()
            .map(|b| home.join(".config").join(b).join("NativeMessagingHosts"))
            .collect(),
        Family::Firefox => vec![home.join(".mozilla").join("native-messaging-hosts")],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifests_name_the_extensions_each_browser_expects() {
        let chromium: serde_json::Value =
            serde_json::from_slice(&manifest(Family::Chromium).unwrap_or_default())
                .unwrap_or_default();
        assert_eq!(chromium["name"], HOST_NAME);
        assert_eq!(
            chromium["allowed_origins"][0],
            "chrome-extension://mnddjkdakjkomjkjebabnkkdpglecjol/"
        );
        assert!(chromium.get("allowed_extensions").is_none());
        let firefox: serde_json::Value =
            serde_json::from_slice(&manifest(Family::Firefox).unwrap_or_default())
                .unwrap_or_default();
        assert_eq!(firefox["name"], HOST_NAME);
        assert_eq!(firefox["allowed_extensions"][0], FIREFOX_IDS[0]);
        assert!(firefox.get("allowed_origins").is_none());
        assert_ne!(Family::Chromium.file_name(), Family::Firefox.file_name());
    }
}
