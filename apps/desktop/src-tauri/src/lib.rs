//! The BlackBoxus app, for desktops and Android.
//!
//! The window shows the screens; everything that touches keys or the
//! server runs here, in Rust, through `client-core`. The window can only
//! call the commands in `commands`, and the content security policy in
//! `tauri.conf.json` stops it loading anything from the network.

#[cfg(any(target_os = "android", test))]
mod autofill;
mod breach;
#[cfg(desktop)]
pub mod browser;
#[cfg(mobile)]
#[path = "browser_mobile.rs"]
pub mod browser;
#[cfg(desktop)]
mod clipboard;
#[cfg(mobile)]
#[path = "clipboard_mobile.rs"]
mod clipboard;
mod commands;
mod device_unlock;
mod error;
pub mod flows;
mod generator;
mod health;
mod hello;
pub mod http;
mod import;
mod importer;
mod items;
mod live;
mod pending;
#[cfg(mobile)]
mod scanner;
pub mod sharing_id;
mod state;
pub mod storage;
mod strength;
mod totp;
mod trusted;
pub mod vaults;

use tauri::Manager;

pub use error::AppError;

/// Why the app could not start.
pub type StartError = tauri::Error;

/// What can unlock without the master password on this device: Windows
/// Hello, or a fingerprint on Android.
#[cfg(target_os = "android")]
fn unlock_keys(app: &tauri::AppHandle, dir: &std::path::Path) -> Box<dyn hello::HelloKeys> {
    hello::fingerprint(app.clone(), dir.to_path_buf())
}

/// What can unlock without the master password on this device: Touch ID
/// or Face ID on Apple devices.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn unlock_keys(app: &tauri::AppHandle, _dir: &std::path::Path) -> Box<dyn hello::HelloKeys> {
    hello::touch_id(app.clone())
}

/// What can unlock without the master password on this device: Windows
/// Hello, or nothing yet on Linux.
#[cfg(not(any(target_os = "android", target_os = "macos", target_os = "ios")))]
fn unlock_keys(_app: &tauri::AppHandle, _dir: &std::path::Path) -> Box<dyn hello::HelloKeys> {
    hello::provider()
}

/// Starts the app and runs until the window is closed.
///
/// # Errors
///
/// Returns an error if the window or webview cannot be created.
pub fn run() -> Result<(), StartError> {
    builder()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            #[cfg(mobile)]
            clipboard::attach(app.handle().clone());
            storage::init_secret_store()?;
            let dir = app.path().app_data_dir()?;
            let storage = storage::Storage::new(dir.clone());
            let browser_on = storage.settings().browser_integration;
            app.manage(state::AppState::new(
                storage,
                http::Https::new(),
                device_unlock::DeviceUnlock::new(dir.clone(), unlock_keys(app.handle(), &dir)),
            ));
            app.manage(browser::Bridge::default());
            if browser_on {
                // Registers again, in case an update moved the app, and
                // listens. If it fails, Settings shows the bridge as off.
                let _ = app
                    .state::<browser::Bridge>()
                    .set_enabled(app.handle(), true);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_status,
            commands::rate_password,
            commands::create_account,
            commands::sign_in,
            commands::unlock,
            commands::lock,
            commands::sync_vaults,
            commands::list_items,
            commands::get_item,
            commands::reveal_field,
            commands::copy_field,
            commands::save_item,
            commands::scan_code,
            commands::cancel_scan,
            commands::autofill_status,
            commands::autofill_settings,
            commands::pending_changes,
            commands::conflict_field,
            commands::resolve_conflict,
            commands::delete_item,
            commands::generate_password,
            commands::my_sharing_id,
            commands::vault_members,
            commands::look_up_member,
            commands::share_vault,
            commands::compare_safety_number,
            commands::copy_text,
            commands::import_choose_file,
            commands::import_start,
            commands::import_duplicates,
            commands::import_progress,
            commands::import_finish,
            commands::hello_enable,
            commands::hello_disable,
            commands::unlock_with_hello,
            commands::totp_code,
            commands::get_settings,
            commands::set_settings,
            commands::show_emergency_kit,
            commands::sign_out,
            commands::change_member_role,
            commands::remove_member,
            commands::leave_vault,
            commands::recovery_key_status,
            commands::create_recovery_key,
            commands::remove_recovery_key,
            commands::recover_account,
            commands::change_password,
            commands::emergency_status,
            commands::look_up_contact,
            commands::set_trusted_contact,
            commands::remove_trusted_contact,
            commands::deny_emergency,
            commands::request_emergency,
            commands::open_emergency,
            commands::close_emergency,
            commands::password_health,
            commands::open_website,
            commands::create_vault,
            commands::rename_vault,
            commands::browser_status,
            commands::set_browser_integration,
            commands::answer_browser_pairing,
            commands::forget_browser,
        ])
        .run(tauri::generate_context!())
}

/// Where Android starts the app. The generated glue is Tauri's.
#[cfg(mobile)]
mod mobile {
    #[tauri::mobile_entry_point]
    fn start() {
        // Nothing to report to: Android shows the app as stopped.
        let _ = super::run();
    }
}

/// The desktop builder: two copies of the app would race on the stored
/// account, so a second launch just brings the open window forward.
#[cfg(desktop)]
fn builder() -> tauri::Builder<tauri::Wry> {
    let builder =
        tauri::Builder::default().plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                // Best effort: the window may be closing.
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }));
    // Touch ID. Only the Rust side calls it: the window has no permission
    // for the plugin's commands.
    #[cfg(target_os = "macos")]
    let builder = builder.plugin(tauri_plugin_biometric::init());
    builder
}

/// The phone builder: Android runs one copy itself, and the clipboard
/// goes through its plugin.
#[cfg(mobile)]
fn builder() -> tauri::Builder<tauri::Wry> {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_fs::init());
    // Fingerprint, Face ID and Touch ID unlock. Only the Rust side calls
    // it: the window has no permission for the plugin's commands.
    let builder = builder
        .plugin(tauri_plugin_biometric::init())
        .plugin(scanner::init());
    #[cfg(target_os = "android")]
    let builder = builder.plugin(autofill::init());
    builder
}

#[cfg(test)]
mod tests {
    /// The isolation script must allow exactly the commands that exist.
    #[test]
    fn isolation_allows_exactly_the_commands() {
        let quoted = |text: &str| -> std::collections::BTreeSet<String> {
            text.lines()
                .filter_map(|l| {
                    l.trim()
                        .strip_prefix('"')
                        .and_then(|l| l.strip_suffix("\","))
                        .map(str::to_owned)
                })
                .filter(|name| !name.contains('|'))
                .collect()
        };
        let commands = quoted(include_str!("../build.rs"));
        let allowed = quoted(include_str!("../../isolation/index.js"));
        assert!(commands.len() > 40);
        assert_eq!(commands, allowed);
    }
}
