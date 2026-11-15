//! The BlackBoxus desktop app.
//!
//! The window shows the screens; everything that touches keys or the
//! server runs here, in Rust, through `client-core`. The window can only
//! call the commands in `commands`, and the content security policy in
//! `tauri.conf.json` stops it loading anything from the network.

mod clipboard;
mod commands;
mod device_unlock;
mod error;
pub mod flows;
mod generator;
mod hello;
pub mod http;
mod import;
mod importer;
mod items;
mod sharing_id;
mod state;
pub mod storage;
mod strength;
mod totp;
pub mod vaults;

use tauri::Manager;

pub use error::AppError;

/// Why the app could not start.
pub type StartError = tauri::Error;

/// Starts the app and runs until the window is closed.
///
/// # Errors
///
/// Returns an error if the window or webview cannot be created.
pub fn run() -> Result<(), StartError> {
    tauri::Builder::default()
        // Two copies of the app would race on the stored account, so a
        // second launch just brings the open window forward.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                // Best effort: the window may be closing.
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            storage::init_secret_store()?;
            let dir = app.path().app_data_dir()?;
            app.manage(state::AppState::new(
                storage::Storage::new(dir.clone()),
                http::Https::new(),
                device_unlock::DeviceUnlock::new(dir, hello::provider()),
            ));
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
            commands::import_progress,
            commands::import_finish,
            commands::hello_enable,
            commands::hello_disable,
            commands::unlock_with_hello,
            commands::totp_code,
        ])
        .run(tauri::generate_context!())
}
