//! Scanning a QR code with the phone's camera, to add a one-time code.
//!
//! This uses the Android code of Tauri's barcode scanner plugin, called
//! from Rust only, so the window has no access to the camera itself. The
//! scan happens on the phone (ML Kit); the picture never leaves it.

use serde::{Deserialize, Serialize};
use tauri::plugin::{Builder, PluginHandle, TauriPlugin};
use tauri::{Manager, Wry};

use crate::error::AppError;

struct Scanner(PluginHandle<Wry>);

/// Registers the scanner's Android code.
pub fn init() -> TauriPlugin<Wry> {
    Builder::new("qr-scanner")
        .setup(|app, api| {
            let handle =
                api.register_android_plugin("app.tauri.barcodescanner", "BarcodeScannerPlugin")?;
            app.manage(Scanner(handle));
            Ok(())
        })
        .build()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Options {
    formats: [&'static str; 1],
    /// The camera shows behind the window, which draws the frame and the
    /// Cancel button on top.
    windowed: bool,
    camera_direction: &'static str,
}

#[derive(Deserialize)]
struct Scanned {
    content: String,
}

/// Asks for the camera if needed, then scans one QR code and returns its
/// text.
///
/// # Errors
///
/// Returns [`AppError::CameraDenied`] without camera permission, or
/// [`AppError::ScanCancelled`] if the scan is cancelled.
pub fn scan(app: &tauri::AppHandle) -> Result<String, AppError> {
    let handle = &app.state::<Scanner>().0;
    let permission: serde_json::Value = handle
        .run_mobile_plugin("requestPermissions", ())
        .map_err(|_| AppError::CameraDenied)?;
    if permission.get("camera").and_then(serde_json::Value::as_str) != Some("granted") {
        return Err(AppError::CameraDenied);
    }
    let scanned: Scanned = handle
        .run_mobile_plugin(
            "scan",
            Options {
                formats: ["QR_CODE"],
                windowed: true,
                camera_direction: "back",
            },
        )
        .map_err(|_| AppError::ScanCancelled)?;
    Ok(scanned.content)
}

/// Stops a scan in progress.
pub fn cancel(app: &tauri::AppHandle) {
    // Best effort: there may be no scan running.
    let _: Result<serde_json::Value, _> = app.state::<Scanner>().0.run_mobile_plugin("cancel", ());
}
