//! Generates the app's permissions: only the commands listed here can be
//! called from the window, and only if a capability allows them.

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "app_status",
            "rate_password",
            "create_account",
            "sign_in",
            "unlock",
            "lock",
        ]),
    ))?;
    Ok(())
}
