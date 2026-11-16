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
            "sync_vaults",
            "list_items",
            "get_item",
            "reveal_field",
            "copy_field",
            "save_item",
            "delete_item",
            "generate_password",
            "my_sharing_id",
            "vault_members",
            "look_up_member",
            "share_vault",
            "compare_safety_number",
            "copy_text",
            "import_choose_file",
            "import_start",
            "import_progress",
            "import_finish",
            "hello_enable",
            "hello_disable",
            "unlock_with_hello",
            "totp_code",
            "get_settings",
            "set_settings",
            "show_emergency_kit",
            "sign_out",
        ]),
    ))?;
    Ok(())
}
