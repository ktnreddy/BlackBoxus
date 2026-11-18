// The app's isolation script (Tauri's isolation pattern). Tauri runs it in
// a separate, sandboxed frame and passes it every message the window sends
// before encrypting it for the app, so even script injected into the window
// cannot call anything not on this list. The list must match the commands
// in build.rs; a test in src/lib.rs checks that it does.
"use strict";

const COMMANDS = new Set([
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
  "change_member_role",
  "remove_member",
  "leave_vault",
  "recovery_key_status",
  "create_recovery_key",
  "remove_recovery_key",
  "recover_account",
  "change_password",
  "emergency_status",
  "look_up_contact",
  "set_trusted_contact",
  "remove_trusted_contact",
  "deny_emergency",
  "request_emergency",
  "open_emergency",
  "close_emergency",
  "create_vault",
  "rename_vault",
  "browser_status",
  "set_browser_integration",
  "answer_browser_pairing",
  "forget_browser",
  // Listening for the app's own events.
  "plugin:event|listen",
  "plugin:event|unlisten",
]);

window.__TAURI_ISOLATION_HOOK__ = (payload) => {
  if (payload === null || typeof payload !== "object" || !COMMANDS.has(payload.cmd)) {
    throw new Error("BlackBoxus blocked a message from the window");
  }
  return payload;
};
