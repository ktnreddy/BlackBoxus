// Typed wrappers around the commands the Rust side exposes. The webview
// never sees keys: it sends what the user types and shows what comes back.
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

export interface AppStatus {
  version: string;
  server: string;
  /** The account set up on this computer, if any. */
  account: { email: string } | null;
  locked: boolean;
  offline: boolean;
  hello: { available: boolean; enabled: boolean; needs_password: boolean };
}

/** An error from the Rust side, safe to show to the user. */
export interface AppError {
  code: string;
  message: string;
}

export function isAppError(value: unknown): value is AppError {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as AppError).code === "string" &&
    typeof (value as AppError).message === "string"
  );
}

/** Turns anything thrown by `invoke` into a message for the user. */
export function errorMessage(value: unknown): string {
  return isAppError(value) ? value.message : "Something went wrong. Please try again.";
}

export function appStatus(): Promise<AppStatus> {
  return invoke<AppStatus>("app_status");
}

export function unlock(password: string): Promise<AppStatus> {
  return invoke<AppStatus>("unlock", { password });
}

export function lock(): Promise<AppStatus> {
  return invoke<AppStatus>("lock");
}

export interface Rating {
  score: number;
  label: string;
  acceptable: boolean;
  chars: number;
  min_chars: number;
  hint: string | null;
}

export interface EmergencyKit {
  email: string;
  server: string;
  secret_key: string;
  /** A recovery key just created, shown only this once. */
  recovery_key: string | null;
}

export interface Created {
  status: AppStatus;
  kit: EmergencyKit;
}

export function ratePassword(password: string, email: string): Promise<Rating> {
  return invoke<Rating>("rate_password", { password, email });
}

export function createAccount(email: string, password: string, confirm: string): Promise<Created> {
  return invoke<Created>("create_account", { email, password, confirm });
}

export function signIn(email: string, secretKey: string, password: string): Promise<AppStatus> {
  return invoke<AppStatus>("sign_in", { email, secretKey, password });
}

export interface VaultSummary {
  id: string;
  name: string;
  items: number;
  writable: boolean;
  /** This account owns it. */
  owner: boolean;
  /** Someone else is a member too. */
  shared: boolean;
}

export type ItemType = "login" | "note" | "card" | "identity" | "api";

export interface ItemSummary {
  id: string;
  type: ItemType;
  title: string;
  subtitle: string;
  modified_ms: number;
}

export interface FieldView {
  kind: string;
  label: string;
  /** Null while the value is concealed. */
  value: string | null;
  concealed: boolean;
}

export interface ItemView {
  id: string;
  type: ItemType;
  title: string;
  fields: FieldView[];
  created_ms: number;
  modified_ms: number;
}

export interface FieldInput {
  kind: string;
  label: string;
  value: string;
}

export interface ItemInput {
  type: ItemType;
  title: string;
  fields: FieldInput[];
}

export function syncVaults(): Promise<{ vaults: VaultSummary[]; offline: boolean }> {
  return invoke("sync_vaults");
}

export function listItems(vault: string): Promise<ItemSummary[]> {
  return invoke<ItemSummary[]>("list_items", { vault });
}

export function getItem(vault: string, item: string): Promise<ItemView> {
  return invoke<ItemView>("get_item", { vault, item });
}

export function revealField(vault: string, item: string, index: number): Promise<string> {
  return invoke<string>("reveal_field", { vault, item, index });
}

export function copyField(vault: string, item: string, index: number): Promise<void> {
  return invoke<void>("copy_field", { vault, item, index });
}

export function saveItem(vault: string, item: string | null, input: ItemInput): Promise<string> {
  return invoke<string>("save_item", { vault, item, input });
}

export function deleteItem(vault: string, item: string): Promise<void> {
  return invoke<void>("delete_item", { vault, item });
}

export type GeneratorOptions =
  | { kind: "random"; length: number; digits: boolean; symbols: boolean }
  | { kind: "passphrase"; words: number; separator: string; capitalise: boolean; number: boolean };

export interface Generated {
  password: string;
  bits: number;
  label: string;
}

export const DEFAULT_GENERATOR: GeneratorOptions = {
  kind: "random",
  length: 20,
  digits: true,
  symbols: true,
};

export function generatePassword(options: GeneratorOptions = DEFAULT_GENERATOR): Promise<Generated> {
  return invoke<Generated>("generate_password", { options });
}

export function copyText(text: string): Promise<void> {
  return invoke<void>("copy_text", { text });
}

export interface Member {
  sharing_id: string;
  role: "owner" | "editor" | "viewer";
  you: boolean;
}

export interface LookedUp {
  sharing_id: string;
  safety_number: string[];
}

export function mySharingId(): Promise<string> {
  return invoke<string>("my_sharing_id");
}

export function vaultMembers(vault: string): Promise<Member[]> {
  return invoke<Member[]>("vault_members", { vault });
}

export function lookUpMember(vault: string, sharingId: string): Promise<LookedUp> {
  return invoke<LookedUp>("look_up_member", { vault, sharingId });
}

export function shareVault(
  vault: string,
  sharingId: string,
  role: "editor" | "viewer",
): Promise<Member[]> {
  return invoke<Member[]>("share_vault", { vault, sharingId, role });
}

export function compareSafetyNumber(sharingId: string): Promise<LookedUp> {
  return invoke<LookedUp>("compare_safety_number", { sharingId });
}

export interface ImportPreview {
  source: string;
  logins: number;
  notes: number;
  skipped: number;
  sample: string[];
}

export interface ImportProgress {
  running: boolean;
  done: number;
  total: number;
  waiting_seconds: number | null;
  error: string | null;
  finished: boolean;
}

export function importChooseFile(): Promise<{ file_name: string; preview: ImportPreview } | null> {
  return invoke("import_choose_file");
}

export function importStart(vault: string): Promise<void> {
  return invoke<void>("import_start", { vault });
}

export function importProgress(): Promise<ImportProgress> {
  return invoke<ImportProgress>("import_progress");
}

export function importFinish(deleteFile: boolean): Promise<void> {
  return invoke<void>("import_finish", { deleteFile });
}

export function helloEnable(): Promise<AppStatus> {
  return invoke<AppStatus>("hello_enable");
}

export function helloDisable(): Promise<AppStatus> {
  return invoke<AppStatus>("hello_disable");
}

export function unlockWithHello(): Promise<AppStatus> {
  return invoke<AppStatus>("unlock_with_hello");
}

export interface TotpCode {
  code: string;
  period: number;
  remaining: number;
}

export function totpCode(vault: string, item: string, index: number): Promise<TotpCode> {
  return invoke<TotpCode>("totp_code", { vault, item, index });
}

export interface Settings {
  /** Changed only with setBrowserIntegration. */
  browser_integration?: boolean;
  auto_lock_minutes: number;
}

export function getSettings(): Promise<Settings> {
  return invoke<Settings>("get_settings");
}

export function setSettings(settings: Settings): Promise<Settings> {
  return invoke<Settings>("set_settings", { settings });
}

export function showEmergencyKit(password: string): Promise<EmergencyKit> {
  return invoke<EmergencyKit>("show_emergency_kit", { password });
}

export function signOut(): Promise<AppStatus> {
  return invoke<AppStatus>("sign_out");
}

export function changeMemberRole(
  vault: string,
  sharingId: string,
  role: Member["role"],
): Promise<Member[]> {
  return invoke<Member[]>("change_member_role", { vault, sharingId, role });
}

export function removeMember(vault: string, sharingId: string): Promise<Member[]> {
  return invoke<Member[]>("remove_member", { vault, sharingId });
}

export function leaveVault(vault: string): Promise<void> {
  return invoke<void>("leave_vault", { vault });
}

export function recoveryKeyStatus(): Promise<boolean> {
  return invoke<boolean>("recovery_key_status");
}

export function createRecoveryKey(password: string): Promise<EmergencyKit> {
  return invoke<EmergencyKit>("create_recovery_key", { password });
}

export function removeRecoveryKey(password: string): Promise<void> {
  return invoke<void>("remove_recovery_key", { password });
}

export function recoverAccount(
  email: string,
  recoveryKey: string,
  password: string,
  confirm: string,
): Promise<Created> {
  return invoke<Created>("recover_account", { email, recoveryKey, password, confirm });
}

export function createVault(name: string): Promise<{ id: string; vaults: VaultSummary[] }> {
  return invoke<{ id: string; vaults: VaultSummary[] }>("create_vault", { name });
}

export function renameVault(vault: string, name: string): Promise<VaultSummary[]> {
  return invoke<VaultSummary[]>("rename_vault", { vault, name });
}

export interface BrowserPairing {
  id: string;
  browser: string;
  created_ms: number;
}

export interface PairingRequest {
  browser: string;
  code: string;
}

export interface BrowserStatus {
  enabled: boolean;
  pairings: BrowserPairing[];
  pending: PairingRequest | null;
}

export function browserStatus(): Promise<BrowserStatus> {
  return invoke<BrowserStatus>("browser_status");
}

export function setBrowserIntegration(enabled: boolean): Promise<BrowserStatus> {
  return invoke<BrowserStatus>("set_browser_integration", { enabled });
}

export function answerBrowserPairing(allow: boolean): Promise<void> {
  return invoke<void>("answer_browser_pairing", { allow });
}

export function forgetBrowser(id: string): Promise<BrowserStatus> {
  return invoke<BrowserStatus>("forget_browser", { id });
}

/** Calls `f` whenever a browser asks to pair, or the request ends (null). */
export function onBrowserPairing(f: (request: PairingRequest | null) => void): Promise<() => void> {
  return listen<PairingRequest | null>("browser-pairing", (e) => f(e.payload));
}
