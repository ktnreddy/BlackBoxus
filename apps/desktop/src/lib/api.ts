// Typed wrappers around the commands the Rust side exposes. The webview
// never sees keys: it sends what the user types and shows what comes back.
import { invoke } from "@tauri-apps/api/core";

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
