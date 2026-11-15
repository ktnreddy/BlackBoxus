// Typed wrappers around the commands the Rust side exposes. The webview
// never sees keys: it sends what the user types and shows what comes back.
import { invoke } from "@tauri-apps/api/core";

export interface AppStatus {
  version: string;
  server: string;
  /** The account set up on this computer, if any. */
  account: { email: string } | null;
  locked: boolean;
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
