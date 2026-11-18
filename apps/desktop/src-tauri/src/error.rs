//! Errors the window can be shown.

use client_core::ClientError;
use serde::Serialize;
use vault_core::Error as CryptoError;

/// An error returned by a command. It is sent to the window as
/// `{ code, message }`; the message is written for the user and never
/// carries secrets or server details.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AppError {
    /// There is no account on this device yet.
    #[error("There is no account on this device yet.")]
    NoAccount,
    /// An account is already set up on this device.
    #[error("An account is already set up on this device.")]
    AccountExists,
    /// The master password field was empty.
    #[error("Enter your master password.")]
    EmptyPassword,
    /// A new master password is too short.
    #[error("Use at least {0} characters for your master password.")]
    PasswordTooShort(usize),
    /// A master password is longer than the maximum.
    #[error("That master password is too long.")]
    PasswordTooLong,
    /// A new master password is too easy to guess.
    #[error("Choose a stronger master password: longer, with words that don't belong together.")]
    WeakPassword,
    /// A new master password appears in known data breaches.
    #[error(
        "That password has shown up in data breaches, so attackers already try it. Choose a different one."
    )]
    BreachedPassword,
    /// The two new passwords differ.
    #[error("The two passwords don't match.")]
    PasswordsDiffer,
    /// The new master password is the current one.
    #[error("Choose a password different from your current one.")]
    SamePassword,
    /// The email address is not valid.
    #[error("Enter a valid email address.")]
    InvalidEmail,
    /// The Secret Key could not be read.
    #[error("That Secret Key isn't valid: {0}. Check it against your Emergency Kit.")]
    InvalidSecretKey(String),
    /// The recovery key could not be read.
    #[error("That recovery key isn't valid: {0}. Check it against your Emergency Kit.")]
    InvalidRecoveryKey(String),
    /// The recovery key does not match the email address, or the account
    /// has no recovery key.
    #[error("That recovery key doesn't match this email address.")]
    WrongRecoveryKey,
    /// Wrong email, Secret Key or password; the server cannot say which.
    #[error("That email address, Secret Key or master password is wrong.")]
    WrongCredentials,
    /// Wrong master password while unlocking.
    #[error("That master password is wrong.")]
    WrongPassword,
    /// Someone already has an account with this email address.
    #[error("An account with this email address already exists.")]
    EmailTaken,
    /// Too many attempts.
    #[error("Too many attempts. Try again {0}.")]
    RateLimited(String),
    /// The session ended.
    #[error("Your session ended. Unlock again.")]
    SignedOut,
    /// The server could not be reached.
    #[error("Can't reach the BlackBoxus server. Check your internet connection and try again.")]
    Offline,
    /// The server refused for a reason the user cannot fix.
    #[error("The server couldn't do that right now. Try again later.")]
    Server,
    /// An answer from the server failed a check.
    #[error(
        "The server's answer failed a security check, so BlackBoxus stopped. \
         If this keeps happening, something may be tampering with your connection."
    )]
    Tampered,
    /// The Secret Key is missing from this device's credential store.
    #[error("This device no longer has your Secret Key. Sign in again with your Emergency Kit.")]
    SecretKeyMissing,
    /// Reading or writing this device's storage failed.
    #[error("BlackBoxus couldn't save to this device. Check there is free space and try again.")]
    Storage,
    /// This build does not know the key transparency log's key.
    #[error("This version of BlackBoxus isn't set up for this server yet. Update the app.")]
    NotConfigured,
    /// An item or vault no longer exists.
    #[error("That item no longer exists. It may have been deleted on another device.")]
    NotFound,
    /// The edit form held something invalid.
    #[error("Give the item a title.")]
    InvalidItem,
    /// A vault name is empty or too long.
    #[error("Give the vault a name of up to 64 characters.")]
    InvalidVaultName,
    /// The vault cannot be changed by this account.
    #[error("You can only view items in this vault.")]
    ReadOnly,
    /// The clipboard could not be used.
    #[error("Couldn't use the clipboard. Try again.")]
    Clipboard,
    /// A sharing ID could not be read.
    #[error("That isn't a sharing ID. Ask them to copy it from their Share screen.")]
    InvalidSharingId,
    /// The person to share with has not been checked.
    #[error("Look the person up and compare the safety number first.")]
    NotVerified,
    /// The person already has access.
    #[error("They already have access to this vault.")]
    AlreadyMember,
    /// Sharing with yourself.
    #[error("That's your own sharing ID.")]
    SelfShare,
    /// Emergency access was asked for before the waiting period ended.
    #[error("The waiting period isn't over yet.")]
    TooEarly,
    /// No emergency access in the state the request needs.
    #[error("That emergency access isn't available. Check its status and try again.")]
    EmergencyUnavailable,
    /// The import file could not be read.
    #[error("That file isn't a password export BlackBoxus can read. Export as CSV and try again.")]
    ImportUnreadable,
    /// The import file is too large.
    #[error("That file is too large to import (the limit is 20 MB and 10,000 entries).")]
    ImportTooLarge,
    /// The camera may not be used.
    #[error(
        "BlackBoxus needs the camera to scan the code. Allow it in your phone's Settings, or paste the setup key instead."
    )]
    CameraDenied,
    /// The scan was cancelled.
    #[error("Scan cancelled.")]
    ScanCancelled,
    /// Everything in the file is already in the vault.
    #[error("Everything in this file is already in this vault, so there's nothing new to import.")]
    NothingNew,
    /// An import is already running.
    #[error("An import is already running.")]
    ImportRunning,
    /// Windows Hello (or, on a phone, fingerprint unlock) is not set up or
    /// not available.
    #[cfg_attr(
        desktop,
        error(
            "Windows Hello isn't available. Set it up in Windows Settings, under Accounts, Sign-in options."
        )
    )]
    #[cfg_attr(
        mobile,
        error(
            "Fingerprint unlock isn't available. Add a fingerprint or face in your phone's Settings, under Security."
        )
    )]
    HelloUnavailable,
    /// The user cancelled the check.
    #[cfg_attr(desktop, error("Windows Hello was cancelled."))]
    #[cfg_attr(mobile, error("Fingerprint check cancelled."))]
    HelloCancelled,
    /// Too many failed tries: the phone has locked fingerprints for now.
    #[error(
        "Too many tries, so your phone has paused fingerprints for a while. Use your master password, or try again later."
    )]
    HelloLockedOut,
    /// The key is gone: on Windows after a reset, on a phone after a new
    /// fingerprint or face was added.
    #[cfg_attr(
        desktop,
        error(
            "Windows Hello unlock needs setting up again. Unlock with your master password, then turn it back on."
        )
    )]
    #[cfg_attr(
        mobile,
        error(
            "Your phone's fingerprints or face changed, so fingerprint unlock needs setting up again. Unlock with your master password, then turn it back on."
        )
    )]
    HelloMissing,
    /// Hello unlock is not turned on.
    #[cfg_attr(
        desktop,
        error("Windows Hello unlock is off. Unlock with your master password.")
    )]
    #[cfg_attr(
        mobile,
        error("Fingerprint unlock is off. Unlock with your master password.")
    )]
    HelloOff,
    /// It has been too long since the master password was used.
    #[cfg_attr(
        desktop,
        error(
            "It's been 14 days, so enter your master password this time. Windows Hello works again after that."
        )
    )]
    #[cfg_attr(
        mobile,
        error(
            "It's been 14 days, so enter your master password this time. Your fingerprint works again after that."
        )
    )]
    PasswordNeeded,
    /// A change was attempted while offline.
    #[error(
        "You're offline, so your vaults are read-only. Changes can be made once you're connected again."
    )]
    ReadOnlyOffline,
    /// Too many changes are waiting to be sent.
    #[error(
        "Too many changes are waiting to be sent. Connect to the internet so they can sync first."
    )]
    TooManyChanges,
    /// A one-time code secret could not be read.
    #[error(
        "That isn't a one-time code secret. Paste the setup key or otpauth:// link the site shows."
    )]
    InvalidTotp,
    /// An unsupported setting.
    #[error("That setting isn't available.")]
    InvalidSetting,
    /// Only an owner can do this.
    #[error("Only the vault's owner can do that.")]
    NotOwner,
    /// The vault would be left without an owner.
    #[error("A vault needs at least one owner. Make someone else an owner first.")]
    LastOwner,
    /// The vaults are locked.
    #[error("Your vaults are locked. Unlock them first.")]
    Locked,
    /// Another action is still running.
    #[error("Please wait for the last step to finish.")]
    Busy,
    /// Anything unexpected.
    #[error("Something went wrong. Please try again.")]
    Internal,
}

impl AppError {
    /// A stable code the window can match on.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoAccount => "no_account",
            Self::AccountExists => "account_exists",
            Self::EmptyPassword => "empty_password",
            Self::PasswordTooShort(_) => "password_too_short",
            Self::PasswordTooLong => "password_too_long",
            Self::WeakPassword => "weak_password",
            Self::BreachedPassword => "breached_password",
            Self::PasswordsDiffer => "passwords_differ",
            Self::SamePassword => "same_password",
            Self::InvalidEmail => "invalid_email",
            Self::InvalidSecretKey(_) => "invalid_secret_key",
            Self::InvalidRecoveryKey(_) => "invalid_recovery_key",
            Self::WrongRecoveryKey => "wrong_recovery_key",
            Self::WrongCredentials => "wrong_credentials",
            Self::WrongPassword => "wrong_password",
            Self::EmailTaken => "email_taken",
            Self::RateLimited(_) => "rate_limited",
            Self::SignedOut => "signed_out",
            Self::Offline => "offline",
            Self::Server => "server",
            Self::Tampered => "tampered",
            Self::SecretKeyMissing => "secret_key_missing",
            Self::Storage => "storage",
            Self::NotConfigured => "not_configured",
            Self::NotFound => "not_found",
            Self::InvalidItem => "invalid_item",
            Self::ReadOnly => "read_only",
            Self::InvalidVaultName => "invalid_vault_name",
            Self::Clipboard => "clipboard",
            Self::Locked => "locked",
            Self::NotOwner => "not_owner",
            Self::LastOwner => "last_owner",
            Self::InvalidSetting => "invalid_setting",
            Self::InvalidTotp => "invalid_totp",
            Self::ReadOnlyOffline => "read_only_offline",
            Self::TooManyChanges => "too_many_changes",
            Self::HelloUnavailable => "hello_unavailable",
            Self::HelloCancelled => "hello_cancelled",
            Self::HelloLockedOut => "hello_locked_out",
            Self::HelloMissing => "hello_missing",
            Self::HelloOff => "hello_off",
            Self::PasswordNeeded => "password_needed",
            Self::ImportUnreadable => "import_unreadable",
            Self::ImportTooLarge => "import_too_large",
            Self::ImportRunning => "import_running",
            Self::NothingNew => "nothing_new",
            Self::CameraDenied => "camera_denied",
            Self::ScanCancelled => "scan_cancelled",
            Self::InvalidSharingId => "invalid_sharing_id",
            Self::NotVerified => "not_verified",
            Self::AlreadyMember => "already_member",
            Self::SelfShare => "self_share",
            Self::TooEarly => "too_early",
            Self::EmergencyUnavailable => "emergency_unavailable",
            Self::Busy => "busy",
            Self::Internal => "internal",
        }
    }
}

impl Serialize for AppError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("AppError", 2)?;
        s.serialize_field("code", self.code())?;
        s.serialize_field("message", &self.to_string())?;
        s.end()
    }
}

/// Says when to try again, in words.
fn retry_in(seconds: Option<u64>) -> String {
    match seconds {
        Some(s) if s <= 90 => "in a minute".into(),
        Some(s) => format!("in {} minutes", s.div_ceil(60)),
        None => "later".into(),
    }
}

impl From<CryptoError> for AppError {
    fn from(error: CryptoError) -> Self {
        match error {
            CryptoError::PasswordEmpty => Self::EmptyPassword,
            CryptoError::PasswordTooShort { min_chars } => Self::PasswordTooShort(min_chars),
            CryptoError::PasswordTooLong { .. } => Self::PasswordTooLong,
            CryptoError::InvalidIdentity => Self::InvalidEmail,
            CryptoError::InvalidSecretKey(why) => Self::InvalidSecretKey(why.to_string()),
            CryptoError::Authentication => Self::WrongCredentials,
            _ => Self::Internal,
        }
    }
}

impl From<ClientError> for AppError {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::WrongCredentials => Self::WrongCredentials,
            ClientError::SignedOut => Self::SignedOut,
            ClientError::RateLimited(after) => Self::RateLimited(retry_in(after)),
            ClientError::Server { status: 409, .. } => Self::EmailTaken,
            ClientError::Server { .. } => Self::Server,
            ClientError::InvalidResponse => Self::Tampered,
            ClientError::Crypto(e) => e.into(),
            _ => Self::Internal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_and_codes() {
        let e = AppError::from(ClientError::RateLimited(Some(600)));
        assert_eq!(e.to_string(), "Too many attempts. Try again in 10 minutes.");
        assert_eq!(e.code(), "rate_limited");
        assert_eq!(
            AppError::from(ClientError::Server {
                status: 409,
                code: "conflict".into()
            }),
            AppError::EmailTaken
        );
        assert_eq!(
            AppError::from(ClientError::Crypto(CryptoError::PasswordTooShort {
                min_chars: 12
            }))
            .to_string(),
            "Use at least 12 characters for your master password."
        );
    }

    #[test]
    fn serialises_as_code_and_message() {
        let json = serde_json::to_string(&AppError::Offline).unwrap_or_default();
        assert!(json.starts_with(r#"{"code":"offline","message":"Can't reach"#));
    }
}
