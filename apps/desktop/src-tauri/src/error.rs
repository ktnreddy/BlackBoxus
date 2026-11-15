//! Errors the window can be shown.

use client_core::ClientError;
use serde::Serialize;
use vault_core::Error as CryptoError;

/// An error returned by a command. It is sent to the window as
/// `{ code, message }`; the message is written for the user and never
/// carries secrets or server details.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AppError {
    /// There is no account on this computer yet.
    #[error("There is no account on this computer yet.")]
    NoAccount,
    /// An account is already set up on this computer.
    #[error("An account is already set up on this computer.")]
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
    /// The two new passwords differ.
    #[error("The two passwords don't match.")]
    PasswordsDiffer,
    /// The email address is not valid.
    #[error("Enter a valid email address.")]
    InvalidEmail,
    /// The Secret Key could not be read.
    #[error("That Secret Key isn't valid: {0}. Check it against your Emergency Kit.")]
    InvalidSecretKey(String),
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
    /// The Secret Key is missing from this computer's credential store.
    #[error("This computer no longer has your Secret Key. Sign in again with your Emergency Kit.")]
    SecretKeyMissing,
    /// Reading or writing this computer's storage failed.
    #[error("BlackBoxus couldn't save to this computer. Check there is free space and try again.")]
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
    /// The import file could not be read.
    #[error("That file isn't a password export BlackBoxus can read. Export as CSV and try again.")]
    ImportUnreadable,
    /// The import file is too large.
    #[error("That file is too large to import (the limit is 20 MB and 10,000 entries).")]
    ImportTooLarge,
    /// An import is already running.
    #[error("An import is already running.")]
    ImportRunning,
    /// Windows Hello is not set up or not available.
    #[error(
        "Windows Hello isn't available. Set it up in Windows Settings, under Accounts, Sign-in options."
    )]
    HelloUnavailable,
    /// The user cancelled Windows Hello.
    #[error("Windows Hello was cancelled.")]
    HelloCancelled,
    /// The Hello key is gone, for example after a Windows reset.
    #[error(
        "Windows Hello unlock needs setting up again. Unlock with your master password, then turn it back on."
    )]
    HelloMissing,
    /// Hello unlock is not turned on.
    #[error("Windows Hello unlock is off. Unlock with your master password.")]
    HelloOff,
    /// It has been too long since the master password was used.
    #[error(
        "It's been 14 days, so enter your master password this time. Windows Hello works again after that."
    )]
    PasswordNeeded,
    /// A change was attempted while offline.
    #[error(
        "You're offline, so your vaults are read-only. Changes can be made once you're connected again."
    )]
    ReadOnlyOffline,
    /// A one-time code secret could not be read.
    #[error(
        "That isn't a one-time code secret. Paste the setup key or otpauth:// link the site shows."
    )]
    InvalidTotp,
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
            Self::PasswordsDiffer => "passwords_differ",
            Self::InvalidEmail => "invalid_email",
            Self::InvalidSecretKey(_) => "invalid_secret_key",
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
            Self::Clipboard => "clipboard",
            Self::Locked => "locked",
            Self::InvalidTotp => "invalid_totp",
            Self::ReadOnlyOffline => "read_only_offline",
            Self::HelloUnavailable => "hello_unavailable",
            Self::HelloCancelled => "hello_cancelled",
            Self::HelloMissing => "hello_missing",
            Self::HelloOff => "hello_off",
            Self::PasswordNeeded => "password_needed",
            Self::ImportUnreadable => "import_unreadable",
            Self::ImportTooLarge => "import_too_large",
            Self::ImportRunning => "import_running",
            Self::InvalidSharingId => "invalid_sharing_id",
            Self::NotVerified => "not_verified",
            Self::AlreadyMember => "already_member",
            Self::SelfShare => "self_share",
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
