//! What the app keeps on this computer between runs.
//!
//! - `account.json` in the app's data folder: the email address, account
//!   ID and server. Nothing secret.
//! - The Secret Key, in the Windows Credential Manager, which encrypts it
//!   for the signed-in Windows user. Other builds keep it in memory only,
//!   for development.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use keyring_core::Entry;
use serde::{Deserialize, Serialize};
use vault_core::{AccountId, ClientIdentity, SecretKey};
use zeroize::Zeroizing;

use crate::error::AppError;

const ACCOUNT_FILE: &str = "account.json";
const OFFLINE_FILE: &str = "offline-unlock.json";
const SETTINGS_FILE: &str = "settings.json";

/// Preferences for this computer. Nothing secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// Lock after this many minutes without keyboard or mouse input.
    pub auto_lock_minutes: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_minutes: 10,
        }
    }
}

/// The auto-lock times on offer, in minutes.
pub const AUTO_LOCK_CHOICES: [u32; 6] = [1, 5, 10, 15, 30, 60];
const SERVICE: &str = "BlackBoxus";
const FORMAT: u32 = 1;

/// The account set up on this computer, as stored in `account.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRecord {
    /// File format version.
    pub format: u32,
    /// The canonical email address.
    pub email: String,
    /// The account ID, base64url.
    pub account_id: String,
    /// The server origin.
    pub server: String,
}

impl AccountRecord {
    /// A record for a signed-in account.
    pub fn new(identity: &ClientIdentity, account_id: &AccountId, server: &str) -> Self {
        Self {
            format: FORMAT,
            email: identity.as_str().into(),
            account_id: wire::b64(account_id.as_bytes()),
            server: server.into(),
        }
    }
}

/// Picks the credential store for this platform. Does nothing if one is
/// already set.
///
/// # Errors
///
/// Returns [`AppError::Storage`] if the store cannot be opened.
pub fn init_secret_store() -> Result<(), AppError> {
    static INIT: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = INIT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if keyring_core::get_default_store().is_some() {
        return Ok(());
    }
    #[cfg(windows)]
    let store = windows_native_keyring_store::Store::new().map_err(|_| AppError::Storage)?;
    #[cfg(not(windows))]
    let store = keyring_core::mock::Store::new().map_err(|_| AppError::Storage)?;
    keyring_core::set_default_store(store);
    Ok(())
}

/// Where the app keeps its files.
#[derive(Debug, Clone)]
pub struct Storage {
    dir: PathBuf,
}

impl Storage {
    /// Storage in `dir`, which is created when first written.
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Where vault copies are kept.
    pub fn vault_dir(&self) -> PathBuf {
        self.dir.join("vaults")
    }

    /// Reads the account record, if there is one.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Storage`] if the file exists but cannot be read
    /// or is not a valid record.
    pub fn load_account(&self) -> Result<Option<AccountRecord>, AppError> {
        let path = self.dir.join(ACCOUNT_FILE);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(AppError::Storage),
        };
        let record: AccountRecord = serde_json::from_str(&text).map_err(|_| AppError::Storage)?;
        if record.format != FORMAT {
            return Err(AppError::Storage);
        }
        Ok(Some(record))
    }

    /// Saves the account record and its Secret Key.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Storage`] if either cannot be written.
    pub fn save_account(
        &self,
        record: &AccountRecord,
        secret_key: &SecretKey,
    ) -> Result<(), AppError> {
        entry(record)?
            .set_password(&secret_key.to_display_string())
            .map_err(|_| AppError::Storage)?;
        let json = serde_json::to_vec_pretty(record).map_err(|_| AppError::Storage)?;
        write_atomically(&self.dir, ACCOUNT_FILE, &json)
    }

    /// Saves what is needed to unlock without the server.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Storage`] if it cannot be written.
    pub fn save_offline(&self, record: &client_core::login::OfflineRecord) -> Result<(), AppError> {
        let json = record.to_json().map_err(|_| AppError::Storage)?;
        write_atomically(&self.dir, OFFLINE_FILE, json.as_bytes())
    }

    /// Reads the record for unlocking without the server, if there is one.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Storage`] if it exists but cannot be read.
    pub fn load_offline(&self) -> Result<Option<client_core::login::OfflineRecord>, AppError> {
        match fs::read_to_string(self.dir.join(OFFLINE_FILE)) {
            Ok(text) => client_core::login::OfflineRecord::from_json(&text)
                .map(Some)
                .map_err(|_| AppError::Storage),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(AppError::Storage),
        }
    }

    /// Reads this computer's settings, or the defaults.
    pub fn settings(&self) -> Settings {
        fs::read_to_string(self.dir.join(SETTINGS_FILE))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    /// Saves this computer's settings.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Storage`] if they cannot be written.
    pub fn save_settings(&self, settings: &Settings) -> Result<(), AppError> {
        let json = serde_json::to_vec_pretty(settings).map_err(|_| AppError::Storage)?;
        write_atomically(&self.dir, SETTINGS_FILE, &json)
    }

    /// Removes the account from this computer: its Secret Key, the account
    /// record, the offline unlock record and every vault copy. Settings
    /// stay. Nothing on the server changes.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Storage`] if something cannot be deleted.
    pub fn remove_account(&self, record: &AccountRecord) -> Result<(), AppError> {
        match entry(record)?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => {}
            Err(_) => return Err(AppError::Storage),
        }
        for file in [ACCOUNT_FILE, OFFLINE_FILE] {
            match fs::remove_file(self.dir.join(file)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(AppError::Storage),
            }
        }
        match fs::remove_dir_all(self.vault_dir()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(AppError::Storage),
        }
    }

    /// Reads the account's Secret Key.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::SecretKeyMissing`] if the credential store has
    /// no Secret Key for the account, or [`AppError::Storage`].
    pub fn secret_key(&self, record: &AccountRecord) -> Result<SecretKey, AppError> {
        let text = match entry(record)?.get_password() {
            Ok(text) => Zeroizing::new(text),
            Err(keyring_core::Error::NoEntry) => return Err(AppError::SecretKeyMissing),
            Err(_) => return Err(AppError::Storage),
        };
        SecretKey::parse(&text).map_err(|_| AppError::SecretKeyMissing)
    }
}

fn entry(record: &AccountRecord) -> Result<Entry, AppError> {
    Entry::new(SERVICE, &format!("secret-key/{}", record.account_id)).map_err(|_| AppError::Storage)
}

/// Writes a file so a crash leaves either the old or the new contents.
pub(crate) fn write_atomically(dir: &Path, name: &str, contents: &[u8]) -> Result<(), AppError> {
    fs::create_dir_all(dir).map_err(|_| AppError::Storage)?;
    let tmp = dir.join(format!("{name}.tmp"));
    let mut file = fs::File::create(&tmp).map_err(|_| AppError::Storage)?;
    file.write_all(contents).map_err(|_| AppError::Storage)?;
    file.sync_all().map_err(|_| AppError::Storage)?;
    drop(file);
    fs::rename(&tmp, dir.join(name)).map_err(|_| AppError::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("blackboxus-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn account_round_trip() -> Result<(), AppError> {
        init_secret_store()?;
        let storage = Storage::new(temp_dir("round-trip"));
        assert_eq!(storage.load_account()?, None);

        let identity = ClientIdentity::new("Alex@Example.com")?;
        let account_id = AccountId::from_bytes([7; 16]);
        let record = AccountRecord::new(&identity, &account_id, "https://api.example.org");
        let key = SecretKey::generate()?;
        storage.save_account(&record, &key)?;

        assert_eq!(storage.load_account()?, Some(record.clone()));
        assert!(storage.secret_key(&record)? == key);
        Ok(())
    }

    #[test]
    fn missing_secret_key_is_reported() -> Result<(), AppError> {
        init_secret_store()?;
        let identity = ClientIdentity::new("sam@example.com")?;
        let record = AccountRecord::new(&identity, &AccountId::from_bytes([9; 16]), "x");
        let storage = Storage::new(temp_dir("missing"));
        assert_eq!(storage.secret_key(&record), Err(AppError::SecretKeyMissing));
        Ok(())
    }

    #[test]
    fn settings_and_removing_the_account() -> Result<(), AppError> {
        init_secret_store()?;
        let storage = Storage::new(temp_dir("remove"));
        assert_eq!(storage.settings().auto_lock_minutes, 10);
        storage.save_settings(&Settings {
            auto_lock_minutes: 5,
        })?;
        assert_eq!(storage.settings().auto_lock_minutes, 5);

        let identity = ClientIdentity::new("remove@example.com")?;
        let record = AccountRecord::new(&identity, &AccountId::from_bytes([8; 16]), "x");
        storage.save_account(&record, &SecretKey::generate()?)?;
        write_atomically(&storage.vault_dir(), "a.vault", b"sealed")?;
        storage.remove_account(&record)?;
        assert_eq!(storage.load_account()?, None);
        assert_eq!(storage.secret_key(&record), Err(AppError::SecretKeyMissing));
        assert!(!storage.vault_dir().exists());
        // Settings are kept for whoever signs in next.
        assert_eq!(storage.settings().auto_lock_minutes, 5);
        Ok(())
    }

    #[test]
    fn rejects_a_damaged_record() {
        let dir = temp_dir("damaged");
        assert!(write_atomically(&dir, ACCOUNT_FILE, b"{\"format\":1}").is_ok());
        assert_eq!(Storage::new(dir).load_account(), Err(AppError::Storage));
    }
}
