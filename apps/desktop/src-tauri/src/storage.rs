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
    fn rejects_a_damaged_record() {
        let dir = temp_dir("damaged");
        assert!(write_atomically(&dir, ACCOUNT_FILE, b"{\"format\":1}").is_ok());
        assert_eq!(Storage::new(dir).load_account(), Err(AppError::Storage));
    }
}
