//! Unlocking with Windows Hello instead of the master password (spec
//! section 10.4).
//!
//! Turning it on wraps the key set with a device key derived from a
//! Windows Hello signature (unlock method 3), and seals the session token
//! under the key set so the app can sync after a Hello unlock. Both are
//! kept only on this computer, in `device-unlock.json`. The master password
//! is asked for again after 14 days without it.

use std::fs;
use std::path::PathBuf;

use client_core::Session;
use client_core::login::Unlocked;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use vault_core::login::SessionToken;
use vault_core::{AccountId, KeySet, SymmetricKey, UnlockMethod, WRAPPED_KEY_SET_LEN, local};
use zeroize::Zeroizing;

use crate::error::AppError;
use crate::hello::HelloKeys;
use crate::storage::write_atomically;

const FILE: &str = "device-unlock.json";
const FORMAT: u32 = 1;
/// How long Hello unlocks keep working without the master password.
pub const PASSWORD_EVERY_MS: u64 = 14 * 86_400_000;
const CHALLENGE_LABEL: &[u8] = b"BlackBoxus v1 windows-hello challenge";
const KEY_LABEL: &[u8] = b"BlackBoxus v1 windows-hello device-key";
const SESSION_CONTEXT: &[u8] = b"device-unlock session";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    format: u32,
    /// The account, base64url.
    account_id: String,
    /// The key set wrapped with the device key, base64url.
    wrapped_key_set: String,
    /// The session token sealed under the key set, base64url.
    sealed_session: String,
    /// When the master password was last used, Unix milliseconds.
    password_ms: u64,
}

/// Whether Hello unlock is on, and whether it can be used now.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct HelloStatus {
    /// Windows Hello is set up on this computer.
    pub available: bool,
    /// Hello unlock is turned on for this account.
    pub enabled: bool,
    /// The master password is needed first (14 days have passed).
    pub needs_password: bool,
    /// The hardware is there but no fingerprint, face or screen lock is
    /// set up on the device yet.
    pub setup_needed: bool,
    /// Which it is: `windows_hello`, `fingerprint`, `touch_id` or `face_id`.
    pub kind: &'static str,
}

fn credential_name(account: &AccountId) -> String {
    format!("BlackBoxus {}", wire::b64(account.as_bytes()))
}

fn challenge(account: &AccountId) -> Vec<u8> {
    let mut c = CHALLENGE_LABEL.to_vec();
    c.extend_from_slice(account.as_bytes());
    c
}

fn device_key(signature: &[u8]) -> Result<SymmetricKey, AppError> {
    let mut key = Zeroizing::new([0_u8; 32]);
    Hkdf::<Sha256>::new(None, signature)
        .expand(KEY_LABEL, key.as_mut())
        .map_err(|_| AppError::Internal)?;
    Ok(SymmetricKey::from_bytes(*key))
}

/// Hello unlock for one computer's data folder.
pub struct DeviceUnlock {
    dir: PathBuf,
    hello: Box<dyn HelloKeys>,
}

impl core::fmt::Debug for DeviceUnlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DeviceUnlock").finish_non_exhaustive()
    }
}

impl DeviceUnlock {
    /// Hello unlock with files in `dir`.
    pub fn new(dir: PathBuf, hello: Box<dyn HelloKeys>) -> Self {
        Self { dir, hello }
    }

    fn load(&self, account: &AccountId) -> Option<Saved> {
        let text = fs::read_to_string(self.dir.join(FILE)).ok()?;
        let saved: Saved = serde_json::from_str(&text).ok()?;
        (saved.format == FORMAT && saved.account_id == wire::b64(account.as_bytes()))
            .then_some(saved)
    }

    fn save(&self, saved: &Saved) -> Result<(), AppError> {
        let json = serde_json::to_vec_pretty(saved).map_err(|_| AppError::Storage)?;
        write_atomically(&self.dir, FILE, &json)
    }

    /// The state to show in the window.
    pub fn status(&self, account: Option<&AccountId>, now_ms: u64) -> HelloStatus {
        let saved = account.and_then(|a| self.load(a));
        HelloStatus {
            available: self.hello.available(),
            enabled: saved.is_some(),
            needs_password: saved
                .is_some_and(|s| now_ms.saturating_sub(s.password_ms) > PASSWORD_EVERY_MS),
            setup_needed: self.hello.setup_needed(),
            kind: self.hello.kind(),
        }
    }

    fn seal_session(unlocked: &Unlocked) -> Result<String, AppError> {
        let sealed = local::seal(
            &unlocked.key_set,
            unlocked.session.account_id(),
            SESSION_CONTEXT,
            unlocked.session.token().as_bytes(),
        )?;
        Ok(wire::b64(&sealed))
    }

    /// Turns Hello unlock on, after a Hello check.
    ///
    /// # Errors
    ///
    /// Returns a Hello error, or [`AppError::Storage`].
    pub fn enable(&self, unlocked: &Unlocked, now_ms: u64) -> Result<(), AppError> {
        let account = *unlocked.session.account_id();
        let name = credential_name(&account);
        self.hello.create(&name)?;
        let signature = self.hello.sign(&name, &challenge(&account))?;
        let key = device_key(&signature)?;
        let wrapped = unlocked.key_set.wrap(
            &key,
            &account,
            unlocked.key_set_version,
            UnlockMethod::Device,
        )?;
        self.save(&Saved {
            format: FORMAT,
            account_id: wire::b64(account.as_bytes()),
            wrapped_key_set: wire::b64(&wrapped),
            sealed_session: Self::seal_session(unlocked)?,
            password_ms: now_ms,
        })
    }

    /// Records a master password unlock: restarts the 14 days and keeps
    /// the new session for Hello unlocks. Does nothing if Hello unlock is
    /// off.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Storage`] if the file cannot be written.
    pub fn password_used(&self, unlocked: &Unlocked, now_ms: u64) -> Result<(), AppError> {
        let Some(mut saved) = self.load(unlocked.session.account_id()) else {
            return Ok(());
        };
        saved.sealed_session = Self::seal_session(unlocked)?;
        saved.password_ms = now_ms;
        self.save(&saved)
    }

    /// Unlocks with Windows Hello.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::HelloOff`] if it is not turned on,
    /// [`AppError::PasswordNeeded`] after 14 days without the master
    /// password, a Hello error, or [`AppError::Tampered`] if the stored
    /// copy does not open.
    pub fn unlock(&self, account: &AccountId, now_ms: u64) -> Result<Unlocked, AppError> {
        let saved = self.load(account).ok_or(AppError::HelloOff)?;
        if now_ms.saturating_sub(saved.password_ms) > PASSWORD_EVERY_MS {
            return Err(AppError::PasswordNeeded);
        }
        let signature = match self
            .hello
            .sign(&credential_name(account), &challenge(account))
        {
            Ok(signature) => signature,
            Err(AppError::HelloMissing) => {
                // The key can't come back: turn unlocking off so the app
                // stops offering it, and the user can set it up again.
                self.disable(account)?;
                return Err(AppError::HelloMissing);
            }
            Err(e) => return Err(e),
        };
        let key = device_key(&signature)?;
        let wrapped =
            wire::unb64(&saved.wrapped_key_set, WRAPPED_KEY_SET_LEN).ok_or(AppError::Tampered)?;
        let (key_set, key_set_version) =
            KeySet::unwrap(&wrapped, &key, account, UnlockMethod::Device, 1)
                .map_err(|_| AppError::Tampered)?;
        let sealed = wire::unb64(&saved.sealed_session, 1024).ok_or(AppError::Tampered)?;
        let token = local::open(&key_set, account, SESSION_CONTEXT, &sealed)
            .map_err(|_| AppError::Tampered)?;
        let token: [u8; 32] = token
            .as_slice()
            .try_into()
            .map_err(|_| AppError::Tampered)?;
        Ok(Unlocked {
            session: Session::restore(SessionToken::from_bytes(token), *account),
            key_set,
            key_set_version,
        })
    }

    /// Turns Hello unlock off and deletes its key.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Storage`] if the file cannot be deleted.
    pub fn disable(&self, account: &AccountId) -> Result<(), AppError> {
        self.hello.delete(&credential_name(account));
        match fs::remove_file(self.dir.join(FILE)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(AppError::Storage),
        }
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    fn unlocked(account: AccountId) -> Result<Unlocked, AppError> {
        Ok(Unlocked {
            session: Session::restore(SessionToken::from_bytes([5; 32]), account),
            key_set: KeySet::generate()?,
            key_set_version: 1,
        })
    }

    fn dir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("blackboxus-hello-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn enable_unlock_and_disable() -> Result<(), AppError> {
        let account = AccountId::from_bytes([1; 16]);
        let device = DeviceUnlock::new(dir("cycle"), crate::hello::fake());
        assert!(!device.status(Some(&account), 0).enabled);
        assert_eq!(device.unlock(&account, 0).err(), Some(AppError::HelloOff));

        let first = unlocked(account)?;
        device.enable(&first, 1_000)?;
        assert!(device.status(Some(&account), 1_000).enabled);

        let again = device.unlock(&account, 2_000)?;
        assert_eq!(again.session.token().as_bytes(), &[5; 32]);
        assert_eq!(again.key_set_version, 1);
        // The unwrapped key set is the same: it opens what the first sealed.
        let sealed = local::seal(&first.key_set, &account, b"t", b"hello")?;
        assert_eq!(
            local::open(&again.key_set, &account, b"t", &sealed)?.as_slice(),
            b"hello"
        );

        // Another account's file is not used.
        let other = AccountId::from_bytes([2; 16]);
        assert_eq!(device.unlock(&other, 2_000).err(), Some(AppError::HelloOff));

        device.disable(&account)?;
        assert_eq!(
            device.unlock(&account, 3_000).err(),
            Some(AppError::HelloOff)
        );
        Ok(())
    }

    #[test]
    fn the_master_password_is_needed_every_14_days() -> Result<(), AppError> {
        let account = AccountId::from_bytes([3; 16]);
        let device = DeviceUnlock::new(dir("expiry"), crate::hello::fake());
        let first = unlocked(account)?;
        device.enable(&first, 0)?;
        let later = PASSWORD_EVERY_MS + 1;
        assert!(device.status(Some(&account), later).needs_password);
        assert_eq!(
            device.unlock(&account, later).err(),
            Some(AppError::PasswordNeeded)
        );
        // Unlocking with the password starts the 14 days again.
        device.password_used(&first, later)?;
        assert!(device.unlock(&account, later + 1).is_ok());
        Ok(())
    }

    #[test]
    fn a_tampered_file_does_not_open() -> Result<(), AppError> {
        let account = AccountId::from_bytes([4; 16]);
        let d = dir("tamper");
        let device = DeviceUnlock::new(d.clone(), crate::hello::fake());
        device.enable(&unlocked(account)?, 0)?;
        let path = d.join(FILE);
        let mut saved: Saved =
            serde_json::from_str(&fs::read_to_string(&path).map_err(|_| AppError::Storage)?)
                .map_err(|_| AppError::Storage)?;
        saved.sealed_session = wire::b64(&[0; 80]);
        device.save(&saved)?;
        assert_eq!(device.unlock(&account, 1).err(), Some(AppError::Tampered));
        Ok(())
    }

    #[test]
    fn a_key_the_phone_invalidated_turns_unlocking_off() -> Result<(), AppError> {
        let account = AccountId::from_bytes([6; 16]);
        let device = DeviceUnlock::new(dir("invalidated"), crate::hello::fake());
        let first = unlocked(account)?;
        device.enable(&first, 0)?;
        // As when a fingerprint is added: the key behind the check is gone.
        device.hello.delete(&credential_name(&account));
        assert_eq!(
            device.unlock(&account, 1).err(),
            Some(AppError::HelloMissing)
        );
        // Unlocking is off, so the app asks for the password and can offer
        // to set the fingerprint up again; doing so works.
        assert!(!device.status(Some(&account), 1).enabled);
        device.enable(&first, 2)?;
        assert!(device.unlock(&account, 3).is_ok());
        Ok(())
    }
}
