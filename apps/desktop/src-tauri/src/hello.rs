//! Windows Hello as a source of a device key (spec section 10.4).
//!
//! Windows Hello keeps a non-exportable RSA key in the TPM for each named
//! credential and only uses it after the user's face, fingerprint or PIN.
//! Signing a fixed challenge with it gives the same signature every time
//! (RSA with PKCS #1 v1.5 padding is deterministic), and the device key is
//! derived from that signature. The signature, and so the device key, can
//! only be produced on this computer, by this Windows user, after Hello.
//!
//! Android (fingerprint) and Apple devices (Touch ID, Face ID) keep a random
//! secret that the system releases only after a biometric check, and "sign"
//! with an HMAC keyed by it, which is just as deterministic.

use zeroize::Zeroizing;

use crate::error::AppError;

/// Something that holds a key behind a user check and signs with it.
pub trait HelloKeys: Send + Sync {
    /// Whether it can be used on this computer.
    fn available(&self) -> bool;
    /// Whether the hardware is there but nothing is set up yet (no
    /// fingerprint, face or screen lock), so the user can be told how.
    fn setup_needed(&self) -> bool {
        false
    }
    /// What the person knows it as, for the screens: `windows_hello`,
    /// `fingerprint`, `touch_id` or `face_id`.
    fn kind(&self) -> &'static str {
        "windows_hello"
    }
    /// Creates (or replaces) the named key, asking the user to verify.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::HelloCancelled`] or [`AppError::HelloUnavailable`].
    fn create(&self, name: &str) -> Result<(), AppError>;
    /// Signs `challenge` with the named key, asking the user to verify.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::HelloCancelled`], or [`AppError::HelloMissing`]
    /// if the key no longer exists.
    fn sign(&self, name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppError>;
    /// Deletes the named key, if it exists.
    fn delete(&self, name: &str);
}

/// The provider for this build. Android uses [`fingerprint`] and Apple
/// devices [`touch_id`] instead.
#[cfg(not(any(target_os = "android", target_os = "macos", target_os = "ios")))]
pub fn provider() -> Box<dyn HelloKeys> {
    #[cfg(windows)]
    {
        Box::new(windows_hello::WindowsHello)
    }
    #[cfg(not(windows))]
    {
        if cfg!(debug_assertions) && std::env::var_os("BLACKBOXUS_FAKE_HELLO").is_some() {
            Box::new(fake::FakeHello::default())
        } else {
            Box::new(Unavailable)
        }
    }
}

/// Fingerprint (or face) unlock on Android, keeping its secret in files
/// in `dir`.
#[cfg(target_os = "android")]
pub fn fingerprint(app: tauri::AppHandle, dir: std::path::PathBuf) -> Box<dyn HelloKeys> {
    Box::new(android::Fingerprint::new(app, dir))
}

/// Touch ID or Face ID on a Mac, iPhone or iPad.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn touch_id(app: tauri::AppHandle) -> Box<dyn HelloKeys> {
    if cfg!(debug_assertions) && std::env::var_os("BLACKBOXUS_FAKE_HELLO").is_some() {
        Box::new(fake::FakeHello::default())
    } else {
        Box::new(apple::TouchId::new(app))
    }
}

/// The development stand-in, for tests.
#[cfg(all(test, not(any(windows, target_os = "android"))))]
pub fn fake() -> Box<dyn HelloKeys> {
    Box::new(fake::FakeHello::default())
}

/// Nothing to unlock with: Linux builds, until a method exists there.
#[cfg(not(any(windows, target_os = "android", target_os = "macos", target_os = "ios")))]
struct Unavailable;

#[cfg(not(any(windows, target_os = "android", target_os = "macos", target_os = "ios")))]
impl HelloKeys for Unavailable {
    fn available(&self) -> bool {
        false
    }
    fn create(&self, _: &str) -> Result<(), AppError> {
        Err(AppError::HelloUnavailable)
    }
    fn sign(&self, _: &str, _: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppError> {
        Err(AppError::HelloUnavailable)
    }
    fn delete(&self, _: &str) {}
}

#[cfg(windows)]
mod windows_hello {
    use windows::Security::Credentials::{
        KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::core::{Array, HSTRING};
    use zeroize::Zeroizing;

    use super::HelloKeys;
    use crate::error::AppError;

    fn status_error(status: KeyCredentialStatus) -> AppError {
        if status == KeyCredentialStatus::UserCanceled {
            AppError::HelloCancelled
        } else if status == KeyCredentialStatus::NotFound {
            AppError::HelloMissing
        } else {
            AppError::HelloUnavailable
        }
    }

    pub(super) struct WindowsHello;

    impl HelloKeys for WindowsHello {
        fn available(&self) -> bool {
            KeyCredentialManager::IsSupportedAsync()
                .and_then(|op| op.join())
                .unwrap_or(false)
        }

        fn create(&self, name: &str) -> Result<(), AppError> {
            let result = KeyCredentialManager::RequestCreateAsync(
                &HSTRING::from(name),
                KeyCredentialCreationOption::ReplaceExisting,
            )
            .and_then(|op| op.join())
            .map_err(|_| AppError::HelloUnavailable)?;
            let status = result.Status().map_err(|_| AppError::HelloUnavailable)?;
            if status == KeyCredentialStatus::Success {
                Ok(())
            } else {
                Err(status_error(status))
            }
        }

        fn sign(&self, name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppError> {
            let opened = KeyCredentialManager::OpenAsync(&HSTRING::from(name))
                .and_then(|op| op.join())
                .map_err(|_| AppError::HelloUnavailable)?;
            let status = opened.Status().map_err(|_| AppError::HelloUnavailable)?;
            if status != KeyCredentialStatus::Success {
                return Err(status_error(status));
            }
            let credential = opened
                .Credential()
                .map_err(|_| AppError::HelloUnavailable)?;
            let data = CryptographicBuffer::CreateFromByteArray(challenge)
                .map_err(|_| AppError::HelloUnavailable)?;
            let signed = credential
                .RequestSignAsync(&data)
                .and_then(|op| op.join())
                .map_err(|_| AppError::HelloUnavailable)?;
            let status = signed.Status().map_err(|_| AppError::HelloUnavailable)?;
            if status != KeyCredentialStatus::Success {
                return Err(status_error(status));
            }
            let buffer = signed.Result().map_err(|_| AppError::HelloUnavailable)?;
            let mut bytes = Array::<u8>::new();
            CryptographicBuffer::CopyToByteArray(&buffer, &mut bytes)
                .map_err(|_| AppError::HelloUnavailable)?;
            Ok(Zeroizing::new(bytes.to_vec()))
        }

        fn delete(&self, name: &str) {
            // Best effort: the key may already be gone.
            let _ =
                KeyCredentialManager::DeleteAsync(&HSTRING::from(name)).and_then(|op| op.join());
        }
    }
}

/// A stand-in for development on Linux, enabled with
/// `BLACKBOXUS_FAKE_HELLO=1` in debug builds only. It has no user check
/// and its keys live in memory.
#[cfg(not(any(windows, target_os = "android")))]
mod fake {
    use std::collections::HashMap;
    use std::sync::{Mutex, PoisonError};

    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    use super::HelloKeys;
    use crate::error::AppError;

    #[derive(Default)]
    pub(super) struct FakeHello {
        keys: Mutex<HashMap<String, [u8; 32]>>,
    }

    impl HelloKeys for FakeHello {
        fn available(&self) -> bool {
            true
        }
        fn create(&self, name: &str) -> Result<(), AppError> {
            let mut key = [0_u8; 32];
            getrandom::fill(&mut key).map_err(|_| AppError::Internal)?;
            self.keys
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(name.to_owned(), key);
            Ok(())
        }
        fn sign(&self, name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppError> {
            let keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
            let key = keys.get(name).ok_or(AppError::HelloMissing)?;
            Ok(Zeroizing::new(
                Sha256::new()
                    .chain_update(key)
                    .chain_update(challenge)
                    .finalize()
                    .to_vec(),
            ))
        }
        fn delete(&self, name: &str) {
            self.keys
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(name);
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple {
    //! The secret is a keychain item in the "data protection" keychain with
    //! an access control of `biometryCurrentSet`: the system hands it over
    //! only after Touch ID or Face ID with the fingers or face enrolled when
    //! it was made. Enrolling another one, or removing the passcode, makes
    //! it unreadable for good, so unlock turns off (as on Android). It is
    //! "this device only": never in backups or on another device.
    //!
    //! On a Mac the data protection keychain needs a signed app; an
    //! unsigned build reports Touch ID as unavailable.

    use std::sync::OnceLock;

    use hmac::{Hmac, KeyInit, Mac};
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::passwords::{
        AccessControlOptions, PasswordOptions, delete_generic_password_options, generic_password,
        set_generic_password_options,
    };
    use sha2::Sha256;
    use tauri_plugin_biometric::BiometricExt;
    use zeroize::Zeroizing;

    use super::HelloKeys;
    use crate::error::AppError;

    const SERVICE: &str = "BlackBoxus device unlock";

    // Security framework result codes (SecBase.h).
    const USER_CANCELED: i32 = -128;
    const AUTH_FAILED: i32 = -25293;
    const ITEM_NOT_FOUND: i32 = -25300;

    pub(super) struct TouchId {
        app: tauri::AppHandle,
    }

    impl TouchId {
        pub(super) fn new(app: tauri::AppHandle) -> Self {
            Self { app }
        }
    }

    fn options(name: &str) -> PasswordOptions {
        let mut options = PasswordOptions::new_generic_password(SERVICE, name);
        options.use_protected_keychain();
        options
    }

    /// Whether this build may use the data protection keychain: always on
    /// iOS; on a Mac only when the app is signed with an application
    /// identifier. Tried once with a harmless item.
    fn keychain_usable() -> bool {
        static USABLE: OnceLock<bool> = OnceLock::new();
        *USABLE.get_or_init(|| {
            let probe = "probe";
            let written = set_generic_password_options(b"probe", options(probe)).is_ok();
            // Best effort: the probe may not have been written.
            let _ = delete_generic_password_options(options(probe));
            written
        })
    }

    fn failure(code: i32) -> AppError {
        match code {
            USER_CANCELED => AppError::HelloCancelled,
            AUTH_FAILED => AppError::HelloLockedOut,
            // Gone, or made unreadable by a change to Touch ID or Face ID.
            ITEM_NOT_FOUND => AppError::HelloMissing,
            _ => AppError::HelloUnavailable,
        }
    }

    impl HelloKeys for TouchId {
        fn kind(&self) -> &'static str {
            match self.app.biometric().status().map(|s| s.biometry_type) {
                Ok(tauri_plugin_biometric::BiometryType::FaceID) => "face_id",
                _ => "touch_id",
            }
        }

        fn available(&self) -> bool {
            self.app.biometric().status().is_ok_and(|s| s.is_available) && keychain_usable()
        }

        fn setup_needed(&self) -> bool {
            self.app.biometric().status().is_ok_and(|s| {
                !s.is_available
                    && matches!(
                        s.error_code.as_deref(),
                        Some("biometryNotEnrolled" | "passcodeNotSet")
                    )
            })
        }

        fn create(&self, name: &str) -> Result<(), AppError> {
            if !self.available() {
                return Err(AppError::HelloUnavailable);
            }
            let mut secret = Zeroizing::new([0_u8; 32]);
            getrandom::fill(secret.as_mut()).map_err(|_| AppError::Internal)?;
            let access = SecAccessControl::create_with_protection(
                Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
                AccessControlOptions::BIOMETRY_CURRENT_SET.bits(),
            )
            .map_err(|_| AppError::HelloUnavailable)?;
            // Replacing an item behind Touch ID would ask for it; a fresh one
            // doesn't, so the first unlock is the only check.
            let _ = delete_generic_password_options(options(name));
            let mut item = options(name);
            item.set_access_control(access);
            item.set_label("BlackBoxus unlock");
            set_generic_password_options(secret.as_ref(), item).map_err(|e| failure(e.code()))
        }

        fn sign(&self, name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppError> {
            let secret =
                Zeroizing::new(generic_password(options(name)).map_err(|e| failure(e.code()))?);
            if secret.len() != 32 {
                return Err(AppError::HelloMissing);
            }
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&secret)
                .map_err(|_| AppError::Internal)?;
            mac.update(challenge);
            Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
        }

        fn delete(&self, name: &str) {
            // Best effort: it may already be gone.
            let _ = delete_generic_password_options(options(name));
        }
    }
}

/// Android's fingerprint or face unlock, through the Keystore.
///
/// Android has no deterministic signing key like Windows Hello's, so each
/// credential is a random 32-byte secret, encrypted with an AES-256-GCM
/// Keystore key that only works right after a strong biometric check
/// (`BiometricPrompt` with a `CryptoObject`). Android deletes that key when
/// someone adds a new fingerprint or face, which turns fingerprint unlock
/// off until it is set up again with the master password. The "signature"
/// is HMAC-SHA256 of the challenge under the secret: the same every time,
/// and only computable after the biometric check.
#[cfg(target_os = "android")]
mod android {
    use std::path::PathBuf;
    use std::sync::{Mutex, PoisonError};

    use hmac::{Hmac, KeyInit, Mac};
    use sha2::{Digest, Sha256};
    use tauri_plugin_biometric::{AuthOptions, BiometricExt};
    use zeroize::Zeroizing;

    use super::HelloKeys;
    use crate::error::AppError;
    use crate::storage::write_atomically;

    pub(super) struct Fingerprint {
        app: tauri::AppHandle,
        dir: PathBuf,
        /// The secret just created, so turning unlock on needs one
        /// fingerprint check, not two. Taken by the next `sign`.
        fresh: Mutex<Option<(String, Zeroizing<[u8; 32]>)>>,
    }

    impl Fingerprint {
        pub(super) fn new(app: tauri::AppHandle, dir: PathBuf) -> Self {
            Self {
                app,
                dir,
                fresh: Mutex::new(None),
            }
        }

        /// The file holding the encrypted secret for `name`.
        fn file_name(name: &str) -> String {
            let digest = Sha256::digest(name.as_bytes());
            let short: Vec<u8> = digest.iter().take(12).copied().collect();
            format!("fingerprint-{}.txt", wire::b64(&short))
        }

        fn options(title: &str) -> AuthOptions {
            AuthOptions {
                title: Some(title.to_owned()),
                subtitle: Some("BlackBoxus".to_owned()),
                cancel_title: Some("Use master password".to_owned()),
                ..AuthOptions::default()
            }
        }
    }

    /// Sorts the plugin's failure into the app's errors, by the error
    /// codes in its Android code (BiometricPlugin.kt).
    fn failure(error: &tauri_plugin_biometric::Error) -> AppError {
        let text = format!("{error:?}");
        if text.contains("userCancel") || text.contains("systemCancel") {
            AppError::HelloCancelled
        } else if text.contains("biometryLockout") {
            AppError::HelloLockedOut
        } else if text.contains("biometryNotEnrolled") || text.contains("passcodeNotSet") {
            AppError::HelloUnavailable
        } else if text.contains("Failed to initialize the cipher")
            || text.contains("Failed to decrypt")
        {
            // The Keystore key no longer opens: Android invalidates it when
            // a fingerprint or face is added, or the screen lock removed.
            AppError::HelloMissing
        } else {
            AppError::HelloUnavailable
        }
    }

    impl HelloKeys for Fingerprint {
        fn kind(&self) -> &'static str {
            "fingerprint"
        }

        fn available(&self) -> bool {
            self.app.biometric().status().is_ok_and(|s| s.is_available)
        }

        fn setup_needed(&self) -> bool {
            self.app.biometric().status().is_ok_and(|s| {
                !s.is_available
                    && matches!(
                        s.error_code.as_deref(),
                        Some("biometryNotEnrolled" | "passcodeNotSet")
                    )
            })
        }

        fn create(&self, name: &str) -> Result<(), AppError> {
            let mut secret = Zeroizing::new([0_u8; 32]);
            getrandom::fill(secret.as_mut()).map_err(|_| AppError::Internal)?;
            let plain = Zeroizing::new(wire::b64(secret.as_ref()));
            let options = AuthOptions {
                data_to_encrypt: Some(plain.to_string()),
                ..Self::options("Turn on fingerprint unlock")
            };
            let sealed = self
                .app
                .biometric()
                .biometric_cipher("Confirm it's you".to_owned(), options)
                .map_err(|e| failure(&e))?;
            write_atomically(&self.dir, &Self::file_name(name), sealed.data.as_bytes())?;
            *self.fresh.lock().unwrap_or_else(PoisonError::into_inner) =
                Some((name.to_owned(), secret));
            Ok(())
        }

        fn sign(&self, name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppError> {
            let fresh = self
                .fresh
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
                .filter(|(n, _)| n == name);
            let secret = if let Some((_, secret)) = fresh {
                secret
            } else {
                let sealed = std::fs::read_to_string(self.dir.join(Self::file_name(name)))
                    .map_err(|_| AppError::HelloMissing)?;
                let options = AuthOptions {
                    data_to_decrypt: Some(sealed),
                    ..Self::options("Unlock BlackBoxus")
                };
                let opened = self
                    .app
                    .biometric()
                    .biometric_cipher("Use your fingerprint".to_owned(), options)
                    .map_err(|e| failure(&e))?;
                let opened = Zeroizing::new(opened.data);
                let bytes = wire::unb64_array::<32>(&opened).ok_or(AppError::HelloMissing)?;
                Zeroizing::new(bytes)
            };
            let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(secret.as_ref())
                .map_err(|_| AppError::Internal)?;
            mac.update(challenge);
            Ok(Zeroizing::new(mac.finalize().into_bytes().to_vec()))
        }

        fn delete(&self, name: &str) {
            // Best effort: the file may already be gone.
            let _ = std::fs::remove_file(self.dir.join(Self::file_name(name)));
        }
    }
}
