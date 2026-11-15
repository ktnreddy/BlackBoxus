//! Windows Hello as a source of a device key (spec section 10.4).
//!
//! Windows Hello keeps a non-exportable RSA key in the TPM for each named
//! credential and only uses it after the user's face, fingerprint or PIN.
//! Signing a fixed challenge with it gives the same signature every time
//! (RSA with PKCS #1 v1.5 padding is deterministic), and the device key is
//! derived from that signature. The signature, and so the device key, can
//! only be produced on this computer, by this Windows user, after Hello.

use zeroize::Zeroizing;

use crate::error::AppError;

/// Something that holds a key behind a user check and signs with it.
pub trait HelloKeys: Send + Sync {
    /// Whether it can be used on this computer.
    fn available(&self) -> bool;
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

/// The provider for this build.
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

/// The development stand-in, for tests.
#[cfg(all(test, not(windows)))]
pub fn fake() -> Box<dyn HelloKeys> {
    Box::new(fake::FakeHello::default())
}

/// No Windows Hello: macOS and Linux builds, until their own unlock methods
/// exist.
#[cfg(not(windows))]
struct Unavailable;

#[cfg(not(windows))]
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
#[cfg(not(windows))]
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
