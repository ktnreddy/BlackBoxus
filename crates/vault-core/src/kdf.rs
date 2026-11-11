//! Two-secret key derivation (spec sections 3.4 and 3.5).

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::key::{KEY_LEN, SymmetricKey};
use crate::password::MasterPassword;
use crate::random;
use crate::secret_key::{SECRET_KEY_LEN, SecretKey};

/// Length of the account salt in bytes.
pub const SALT_LEN: usize = 16;

const LABEL_AUK: &[u8] = b"BlackBoxus v1 account-unlock-key";
const LABEL_OPAQUE: &[u8] = b"BlackBoxus v1 opaque-password";

/// Argon2id parameters stored with an account.
///
/// These come from the untrusted server when signing in, so they must pass
/// [`KdfParams::validate`] before use. [`derive_account_keys`] does this
/// automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Number of passes.
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    pub parallelism: u32,
}

impl KdfParams {
    /// Parameters for new accounts: 128 MiB, 4 passes, 4 lanes.
    pub const DEFAULT: Self = Self {
        memory_kib: 128 * 1024,
        iterations: 4,
        parallelism: 4,
    };

    /// Smallest accepted parameters, which prevent downgrade attacks.
    pub const MIN: Self = Self {
        memory_kib: 64 * 1024,
        iterations: 3,
        parallelism: 1,
    };

    /// Largest accepted parameters, which prevent resource exhaustion.
    pub const MAX: Self = Self {
        memory_kib: 1024 * 1024,
        iterations: 10,
        parallelism: 8,
    };

    /// Checks every parameter against [`KdfParams::MIN`] and
    /// [`KdfParams::MAX`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::KdfParamOutOfRange`] naming the first bad parameter.
    pub const fn validate(&self) -> Result<()> {
        if self.memory_kib < Self::MIN.memory_kib || self.memory_kib > Self::MAX.memory_kib {
            return Err(Error::KdfParamOutOfRange {
                param: "memory_kib",
            });
        }
        if self.iterations < Self::MIN.iterations || self.iterations > Self::MAX.iterations {
            return Err(Error::KdfParamOutOfRange {
                param: "iterations",
            });
        }
        if self.parallelism < Self::MIN.parallelism || self.parallelism > Self::MAX.parallelism {
            return Err(Error::KdfParamOutOfRange {
                param: "parallelism",
            });
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The per-account random salt. Not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountSalt([u8; SALT_LEN]);

impl AccountSalt {
    /// Generates a new random salt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomUnavailable`] if the generator fails.
    pub fn generate() -> Result<Self> {
        random::bytes().map(Self)
    }

    /// Wraps salt bytes received from the server.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SALT_LEN]) -> Self {
        Self(bytes)
    }

    /// The salt bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.0
    }
}

/// Keys derived from the master password and Secret Key.
#[derive(Debug)]
pub struct AccountKeys {
    /// Account Unlock Key: decrypts the account key set. Never leaves the
    /// device.
    pub account_unlock_key: SymmetricKey,
    /// Password input for OPAQUE login. Never sent to the server.
    pub opaque_password: SymmetricKey,
}

/// Derives the Account Unlock Key and OPAQUE password (spec section 3.5).
///
/// ```text
/// pw  = Argon2id(password, salt, m, t, p, 32)
/// prk = HKDF-Extract(salt, pw ‖ secret_key)
/// AUK = HKDF-Expand(prk, "BlackBoxus v1 account-unlock-key", 32)
/// OPW = HKDF-Expand(prk, "BlackBoxus v1 opaque-password", 32)
/// ```
///
/// # Errors
///
/// Returns [`Error::KdfParamOutOfRange`] if `params` fail validation (checked
/// before any work is done), or [`Error::KeyDerivation`] if a primitive
/// fails.
pub fn derive_account_keys(
    password: &MasterPassword,
    secret_key: &SecretKey,
    salt: &AccountSalt,
    params: &KdfParams,
) -> Result<AccountKeys> {
    params.validate()?;

    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::KeyDerivation)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut ikm = Zeroizing::new([0_u8; KEY_LEN + SECRET_KEY_LEN]);
    let (pw_part, sk_part) = ikm.split_at_mut(KEY_LEN);
    argon
        .hash_password_into(password.as_bytes(), salt.as_bytes(), pw_part)
        .map_err(|_| Error::KeyDerivation)?;
    sk_part.copy_from_slice(secret_key.as_bytes());

    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_bytes()), ikm.as_slice());

    let mut keys = AccountKeys {
        account_unlock_key: SymmetricKey::zeroed(),
        opaque_password: SymmetricKey::zeroed(),
    };
    hkdf.expand(LABEL_AUK, keys.account_unlock_key.as_mut_bytes())
        .map_err(|_| Error::KeyDerivation)?;
    hkdf.expand(LABEL_OPAQUE, keys.opaque_password.as_mut_bytes())
        .map_err(|_| Error::KeyDerivation)?;
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> (MasterPassword, SecretKey, AccountSalt) {
        (
            MasterPassword::new("correct horse battery staple").unwrap(),
            SecretKey::from_bytes([7; SECRET_KEY_LEN]),
            AccountSalt::from_bytes([9; SALT_LEN]),
        )
    }

    #[test]
    fn default_params_are_valid_and_within_bounds() {
        assert!(KdfParams::DEFAULT.validate().is_ok());
        assert!(KdfParams::MIN.validate().is_ok());
        assert!(KdfParams::MAX.validate().is_ok());
    }

    #[test]
    fn rejects_downgraded_parameters() {
        let weak = [
            KdfParams {
                memory_kib: 64 * 1024 - 1,
                ..KdfParams::MIN
            },
            KdfParams {
                iterations: 2,
                ..KdfParams::MIN
            },
            KdfParams {
                parallelism: 0,
                ..KdfParams::MIN
            },
        ];
        for params in weak {
            assert!(
                matches!(params.validate(), Err(Error::KdfParamOutOfRange { .. })),
                "{params:?}"
            );
        }
    }

    #[test]
    fn rejects_resource_exhausting_parameters() {
        let heavy = [
            KdfParams {
                memory_kib: 1024 * 1024 + 1,
                ..KdfParams::MIN
            },
            KdfParams {
                iterations: 11,
                ..KdfParams::MIN
            },
            KdfParams {
                parallelism: 9,
                ..KdfParams::MIN
            },
        ];
        for params in heavy {
            assert!(params.validate().is_err(), "{params:?}");
        }
    }

    #[test]
    fn derivation_refuses_bad_params_before_hashing() {
        let (pw, sk, salt) = fixtures();
        let bad = KdfParams {
            iterations: 1,
            ..KdfParams::MIN
        };
        assert!(matches!(
            derive_account_keys(&pw, &sk, &salt, &bad),
            Err(Error::KdfParamOutOfRange {
                param: "iterations"
            })
        ));
    }

    #[test]
    fn derivation_is_deterministic_and_keys_are_independent() {
        let (pw, sk, salt) = fixtures();
        let a = derive_account_keys(&pw, &sk, &salt, &KdfParams::MIN).unwrap();
        let b = derive_account_keys(&pw, &sk, &salt, &KdfParams::MIN).unwrap();
        assert_eq!(a.account_unlock_key, b.account_unlock_key);
        assert_eq!(a.opaque_password, b.opaque_password);
        assert_ne!(a.account_unlock_key, a.opaque_password);
    }

    #[test]
    fn every_input_changes_the_result() {
        let (pw, sk, salt) = fixtures();
        let base = derive_account_keys(&pw, &sk, &salt, &KdfParams::MIN).unwrap();

        let other_pw = MasterPassword::new("correct horse battery stapler").unwrap();
        let other_sk = SecretKey::from_bytes([8; SECRET_KEY_LEN]);
        let other_salt = AccountSalt::from_bytes([10; SALT_LEN]);
        let other_params = KdfParams {
            iterations: 4,
            ..KdfParams::MIN
        };

        let variants = [
            derive_account_keys(&other_pw, &sk, &salt, &KdfParams::MIN).unwrap(),
            derive_account_keys(&pw, &other_sk, &salt, &KdfParams::MIN).unwrap(),
            derive_account_keys(&pw, &sk, &other_salt, &KdfParams::MIN).unwrap(),
            derive_account_keys(&pw, &sk, &salt, &other_params).unwrap(),
        ];
        for v in &variants {
            assert_ne!(v.account_unlock_key, base.account_unlock_key);
            assert_ne!(v.opaque_password, base.opaque_password);
        }
    }
}
