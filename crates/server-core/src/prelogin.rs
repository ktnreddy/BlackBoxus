//! Pre-login answers for unknown accounts (spec section 3.8).
//!
//! The server must answer a request for an unknown email address with a salt
//! and parameters that look exactly like a real account's, so that responses
//! do not reveal which addresses have accounts.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use vault_core::{AccountSalt, ClientIdentity, KdfParams, SALT_LEN};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

const LABEL_FAKE_SALT: &[u8] = b"BlackBoxus v1 fake-salt";

/// Length of the fake-salt key in bytes.
pub const FAKE_SALT_KEY_LEN: usize = 32;

/// Server secret used to derive stable fake salts for unknown accounts.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FakeSaltKey([u8; FAKE_SALT_KEY_LEN]);

impl FakeSaltKey {
    /// Loads the key from the server's secret store.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfiguration`] if `bytes` has the wrong length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let array: [u8; FAKE_SALT_KEY_LEN] =
            bytes.try_into().map_err(|_| Error::InvalidConfiguration)?;
        Ok(Self(array))
    }

    /// The salt and parameters to return for an email address with no
    /// account. The same address always gets the same answer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfiguration`] if HMAC cannot be initialised.
    pub fn fake_prelogin(&self, client: &ClientIdentity) -> Result<(AccountSalt, KdfParams)> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.0)
            .map_err(|_| Error::InvalidConfiguration)?;
        mac.update(LABEL_FAKE_SALT);
        mac.update(client.as_bytes());
        let tag = mac.finalize().into_bytes();
        let mut salt = [0_u8; SALT_LEN];
        for (dst, src) in salt.iter_mut().zip(tag.iter()) {
            *dst = *src;
        }
        Ok((AccountSalt::from_bytes(salt), KdfParams::DEFAULT))
    }
}

impl core::fmt::Debug for FakeSaltKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FakeSaltKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_answers_are_stable_and_per_address() {
        let key = FakeSaltKey::from_bytes(&[5; FAKE_SALT_KEY_LEN]).unwrap();
        let alice = ClientIdentity::new("alice@example.com").unwrap();
        let bob = ClientIdentity::new("bob@example.com").unwrap();

        let (a1, p1) = key.fake_prelogin(&alice).unwrap();
        let (a2, _) = key.fake_prelogin(&alice).unwrap();
        let (b, _) = key.fake_prelogin(&bob).unwrap();
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
        assert_eq!(p1, KdfParams::DEFAULT);
    }

    #[test]
    fn different_keys_give_different_salts() {
        let alice = ClientIdentity::new("alice@example.com").unwrap();
        let k1 = FakeSaltKey::from_bytes(&[1; FAKE_SALT_KEY_LEN]).unwrap();
        let k2 = FakeSaltKey::from_bytes(&[2; FAKE_SALT_KEY_LEN]).unwrap();
        assert_ne!(
            k1.fake_prelogin(&alice).unwrap().0,
            k2.fake_prelogin(&alice).unwrap().0
        );
    }

    #[test]
    fn rejects_wrong_key_length() {
        assert!(FakeSaltKey::from_bytes(&[0; 31]).is_err());
    }
}
