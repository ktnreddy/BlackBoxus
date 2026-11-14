//! Encrypting data a client keeps on its own device, such as the local copy
//! of the vaults (spec section 6.8).
//!
//! The key is derived from the account key, so the local copy can only be
//! read while the account is unlocked, and is bound to the account.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{AccountId, Error, KeySet, Result, SymmetricKey, aead};

const LABEL: &[u8] = b"BlackBoxus v1 local-storage";

fn key(key_set: &KeySet, account_id: &AccountId) -> Result<SymmetricKey> {
    let mut key = SymmetricKey::zeroed();
    Hkdf::<Sha256>::new(
        Some(account_id.as_bytes()),
        key_set.account_key().as_bytes(),
    )
    .expand(LABEL, key.as_mut_bytes())
    .map_err(|_| Error::KeyDerivation)?;
    Ok(key)
}

fn aad(account_id: &AccountId, context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(LABEL.len().saturating_add(16).saturating_add(context.len()));
    aad.extend_from_slice(LABEL);
    aad.extend_from_slice(account_id.as_bytes());
    aad.extend_from_slice(context);
    aad
}

/// Encrypts `data` for this device. `context` names what is stored (for
/// example a vault ID) so one stored blob cannot be swapped for another.
///
/// # Errors
///
/// Returns [`Error::KeyDerivation`] or [`Error::RandomUnavailable`].
pub fn seal(
    key_set: &KeySet,
    account_id: &AccountId,
    context: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    aead::seal(&key(key_set, account_id)?, data, &aad(account_id, context))
}

/// Decrypts data sealed with [`seal`] for the same account and context.
///
/// # Errors
///
/// Returns [`Error::Decryption`] if the key, account or context differ, or
/// the data was modified.
pub fn open(
    key_set: &KeySet,
    account_id: &AccountId,
    context: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    aead::open(
        &key(key_set, account_id)?,
        sealed,
        &aad(account_id, context),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    #[test]
    fn round_trip_and_binding() {
        let keys = KeySet::generate().unwrap();
        let other = KeySet::generate().unwrap();
        let a = AccountId::from_bytes([1; 16]);
        let b = AccountId::from_bytes([2; 16]);
        let sealed = seal(&keys, &a, b"vault-1", b"secret").unwrap();
        assert_eq!(
            open(&keys, &a, b"vault-1", &sealed).unwrap().as_slice(),
            b"secret"
        );
        assert!(open(&keys, &a, b"vault-2", &sealed).is_err());
        assert!(open(&keys, &b, b"vault-1", &sealed).is_err());
        assert!(open(&other, &a, b"vault-1", &sealed).is_err());
        let mut tampered = sealed;
        tampered[30] ^= 1;
        assert!(open(&keys, &a, b"vault-1", &tampered).is_err());
    }
}
