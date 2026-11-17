//! Server side of account recovery (spec section 11): checking recovery
//! tokens and holding emergency grants through their waiting period.
//!
//! The server never sees a recovery key or an emergency key. It stores a
//! hash of the recovery token, and emergency grants it cannot open.

use vault_core::recovery::{EmergencyGrant, check_auth_token};
use vault_core::{AccountId, AccountSalt, KdfParams, UnlockMethod};

use crate::api::{AccountRecord, check_wrapped_copy, check_wrapped_key_set};
use crate::login::finish_registration;
use crate::{Error, Result};

const MS_PER_DAY: u64 = 86_400_000;

/// Checks a recovery token presented by a client against the stored
/// verifier, in constant time.
///
/// # Errors
///
/// Returns [`Error::Authentication`] if the token does not match.
pub fn check_recovery_token(stored_verifier: &[u8; 32], presented: &[u8]) -> Result<()> {
    if check_auth_token(stored_verifier, presented) {
        Ok(())
    } else {
        Err(Error::Authentication)
    }
}

/// An account's recovery key, as the server stores it (spec section 11.2):
/// a hash of its token, and the key set wrapped with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryRecord {
    /// `SHA-256(auth_token)`.
    pub verifier: [u8; 32],
    /// The key set wrapped with method 4.
    pub wrapped_key_set: Vec<u8>,
}

/// `PUT /v1/recovery`: checks a new recovery key for `account`. The adapter
/// replaces any earlier one. The session must be fresh
/// ([`crate::api::require_fresh_session`]).
///
/// # Errors
///
/// Returns [`Error::MalformedMessage`] if the verifier is not 32 bytes or
/// the wrapped copy is not method 4 for the current key set version.
pub fn accept_recovery_key(
    account: &AccountRecord,
    verifier: &[u8],
    wrapped_key_set: &[u8],
) -> Result<RecoveryRecord> {
    let verifier = <[u8; 32]>::try_from(verifier).map_err(|_| Error::MalformedMessage)?;
    check_wrapped_copy(
        wrapped_key_set,
        account.key_set_version,
        UnlockMethod::Recovery,
    )?;
    Ok(RecoveryRecord {
        verifier,
        wrapped_key_set: wrapped_key_set.to_vec(),
    })
}

/// Checks a recovery token against an account found by email address, if
/// it has a recovery key. Unknown addresses and accounts without a recovery
/// key fail exactly like a wrong token, after the same work.
fn check_token<'a>(
    found: Option<(&'a AccountRecord, &'a RecoveryRecord)>,
    token: &[u8],
) -> Result<(&'a AccountRecord, &'a RecoveryRecord)> {
    match found {
        Some((account, recovery)) => {
            check_recovery_token(&recovery.verifier, token)?;
            Ok((account, recovery))
        }
        None => {
            // No verifier hashes to all zeros, but the work is the same.
            let _ = check_auth_token(&[0; 32], token);
            Err(Error::Authentication)
        }
    }
}

/// `POST /v1/recovery/start` (spec section 11.3, step 2): returns the
/// account ID and the method-4 wrapped key set.
///
/// # Errors
///
/// Returns [`Error::Authentication`] for a wrong token, an unknown address,
/// or an account without a recovery key.
pub fn recovery_start(
    found: Option<(&AccountRecord, &RecoveryRecord)>,
    token: &[u8],
) -> Result<(AccountId, Vec<u8>)> {
    let (account, recovery) = check_token(found, token)?;
    Ok((account.account_id, recovery.wrapped_key_set.clone()))
}

/// A new master password, set by a password change or a recovery.
#[derive(Debug, Clone)]
pub struct NewPassword<'a> {
    /// OPAQUE registration upload.
    pub registration_upload: &'a [u8],
    /// New Argon2id salt.
    pub salt: AccountSalt,
    /// Argon2id parameters.
    pub kdf: KdfParams,
    /// The key set wrapped with method 1, for the current key set version.
    pub wrapped_key_set: &'a [u8],
}

/// `POST /v1/recovery/finish` (spec section 11.3, step 3): returns the
/// account record to store in place of the old one. The adapter MUST also
/// end all of the account's sessions, atomically.
///
/// # Errors
///
/// As [`recovery_start`], or [`Error::MalformedMessage`] if the new
/// password's parts are invalid.
pub fn recovery_finish(
    found: Option<(&AccountRecord, &RecoveryRecord)>,
    token: &[u8],
    new: &NewPassword<'_>,
) -> Result<AccountRecord> {
    let (account, _) = check_token(found, token)?;
    change_password(account, new)
}

/// `POST /v1/password` (spec section 12.7): returns the account record to
/// store in place of the old one. The session must be fresh
/// ([`crate::api::require_fresh_session`]), and the adapter MUST also end
/// every other session of the account and its pending logins, atomically.
/// Recovery uses the same checks.
///
/// # Errors
///
/// Returns [`Error::MalformedMessage`] if the KDF parameters, the OPAQUE
/// registration upload or the wrapped key set are invalid.
pub fn change_password(account: &AccountRecord, new: &NewPassword<'_>) -> Result<AccountRecord> {
    new.kdf.validate().map_err(|_| Error::MalformedMessage)?;
    let opaque_record = finish_registration(new.registration_upload)?;
    check_wrapped_key_set(new.wrapped_key_set, account.key_set_version)?;
    Ok(AccountRecord {
        salt: new.salt,
        kdf: new.kdf,
        opaque_record,
        wrapped_key_set: new.wrapped_key_set.to_vec(),
        ..account.clone()
    })
}

/// Where an emergency grant is in its life (spec section 11.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantState {
    /// Stored; the contact has not asked for access.
    Idle,
    /// The contact asked for access at this time (Unix milliseconds).
    Requested {
        /// When the request was made.
        at_ms: u64,
    },
    /// The waiting period passed and the grant was handed to the contact.
    Released,
}

/// An emergency grant stored by the server, with its waiting-period state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredGrant {
    grant: Vec<u8>,
    header: EmergencyGrant,
    state: GrantState,
}

impl StoredGrant {
    /// Accepts a grant uploaded by `owner`.
    ///
    /// The server checks only the format and that the uploader is the
    /// grant's owner; the contact verifies the owner's signature.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] or [`Error::NotAllowed`].
    pub fn new(owner: &AccountId, grant: Vec<u8>) -> Result<Self> {
        let header = EmergencyGrant::inspect(&grant)?;
        if header.owner != *owner {
            return Err(Error::NotAllowed);
        }
        Ok(Self {
            grant,
            header,
            state: GrantState::Idle,
        })
    }

    /// The grant's header.
    #[must_use]
    pub const fn header(&self) -> &EmergencyGrant {
        &self.header
    }

    /// The current state.
    #[must_use]
    pub const fn state(&self) -> GrantState {
        self.state
    }

    /// The time from which the grant can be released, if requested.
    #[must_use]
    pub fn release_at_ms(&self) -> Option<u64> {
        match self.state {
            GrantState::Requested { at_ms } => Some(
                at_ms.saturating_add(u64::from(self.header.wait_days).saturating_mul(MS_PER_DAY)),
            ),
            GrantState::Idle | GrantState::Released => None,
        }
    }

    /// The contact asks for access. The server MUST notify the owner.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAllowed`] if `contact` is not the grant's
    /// contact, or a request is already pending or released.
    pub fn request(&mut self, contact: &AccountId, now_ms: u64) -> Result<()> {
        if *contact != self.header.contact || self.state != GrantState::Idle {
            return Err(Error::NotAllowed);
        }
        self.state = GrantState::Requested { at_ms: now_ms };
        Ok(())
    }

    /// The owner denies a pending request, returning the grant to idle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAllowed`] if `owner` is not the grant's owner or
    /// nothing is pending.
    pub fn deny(&mut self, owner: &AccountId) -> Result<()> {
        if *owner != self.header.owner || !matches!(self.state, GrantState::Requested { .. }) {
            return Err(Error::NotAllowed);
        }
        self.state = GrantState::Idle;
        Ok(())
    }

    /// Hands the grant to the contact once the waiting period is over.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAllowed`] if `contact` is not the grant's
    /// contact or nothing was requested, or [`Error::TooEarly`].
    pub fn release(&mut self, contact: &AccountId, now_ms: u64) -> Result<&[u8]> {
        if *contact != self.header.contact {
            return Err(Error::NotAllowed);
        }
        if self.state != GrantState::Released {
            let release_at = self.release_at_ms().ok_or(Error::NotAllowed)?;
            if now_ms < release_at {
                return Err(Error::TooEarly);
            }
            self.state = GrantState::Released;
        }
        Ok(&self.grant)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use vault_core::recovery::{EmergencyGrant, EmergencyKey, RecoveryKey};
    use vault_core::{KeySet, PublicKeyBundle};

    use super::*;

    const OWNER: AccountId = AccountId::from_bytes([1; 16]);
    const CONTACT: AccountId = AccountId::from_bytes([2; 16]);

    fn grant(wait_days: u16) -> Vec<u8> {
        let owner = KeySet::generate().unwrap();
        let contact = KeySet::generate().unwrap();
        let bundle =
            PublicKeyBundle::verify_signed(&contact.signed_public_bundle(&CONTACT, 1).unwrap())
                .unwrap();
        let key = EmergencyKey::generate().unwrap();
        EmergencyGrant::seal(&key, &owner, &OWNER, 1, &bundle, wait_days).unwrap()
    }

    #[test]
    fn recovery_tokens_are_checked() {
        let key = RecoveryKey::generate().unwrap();
        let owner = vault_core::ClientIdentity::new("owner@example.com").unwrap();
        let contact = vault_core::ClientIdentity::new("contact@example.com").unwrap();
        let verifier = key.auth_verifier(&owner).unwrap();
        let token = key.auth_token(&owner).unwrap();
        assert!(check_recovery_token(&verifier, token.as_bytes()).is_ok());
        let other = key.auth_token(&contact).unwrap();
        assert_eq!(
            check_recovery_token(&verifier, other.as_bytes()),
            Err(Error::Authentication)
        );
        assert_eq!(
            check_recovery_token(&verifier, &verifier),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn only_the_owner_can_upload() {
        assert_eq!(
            StoredGrant::new(&CONTACT, grant(7)).unwrap_err(),
            Error::NotAllowed
        );
        assert_eq!(
            StoredGrant::new(&OWNER, vec![0; 10]).unwrap_err(),
            Error::MalformedMessage
        );
    }

    #[test]
    fn the_waiting_period_is_enforced() {
        let mut stored = StoredGrant::new(&OWNER, grant(7)).unwrap();
        assert_eq!(stored.release(&CONTACT, 0).unwrap_err(), Error::NotAllowed);
        assert_eq!(stored.request(&OWNER, 0).unwrap_err(), Error::NotAllowed);

        let t0 = 1_000;
        stored.request(&CONTACT, t0).unwrap();
        assert_eq!(stored.request(&CONTACT, t0).unwrap_err(), Error::NotAllowed);
        let due = t0 + 7 * MS_PER_DAY;
        assert_eq!(stored.release_at_ms(), Some(due));
        assert_eq!(stored.release(&OWNER, due).unwrap_err(), Error::NotAllowed);
        assert_eq!(
            stored.release(&CONTACT, due - 1).unwrap_err(),
            Error::TooEarly
        );
        assert_eq!(stored.release(&CONTACT, due).unwrap().len(), 4609);
        assert_eq!(stored.state(), GrantState::Released);
        assert_eq!(stored.deny(&OWNER).unwrap_err(), Error::NotAllowed);
    }

    #[test]
    fn the_owner_can_deny_a_request() {
        let mut stored = StoredGrant::new(&OWNER, grant(3)).unwrap();
        stored.request(&CONTACT, 0).unwrap();
        assert_eq!(stored.deny(&CONTACT).unwrap_err(), Error::NotAllowed);
        stored.deny(&OWNER).unwrap();
        assert_eq!(stored.state(), GrantState::Idle);
        assert_eq!(
            stored.release(&CONTACT, 10 * MS_PER_DAY).unwrap_err(),
            Error::NotAllowed
        );
    }

    fn account(key: &RecoveryKey, keys: &KeySet) -> (AccountRecord, RecoveryRecord) {
        let identity = vault_core::ClientIdentity::new("owner@example.com").unwrap();
        let wrapping = vault_core::SymmetricKey::from_bytes([5; 32]);
        let record = AccountRecord {
            account_id: OWNER,
            identity: identity.clone(),
            salt: AccountSalt::from_bytes([1; 16]),
            kdf: KdfParams::MIN,
            opaque_record: vec![1, 2, 3],
            signed_bundle: keys.signed_public_bundle(&OWNER, 1).unwrap(),
            key_set_version: 1,
            wrapped_key_set: keys
                .wrap(&wrapping, &OWNER, 1, UnlockMethod::MasterPassword)
                .unwrap(),
        };
        let wrapped = keys
            .wrap(
                &key.wrapping_key(&OWNER).unwrap(),
                &OWNER,
                1,
                UnlockMethod::Recovery,
            )
            .unwrap();
        let verifier = key.auth_verifier(&identity).unwrap();
        let stored = accept_recovery_key(&record, &verifier, &wrapped).unwrap();
        (record, stored)
    }

    #[test]
    fn setting_a_recovery_key() {
        let key = RecoveryKey::generate().unwrap();
        let keys = KeySet::generate().unwrap();
        let (record, stored) = account(&key, &keys);
        // The verifier must be 32 bytes, and the copy must be method 4 for
        // the current key set version.
        assert_eq!(
            accept_recovery_key(&record, &[0; 31], &stored.wrapped_key_set),
            Err(Error::MalformedMessage)
        );
        assert_eq!(
            accept_recovery_key(&record, &stored.verifier, &record.wrapped_key_set),
            Err(Error::MalformedMessage)
        );
        let newer = AccountRecord {
            key_set_version: 2,
            ..record
        };
        assert_eq!(
            accept_recovery_key(&newer, &stored.verifier, &stored.wrapped_key_set),
            Err(Error::MalformedMessage)
        );
    }

    #[test]
    fn recovering_an_account() {
        use crate::login::OpaqueServer;
        use vault_core::login::start_registration;

        let key = RecoveryKey::generate().unwrap();
        let keys = KeySet::generate().unwrap();
        let (record, stored) = account(&key, &keys);
        let token = key.auth_token(&record.identity).unwrap();
        let wrong = RecoveryKey::generate()
            .unwrap()
            .auth_token(&record.identity)
            .unwrap();

        // Starting hands over the wrapped copy, which the recovery key opens.
        let (id, wrapped) = recovery_start(Some((&record, &stored)), token.as_bytes()).unwrap();
        assert_eq!(id, OWNER);
        let (opened, version) = KeySet::unwrap(
            &wrapped,
            &key.wrapping_key(&OWNER).unwrap(),
            &OWNER,
            UnlockMethod::Recovery,
            1,
        )
        .unwrap();
        assert_eq!(version, 1);
        assert_eq!(
            opened.identity().public_key().to_bytes(),
            keys.identity().public_key().to_bytes()
        );
        // A wrong token, an unknown address and an account without a
        // recovery key all fail the same way.
        for found in [Some((&record, &stored)), None] {
            assert_eq!(
                recovery_start(found, wrong.as_bytes()),
                Err(Error::Authentication)
            );
        }
        assert_eq!(
            recovery_start(None, token.as_bytes()),
            Err(Error::Authentication)
        );

        // Finishing sets a new password for the same key set.
        let opaque = OpaqueServer::generate();
        let password = vault_core::SymmetricKey::from_bytes([8; 32]);
        let (state, request) = start_registration(&password).unwrap();
        let response = opaque
            .registration_response(&request, &record.identity)
            .unwrap();
        let upload = state
            .finish(
                &password,
                &response,
                &record.identity,
                &vault_core::ServerIdentity::new("https://api.blackboxus.test").unwrap(),
            )
            .unwrap();
        let new_unlock = vault_core::SymmetricKey::from_bytes([9; 32]);
        let new_wrapped = keys
            .wrap(&new_unlock, &OWNER, 1, UnlockMethod::MasterPassword)
            .unwrap();
        let new = NewPassword {
            registration_upload: &upload,
            salt: AccountSalt::from_bytes([2; 16]),
            kdf: KdfParams::MIN,
            wrapped_key_set: &new_wrapped,
        };
        assert_eq!(
            recovery_finish(Some((&record, &stored)), wrong.as_bytes(), &new),
            Err(Error::Authentication)
        );
        let updated = recovery_finish(Some((&record, &stored)), token.as_bytes(), &new).unwrap();
        assert_eq!(updated.account_id, OWNER);
        assert_eq!(updated.salt, AccountSalt::from_bytes([2; 16]));
        assert_eq!(updated.wrapped_key_set, new_wrapped);
        assert_ne!(updated.opaque_record, record.opaque_record);
        assert_eq!(updated.signed_bundle, record.signed_bundle);

        // The new copy must be method 1 for the same key set version.
        let bad = NewPassword {
            wrapped_key_set: &wrapped,
            ..new
        };
        assert_eq!(
            recovery_finish(Some((&record, &stored)), token.as_bytes(), &bad),
            Err(Error::MalformedMessage)
        );
    }

    #[test]
    fn changing_the_password() {
        use crate::login::OpaqueServer;
        use vault_core::login::start_registration;

        let keys = KeySet::generate().unwrap();
        let (record, _) = account(&RecoveryKey::generate().unwrap(), &keys);
        let opaque = OpaqueServer::generate();
        let password = vault_core::SymmetricKey::from_bytes([8; 32]);
        let (state, request) = start_registration(&password).unwrap();
        let response = opaque
            .registration_response(&request, &record.identity)
            .unwrap();
        let upload = state
            .finish(
                &password,
                &response,
                &record.identity,
                &vault_core::ServerIdentity::new("https://api.blackboxus.test").unwrap(),
            )
            .unwrap();
        let unlock = vault_core::SymmetricKey::from_bytes([9; 32]);
        let wrapped = keys
            .wrap(&unlock, &OWNER, 1, UnlockMethod::MasterPassword)
            .unwrap();
        let new = NewPassword {
            registration_upload: &upload,
            salt: AccountSalt::from_bytes([3; 16]),
            kdf: KdfParams::MIN,
            wrapped_key_set: &wrapped,
        };
        let updated = change_password(&record, &new).unwrap();
        assert_eq!(updated.salt, AccountSalt::from_bytes([3; 16]));
        assert_eq!(updated.wrapped_key_set, wrapped);
        assert_ne!(updated.opaque_record, record.opaque_record);
        assert_eq!(updated.identity, record.identity);
        assert_eq!(updated.signed_bundle, record.signed_bundle);

        // Another method, a garbled upload or weak parameters are refused.
        let recovery_copy = keys
            .wrap(&unlock, &OWNER, 1, UnlockMethod::Recovery)
            .unwrap();
        for bad in [
            NewPassword {
                wrapped_key_set: &recovery_copy,
                ..new.clone()
            },
            NewPassword {
                registration_upload: &upload[1..],
                ..new.clone()
            },
            NewPassword {
                kdf: KdfParams {
                    memory_kib: 1024,
                    ..KdfParams::MIN
                },
                ..new.clone()
            },
        ] {
            assert_eq!(change_password(&record, &bad), Err(Error::MalformedMessage));
        }
    }
}
