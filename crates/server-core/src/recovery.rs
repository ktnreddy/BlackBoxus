//! Server side of account recovery (spec section 11): checking recovery
//! tokens and holding emergency grants through their waiting period.
//!
//! The server never sees a recovery key or an emergency key. It stores a
//! hash of the recovery token, and emergency grants it cannot open.

use vault_core::AccountId;
use vault_core::recovery::{EmergencyGrant, check_auth_token};

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
        let verifier = key.auth_verifier(&OWNER).unwrap();
        let token = key.auth_token(&OWNER).unwrap();
        assert!(check_recovery_token(&verifier, token.as_bytes()).is_ok());
        let other = key.auth_token(&CONTACT).unwrap();
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
}
