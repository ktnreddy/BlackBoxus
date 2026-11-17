//! Changing the master password (spec section 3.9 and 12.7).
//!
//! With a session less than five minutes old:
//!
//! ```text
//! PasswordChange::start ─► POST /v1/register/start
//!   ─► PasswordChange::register ─► POST /v1/password
//!   ─► PasswordChanging::complete ─► OfflineRecord
//! ```
//!
//! The key set stays the same: it is only wrapped again under the new
//! master password, so vaults, shares and the account's public keys are
//! untouched. The Secret Key stays the same too. The server ends every
//! other session of the account, so other devices have to sign in again
//! with the new password.

use vault_core::login::{RegistrationState, start_registration};
use vault_core::{
    AccountKeys, AccountSalt, ClientIdentity, KdfParams, MasterPassword, SecretKey, ServerIdentity,
    UnlockMethod, derive_account_keys,
};
use wire::{PasswordChangeRequest, RegisterStartRequest, RegisterStartResponse, b64};

use crate::Result;
use crate::http::{Method, Request, Response, field};
use crate::login::{OfflineRecord, Unlocked};

/// Largest OPAQUE message accepted from the server.
const MAX_OPAQUE_BYTES: usize = 1024;

/// A new master password waiting for the server's registration response.
pub struct PasswordChange {
    identity: ClientIdentity,
    server: ServerIdentity,
    salt: AccountSalt,
    kdf: KdfParams,
    keys: AccountKeys,
    state: RegistrationState,
}

impl core::fmt::Debug for PasswordChange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PasswordChange")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl PasswordChange {
    /// Starts changing the master password of the signed-in account for
    /// `email`. A fresh salt is generated, so nothing derived from the old
    /// password is reused. Use [`KdfParams::DEFAULT`] unless the user chose
    /// otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Crypto`] for an invalid email address, a
    /// password that is too short, invalid parameters, or if randomness or
    /// key derivation fails.
    pub fn start(
        email: &str,
        new_password: &str,
        secret_key: &SecretKey,
        server: &ServerIdentity,
        kdf: KdfParams,
    ) -> Result<(Self, Request)> {
        let identity = ClientIdentity::new(email)?;
        let password = MasterPassword::new_for_account_creation(new_password)?;
        let salt = AccountSalt::generate()?;
        let keys = derive_account_keys(&password, secret_key, &salt, &kdf)?;
        let (state, message) = start_registration(&keys.opaque_password)?;
        let request = Request::json(
            Method::Post,
            "/v1/register/start".into(),
            &RegisterStartRequest {
                email: identity.as_str().into(),
                request: b64(&message),
            },
            None,
        )?;
        Ok((
            Self {
                identity,
                server: server.clone(),
                salt,
                kdf,
                keys,
                state,
            },
            request,
        ))
    }

    /// Finishes OPAQUE registration for the new password, wraps the key set
    /// with it and returns `POST /v1/password`, to send with `unlocked`'s
    /// session (which must be less than five minutes old).
    ///
    /// # Errors
    ///
    /// Returns an error if the server refused or answered with an invalid
    /// registration response.
    pub fn register(
        self,
        unlocked: &Unlocked,
        response: &Response,
    ) -> Result<(PasswordChanging, Request)> {
        let answer: RegisterStartResponse = response.parse()?;
        let upload = self.state.finish(
            &self.keys.opaque_password,
            &field(&answer.response, MAX_OPAQUE_BYTES)?,
            &self.identity,
            &self.server,
        )?;
        let wrapped = unlocked.key_set.wrap(
            &self.keys.account_unlock_key,
            unlocked.session.account_id(),
            unlocked.key_set_version,
            UnlockMethod::MasterPassword,
        )?;
        let request = Request::json(
            Method::Post,
            "/v1/password".into(),
            &PasswordChangeRequest {
                upload: b64(&upload),
                salt: b64(self.salt.as_bytes()),
                kdf: self.kdf.into(),
                wrapped_key_set: b64(&wrapped),
            },
            Some(&unlocked.session),
        )?;
        let record =
            OfflineRecord::new(*unlocked.session.account_id(), self.salt, self.kdf, wrapped);
        Ok((PasswordChanging { record }, request))
    }
}

/// A password change waiting for the server to store the new password.
#[derive(Debug)]
pub struct PasswordChanging {
    record: OfflineRecord,
}

impl PasswordChanging {
    /// Checks the server stored the new password, and returns the record to
    /// keep for unlocking offline with it, in place of the old one. Every
    /// other session of the account has now ended; the one used for the
    /// change remains.
    ///
    /// # Errors
    ///
    /// Returns the server's error, for example if the session is more than
    /// five minutes old.
    pub fn complete(self, response: &Response) -> Result<OfflineRecord> {
        response.ok()?;
        Ok(self.record)
    }
}
