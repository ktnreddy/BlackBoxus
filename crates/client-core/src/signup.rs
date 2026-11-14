//! Creating an account (spec sections 3 and 4.4).
//!
//! ```text
//! Signup::start ─► POST /v1/register/start ─► Signup::register
//!               ─► POST /v1/register/finish ─► PendingAccount::complete ─► NewAccount
//! ```

use vault_core::login::{RegistrationState, start_registration};
use vault_core::{
    AccountId, AccountKeys, AccountSalt, ClientIdentity, KdfParams, KeySet, MasterPassword,
    SecretKey, ServerIdentity, UnlockMethod, derive_account_keys,
};
use wire::{
    RegisterFinishRequest, RegisterFinishResponse, RegisterStartRequest, RegisterStartResponse, b64,
};
use zeroize::Zeroizing;

use crate::http::{Method, Request, Response, field};
use crate::{ClientError, Result};

/// Largest OPAQUE message accepted from the server.
const MAX_OPAQUE_BYTES: usize = 1024;

/// A sign-up waiting for the server's registration response.
pub struct Signup {
    identity: ClientIdentity,
    server: ServerIdentity,
    secret_key: SecretKey,
    salt: AccountSalt,
    kdf: KdfParams,
    keys: AccountKeys,
    state: RegistrationState,
}

impl core::fmt::Debug for Signup {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Signup")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl Signup {
    /// Starts creating an account: checks the password meets the minimum
    /// for new accounts, generates the Secret Key and salt, and derives the
    /// account keys. Use [`KdfParams::DEFAULT`] unless the user explicitly
    /// chose otherwise (spec section 3.4).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Crypto`] for an invalid email address, a
    /// password that is too short, or invalid parameters.
    pub fn start(
        email: &str,
        password: &str,
        server: &ServerIdentity,
        kdf: KdfParams,
    ) -> Result<(Self, Request)> {
        let identity = ClientIdentity::new(email)?;
        let password = MasterPassword::new_for_account_creation(password)?;
        let secret_key = SecretKey::generate()?;
        let salt = AccountSalt::generate()?;
        let keys = derive_account_keys(&password, &secret_key, &salt, &kdf)?;
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
                secret_key,
                salt,
                kdf,
                keys,
                state,
            },
            request,
        ))
    }

    /// Finishes OPAQUE registration and creates the account's key set.
    ///
    /// # Errors
    ///
    /// Returns an error if the server refused or answered with an invalid
    /// registration response.
    pub fn register(self, response: &Response) -> Result<(PendingAccount, Request)> {
        let answer: RegisterStartResponse = response.parse()?;
        let upload = self.state.finish(
            &self.keys.opaque_password,
            &field(&answer.response, MAX_OPAQUE_BYTES)?,
            &self.identity,
            &self.server,
        )?;
        let account_id = AccountId::generate()?;
        let key_set = KeySet::generate()?;
        let signed_bundle = key_set.signed_public_bundle(&account_id, 1)?;
        let wrapped = key_set.wrap(
            &self.keys.account_unlock_key,
            &account_id,
            1,
            UnlockMethod::MasterPassword,
        )?;
        let request = Request::json(
            Method::Post,
            "/v1/register/finish".into(),
            &RegisterFinishRequest {
                email: self.identity.as_str().into(),
                salt: b64(self.salt.as_bytes()),
                kdf: self.kdf.into(),
                upload: b64(&upload),
                signed_bundle: b64(&signed_bundle),
                wrapped_key_set: b64(&wrapped),
            },
            None,
        )?;
        Ok((
            PendingAccount {
                account: NewAccount {
                    account_id,
                    identity: self.identity,
                    server: self.server,
                    secret_key: self.secret_key,
                    key_set,
                },
            },
            request,
        ))
    }
}

/// An account waiting for the server to confirm it was created.
#[derive(Debug)]
pub struct PendingAccount {
    account: NewAccount,
}

impl PendingAccount {
    /// Checks the server created the account.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Server`] with code `conflict` if the email
    /// address is taken (or, rarely, a concurrent sign-up raced this one;
    /// start again), or [`ClientError::InvalidResponse`] if the server
    /// confirmed a different account.
    pub fn complete(self, response: &Response) -> Result<NewAccount> {
        let answer: RegisterFinishResponse = response.parse()?;
        if field(&answer.account_id, 16)? != self.account.account_id.as_bytes() {
            return Err(ClientError::InvalidResponse);
        }
        Ok(self.account)
    }
}

/// A newly created account.
pub struct NewAccount {
    /// The account's ID.
    pub account_id: AccountId,
    /// The canonical email address.
    pub identity: ClientIdentity,
    /// The server.
    pub server: ServerIdentity,
    /// The Secret Key. Store it in the platform's secure storage and show it
    /// in the Emergency Kit.
    pub secret_key: SecretKey,
    /// The unlocked key set.
    pub key_set: KeySet,
}

impl core::fmt::Debug for NewAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NewAccount")
            .field("account_id", &self.account_id)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl NewAccount {
    /// What to print in the Emergency Kit (spec section 3.7).
    #[must_use]
    pub fn emergency_kit(&self) -> EmergencyKit {
        EmergencyKit {
            email: self.identity.as_str().into(),
            server: self.server.as_str().into(),
            secret_key: self.secret_key.to_display_string(),
        }
    }
}

/// The contents of the Emergency Kit. The master password is never in it;
/// the user writes it by hand if they choose to.
#[derive(Debug)]
pub struct EmergencyKit {
    /// Email address.
    pub email: String,
    /// Server address.
    pub server: String,
    /// The Secret Key, formatted for printing.
    pub secret_key: Zeroizing<String>,
}
