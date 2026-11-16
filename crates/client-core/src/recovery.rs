//! Account recovery with a recovery key (spec section 11).
//!
//! Setting up, with a session less than five minutes old:
//!
//! ```text
//! new_recovery_key ─► PUT /v1/recovery      (show the key once, then erase it)
//! ```
//!
//! Recovering, without a session:
//!
//! ```text
//! Recovery::start ─► POST /v1/recovery/start ─► Recovery::open ─► Recovered
//!   Recovered::choose_password ─► POST /v1/register/start
//!   ─► RecoverySetting::register ─► POST /v1/recovery/finish
//!   ─► RecoveryFinishing::complete ─► RecoveredAccount
//! ```
//!
//! Then sign in with the new master password as usual, and set up a new
//! recovery key, because the old one has been typed on this device.

use vault_core::login::{RegistrationState, start_registration};
use vault_core::recovery::RecoveryKey;
use vault_core::{
    AccountId, AccountKeys, AccountSalt, ClientIdentity, KdfParams, KeySet, MasterPassword,
    SecretKey, ServerIdentity, SymmetricKey, UnlockMethod, derive_account_keys,
};
use wire::{
    KeySetResponse, RecoveryFinishRequest, RecoveryPutRequest, RecoveryStartRequest,
    RecoveryStartResponse, RegisterStartRequest, RegisterStartResponse, b64,
};

use crate::http::{Method, Request, Response, field, field_array};
use crate::login::Unlocked;
use crate::signup::EmergencyKit;
use crate::{ClientError, Result};

/// Largest OPAQUE message accepted from the server.
const MAX_OPAQUE_BYTES: usize = 1024;

/// Length of a wrapped key set (spec section 5.4).
const WRAPPED_LEN: usize = vault_core::WRAPPED_KEY_SET_LEN;

/// Creates a recovery key for the signed-in account and the request that
/// stores it, replacing any earlier one. The session must be less than five
/// minutes old, so sign in with the master password first. Show the key
/// once, offer to print it, then drop it.
///
/// # Errors
///
/// Returns [`ClientError::Crypto`] for an invalid email address or if
/// randomness or key derivation fails.
pub fn new_recovery_key(unlocked: &Unlocked, email: &str) -> Result<(RecoveryKey, Request)> {
    let identity = ClientIdentity::new(email)?;
    let account_id = unlocked.session.account_id();
    let key = RecoveryKey::generate()?;
    let wrapped = unlocked.key_set.wrap(
        &key.wrapping_key(account_id)?,
        account_id,
        unlocked.key_set_version,
        UnlockMethod::Recovery,
    )?;
    let request = Request::json(
        Method::Put,
        "/v1/recovery".into(),
        &RecoveryPutRequest {
            verifier: b64(&key.auth_verifier(&identity)?),
            wrapped_key_set: b64(&wrapped),
        },
        Some(&unlocked.session),
    )?;
    Ok((key, request))
}

/// `DELETE /v1/recovery`: removes the recovery key. The session must be
/// less than five minutes old.
#[must_use]
pub fn remove_recovery_key(unlocked: &Unlocked) -> Request {
    Request {
        method: Method::Delete,
        path: "/v1/recovery".into(),
        body: None,
        authorization: Some(unlocked.session.authorization()),
    }
}

/// `GET /v1/keyset`, to see whether the account has a recovery key with
/// [`has_recovery_key`].
#[must_use]
pub fn recovery_status_request(unlocked: &Unlocked) -> Request {
    Request::get("/v1/keyset".into(), Some(&unlocked.session))
}

/// Whether the server holds a recovery copy of the key set.
///
/// # Errors
///
/// Returns a server error or [`ClientError::InvalidResponse`].
pub fn has_recovery_key(response: &Response) -> Result<bool> {
    let answer: KeySetResponse = response.parse()?;
    Ok(answer
        .wrapped
        .iter()
        .any(|w| w.method == UnlockMethod::Recovery.code()))
}

/// A recovery waiting for the server to check the recovery token.
pub struct Recovery {
    identity: ClientIdentity,
    server: ServerIdentity,
    key: RecoveryKey,
    token: SymmetricKey,
}

impl core::fmt::Debug for Recovery {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Recovery")
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl Recovery {
    /// Starts recovering the account for `email` with a recovery key as the
    /// user typed it.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Crypto`] for an invalid email address or a
    /// recovery key that does not parse or whose checksum is wrong.
    pub fn start(
        email: &str,
        recovery_key: &str,
        server: &ServerIdentity,
    ) -> Result<(Self, Request)> {
        let identity = ClientIdentity::new(email)?;
        let key = RecoveryKey::parse(recovery_key)?;
        let token = key.auth_token(&identity)?;
        let request = Request::json(
            Method::Post,
            "/v1/recovery/start".into(),
            &RecoveryStartRequest {
                email: identity.as_str().into(),
                auth_token: b64(token.as_bytes()),
            },
            None,
        )?;
        Ok((
            Self {
                identity,
                server: server.clone(),
                key,
                token,
            },
            request,
        ))
    }

    /// Opens the key set the server returned with the recovery key.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::SignedOut`] if the server did not accept the
    /// recovery key for this address, or [`ClientError::InvalidResponse`] if
    /// what it returned does not open with it.
    pub fn open(self, response: &Response) -> Result<Recovered> {
        let answer: RecoveryStartResponse = response.parse()?;
        let account_id = AccountId::from_bytes(field_array(&answer.account_id)?);
        let wrapped = field(&answer.wrapped_key_set, WRAPPED_LEN)?;
        let version = wrapped
            .get(2..6)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_be_bytes)
            .ok_or(ClientError::InvalidResponse)?;
        let (key_set, key_set_version) = KeySet::unwrap(
            &wrapped,
            &self.key.wrapping_key(&account_id)?,
            &account_id,
            UnlockMethod::Recovery,
            version,
        )
        .map_err(|_| ClientError::InvalidResponse)?;
        Ok(Recovered {
            identity: self.identity,
            server: self.server,
            token: self.token,
            account_id,
            key_set,
            key_set_version,
        })
    }
}

/// An account whose key set the recovery key opened, waiting for a new
/// master password.
pub struct Recovered {
    identity: ClientIdentity,
    server: ServerIdentity,
    token: SymmetricKey,
    account_id: AccountId,
    key_set: KeySet,
    key_set_version: u32,
}

impl core::fmt::Debug for Recovered {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Recovered")
            .field("account_id", &self.account_id)
            .finish_non_exhaustive()
    }
}

impl Recovered {
    /// The recovered account's ID.
    #[must_use]
    pub const fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Sets a new master password. Pass the account's Secret Key if this
    /// device has it; otherwise a new one is generated, and the user needs
    /// a new Emergency Kit. Use [`KdfParams::DEFAULT`] unless the user
    /// chose otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Crypto`] for a password that is too short or
    /// invalid parameters.
    pub fn choose_password(
        self,
        password: &str,
        secret_key: Option<SecretKey>,
        kdf: KdfParams,
    ) -> Result<(RecoverySetting, Request)> {
        let password = MasterPassword::new_for_account_creation(password)?;
        let new_secret_key = secret_key.is_none();
        let secret_key = match secret_key {
            Some(k) => k,
            None => SecretKey::generate()?,
        };
        let salt = AccountSalt::generate()?;
        let keys = derive_account_keys(&password, &secret_key, &salt, &kdf)?;
        let (state, message) = start_registration(&keys.opaque_password)?;
        let request = Request::json(
            Method::Post,
            "/v1/register/start".into(),
            &RegisterStartRequest {
                email: self.identity.as_str().into(),
                request: b64(&message),
            },
            None,
        )?;
        Ok((
            RecoverySetting {
                recovered: self,
                secret_key,
                new_secret_key,
                salt,
                kdf,
                keys,
                state,
            },
            request,
        ))
    }
}

/// A new master password waiting for the server's registration response.
pub struct RecoverySetting {
    recovered: Recovered,
    secret_key: SecretKey,
    new_secret_key: bool,
    salt: AccountSalt,
    kdf: KdfParams,
    keys: AccountKeys,
    state: RegistrationState,
}

impl core::fmt::Debug for RecoverySetting {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoverySetting")
            .field("account_id", &self.recovered.account_id)
            .finish_non_exhaustive()
    }
}

impl RecoverySetting {
    /// Finishes OPAQUE registration for the new password and wraps the key
    /// set with it.
    ///
    /// # Errors
    ///
    /// Returns an error if the server refused or answered with an invalid
    /// registration response.
    pub fn register(self, response: &Response) -> Result<(RecoveryFinishing, Request)> {
        let answer: RegisterStartResponse = response.parse()?;
        let r = &self.recovered;
        let upload = self.state.finish(
            &self.keys.opaque_password,
            &field(&answer.response, MAX_OPAQUE_BYTES)?,
            &r.identity,
            &r.server,
        )?;
        let wrapped = r.key_set.wrap(
            &self.keys.account_unlock_key,
            &r.account_id,
            r.key_set_version,
            UnlockMethod::MasterPassword,
        )?;
        let request = Request::json(
            Method::Post,
            "/v1/recovery/finish".into(),
            &RecoveryFinishRequest {
                email: r.identity.as_str().into(),
                auth_token: b64(r.token.as_bytes()),
                upload: b64(&upload),
                salt: b64(self.salt.as_bytes()),
                kdf: self.kdf.into(),
                wrapped_key_set: b64(&wrapped),
            },
            None,
        )?;
        Ok((
            RecoveryFinishing {
                account: RecoveredAccount {
                    account_id: self.recovered.account_id,
                    identity: self.recovered.identity,
                    server: self.recovered.server,
                    secret_key: self.secret_key,
                    new_secret_key: self.new_secret_key,
                },
            },
            request,
        ))
    }
}

/// A recovery waiting for the server to store the new password.
#[derive(Debug)]
pub struct RecoveryFinishing {
    account: RecoveredAccount,
}

impl RecoveryFinishing {
    /// Checks the server stored the new password. Every session the account
    /// had has now ended; sign in with the new password.
    ///
    /// # Errors
    ///
    /// Returns a server error.
    pub fn complete(self, response: &Response) -> Result<RecoveredAccount> {
        response.ok()?;
        Ok(self.account)
    }
}

/// An account with a new master password.
pub struct RecoveredAccount {
    /// The account's ID.
    pub account_id: AccountId,
    /// The canonical email address.
    pub identity: ClientIdentity,
    /// The server.
    pub server: ServerIdentity,
    /// The Secret Key to sign in with. Store it in the platform's secure
    /// storage.
    pub secret_key: SecretKey,
    /// `true` if the Secret Key is new, so the user needs a new Emergency
    /// Kit and other devices must be added again.
    pub new_secret_key: bool,
}

impl core::fmt::Debug for RecoveredAccount {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveredAccount")
            .field("account_id", &self.account_id)
            .field("new_secret_key", &self.new_secret_key)
            .finish_non_exhaustive()
    }
}

impl RecoveredAccount {
    /// What to print in a new Emergency Kit (spec section 3.7).
    #[must_use]
    pub fn emergency_kit(&self) -> EmergencyKit {
        EmergencyKit {
            email: self.identity.as_str().into(),
            server: self.server.as_str().into(),
            secret_key: self.secret_key.to_display_string(),
        }
    }
}
