//! Signing in and unlocking (spec sections 3.8, 4.5 and 5.4).
//!
//! ```text
//! Login::start ─► POST /v1/prelogin ─► Login::prelogin
//!   ─► POST /v1/login/start ─► LoginStarted::key_exchange
//!   ─► POST /v1/login/finish ─► LoginFinishing::finished
//!   ─► GET /v1/keyset ─► Unlocking::unlock ─► Unlocked
//! ```

use vault_core::login::{LoginState, start_login};
use vault_core::{
    AccountId, AccountKeys, AccountSalt, ClientIdentity, KdfParams, KeySet, MasterPassword,
    SecretKey, ServerIdentity, UnlockMethod, WRAPPED_KEY_SET_LEN, derive_account_keys,
};
use wire::{
    KeySetResponse, LoginFinishRequest, LoginStartRequest, LoginStartResponse, PreloginRequest,
    PreloginResponse, b64,
};

use crate::http::{Method, Request, Response, Session, field, field_array};
use crate::{ClientError, Result};

const MAX_OPAQUE_BYTES: usize = 1024;

/// A login waiting for the account's salt and parameters.
#[derive(Debug)]
pub struct Login {
    identity: ClientIdentity,
    server: ServerIdentity,
}

impl Login {
    /// Starts signing in.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Crypto`] for an invalid email address.
    pub fn start(email: &str, server: &ServerIdentity) -> Result<(Self, Request)> {
        let identity = ClientIdentity::new(email)?;
        let request = Request::json(
            Method::Post,
            "/v1/prelogin".into(),
            &PreloginRequest {
                email: identity.as_str().into(),
            },
            None,
        )?;
        Ok((
            Self {
                identity,
                server: server.clone(),
            },
            request,
        ))
    }

    /// Derives the account keys with the salt and parameters the server
    /// sent. The parameters are checked against fixed bounds first, so a
    /// malicious server cannot weaken the derivation (spec section 3.4).
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Crypto`] for parameters out of bounds, or a
    /// server error.
    pub fn prelogin(
        self,
        response: &Response,
        password: &str,
        secret_key: &SecretKey,
    ) -> Result<(LoginStarted, Request)> {
        let answer: PreloginResponse = response.parse()?;
        let salt = AccountSalt::from_bytes(field_array(&answer.salt)?);
        let kdf = KdfParams::from(answer.kdf);
        let password = MasterPassword::new(password)?;
        let keys = derive_account_keys(&password, secret_key, &salt, &kdf)?;
        let (state, ke1) = start_login(&keys.opaque_password)?;
        let request = Request::json(
            Method::Post,
            "/v1/login/start".into(),
            &LoginStartRequest {
                email: self.identity.as_str().into(),
                ke1: b64(&ke1),
            },
            None,
        )?;
        Ok((
            LoginStarted {
                identity: self.identity,
                server: self.server,
                keys,
                state,
            },
            request,
        ))
    }
}

/// A login waiting for the server's `KE2`.
pub struct LoginStarted {
    identity: ClientIdentity,
    server: ServerIdentity,
    keys: AccountKeys,
    state: LoginState,
}

impl core::fmt::Debug for LoginStarted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoginStarted").finish_non_exhaustive()
    }
}

impl LoginStarted {
    /// Checks the server's `KE2`, which proves it holds this account's
    /// registration and the client holds the right credentials.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::WrongCredentials`] if the password or Secret
    /// Key is wrong or the address has no account (indistinguishable by
    /// design), or [`ClientError::RateLimited`].
    pub fn key_exchange(self, response: &Response) -> Result<(LoginFinishing, Request)> {
        let answer: LoginStartResponse = response.parse()?;
        let ke2 = field(&answer.ke2, MAX_OPAQUE_BYTES)?;
        let finish = self
            .state
            .finish(
                &self.keys.opaque_password,
                &ke2,
                &self.identity,
                &self.server,
            )
            .map_err(|_| ClientError::WrongCredentials)?;
        let request = Request::json(
            Method::Post,
            "/v1/login/finish".into(),
            &LoginFinishRequest {
                login_id: answer.login_id,
                ke3: b64(&finish.ke3),
            },
            None,
        )?;
        Ok((
            LoginFinishing {
                keys: self.keys,
                token: finish.session_token,
            },
            request,
        ))
    }
}

/// A login waiting for the server to accept `KE3`.
pub struct LoginFinishing {
    keys: AccountKeys,
    token: vault_core::login::SessionToken,
}

impl core::fmt::Debug for LoginFinishing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoginFinishing").finish_non_exhaustive()
    }
}

impl LoginFinishing {
    /// Checks the server accepted the login, and returns the request that
    /// downloads the wrapped key set.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::WrongCredentials`] if the server rejected
    /// `KE3`, or [`ClientError::RateLimited`].
    pub fn finished(self, response: &Response) -> Result<(Unlocking, Request)> {
        response.ok().map_err(|e| match e {
            ClientError::SignedOut => ClientError::WrongCredentials,
            other => other,
        })?;
        let request = Request {
            method: Method::Get,
            path: "/v1/keyset".into(),
            body: None,
            authorization: Some(format!("Bearer {}", b64(self.token.as_bytes()))),
        };
        Ok((
            Unlocking {
                keys: self.keys,
                token: self.token,
            },
            request,
        ))
    }
}

/// A signed-in login waiting for the wrapped key set.
pub struct Unlocking {
    keys: AccountKeys,
    token: vault_core::login::SessionToken,
}

impl core::fmt::Debug for Unlocking {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Unlocking").finish_non_exhaustive()
    }
}

impl Unlocking {
    /// Unwraps the key set with the Account Unlock Key. The wrapped key set
    /// is bound to the account ID, so a server that lies about the ID only
    /// makes this fail.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidResponse`] if the key set does not
    /// decrypt, or a server error.
    pub fn unlock(self, response: &Response) -> Result<Unlocked> {
        let answer: KeySetResponse = response.parse()?;
        let account_id = AccountId::from_bytes(field_array(&answer.account_id)?);
        let wrapped = answer
            .wrapped
            .iter()
            .find(|w| w.method == UnlockMethod::MasterPassword.code())
            .ok_or(ClientError::InvalidResponse)?;
        let (key_set, key_set_version) = KeySet::unwrap(
            &field(&wrapped.data, WRAPPED_KEY_SET_LEN)?,
            &self.keys.account_unlock_key,
            &account_id,
            UnlockMethod::MasterPassword,
            1,
        )
        .map_err(|_| ClientError::InvalidResponse)?;
        if key_set_version != answer.key_set_version {
            return Err(ClientError::InvalidResponse);
        }
        Ok(Unlocked {
            session: Session::new(self.token, account_id),
            key_set,
            key_set_version,
        })
    }
}

/// A signed-in, unlocked account.
pub struct Unlocked {
    /// The session for further requests.
    pub session: Session,
    /// The account's key set.
    pub key_set: KeySet,
    /// Its version.
    pub key_set_version: u32,
}

impl core::fmt::Debug for Unlocked {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Unlocked")
            .field("account_id", self.session.account_id())
            .field("key_set_version", &self.key_set_version)
            .finish_non_exhaustive()
    }
}
