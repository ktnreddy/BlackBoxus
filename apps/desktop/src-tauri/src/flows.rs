//! Account flows: `client-core`'s steps joined up with a [`Transport`].
//!
//! Each runs on a worker thread, because key derivation takes a second or
//! two on purpose.

use client_core::ClientError;
use client_core::login::{Login, OfflineRecord, Unlocked};
use client_core::recovery::{
    RecoveredAccount, Recovery, has_recovery_key, new_recovery_key, recovery_status_request,
    remove_recovery_key,
};
use client_core::signup::{EmergencyKit, Signup};
use vault_core::recovery::RecoveryKey;
use vault_core::{AccountId, KdfParams, SecretKey, ServerIdentity};

use crate::error::AppError;
use crate::http::Transport;

/// Creates an account, then signs in to it. Returns the signed-in account,
/// its Secret Key (to store) and the Emergency Kit (to show).
///
/// # Errors
///
/// Returns an error for invalid input, an address that is taken, or a
/// server or network failure.
pub fn create_account(
    transport: &impl Transport,
    server: &ServerIdentity,
    email: &str,
    password: &str,
) -> Result<(Unlocked, OfflineRecord, SecretKey, EmergencyKit), AppError> {
    let (signup, request) = Signup::start(email, password, server, KdfParams::DEFAULT)?;
    let (pending, request) = signup.register(&transport.send(&request)?)?;
    let account = pending.complete(&transport.send(&request)?)?;
    let kit = account.emergency_kit();
    let (unlocked, record) = sign_in(transport, server, email, &account.secret_key, password)?;
    // The account the server signed us in to must be the one just created.
    if unlocked.session.account_id() != &account.account_id {
        return Err(AppError::Tampered);
    }
    Ok((unlocked, record, account.secret_key, kit))
}

/// Signs in with an email address, Secret Key and master password. Also
/// returns the record for unlocking offline later.
///
/// # Errors
///
/// Returns [`AppError::WrongCredentials`] if any of the three is wrong,
/// or a server or network failure.
pub fn sign_in(
    transport: &impl Transport,
    server: &ServerIdentity,
    email: &str,
    secret_key: &SecretKey,
    password: &str,
) -> Result<(Unlocked, OfflineRecord), AppError> {
    let (login, request) = Login::start(email, server)?;
    let (login, request) = login.prelogin(&transport.send(&request)?, password, secret_key)?;
    let (login, request) = login.key_exchange(&transport.send(&request)?)?;
    let (login, request) = login.finished(&transport.send(&request)?)?;
    Ok(login.unlock_keeping_record(&transport.send(&request)?)?)
}

/// Signs in again with the master password to get a session less than five
/// minutes old, runs `job` with it, then ends that session. The server asks
/// for this before changing how the account can be unlocked, so a stolen
/// session token cannot.
fn with_fresh_session<T>(
    transport: &impl Transport,
    server: &ServerIdentity,
    email: &str,
    secret_key: &SecretKey,
    password: &str,
    account: &AccountId,
    job: impl FnOnce(&Unlocked) -> Result<T, AppError>,
) -> Result<T, AppError> {
    let (fresh, _) = match sign_in(transport, server, email, secret_key, password) {
        Err(AppError::WrongCredentials) => return Err(AppError::WrongPassword),
        other => other?,
    };
    if fresh.session.account_id() != account {
        return Err(AppError::Tampered);
    }
    let result = job(&fresh);
    // Best effort: the session expires on its own anyway.
    let _ = transport.send(&fresh.session.logout_request());
    result
}

/// Creates a recovery key, replacing any earlier one. Returns it to show
/// once.
///
/// # Errors
///
/// Returns [`AppError::WrongPassword`], or a server or network failure.
pub fn set_recovery_key(
    transport: &impl Transport,
    server: &ServerIdentity,
    email: &str,
    secret_key: &SecretKey,
    password: &str,
    account: &AccountId,
) -> Result<RecoveryKey, AppError> {
    with_fresh_session(
        transport,
        server,
        email,
        secret_key,
        password,
        account,
        |u| {
            let (key, request) = new_recovery_key(u, email)?;
            client_core::vaults::written(&transport.send(&request)?)?;
            Ok(key)
        },
    )
}

/// Removes the recovery key.
///
/// # Errors
///
/// As [`set_recovery_key`].
pub fn delete_recovery_key(
    transport: &impl Transport,
    server: &ServerIdentity,
    email: &str,
    secret_key: &SecretKey,
    password: &str,
    account: &AccountId,
) -> Result<(), AppError> {
    with_fresh_session(
        transport,
        server,
        email,
        secret_key,
        password,
        account,
        |u| {
            Ok(client_core::vaults::written(
                &transport.send(&remove_recovery_key(u))?,
            )?)
        },
    )
}

/// Whether the account has a recovery key.
///
/// # Errors
///
/// Returns a server or network failure.
pub fn recovery_key_set(transport: &impl Transport, unlocked: &Unlocked) -> Result<bool, AppError> {
    Ok(has_recovery_key(
        &transport.send(&recovery_status_request(unlocked))?,
    )?)
}

/// Sets a new master password with the recovery key (spec section 11.3).
/// Pass the Secret Key if this computer has the account's; otherwise a new
/// one is made. Every session the account had ends.
///
/// # Errors
///
/// Returns [`AppError::InvalidRecoveryKey`] or [`AppError::WrongRecoveryKey`]
/// for a recovery key that is mistyped or does not match the address, an
/// error for an unacceptable password, or a server or network failure.
pub fn recover(
    transport: &impl Transport,
    server: &ServerIdentity,
    email: &str,
    recovery_key: &str,
    password: &str,
    secret_key: Option<SecretKey>,
) -> Result<RecoveredAccount, AppError> {
    let (recovery, request) =
        Recovery::start(email, recovery_key, server).map_err(|e| match e {
            ClientError::Crypto(vault_core::Error::InvalidSecretKey(why)) => {
                AppError::InvalidRecoveryKey(why.to_string())
            }
            other => other.into(),
        })?;
    let recovered = recovery
        .open(&transport.send(&request)?)
        .map_err(|e| match e {
            ClientError::SignedOut => AppError::WrongRecoveryKey,
            other => other.into(),
        })?;
    let (setting, request) = recovered.choose_password(password, secret_key, KdfParams::DEFAULT)?;
    let (finishing, request) = setting.register(&transport.send(&request)?)?;
    Ok(finishing.complete(&transport.send(&request)?)?)
}
