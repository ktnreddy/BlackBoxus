//! Account flows: `client-core`'s steps joined up with a [`Transport`].
//!
//! Each runs on a worker thread, because key derivation takes a second or
//! two on purpose.

use client_core::login::{Login, Unlocked};
use client_core::signup::{EmergencyKit, Signup};
use vault_core::{KdfParams, SecretKey, ServerIdentity};

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
) -> Result<(Unlocked, SecretKey, EmergencyKit), AppError> {
    let (signup, request) = Signup::start(email, password, server, KdfParams::DEFAULT)?;
    let (pending, request) = signup.register(&transport.send(&request)?)?;
    let account = pending.complete(&transport.send(&request)?)?;
    let kit = account.emergency_kit();
    let unlocked = sign_in(transport, server, email, &account.secret_key, password)?;
    // The account the server signed us in to must be the one just created.
    if unlocked.session.account_id() != &account.account_id {
        return Err(AppError::Tampered);
    }
    Ok((unlocked, account.secret_key, kit))
}

/// Signs in with an email address, Secret Key and master password.
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
) -> Result<Unlocked, AppError> {
    let (login, request) = Login::start(email, server)?;
    let (login, request) = login.prelogin(&transport.send(&request)?, password, secret_key)?;
    let (login, request) = login.key_exchange(&transport.send(&request)?)?;
    let (login, request) = login.finished(&transport.send(&request)?)?;
    Ok(login.unlock(&transport.send(&request)?)?)
}
