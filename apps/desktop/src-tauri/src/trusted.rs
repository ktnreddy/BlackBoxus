//! Trusted contacts (spec sections 11.4 and 11.5), as the desktop app shows
//! them: the contact this account named, people who named this account,
//! and read-only access to an account whose grant was released.

use std::path::Path;

use client_core::ClientError;
use client_core::emergency::{
    EmergencyStatus, GrantStage, GrantStatus, access_requested, deny_request, open_release,
    release_request, remove_request, request_access, status, status_request,
};
use client_core::login::Unlocked;
use serde::Serialize;
use vault_core::{AccountId, IdentityPublicKey};

use crate::error::AppError;
use crate::http::Transport;
use crate::sharing_id;
use crate::vaults::{VaultFiles, Vaults};

/// An account opened with a released grant, read-only.
pub struct EmergencyAccess {
    /// Whose account it is.
    pub owner: AccountId,
    /// The owner's key set, with the read-only session for their account.
    pub unlocked: Unlocked,
    /// The owner's vaults.
    pub vaults: Vaults,
}

impl core::fmt::Debug for EmergencyAccess {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EmergencyAccess")
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

/// One grant, for the window.
#[derive(Debug, Clone, Serialize)]
pub struct GrantView {
    /// The other person's sharing ID.
    pub sharing_id: String,
    /// The waiting period in days.
    pub wait_days: u16,
    /// `idle`, `requested` or `released`.
    pub stage: &'static str,
    /// When access opens, if requested (Unix milliseconds).
    pub release_at_ms: Option<u64>,
}

/// Trusted contacts, for the window.
#[derive(Debug, Clone, Serialize)]
pub struct EmergencyView {
    /// The contact this account named, if any.
    pub contact: Option<GrantView>,
    /// People who named this account as their contact.
    pub received: Vec<GrantView>,
}

fn view(grant: &GrantStatus, other: &AccountId) -> GrantView {
    let (stage, release_at_ms) = match grant.stage {
        GrantStage::Idle => ("idle", None),
        GrantStage::Requested { release_at_ms, .. } => ("requested", Some(release_at_ms)),
        GrantStage::Released => ("released", None),
    };
    GrantView {
        sharing_id: sharing_id::encode(other),
        wait_days: grant.wait_days,
        stage,
        release_at_ms,
    }
}

impl From<&EmergencyStatus> for EmergencyView {
    fn from(s: &EmergencyStatus) -> Self {
        Self {
            contact: s.granted.as_ref().map(|g| view(g, &g.contact)),
            received: s.received.iter().map(|g| view(g, &g.owner)).collect(),
        }
    }
}

/// Maps the server's answers about grants to messages for the user.
fn emergency_error(error: ClientError) -> AppError {
    match error {
        ClientError::Server { code, .. } if code == "too_early" => AppError::TooEarly,
        ClientError::Server { status: 403, .. } => AppError::EmergencyUnavailable,
        other => other.into(),
    }
}

/// Where this account's grants stand.
///
/// # Errors
///
/// Returns a server or network error.
pub fn emergency_status(
    transport: &impl Transport,
    unlocked: &Unlocked,
) -> Result<EmergencyStatus, AppError> {
    Ok(status(
        unlocked.session.account_id(),
        &transport.send(&status_request(unlocked))?,
    )?)
}

/// Removes this account's trusted contact.
///
/// # Errors
///
/// Returns a server or network error.
pub fn remove_contact(transport: &impl Transport, unlocked: &Unlocked) -> Result<(), AppError> {
    Ok(client_core::vaults::written(
        &transport.send(&remove_request(unlocked))?,
    )?)
}

/// Denies the trusted contact's pending request.
///
/// # Errors
///
/// Returns [`AppError::EmergencyUnavailable`] if nothing is pending, or a
/// server or network error.
pub fn deny(
    transport: &impl Transport,
    unlocked: &Unlocked,
    contact: &AccountId,
) -> Result<(), AppError> {
    client_core::vaults::written(&transport.send(&deny_request(unlocked, contact))?)
        .map_err(emergency_error)
}

/// Asks for access to `owner`'s account. Returns when it opens.
///
/// # Errors
///
/// Returns [`AppError::EmergencyUnavailable`] if this account is not their
/// contact or a request is already pending, or a server or network error.
pub fn request(
    transport: &impl Transport,
    unlocked: &Unlocked,
    owner: &AccountId,
) -> Result<u64, AppError> {
    access_requested(&transport.send(&request_access(unlocked, owner))?).map_err(emergency_error)
}

/// Opens `owner`'s account after the waiting period and syncs their
/// vaults into `dir`, read-only.
///
/// # Errors
///
/// Returns [`AppError::TooEarly`], [`AppError::EmergencyUnavailable`],
/// [`AppError::Tampered`] if the grant does not check out against the
/// owner's keys, or a server or network error.
pub fn open(
    transport: &impl Transport,
    unlocked: &Unlocked,
    vaults: &mut Vaults,
    owner: &AccountId,
    dir: &Path,
    log_key: IdentityPublicKey,
) -> Result<EmergencyAccess, AppError> {
    let owner_keys = vaults.verified_keys(transport, unlocked, owner)?;
    let response = transport.send(&release_request(unlocked, owner))?;
    let as_owner = open_release(unlocked, &owner_keys, &response).map_err(|e| match e {
        ClientError::Server { .. } => emergency_error(e),
        ClientError::Crypto(_) | ClientError::InvalidResponse => AppError::Tampered,
        other => other.into(),
    })?;
    // Nothing from an earlier visit is reused.
    let _ = std::fs::remove_dir_all(dir);
    let mut theirs = Vaults::new(VaultFiles::new(dir.to_path_buf()), log_key);
    theirs.sync_existing(transport, &as_owner)?;
    Ok(EmergencyAccess {
        owner: *owner,
        unlocked: as_owner,
        vaults: theirs,
    })
}
