//! Trusted contacts (spec sections 11.4 and 11.5).
//!
//! The owner names one trusted contact, whose keys they have verified
//! through key transparency or a safety number, with a waiting period:
//!
//! ```text
//! grant_request ─► PUT /v1/emergency      (session less than five minutes old)
//! remove_request ─► DELETE /v1/emergency
//! ```
//!
//! The contact asks for access, and the owner can deny it until the waiting
//! period is over:
//!
//! ```text
//! request_access ─► POST /v1/emergency/{owner}/request
//! deny_request   ─► POST /v1/emergency/{contact}/deny     (the owner)
//! ```
//!
//! After the waiting period the contact fetches the grant, checks the
//! owner's signature against the owner's keys from key transparency, and
//! unlocks the owner's key set. The server also hands over a read-only
//! session for the owner's account, valid for a day, so the contact's app
//! can sync the owner's vaults with the usual flows:
//!
//! ```text
//! release_request ─► GET /v1/emergency/{owner} ─► open_release ─► Unlocked
//! ```
//!
//! Both sides read where things stand with `GET /v1/emergency`
//! ([`status_request`], [`status`]), which is how an owner learns of a
//! request: clients should check it on every sync.

use vault_core::login::SessionToken;
use vault_core::recovery::{EMERGENCY_GRANT_LEN, EmergencyGrant, EmergencyKey, MAX_WAIT_DAYS};
use vault_core::{AccountId, KeySet, UnlockMethod, WRAPPED_KEY_SET_LEN};
use wire::{
    EmergencyGrantJson, EmergencyPutRequest, EmergencyReleaseResponse, EmergencyRequestResponse,
    EmergencyStatusResponse, b64,
};

use crate::http::{Method, Request, Response, Session, field, field_array};
use crate::keys::VerifiedKeys;
use crate::login::Unlocked;
use crate::{ClientError, Result};

/// A sensible default waiting period.
pub const DEFAULT_WAIT_DAYS: u16 = 7;

/// Makes a grant naming `contact` as this account's trusted contact, and the
/// request that stores it, replacing any earlier one. `contact` must come
/// from a key transparency lookup. The session must be less than five
/// minutes old.
///
/// # Errors
///
/// Returns [`ClientError::Crypto`] if `wait_days` is over 90, `contact` is
/// this account, or randomness or encryption fails.
pub fn grant_request(
    unlocked: &Unlocked,
    contact: &VerifiedKeys,
    wait_days: u16,
) -> Result<Request> {
    let me = unlocked.session.account_id();
    if contact.bundle.account_id == *me || wait_days > MAX_WAIT_DAYS {
        return Err(ClientError::Crypto(vault_core::Error::MalformedMessage));
    }
    let key = EmergencyKey::generate()?;
    let grant = EmergencyGrant::seal(
        &key,
        &unlocked.key_set,
        me,
        unlocked.key_set_version,
        &contact.bundle,
        wait_days,
    )?;
    let wrapped = unlocked.key_set.wrap(
        key.wrapping_key(),
        me,
        unlocked.key_set_version,
        UnlockMethod::TrustedContact,
    )?;
    Request::json(
        Method::Put,
        "/v1/emergency".into(),
        &EmergencyPutRequest {
            grant: b64(&grant),
            wrapped_key_set: b64(&wrapped),
        },
        Some(&unlocked.session),
    )
}

/// `DELETE /v1/emergency`: removes the trusted contact, and ends any
/// emergency session they were given.
#[must_use]
pub fn remove_request(unlocked: &Unlocked) -> Request {
    Request {
        method: Method::Delete,
        path: "/v1/emergency".into(),
        body: None,
        authorization: Some(unlocked.session.authorization()),
    }
}

/// `GET /v1/emergency`.
#[must_use]
pub fn status_request(unlocked: &Unlocked) -> Request {
    Request::get("/v1/emergency".into(), Some(&unlocked.session))
}

/// Where a grant is in its waiting period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantStage {
    /// Nobody has asked for access.
    Idle,
    /// The contact asked; access opens at `release_at_ms` unless denied.
    Requested {
        /// When the contact asked (Unix milliseconds).
        requested_ms: u64,
        /// When the grant can be released (Unix milliseconds).
        release_at_ms: u64,
    },
    /// The contact has been given access.
    Released,
}

/// One grant, as the server reports it. These are the server's claims: the
/// grant itself is checked only when it is released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantStatus {
    /// The account that named the contact.
    pub owner: AccountId,
    /// The trusted contact.
    pub contact: AccountId,
    /// The waiting period in days.
    pub wait_days: u16,
    /// Where it is.
    pub stage: GrantStage,
}

/// The answer to [`status_request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyStatus {
    /// The grant this account made, if any.
    pub granted: Option<GrantStatus>,
    /// Grants naming this account as the trusted contact.
    pub received: Vec<GrantStatus>,
}

fn grant_status(json: &EmergencyGrantJson) -> Result<GrantStatus> {
    let stage = match (json.state.as_str(), json.requested_ms, json.release_at_ms) {
        ("idle", _, _) => GrantStage::Idle,
        ("requested", Some(requested_ms), Some(release_at_ms)) if release_at_ms >= requested_ms => {
            GrantStage::Requested {
                requested_ms,
                release_at_ms,
            }
        }
        ("released", _, _) => GrantStage::Released,
        _ => return Err(ClientError::InvalidResponse),
    };
    if json.wait_days > MAX_WAIT_DAYS {
        return Err(ClientError::InvalidResponse);
    }
    Ok(GrantStatus {
        owner: AccountId::from_bytes(field_array(&json.owner_id)?),
        contact: AccountId::from_bytes(field_array(&json.contact_id)?),
        wait_days: json.wait_days,
        stage,
    })
}

/// Reads the answer to [`status_request`] for `me`.
///
/// # Errors
///
/// Returns a server error, or [`ClientError::InvalidResponse`] if a grant
/// is malformed or does not involve `me` as described.
pub fn status(me: &AccountId, response: &Response) -> Result<EmergencyStatus> {
    let answer: EmergencyStatusResponse = response.parse()?;
    let granted = answer.granted.as_ref().map(grant_status).transpose()?;
    if granted.as_ref().is_some_and(|g| g.owner != *me) {
        return Err(ClientError::InvalidResponse);
    }
    if answer.received.len() > 100 {
        return Err(ClientError::InvalidResponse);
    }
    let received = answer
        .received
        .iter()
        .map(grant_status)
        .collect::<Result<Vec<_>>>()?;
    if received.iter().any(|g| g.contact != *me) {
        return Err(ClientError::InvalidResponse);
    }
    Ok(EmergencyStatus { granted, received })
}

/// `POST /v1/emergency/{owner}/request`: the contact asks for access.
#[must_use]
pub fn request_access(unlocked: &Unlocked, owner: &AccountId) -> Request {
    Request {
        method: Method::Post,
        path: format!("/v1/emergency/{}/request", b64(owner.as_bytes())),
        body: None,
        authorization: Some(unlocked.session.authorization()),
    }
}

/// Reads when the requested access opens (Unix milliseconds).
///
/// # Errors
///
/// Returns a server error, for example if this account is not the
/// contact or a request is already pending.
pub fn access_requested(response: &Response) -> Result<u64> {
    let answer: EmergencyRequestResponse = response.parse()?;
    Ok(answer.release_at_ms)
}

/// `POST /v1/emergency/{contact}/deny`: the owner denies a pending request.
#[must_use]
pub fn deny_request(unlocked: &Unlocked, contact: &AccountId) -> Request {
    Request {
        method: Method::Post,
        path: format!("/v1/emergency/{}/deny", b64(contact.as_bytes())),
        body: None,
        authorization: Some(unlocked.session.authorization()),
    }
}

/// `GET /v1/emergency/{owner}`: the contact fetches a released grant.
#[must_use]
pub fn release_request(unlocked: &Unlocked, owner: &AccountId) -> Request {
    Request::get(
        format!("/v1/emergency/{}", b64(owner.as_bytes())),
        Some(&unlocked.session),
    )
}

/// Opens a released grant (spec section 11.4). `owner` must be the owner's
/// keys from a key transparency lookup made with the contact's own
/// session. Checks the grant names this account as the contact and is
/// signed by the owner, then unlocks the owner's key set. Returns it with
/// the read-only session the server gave for the owner's account.
///
/// # Errors
///
/// Returns a server error ([`ClientError::Server`] with status 403 and code
/// `too_early` while the waiting period lasts), or [`ClientError::Crypto`]
/// or [`ClientError::InvalidResponse`] if the grant or key set copy does
/// not check out.
pub fn open_release(
    contact: &Unlocked,
    owner: &VerifiedKeys,
    response: &Response,
) -> Result<Unlocked> {
    let answer: EmergencyReleaseResponse = response.parse()?;
    let grant = field(&answer.grant, EMERGENCY_GRANT_LEN)?;
    let wrapped = field(&answer.wrapped_key_set, WRAPPED_KEY_SET_LEN)?;
    let token: [u8; 32] = field_array(&answer.session_token)?;
    let (header, key) = EmergencyGrant::open(
        &grant,
        &contact.key_set,
        contact.session.account_id(),
        contact.key_set_version,
        &owner.bundle,
    )?;
    let (key_set, version): (KeySet, u32) = KeySet::unwrap(
        &wrapped,
        key.wrapping_key(),
        &header.owner,
        UnlockMethod::TrustedContact,
        header.owner_key_set_version,
    )
    .map_err(|_| ClientError::InvalidResponse)?;
    // The unlocked key set must be the one the owner published.
    if version != owner.bundle.key_set_version
        || key_set.identity().public_key().to_bytes() != owner.bundle.identity.to_bytes()
        || key_set.xwing_public_key().as_bytes() != owner.bundle.xwing.as_bytes()
    {
        return Err(ClientError::InvalidResponse);
    }
    Ok(Unlocked {
        session: Session::new(SessionToken::from_bytes(token), header.owner),
        key_set,
        key_set_version: version,
    })
}
