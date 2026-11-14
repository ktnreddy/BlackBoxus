//! Adding a device by QR code (spec section 10.3).
//!
//! On the signed-in device: [`EnrolmentOffer::generate`], show
//! [`EnrolmentOffer::to_qr_text`], then send [`offer_request`]. On the new
//! device: [`EnrolmentOffer::from_qr_text`], send [`fetch_request`], then
//! [`receive`]. The new device then signs in as usual with the received
//! Secret Key and the master password, which the transfer never contains.

use vault_core::device::{EnrolmentOffer, EnrolmentPayload};
use vault_core::{ClientIdentity, SecretKey, ServerIdentity};
use wire::{EnrolmentGetResponse, EnrolmentPutRequest, b64};

use crate::http::{Method, Request, Response, Session, field};
use crate::{ClientError, Result};

/// Largest enrolment transfer.
const MAX_TRANSFER_BYTES: usize = 8192;

/// `PUT /v1/enrolment/{session_id}` from the signed-in device.
///
/// # Errors
///
/// Returns an error if encryption fails.
pub fn offer_request(
    offer: &EnrolmentOffer,
    session: &Session,
    email: &ClientIdentity,
    server: &ServerIdentity,
    secret_key: &SecretKey,
    signed_tree_head: Option<Vec<u8>>,
) -> Result<Request> {
    let sealed = offer.seal(&EnrolmentPayload {
        account_id: *session.account_id(),
        email: email.clone(),
        server: server.clone(),
        secret_key: secret_key.clone(),
        signed_tree_head,
    })?;
    Request::json(
        Method::Put,
        path(offer),
        &EnrolmentPutRequest {
            sealed: b64(&sealed),
        },
        Some(session),
    )
}

/// Checks the server stored the transfer.
///
/// # Errors
///
/// Returns a server error, such as `conflict` if this offer was already
/// used.
pub fn offer_sent(response: &Response) -> Result<()> {
    response.ok()
}

/// `GET /v1/enrolment/{session_id}` from the new device.
#[must_use]
pub fn fetch_request(offer: &EnrolmentOffer) -> Request {
    Request::get(path(offer), None)
}

/// Decrypts the transfer on the new device.
///
/// # Errors
///
/// Returns [`ClientError::Server`] with code `not_allowed` if the transfer
/// expired or was already taken (possibly by someone else; start again), or
/// [`ClientError::Crypto`] if it was tampered with.
pub fn receive(offer: &EnrolmentOffer, response: &Response) -> Result<EnrolmentPayload> {
    let answer: EnrolmentGetResponse = response.parse()?;
    let sealed = field(&answer.sealed, MAX_TRANSFER_BYTES)?;
    offer.open(&sealed).map_err(ClientError::from)
}

fn path(offer: &EnrolmentOffer) -> String {
    format!("/v1/enrolment/{}", b64(offer.session_id()))
}
