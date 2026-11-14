//! Internal decoders exposed for fuzz testing only (the `fuzzing` feature).
//! Not part of the API; never enable this feature in a release build.
//!
//! These cover content that is only reachable after decryption, which a
//! fuzzer could not otherwise produce, but which a vault member who holds
//! the key could craft.

use zeroize::Zeroizing;

use crate::Result;
use crate::device::EnrolmentPayload;
use crate::item::{Item, pad, unpad};

/// Decodes item content (spec section 6.3).
///
/// # Errors
///
/// Whatever decoding returns.
pub fn decode_item(bytes: &[u8]) -> Result<Item> {
    Item::decode(bytes)
}

/// Encodes item content.
///
/// # Errors
///
/// Whatever encoding returns.
pub fn encode_item(item: &Item) -> Result<Zeroizing<Vec<u8>>> {
    item.encode()
}

/// Removes padding (spec section 6.4).
///
/// # Errors
///
/// Whatever unpadding returns.
pub fn unpad_content(padded: &[u8]) -> Result<Vec<u8>> {
    unpad(padded).map(<[u8]>::to_vec)
}

/// Adds padding.
///
/// # Errors
///
/// Whatever padding returns.
pub fn pad_content(content: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    pad(content)
}

/// Decodes an enrolment payload (spec section 10.3).
///
/// # Errors
///
/// Whatever decoding returns.
pub fn decode_enrolment_payload(bytes: &[u8]) -> Result<EnrolmentPayload> {
    EnrolmentPayload::decode(bytes)
}

/// Encodes an enrolment payload.
///
/// # Errors
///
/// Whatever encoding returns.
pub fn encode_enrolment_payload(payload: &EnrolmentPayload) -> Result<Zeroizing<Vec<u8>>> {
    payload.encode()
}
