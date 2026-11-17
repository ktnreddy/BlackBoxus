//! The JSON messages of the server API (spec section 12), shared by the
//! server and the clients so both always agree on the wire format.
//!
//! Requests reject unknown fields; responses accept them, so a newer server
//! can add fields without breaking older clients.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};
use vault_core::KdfParams;

/// Encodes bytes as base64url without padding.
#[must_use]
pub fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Decodes canonical base64url without padding, of at most `max_len` bytes.
/// Returns `None` for padding, other alphabets, non-zero trailing bits or
/// excess length.
#[must_use]
pub fn unb64(text: &str, max_len: usize) -> Option<Vec<u8>> {
    // Four characters carry three bytes; reject before decoding anything big.
    if text.len() > max_len.saturating_mul(4).div_ceil(3) {
        return None;
    }
    Base64UrlUnpadded::decode_vec(text)
        .ok()
        .filter(|b| b.len() <= max_len)
}

/// Decodes canonical base64url of exactly `N` bytes.
#[must_use]
pub fn unb64_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    unb64(text, N)?.try_into().ok()
}

/// An error answer: `{"error": "<code>"}` (spec section 12.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorResponse {
    /// The error code.
    pub error: String,
}

/// Argon2id parameters as sent in JSON.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KdfJson {
    /// Memory in KiB.
    pub m: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl From<KdfParams> for KdfJson {
    fn from(k: KdfParams) -> Self {
        Self {
            m: k.memory_kib,
            t: k.iterations,
            p: k.parallelism,
        }
    }
}

impl From<KdfJson> for KdfParams {
    fn from(k: KdfJson) -> Self {
        Self {
            memory_kib: k.m,
            iterations: k.t,
            parallelism: k.p,
        }
    }
}

/// `POST /v1/prelogin`
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreloginRequest {
    /// Email address.
    pub email: String,
}

/// Answer to `POST /v1/prelogin`.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreloginResponse {
    /// Argon2id salt.
    pub salt: String,
    /// Argon2id parameters.
    pub kdf: KdfJson,
}

/// `POST /v1/register/start`
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterStartRequest {
    /// Email address.
    pub email: String,
    /// OPAQUE registration request.
    pub request: String,
}

/// Answer to `POST /v1/register/start`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterStartResponse {
    /// OPAQUE registration response.
    pub response: String,
}

/// `POST /v1/register/finish`
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterFinishRequest {
    /// Email address.
    pub email: String,
    /// Argon2id salt.
    pub salt: String,
    /// Argon2id parameters.
    pub kdf: KdfJson,
    /// OPAQUE registration upload.
    pub upload: String,
    /// Signed public key bundle.
    pub signed_bundle: String,
    /// Key set wrapped with method 1.
    pub wrapped_key_set: String,
}

/// Answer to `POST /v1/register/finish`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterFinishResponse {
    /// The new account's ID, lower-case hex.
    pub account_id: String,
}

/// `POST /v1/login/start`
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginStartRequest {
    /// Email address.
    pub email: String,
    /// OPAQUE `KE1`.
    pub ke1: String,
}

/// Answer to `POST /v1/login/start`.
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginStartResponse {
    /// ID to send back with `KE3`.
    pub login_id: String,
    /// OPAQUE `KE2`.
    pub ke2: String,
}

/// `POST /v1/login/finish`
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginFinishRequest {
    /// From `login/start`.
    pub login_id: String,
    /// OPAQUE `KE3`.
    pub ke3: String,
}

/// One wrapped copy of the key set.
#[derive(Debug, Serialize, Deserialize)]
pub struct WrappedJson {
    /// Unlock method (spec section 5.4).
    pub method: u8,
    /// The wrapped key set.
    pub data: String,
}

/// Answer to `GET /v1/keyset`.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeySetResponse {
    /// The account's ID. Clients may not know it yet on a new device; a
    /// wrong value only makes unwrapping fail, because the wrapped key set
    /// is bound to it (spec section 5.4).
    pub account_id: String,
    /// Current key set version.
    pub key_set_version: u32,
    /// Wrapped copies stored on the server.
    pub wrapped: Vec<WrappedJson>,
}

/// Answer to `GET /v1/accounts/{id}/keys`.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyLookupJson {
    /// Signed public key bundle.
    pub signed_bundle: String,
    /// Its log leaf.
    pub leaf: String,
    /// The leaf's index.
    pub leaf_index: u64,
    /// Inclusion proof.
    pub inclusion_proof: Vec<String>,
    /// Signed tree head.
    pub signed_tree_head: String,
    /// Consistency proof from `seen`.
    pub consistency_proof: Vec<String>,
}

/// One leaf in the answer to `GET /v1/accounts/self/leaves`.
#[derive(Debug, Serialize, Deserialize)]
pub struct OwnLeafJson {
    /// The log leaf.
    pub leaf: String,
    /// Its index.
    pub leaf_index: u64,
    /// Inclusion proof.
    pub inclusion_proof: Vec<String>,
}

/// Answer to `GET /v1/accounts/self/leaves`.
#[derive(Debug, Serialize, Deserialize)]
pub struct OwnLeavesJson {
    /// Every leaf for this account, in log order.
    pub leaves: Vec<OwnLeafJson>,
    /// Signed tree head.
    pub signed_tree_head: String,
    /// Consistency proof from `seen`.
    pub consistency_proof: Vec<String>,
}

/// `PUT /v1/enrolment/{session_id}`
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolmentPutRequest {
    /// The encrypted transfer.
    pub sealed: String,
}

/// Answer to `GET /v1/enrolment/{session_id}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct EnrolmentGetResponse {
    /// The encrypted transfer.
    pub sealed: String,
}

/// One vault the account may read.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultSummary {
    /// The vault ID.
    pub vault_id: String,
    /// Sequence number of its last log entry.
    pub head_seq: u64,
}

/// Answer to `GET /v1/vaults`.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultListResponse {
    /// Vaults the account may read.
    pub vaults: Vec<VaultSummary>,
}

/// `POST /v1/vaults/{vault_id}/log`
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogAppendRequest {
    /// The signed log entry.
    pub entry: String,
    /// The item envelope, with a `PutItem` entry only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope: Option<String>,
}

/// Answer to `POST /v1/vaults/{vault_id}/log`.
#[derive(Debug, Serialize, Deserialize)]
pub struct LogAppendResponse {
    /// The entry's sequence number.
    pub seq: u64,
}

/// Answer to `GET /v1/vaults/{vault_id}/log?from={seq}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct LogResponse {
    /// Signed entries, in order, starting at `from`.
    pub entries: Vec<String>,
    /// `true` if more entries follow; ask again from the next sequence.
    pub more: bool,
}

/// An item's current envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ItemJson {
    /// The item ID.
    pub item_id: String,
    /// Its current revision.
    pub revision: u64,
    /// The envelope, or `None` if the item was deleted.
    pub envelope: Option<String>,
    /// The log entry that set this revision.
    pub seq: u64,
}

/// Answer to `GET /v1/vaults/{vault_id}/items?after={seq}`.
#[derive(Debug, Serialize, Deserialize)]
pub struct ItemsResponse {
    /// Items changed by log entries after `after`, ordered by `seq`.
    pub items: Vec<ItemJson>,
    /// `true` if more items follow; ask again after the last `seq`.
    pub more: bool,
}

/// `PUT /v1/vaults/{vault_id}/keys`
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultKeyPutRequest {
    /// The vault key wrapped by the member for themself.
    pub wrapped: String,
}

/// Answer to `GET /v1/vaults/{vault_id}/keys`.
#[derive(Debug, Serialize, Deserialize)]
pub struct VaultKeysResponse {
    /// This account's wrapped copies of the vault key, every version.
    pub keys: Vec<String>,
}

/// `POST /v1/shares`
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharePostRequest {
    /// The signed vault share.
    pub share: String,
}

/// Answer to `GET /v1/shares`.
#[derive(Debug, Serialize, Deserialize)]
pub struct SharesResponse {
    /// Shares addressed to this account.
    pub shares: Vec<String>,
}

/// `PUT /v1/recovery`
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPutRequest {
    /// `SHA-256(auth_token)`.
    pub verifier: String,
    /// Key set wrapped with method 4.
    pub wrapped_key_set: String,
}

/// `POST /v1/recovery/start`
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryStartRequest {
    /// Email address.
    pub email: String,
    /// The recovery token derived from the recovery key.
    pub auth_token: String,
}

/// Answer to `POST /v1/recovery/start`.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryStartResponse {
    /// The account's ID. A wrong value only makes unwrapping fail.
    pub account_id: String,
    /// Key set wrapped with method 4.
    pub wrapped_key_set: String,
}

/// `POST /v1/password`
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordChangeRequest {
    /// OPAQUE registration upload for the new master password.
    pub upload: String,
    /// New Argon2id salt.
    pub salt: String,
    /// Argon2id parameters.
    pub kdf: KdfJson,
    /// Key set wrapped with method 1 under the new master password.
    pub wrapped_key_set: String,
}

/// `POST /v1/recovery/finish`
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryFinishRequest {
    /// Email address.
    pub email: String,
    /// The recovery token derived from the recovery key.
    pub auth_token: String,
    /// OPAQUE registration upload for the new master password.
    pub upload: String,
    /// New Argon2id salt.
    pub salt: String,
    /// Argon2id parameters.
    pub kdf: KdfJson,
    /// Key set wrapped with method 1 under the new master password.
    pub wrapped_key_set: String,
}

/// `PUT /v1/emergency`
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmergencyPutRequest {
    /// The signed emergency grant (spec section 11.4).
    pub grant: String,
    /// Key set wrapped with method 5 under the grant's emergency key.
    pub wrapped_key_set: String,
}

/// One emergency grant's waiting-period state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyGrantJson {
    /// The account that named a trusted contact.
    pub owner_id: String,
    /// The trusted contact.
    pub contact_id: String,
    /// Days between a request and the release.
    pub wait_days: u16,
    /// `idle`, `requested` or `released`.
    pub state: String,
    /// When access was requested (Unix milliseconds).
    pub requested_ms: Option<u64>,
    /// When the grant can be released (Unix milliseconds).
    pub release_at_ms: Option<u64>,
}

/// Answer to `GET /v1/emergency`.
#[derive(Debug, Serialize, Deserialize)]
pub struct EmergencyStatusResponse {
    /// The grant this account made, if any.
    pub granted: Option<EmergencyGrantJson>,
    /// Grants naming this account as the trusted contact.
    pub received: Vec<EmergencyGrantJson>,
}

/// Answer to `POST /v1/emergency/{owner_id}/request`.
#[derive(Debug, Serialize, Deserialize)]
pub struct EmergencyRequestResponse {
    /// When the grant can be released (Unix milliseconds).
    pub release_at_ms: u64,
}

/// Answer to `GET /v1/emergency/{owner_id}` once released.
#[derive(Debug, Serialize, Deserialize)]
pub struct EmergencyReleaseResponse {
    /// The signed emergency grant.
    pub grant: String,
    /// The owner's key set wrapped with method 5.
    pub wrapped_key_set: String,
    /// A read-only session for the owner's account, valid for a day.
    pub session_token: String,
}
