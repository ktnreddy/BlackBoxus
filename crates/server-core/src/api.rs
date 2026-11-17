//! Request handling for the server API (spec section 12).
//!
//! This module does no I/O. Each handler takes the records the hosting
//! adapter loaded, checks the request, and returns what the adapter must
//! store or send. This keeps every security check in one tested place and
//! lets the adapter use whatever (asynchronous) storage its platform offers.
//!
//! The adapter's only duties are the ones handlers cannot do alone: loading
//! and storing records atomically, enforcing uniqueness, deleting one-time
//! records after use, and rate limiting.

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use vault_core::log::bundle_hash;
use vault_core::login::SESSION_TOKEN_LEN;
use vault_core::transparency::{KtLeaf, LEAF_LEN};
use vault_core::{
    AccountId, AccountSalt, ClientIdentity, IdentitySecretKey, KdfParams, PublicKeyBundle,
    ServerIdentity, UnlockMethod, WRAPPED_KEY_SET_LEN,
};
use zeroize::Zeroizing;

use crate::login::{OpaqueServer, ServerLoginState, finish_registration};
use crate::prelogin::FakeSaltKey;
use crate::transparency::KtLog;
use crate::{Error, Result};

/// Largest request body the server accepts, in bytes.
pub const MAX_REQUEST_BYTES: usize = 1 << 20;

/// How long a login may take between `KE1` and `KE3`, in milliseconds.
pub const LOGIN_TTL_MS: u64 = 60_000;

/// A session expires after this long without use, in milliseconds (14 days).
pub const SESSION_IDLE_MS: u64 = 14 * 86_400_000;

/// A session expires this long after login however it is used, in
/// milliseconds (90 days).
pub const SESSION_MAX_MS: u64 = 90 * 86_400_000;

/// How long an enrolment transfer is kept, in milliseconds.
pub const ENROLMENT_TTL_MS: u64 = 300_000;

/// Largest enrolment transfer, in bytes.
pub const MAX_ENROLMENT_BYTES: usize = 8192;

/// Smallest enrolment transfer (nonce, tag and fixed fields), in bytes.
pub const MIN_ENROLMENT_BYTES: usize = 96;

/// Longest an emergency session lasts (spec section 11.5).
pub const EMERGENCY_SESSION_MS: u64 = 86_400_000;

/// Length of a login ID, in bytes.
pub const LOGIN_ID_LEN: usize = 16;

/// Everything the server stores for an account. Contains no secrets that
/// would let the server decrypt anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRecord {
    /// The account's random ID.
    pub account_id: AccountId,
    /// The canonical email address.
    pub identity: ClientIdentity,
    /// Argon2id salt (spec section 3.4).
    pub salt: AccountSalt,
    /// Argon2id parameters.
    pub kdf: KdfParams,
    /// OPAQUE registration record (spec section 4.4).
    pub opaque_record: Vec<u8>,
    /// The current signed public key bundle (spec section 5.5).
    pub signed_bundle: Vec<u8>,
    /// The current key set version.
    pub key_set_version: u32,
    /// The key set wrapped with the master password (method 1).
    pub wrapped_key_set: Vec<u8>,
}

/// A client's request to create an account.
#[derive(Debug, Clone)]
pub struct NewAccount<'a> {
    /// The email address, as typed.
    pub email: &'a str,
    /// Argon2id salt chosen by the client.
    pub salt: AccountSalt,
    /// Argon2id parameters chosen by the client.
    pub kdf: KdfParams,
    /// OPAQUE registration upload.
    pub registration_upload: &'a [u8],
    /// Signed public key bundle for key set version 1.
    pub signed_bundle: &'a [u8],
    /// Key set version 1 wrapped with method 1.
    pub wrapped_key_set: &'a [u8],
}

/// A login between `KE1` and `KE3`. The adapter keeps it server-side only,
/// under [`PendingLogin::login_id`], and deletes it when it is used or
/// expires.
#[derive(Debug)]
pub struct PendingLogin {
    /// Random ID the client sends back with `KE3`.
    pub login_id: [u8; LOGIN_ID_LEN],
    /// The canonical email address.
    pub identity: ClientIdentity,
    /// The account, or `None` for a fake login of an unknown address.
    pub account_id: Option<AccountId>,
    /// OPAQUE server state. Contains ephemeral secrets.
    pub state: Zeroizing<Vec<u8>>,
    /// When the login expires (Unix milliseconds).
    pub expires_ms: u64,
}

/// A signed-in session. The server never stores the token itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// `SHA-256(session_token)`; also the storage key.
    pub token_hash: [u8; 32],
    /// The account.
    pub account_id: AccountId,
    /// When the session was created (Unix milliseconds).
    pub created_ms: u64,
    /// When the session was last used (Unix milliseconds).
    pub last_used_ms: u64,
    /// An emergency session, given to a trusted contact (spec section
    /// 11.5): it can only read, and lasts at most a day.
    pub read_only: bool,
}

/// The server's answer to a key lookup (spec section 9.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLookupResponse {
    /// The account's signed public key bundle.
    pub signed_bundle: Vec<u8>,
    /// Its log leaf.
    pub leaf: Vec<u8>,
    /// The leaf's index in the log.
    pub leaf_index: u64,
    /// Inclusion proof against the current tree head.
    pub inclusion_proof: Vec<[u8; 32]>,
    /// The current signed tree head.
    pub signed_tree_head: Vec<u8>,
    /// Consistency proof from the tree size the client last saw.
    pub consistency_proof: Vec<[u8; 32]>,
}

/// One of an account's own log leaves, with its inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnLeaf {
    /// The leaf.
    pub leaf: Vec<u8>,
    /// Its index in the log.
    pub leaf_index: u64,
    /// Inclusion proof against the current tree head.
    pub inclusion_proof: Vec<[u8; 32]>,
}

/// The server's answer when an account asks for its own leaves (spec
/// section 9.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnLeavesResponse {
    /// Every leaf for the account, in log order.
    pub leaves: Vec<OwnLeaf>,
    /// The current signed tree head.
    pub signed_tree_head: Vec<u8>,
    /// Consistency proof from the tree size the client last saw.
    pub consistency_proof: Vec<[u8; 32]>,
}

/// Most leaves one account can have: one per key set version, and key sets
/// are replaced rarely.
pub const MAX_OWN_LEAVES: usize = 1000;

/// An enrolment transfer waiting to be picked up (spec section 10.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolmentTransfer {
    /// The encrypted payload; the server cannot read it.
    pub sealed: Vec<u8>,
    /// When the transfer expires (Unix milliseconds).
    pub expires_ms: u64,
}

/// `SHA-256` of a presented session token, used to look up the session.
///
/// # Errors
///
/// Returns [`Error::Authentication`] if the token has the wrong length.
pub fn session_token_hash(presented: &[u8]) -> Result<[u8; 32]> {
    if presented.len() != SESSION_TOKEN_LEN {
        return Err(Error::Authentication);
    }
    Ok(Sha256::digest(presented).into())
}

/// The server's long-term secrets and identity.
pub struct Api {
    opaque: OpaqueServer,
    fake_salt: FakeSaltKey,
    log_key: IdentitySecretKey,
    server: ServerIdentity,
}

impl core::fmt::Debug for Api {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Api")
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

impl Api {
    /// Builds the API from the server's configuration.
    #[must_use]
    pub const fn new(
        opaque: OpaqueServer,
        fake_salt: FakeSaltKey,
        log_key: IdentitySecretKey,
        server: ServerIdentity,
    ) -> Self {
        Self {
            opaque,
            fake_salt,
            log_key,
            server,
        }
    }

    /// `POST /v1/prelogin`: the salt and parameters for an address. Unknown
    /// addresses get a stable fake answer (spec section 3.8).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfiguration`].
    pub fn prelogin(
        &self,
        identity: &ClientIdentity,
        account: Option<&AccountRecord>,
    ) -> Result<(AccountSalt, KdfParams)> {
        match account {
            Some(a) if a.identity == *identity => Ok((a.salt, a.kdf)),
            _ => self.fake_salt.fake_prelogin(identity),
        }
    }

    /// `POST /v1/register/start`: answers an OPAQUE registration request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] or [`Error::Authentication`].
    pub fn registration_response(
        &self,
        identity: &ClientIdentity,
        request: &[u8],
    ) -> Result<Vec<u8>> {
        self.opaque.registration_response(request, identity)
    }

    /// `POST /v1/register/finish`: checks a new account and returns the
    /// record and key transparency leaf to store.
    ///
    /// The adapter MUST store both atomically, and MUST fail with
    /// [`Error::Conflict`] if the email address or account ID is taken.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if any part is invalid.
    pub fn create_account(
        &self,
        request: &NewAccount<'_>,
        now_ms: u64,
    ) -> Result<(AccountRecord, [u8; LEAF_LEN])> {
        let identity = ClientIdentity::new(request.email).map_err(|_| Error::MalformedMessage)?;
        request
            .kdf
            .validate()
            .map_err(|_| Error::MalformedMessage)?;
        let opaque_record = finish_registration(request.registration_upload)?;
        let bundle = PublicKeyBundle::verify_signed(request.signed_bundle)
            .map_err(|_| Error::MalformedMessage)?;
        if bundle.key_set_version != 1 {
            return Err(Error::MalformedMessage);
        }
        check_wrapped_key_set(request.wrapped_key_set, 1)?;

        let leaf = KtLeaf {
            account_id: bundle.account_id,
            key_set_version: 1,
            bundle_hash: bundle_hash(request.signed_bundle),
            timestamp_ms: now_ms,
        }
        .encode();
        let record = AccountRecord {
            account_id: bundle.account_id,
            identity,
            salt: request.salt,
            kdf: request.kdf,
            opaque_record,
            signed_bundle: request.signed_bundle.to_vec(),
            key_set_version: 1,
            wrapped_key_set: request.wrapped_key_set.to_vec(),
        };
        Ok((record, leaf))
    }

    /// `POST /v1/login/start`: answers `KE1`. Unknown addresses get a fake
    /// `KE2` that looks the same (spec section 4.5).
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`], [`Error::Authentication`] or
    /// [`Error::InvalidConfiguration`] if the random generator fails.
    pub fn start_login(
        &self,
        identity: &ClientIdentity,
        account: Option<&AccountRecord>,
        ke1: &[u8],
        now_ms: u64,
    ) -> Result<(PendingLogin, Vec<u8>)> {
        let account = account.filter(|a| a.identity == *identity);
        let (state, ke2) = self.opaque.start_login(
            account.map(|a| a.opaque_record.as_slice()),
            ke1,
            identity,
            &self.server,
        )?;
        let mut login_id = [0_u8; LOGIN_ID_LEN];
        OsRng
            .try_fill_bytes(&mut login_id)
            .map_err(|_| Error::InvalidConfiguration)?;
        Ok((
            PendingLogin {
                login_id,
                identity: identity.clone(),
                account_id: account.map(|a| a.account_id),
                state: state.to_bytes(),
                expires_ms: now_ms.saturating_add(LOGIN_TTL_MS),
            },
            ke2,
        ))
    }

    /// `POST /v1/login/finish`: checks `KE3` and returns the session to
    /// store. The adapter MUST have deleted `pending` before calling this,
    /// so it is used at most once.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Authentication`] for a wrong password, an unknown
    /// address or an expired login, or [`Error::MalformedMessage`].
    pub fn finish_login(&self, pending: PendingLogin, ke3: &[u8], now_ms: u64) -> Result<Session> {
        if now_ms >= pending.expires_ms {
            return Err(Error::Authentication);
        }
        let state = ServerLoginState::from_bytes(&pending.state)?;
        let token = state.finish(ke3, &pending.identity, &self.server)?;
        // A fake login cannot normally reach here, but never let one through.
        let account_id = pending.account_id.ok_or(Error::Authentication)?;
        Ok(Session {
            token_hash: token.storage_hash(),
            account_id,
            created_ms: now_ms,
            last_used_ms: now_ms,
            read_only: false,
        })
    }

    /// Checks a bearer token against the session the adapter looked up by
    /// [`session_token_hash`]. On success the adapter stores the returned
    /// session, whose last-use time is updated; on failure it deletes any
    /// expired session.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Authentication`] for an unknown, wrong or expired
    /// session.
    pub fn authenticate(
        &self,
        presented: &[u8],
        session: Option<&Session>,
        now_ms: u64,
    ) -> Result<Session> {
        let hash = session_token_hash(presented)?;
        let session = session.ok_or(Error::Authentication)?;
        let max = if session.read_only {
            EMERGENCY_SESSION_MS
        } else {
            SESSION_MAX_MS
        };
        if !bool::from(hash.ct_eq(&session.token_hash))
            || now_ms >= session.last_used_ms.saturating_add(SESSION_IDLE_MS)
            || now_ms >= session.created_ms.saturating_add(max)
        {
            return Err(Error::Authentication);
        }
        let mut updated = session.clone();
        updated.last_used_ms = updated.last_used_ms.max(now_ms);
        Ok(updated)
    }

    /// Signs the log's current tree head. The adapter stores the result with
    /// the log, atomically, every time a leaf is appended.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfiguration`] if signing fails.
    pub fn sign_tree_head(&self, log: &KtLog, now_ms: u64) -> Result<Vec<u8>> {
        log.signed_tree_head(&self.log_key, now_ms)
    }

    /// `GET /v1/accounts/{id}/keys`: a key lookup with proofs against a
    /// freshly signed tree head. `seen_size` is the tree size the client
    /// last saw, if any.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if the index or size is beyond
    /// the log, or [`Error::InvalidConfiguration`] if signing fails.
    pub fn key_lookup(
        &self,
        log: &KtLog,
        account: &AccountRecord,
        leaf: &[u8],
        leaf_index: u64,
        seen_size: Option<u64>,
        now_ms: u64,
    ) -> Result<KeyLookupResponse> {
        let head = self.sign_tree_head(log, now_ms)?;
        Self::key_lookup_with_head(log, account, leaf, leaf_index, seen_size, head)
    }

    /// Like [`Api::key_lookup`], but answers with the tree head stored by
    /// the adapter when the log last grew, instead of signing a new one.
    /// This keeps each lookup cheap.
    ///
    /// # Errors
    ///
    /// As [`Api::key_lookup`]; also [`Error::InvalidConfiguration`] if the
    /// stored head is not for the log's current size.
    pub fn key_lookup_with_head(
        log: &KtLog,
        account: &AccountRecord,
        leaf: &[u8],
        leaf_index: u64,
        seen_size: Option<u64>,
        signed_tree_head: Vec<u8>,
    ) -> Result<KeyLookupResponse> {
        let size = log.size();
        let head_size = signed_tree_head
            .get(2..10)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_be_bytes);
        if head_size != Some(size) {
            return Err(Error::InvalidConfiguration);
        }
        let consistency_proof = match seen_size {
            Some(old) if old > size => return Err(Error::MalformedMessage),
            Some(old) if old > 0 => log.consistency_proof(old, size)?,
            _ => Vec::new(),
        };
        Ok(KeyLookupResponse {
            signed_bundle: account.signed_bundle.clone(),
            leaf: leaf.to_vec(),
            leaf_index,
            inclusion_proof: log.inclusion_proof(leaf_index, size)?,
            signed_tree_head,
            consistency_proof,
        })
    }

    /// `GET /v1/accounts/self/leaves` (spec section 9.5): every leaf the
    /// log holds for the signed-in account, given as `(leaf_index, leaf)`
    /// in log order, each with an inclusion proof against the current
    /// signed tree head.
    ///
    /// # Errors
    ///
    /// As [`Api::key_lookup_with_head`]; also [`Error::InvalidConfiguration`]
    /// for more than [`MAX_OWN_LEAVES`] leaves.
    pub fn own_leaves(
        log: &KtLog,
        leaves: &[(u64, Vec<u8>)],
        seen_size: Option<u64>,
        signed_tree_head: Vec<u8>,
    ) -> Result<OwnLeavesResponse> {
        let size = log.size();
        let head_size = signed_tree_head
            .get(2..10)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_be_bytes);
        if head_size != Some(size) || leaves.len() > MAX_OWN_LEAVES {
            return Err(Error::InvalidConfiguration);
        }
        let consistency_proof = match seen_size {
            Some(old) if old > size => return Err(Error::MalformedMessage),
            Some(old) if old > 0 => log.consistency_proof(old, size)?,
            _ => Vec::new(),
        };
        let leaves = leaves
            .iter()
            .map(|(index, leaf)| {
                Ok(OwnLeaf {
                    leaf: leaf.clone(),
                    leaf_index: *index,
                    inclusion_proof: log.inclusion_proof(*index, size)?,
                })
            })
            .collect::<Result<_>>()?;
        Ok(OwnLeavesResponse {
            leaves,
            signed_tree_head,
            consistency_proof,
        })
    }
}

/// `PUT /v1/enrolment/{session_id}`: accepts an enrolment transfer from a
/// signed-in device. The adapter MUST fail with [`Error::Conflict`] if one
/// already exists for the session ID.
///
/// # Errors
///
/// Returns [`Error::MalformedMessage`] for a size no client produces.
pub fn accept_enrolment(sealed: &[u8], now_ms: u64) -> Result<EnrolmentTransfer> {
    if !(MIN_ENROLMENT_BYTES..=MAX_ENROLMENT_BYTES).contains(&sealed.len()) {
        return Err(Error::MalformedMessage);
    }
    Ok(EnrolmentTransfer {
        sealed: sealed.to_vec(),
        expires_ms: now_ms.saturating_add(ENROLMENT_TTL_MS),
    })
}

/// `GET /v1/enrolment/{session_id}`: hands over a transfer. The adapter MUST
/// delete it before answering, whatever the result.
///
/// # Errors
///
/// Returns [`Error::NotAllowed`] if there is none or it expired.
pub fn take_enrolment(transfer: Option<EnrolmentTransfer>, now_ms: u64) -> Result<Vec<u8>> {
    match transfer {
        Some(t) if now_ms < t.expires_ms => Ok(t.sealed),
        _ => Err(Error::NotAllowed),
    }
}

/// Checks a wrapped key set's length, format, version and method 1
/// (spec section 5.4). The server cannot check the ciphertext.
///
/// # Errors
///
/// Returns [`Error::MalformedMessage`].
pub fn check_wrapped_key_set(wrapped: &[u8], key_set_version: u32) -> Result<()> {
    check_wrapped_copy(wrapped, key_set_version, UnlockMethod::MasterPassword)
}

/// As [`check_wrapped_key_set`], for a copy wrapped with `method`.
///
/// # Errors
///
/// Returns [`Error::MalformedMessage`].
pub fn check_wrapped_copy(
    wrapped: &[u8],
    key_set_version: u32,
    method: UnlockMethod,
) -> Result<()> {
    let mut expected = [0_u8; 7];
    let (format, rest) = expected.split_at_mut(2);
    format.copy_from_slice(&1_u16.to_be_bytes());
    let (version, code) = rest.split_at_mut(4);
    version.copy_from_slice(&key_set_version.to_be_bytes());
    code.fill(method.code());
    if wrapped.len() != WRAPPED_KEY_SET_LEN || wrapped.get(..7) != Some(expected.as_slice()) {
        return Err(Error::MalformedMessage);
    }
    Ok(())
}

/// A new emergency session for `owner`, handed to the trusted contact whose
/// grant was released (spec section 11.5). Returns the token to send once
/// and the session to store. Such a session can only read: the adapter
/// MUST refuse every other request made with it.
///
/// # Errors
///
/// Returns [`Error::InvalidConfiguration`] if the generator fails.
pub fn emergency_session(owner: &AccountId, now_ms: u64) -> Result<([u8; 32], Session)> {
    let mut token = [0_u8; SESSION_TOKEN_LEN];
    OsRng
        .try_fill_bytes(&mut token)
        .map_err(|_| Error::InvalidConfiguration)?;
    Ok((
        token,
        Session {
            token_hash: session_token_hash(&token)?,
            account_id: *owner,
            created_ms: now_ms,
            last_used_ms: now_ms,
            read_only: true,
        },
    ))
}

/// How recently a session must have been created for changes to how the
/// account is unlocked (spec section 12.7).
pub const FRESH_SESSION_MS: u64 = 300_000;

/// Checks that a session was created in the last five minutes, by signing
/// in with the master password.
///
/// # Errors
///
/// Returns [`Error::NotAllowed`] if it is older.
pub fn require_fresh_session(session: &Session, now_ms: u64) -> Result<()> {
    if now_ms.saturating_sub(session.created_ms) < FRESH_SESSION_MS {
        Ok(())
    } else {
        Err(Error::NotAllowed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    #[test]
    fn emergency_sessions_are_read_only_and_short() {
        let api = Api::new(
            OpaqueServer::generate(),
            FakeSaltKey::from_bytes(&[7; 32]).unwrap(),
            IdentitySecretKey::generate().unwrap(),
            ServerIdentity::new("https://api.blackboxus.test").unwrap(),
        );
        let owner = AccountId::from_bytes([1; 16]);
        let (token, session) = emergency_session(&owner, 1000).unwrap();
        let (other, _) = emergency_session(&owner, 1000).unwrap();
        assert_ne!(token, other);
        assert!(session.read_only);
        assert_eq!(session.account_id, owner);
        assert!(api.authenticate(&token, Some(&session), 2000).is_ok());
        let mut used = session.clone();
        used.last_used_ms = EMERGENCY_SESSION_MS;
        assert_eq!(
            api.authenticate(&token, Some(&used), 1000 + EMERGENCY_SESSION_MS),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn session_expiry() {
        let api = Api::new(
            OpaqueServer::generate(),
            FakeSaltKey::from_bytes(&[7; 32]).unwrap(),
            IdentitySecretKey::generate().unwrap(),
            ServerIdentity::new("https://api.blackboxus.test").unwrap(),
        );
        let token = [9_u8; SESSION_TOKEN_LEN];
        let session = Session {
            token_hash: session_token_hash(&token).unwrap(),
            account_id: AccountId::from_bytes([1; 16]),
            created_ms: 0,
            last_used_ms: 0,
            read_only: false,
        };
        let ok = api.authenticate(&token, Some(&session), 1000).unwrap();
        assert_eq!(ok.last_used_ms, 1000);

        let auth = |s: &Session, now| api.authenticate(&token, Some(s), now);
        assert_eq!(auth(&session, SESSION_IDLE_MS), Err(Error::Authentication));
        let mut active = session.clone();
        active.last_used_ms = SESSION_MAX_MS - 1;
        assert_eq!(auth(&active, SESSION_MAX_MS), Err(Error::Authentication));
        assert!(auth(&active, SESSION_MAX_MS - 1).is_ok());

        assert_eq!(
            api.authenticate(&[8; SESSION_TOKEN_LEN], Some(&session), 1),
            Err(Error::Authentication)
        );
        assert_eq!(
            api.authenticate(&token[..31], Some(&session), 1),
            Err(Error::Authentication)
        );
        assert_eq!(
            api.authenticate(&token, None, 1),
            Err(Error::Authentication)
        );
    }

    #[test]
    fn enrolment_transfers_expire() {
        assert_eq!(
            accept_enrolment(&[0; MIN_ENROLMENT_BYTES - 1], 0),
            Err(Error::MalformedMessage)
        );
        assert_eq!(
            accept_enrolment(&[0; MAX_ENROLMENT_BYTES + 1], 0),
            Err(Error::MalformedMessage)
        );
        let t = accept_enrolment(&[1; 200], 10).unwrap();
        assert_eq!(
            take_enrolment(Some(t.clone()), 10 + ENROLMENT_TTL_MS),
            Err(Error::NotAllowed)
        );
        assert_eq!(take_enrolment(Some(t), 11).unwrap(), vec![1; 200]);
        assert_eq!(take_enrolment(None, 0), Err(Error::NotAllowed));
    }

    #[test]
    fn wrapped_key_set_headers_are_checked() {
        let mut w = vec![0_u8; WRAPPED_KEY_SET_LEN];
        w[..7].copy_from_slice(&[0, 1, 0, 0, 0, 1, 1]);
        assert!(check_wrapped_key_set(&w, 1).is_ok());
        assert!(check_wrapped_key_set(&w, 2).is_err());
        w[6] = 2;
        assert!(check_wrapped_key_set(&w, 1).is_err());
        assert!(check_wrapped_key_set(&w[..100], 1).is_err());
    }
}
