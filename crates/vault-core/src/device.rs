//! Device enrolment and unlock keys (spec section 10).
//!
//! - Adding a device by scanning a QR code from a signed-in device, which
//!   transfers the Secret Key end to end without the server reading it.
//! - Unlock keys for the device secure element and for passkeys (WebAuthn
//!   PRF), each of which wraps a copy of the key set (spec section 5.4).

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::aead::{self, NONCE_LEN};
use crate::error::{Error, Result};
use crate::identity::{ClientIdentity, ServerIdentity};
use crate::key::{KEY_LEN, SymmetricKey};
use crate::keyset::{ACCOUNT_ID_LEN, AccountId};
use crate::random;
use crate::secret_key::{SECRET_KEY_LEN, SecretKey};
use crate::transparency::SIGNED_TREE_HEAD_LEN;

const FORMAT_VERSION: u16 = 1;
const LABEL_ENROLMENT: &[u8] = b"BlackBoxus v1 enrolment";
const LABEL_PRF_INPUT: &[u8] = b"BlackBoxus v1 passkey-prf-input";
const LABEL_PASSKEY_KEY: &[u8] = b"BlackBoxus v1 passkey-unlock";
const QR_PREFIX: &str = "blackboxus-enrol:1:";

/// Length of an enrolment session ID in bytes.
pub const SESSION_ID_LEN: usize = 16;

/// Length of an enrolment secret in bytes.
pub const ENROLMENT_SECRET_LEN: usize = 32;

/// How long an enrolment offer stays valid, in seconds.
pub const ENROLMENT_TTL_SECONDS: u64 = 300;

/// An offer to enrol a new device, shown as a QR code on a signed-in device.
///
/// The session ID routes the transfer through the server; the secret never
/// leaves the two devices. Erased on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EnrolmentOffer {
    session_id: [u8; SESSION_ID_LEN],
    secret: [u8; ENROLMENT_SECRET_LEN],
}

impl EnrolmentOffer {
    /// Creates a new offer on the signed-in device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomUnavailable`] if the generator fails.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            session_id: random::bytes()?,
            secret: random::bytes()?,
        })
    }

    #[doc(hidden)]
    /// Builds an offer from fixed values, for test vectors only.
    #[must_use]
    pub const fn from_parts_for_test_vectors(
        session_id: [u8; SESSION_ID_LEN],
        secret: [u8; ENROLMENT_SECRET_LEN],
    ) -> Self {
        Self { session_id, secret }
    }

    /// The session ID, which the server uses to route the transfer.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }

    /// The text to encode in the QR code:
    /// `blackboxus-enrol:1:` followed by the session ID and secret in hex.
    /// Erased on drop.
    #[must_use]
    pub fn to_qr_text(&self) -> Zeroizing<String> {
        let mut out =
            Zeroizing::new(String::with_capacity(QR_PREFIX.len().saturating_add(
                2_usize.saturating_mul(SESSION_ID_LEN + ENROLMENT_SECRET_LEN),
            )));
        out.push_str(QR_PREFIX);
        for b in self.session_id.iter().chain(self.secret.iter()) {
            out.push(hex_digit(b >> 4));
            out.push(hex_digit(b & 0x0F));
        }
        out
    }

    /// Parses QR text scanned by the new device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if the text is not a valid offer.
    pub fn from_qr_text(text: &str) -> Result<Self> {
        let body = text
            .strip_prefix(QR_PREFIX)
            .ok_or(Error::MalformedMessage)?
            .as_bytes();
        if body.len() != 2 * (SESSION_ID_LEN + ENROLMENT_SECRET_LEN) {
            return Err(Error::MalformedMessage);
        }
        let mut bytes = Zeroizing::new([0_u8; SESSION_ID_LEN + ENROLMENT_SECRET_LEN]);
        for (dst, pair) in bytes.iter_mut().zip(body.chunks_exact(2)) {
            let (hi, lo) = match pair {
                [h, l] => (hex_value(*h)?, hex_value(*l)?),
                _ => return Err(Error::MalformedMessage),
            };
            *dst = (hi << 4) | lo;
        }
        let (sid, secret) = bytes.split_at(SESSION_ID_LEN);
        Ok(Self {
            session_id: sid.try_into().map_err(|_| Error::MalformedMessage)?,
            secret: secret.try_into().map_err(|_| Error::MalformedMessage)?,
        })
    }

    fn transfer_key(&self) -> Result<SymmetricKey> {
        let mut info = Vec::with_capacity(LABEL_ENROLMENT.len().saturating_add(SESSION_ID_LEN));
        info.extend_from_slice(LABEL_ENROLMENT);
        info.extend_from_slice(&self.session_id);
        let mut key = SymmetricKey::zeroed();
        Hkdf::<Sha256>::new(None, &self.secret)
            .expand(&info, key.as_mut_bytes())
            .map_err(|_| Error::KeyDerivation)?;
        Ok(key)
    }

    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(LABEL_ENROLMENT.len().saturating_add(SESSION_ID_LEN));
        aad.extend_from_slice(LABEL_ENROLMENT);
        aad.extend_from_slice(&self.session_id);
        aad
    }

    /// Encrypts the enrolment payload on the signed-in device, for upload to
    /// the server under the session ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if a field is too long,
    /// [`Error::RandomUnavailable`] or [`Error::Encryption`].
    pub fn seal(&self, payload: &EnrolmentPayload) -> Result<Vec<u8>> {
        let nonce: [u8; NONCE_LEN] = random::bytes()?;
        self.seal_with_nonce(payload, &nonce)
    }

    #[doc(hidden)]
    /// Deterministic sealing for test vectors only. Never reuse a nonce.
    ///
    /// # Errors
    ///
    /// As [`EnrolmentOffer::seal`].
    pub fn seal_with_nonce(
        &self,
        payload: &EnrolmentPayload,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let plaintext = payload.encode()?;
        aead::seal_with_nonce(&self.transfer_key()?, nonce, &plaintext, &self.aad())
    }

    /// Decrypts the payload on the new device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decryption`] if the transfer was not made with this
    /// offer or was modified, or [`Error::MalformedMessage`].
    pub fn open(&self, sealed: &[u8]) -> Result<EnrolmentPayload> {
        let plaintext = aead::open(&self.transfer_key()?, sealed, &self.aad())?;
        EnrolmentPayload::decode(&plaintext)
    }
}

impl core::fmt::Debug for EnrolmentOffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EnrolmentOffer(<redacted>)")
    }
}

/// What a signed-in device sends to a new device (spec section 10.3).
pub struct EnrolmentPayload {
    /// The account ID.
    pub account_id: AccountId,
    /// The account's email address.
    pub email: ClientIdentity,
    /// The server the account lives on.
    pub server: ServerIdentity,
    /// The Secret Key.
    pub secret_key: SecretKey,
    /// The latest key transparency tree head the sending device has seen,
    /// so the two devices start from the same view of the log.
    pub signed_tree_head: Option<Vec<u8>>,
}

impl EnrolmentPayload {
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let email = self.email.as_bytes();
        let server = self.server.as_bytes();
        let email_len = u8::try_from(email.len()).map_err(|_| Error::MalformedMessage)?;
        let server_len = u8::try_from(server.len()).map_err(|_| Error::MalformedMessage)?;
        let sth: &[u8] = self.signed_tree_head.as_deref().unwrap_or(&[]);
        if !sth.is_empty() && sth.len() != SIGNED_TREE_HEAD_LEN {
            return Err(Error::MalformedMessage);
        }
        let sth_len = u16::try_from(sth.len()).map_err(|_| Error::MalformedMessage)?;

        let mut out = Zeroizing::new(Vec::with_capacity(4096));
        out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(self.account_id.as_bytes());
        out.extend_from_slice(self.secret_key.as_bytes());
        out.push(email_len);
        out.extend_from_slice(email);
        out.push(server_len);
        out.extend_from_slice(server);
        out.extend_from_slice(&sth_len.to_be_bytes());
        out.extend_from_slice(sth);
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        if r.u16()? != FORMAT_VERSION {
            return Err(Error::MalformedMessage);
        }
        let account_id = AccountId::from_bytes(r.array::<ACCOUNT_ID_LEN>()?);
        let mut sk = Zeroizing::new(r.array::<SECRET_KEY_LEN>()?);
        let secret_key = SecretKey::from_bytes(*sk);
        sk.zeroize();
        let email_len = usize::from(r.u8()?);
        let email =
            core::str::from_utf8(r.take(email_len)?).map_err(|_| Error::MalformedMessage)?;
        let server_len = usize::from(r.u8()?);
        let server =
            core::str::from_utf8(r.take(server_len)?).map_err(|_| Error::MalformedMessage)?;
        let sth_len = usize::from(r.u16()?);
        if sth_len != 0 && sth_len != SIGNED_TREE_HEAD_LEN {
            return Err(Error::MalformedMessage);
        }
        let sth = r.take(sth_len)?;
        if !r.0.is_empty() {
            return Err(Error::MalformedMessage);
        }
        let email = ClientIdentity::new(email)?;
        let server = ServerIdentity::new(server)?;
        // Only canonical values are accepted, so both devices agree exactly.
        if email.as_bytes().len() != email_len || server.as_bytes().len() != server_len {
            return Err(Error::MalformedMessage);
        }
        Ok(Self {
            account_id,
            email,
            server,
            secret_key,
            signed_tree_head: (!sth.is_empty()).then(|| sth.to_vec()),
        })
    }
}

impl core::fmt::Debug for EnrolmentPayload {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EnrolmentPayload")
            .field("account_id", &self.account_id)
            .field("email", &self.email)
            .field("server", &self.server)
            .field("secret_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Generates a random device key, to be stored in the platform's secure
/// element and used to wrap a copy of the key set (method 3).
///
/// # Errors
///
/// Returns [`Error::RandomUnavailable`] if the generator fails.
pub fn generate_device_key() -> Result<SymmetricKey> {
    Ok(SymmetricKey::from_bytes(random::bytes()?))
}

/// The WebAuthn PRF input (`prf.eval.first`) for an account
/// (spec section 10.5).
#[must_use]
pub fn passkey_prf_input(account_id: &AccountId) -> [u8; 32] {
    Sha256::new()
        .chain_update(LABEL_PRF_INPUT)
        .chain_update(account_id.as_bytes())
        .finalize()
        .into()
}

/// Derives the key that wraps a copy of the key set (method 2) from a
/// passkey's PRF output.
///
/// # Errors
///
/// Returns [`Error::MalformedMessage`] if the PRF output is not 32 bytes or
/// the credential ID is empty, or [`Error::KeyDerivation`].
pub fn passkey_wrapping_key(prf_output: &[u8], credential_id: &[u8]) -> Result<SymmetricKey> {
    if prf_output.len() != KEY_LEN || credential_id.is_empty() || credential_id.len() > 1023 {
        return Err(Error::MalformedMessage);
    }
    let salt = Sha256::digest(credential_id);
    let mut key = SymmetricKey::zeroed();
    Hkdf::<Sha256>::new(Some(&salt), prf_output)
        .expand(LABEL_PASSKEY_KEY, key.as_mut_bytes())
        .map_err(|_| Error::KeyDerivation)?;
    Ok(key)
}

fn hex_digit(v: u8) -> char {
    char::from(
        b"0123456789abcdef"
            .get(usize::from(v))
            .copied()
            .unwrap_or(b'0'),
    )
}

fn hex_value(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c.saturating_sub(b'0')),
        b'a'..=b'f' => Ok(c.saturating_sub(b'a').saturating_add(10)),
        _ => Err(Error::MalformedMessage),
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::MalformedMessage);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::MalformedMessage)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyset::{KeySet, UnlockMethod};

    fn payload() -> EnrolmentPayload {
        EnrolmentPayload {
            account_id: AccountId::from_bytes([1; ACCOUNT_ID_LEN]),
            email: ClientIdentity::new("alice@example.com").unwrap(),
            server: ServerIdentity::new("https://api.example.org").unwrap(),
            secret_key: SecretKey::from_bytes([2; SECRET_KEY_LEN]),
            signed_tree_head: None,
        }
    }

    #[test]
    fn qr_round_trip() {
        let offer = EnrolmentOffer::generate().unwrap();
        let text = offer.to_qr_text();
        assert!(text.starts_with(QR_PREFIX));
        assert_eq!(text.len(), QR_PREFIX.len() + 96);
        let parsed = EnrolmentOffer::from_qr_text(&text).unwrap();
        assert_eq!(parsed.session_id, offer.session_id);
        assert_eq!(parsed.secret, offer.secret);
    }

    #[test]
    fn qr_rejects_malformed_text() {
        let text = EnrolmentOffer::generate().unwrap().to_qr_text();
        for bad in [
            String::new(),
            text.replace(QR_PREFIX, "blackboxus-enrol:2:"),
            text.to_uppercase(),
            format!("{}0", text.as_str()),
            text[..text.len() - 1].to_owned(),
        ] {
            assert!(EnrolmentOffer::from_qr_text(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn transfer_round_trip() {
        let offer = EnrolmentOffer::generate().unwrap();
        let sealed = offer.seal(&payload()).unwrap();
        let scanned = EnrolmentOffer::from_qr_text(&offer.to_qr_text()).unwrap();
        let got = scanned.open(&sealed).unwrap();
        assert_eq!(got.account_id, payload().account_id);
        assert_eq!(got.email, payload().email);
        assert_eq!(got.server, payload().server);
        assert_eq!(got.secret_key, payload().secret_key);
        assert!(got.signed_tree_head.is_none());
    }

    #[test]
    fn transfer_carries_a_tree_head() {
        let offer = EnrolmentOffer::generate().unwrap();
        let mut p = payload();
        p.signed_tree_head = Some(vec![7; SIGNED_TREE_HEAD_LEN]);
        let got = offer.open(&offer.seal(&p).unwrap()).unwrap();
        assert_eq!(got.signed_tree_head.unwrap(), vec![7; SIGNED_TREE_HEAD_LEN]);

        p.signed_tree_head = Some(vec![7; 10]);
        assert_eq!(offer.seal(&p).unwrap_err(), Error::MalformedMessage);
    }

    #[test]
    fn transfer_needs_the_matching_offer() {
        let offer = EnrolmentOffer::generate().unwrap();
        let sealed = offer.seal(&payload()).unwrap();
        let other = EnrolmentOffer::generate().unwrap();
        assert_eq!(other.open(&sealed).unwrap_err(), Error::Decryption);

        // Same secret, different session: still rejected.
        let mut relabelled = offer.clone();
        relabelled.session_id[0] ^= 1;
        assert_eq!(relabelled.open(&sealed).unwrap_err(), Error::Decryption);

        let mut tampered = sealed.clone();
        tampered[40] ^= 1;
        assert_eq!(offer.open(&tampered).unwrap_err(), Error::Decryption);
    }

    #[test]
    fn passkey_key_wraps_the_key_set() {
        let account = AccountId::from_bytes([3; ACCOUNT_ID_LEN]);
        let input = passkey_prf_input(&account);
        assert_ne!(
            input,
            passkey_prf_input(&AccountId::from_bytes([4; ACCOUNT_ID_LEN]))
        );

        // Simulated authenticator output for that input.
        let prf_output = [9_u8; 32];
        let key = passkey_wrapping_key(&prf_output, b"credential-1").unwrap();
        let keys = KeySet::generate().unwrap();
        let wrapped = keys.wrap(&key, &account, 1, UnlockMethod::Passkey).unwrap();
        let (back, _) = KeySet::unwrap(&wrapped, &key, &account, UnlockMethod::Passkey, 1).unwrap();
        assert_eq!(back.account_key(), keys.account_key());

        // A different credential gives a different key.
        let other = passkey_wrapping_key(&prf_output, b"credential-2").unwrap();
        assert_ne!(other, key);
        assert!(KeySet::unwrap(&wrapped, &other, &account, UnlockMethod::Passkey, 1).is_err());
    }

    #[test]
    fn passkey_key_rejects_bad_input() {
        assert!(passkey_wrapping_key(&[0; 31], b"id").is_err());
        assert!(passkey_wrapping_key(&[0; 32], b"").is_err());
        assert!(passkey_wrapping_key(&[0; 32], &[0; 1024]).is_err());
    }

    #[test]
    fn device_keys_are_random() {
        assert_ne!(
            generate_device_key().unwrap(),
            generate_device_key().unwrap()
        );
    }
}
