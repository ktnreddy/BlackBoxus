//! Account recovery (spec section 11): recovery keys and emergency access
//! for trusted contacts.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::aead::{self, NONCE_LEN};
use crate::error::{Error, Result, SecretKeyError};
use crate::identity::ClientIdentity;
use crate::key::{KEY_LEN, SymmetricKey};
use crate::keyset::{ACCOUNT_ID_LEN, AccountId, KeySet, PublicKeyBundle};
use crate::random;
use crate::secret_key::{alphabet_char, decode_char};
use crate::signature::HYBRID_SIGNATURE_LEN;
use crate::xwing::XWING_CIPHERTEXT_LEN;

const FORMAT_VERSION: u16 = 1;
const RECOVERY_PREFIX: &str = "BR1";
const LABEL_CHECKSUM: &[u8] = b"BlackBoxus v1 recovery-key checksum";
const LABEL_WRAP: &[u8] = b"BlackBoxus v1 recovery-wrap";
const LABEL_AUTH: &[u8] = b"BlackBoxus v1 recovery-auth";
const LABEL_GRANT: &[u8] = b"BlackBoxus v1 emergency-grant";

/// Base32 digits encoding the 256-bit key (260 bits, 4 leading zero bits).
const KEY_DIGITS: usize = 52;
/// Base32 digits in a displayed recovery key, including 2 checksum digits.
const TOTAL_DIGITS: usize = 54;
const GROUP_LEN: usize = 6;
/// Leading zero bits before the key bits.
const PAD_BITS: u32 = 4;

/// Length of an emergency grant header, in bytes.
const GRANT_HEADER_LEN: usize = 44;

/// Length of an emergency grant, in bytes.
pub const EMERGENCY_GRANT_LEN: usize = 4609;

/// Longest allowed waiting period for emergency access, in days.
pub const MAX_WAIT_DAYS: u16 = 90;

/// A recovery key: 256 random bits, printed in the Emergency Kit. Erased on
/// drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; KEY_LEN]);

impl RecoveryKey {
    /// Generates a new recovery key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomUnavailable`] if the generator fails.
    pub fn generate() -> Result<Self> {
        random::bytes().map(Self)
    }

    #[doc(hidden)]
    /// Builds a recovery key from fixed bytes, for test vectors only.
    #[must_use]
    pub const fn from_bytes_for_test_vectors(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Formats the key as `BR1-XXXXXX-…` (nine groups of six). Erased on
    /// drop.
    #[must_use]
    pub fn to_display_string(&self) -> Zeroizing<String> {
        let digits = self.digits();
        let mut out = Zeroizing::new(String::with_capacity(72));
        out.push_str(RECOVERY_PREFIX);
        for group in digits.chunks(GROUP_LEN) {
            out.push('-');
            for &d in group {
                out.push(char::from(alphabet_char(d)));
            }
        }
        out
    }

    /// Parses a recovery key typed by the user. Spaces, tabs, hyphens and
    /// case are ignored, and `O`, `I`, `L` are read as `0`, `1`, `1`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSecretKey`] describing what is wrong.
    pub fn parse(input: &str) -> Result<Self> {
        let mut cleaned: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(input.len()));
        cleaned.extend(
            input
                .bytes()
                .filter(|b| !matches!(b, b' ' | b'\t' | b'-'))
                .map(|b| b.to_ascii_uppercase()),
        );
        let body = cleaned
            .strip_prefix(RECOVERY_PREFIX.as_bytes())
            .ok_or(SecretKeyError::MissingPrefix)?;
        if body.len() != TOTAL_DIGITS {
            return Err(SecretKeyError::WrongLength.into());
        }
        let mut digits = Zeroizing::new([0_u8; TOTAL_DIGITS]);
        for (slot, &c) in digits.iter_mut().zip(body) {
            *slot = decode_char(c).ok_or(SecretKeyError::InvalidCharacter)?;
        }
        let (key_digits, check) = digits.split_at(KEY_DIGITS);

        // Unpack 5-bit digits into bits; the first PAD_BITS must be zero.
        let mut key = Self([0; KEY_LEN]);
        let mut bit_index: u32 = 0;
        for &d in key_digits {
            for shift in (0..5_u32).rev() {
                let bit = (d >> shift) & 1;
                if bit_index < PAD_BITS {
                    if bit != 0 {
                        return Err(SecretKeyError::OutOfRange.into());
                    }
                } else {
                    let pos = bit_index.saturating_sub(PAD_BITS);
                    let byte = usize::try_from(pos >> 3).map_err(|_| SecretKeyError::OutOfRange)?;
                    let slot = key.0.get_mut(byte).ok_or(SecretKeyError::OutOfRange)?;
                    *slot |= bit << ((pos & 7) ^ 7);
                }
                bit_index = bit_index.saturating_add(1);
            }
        }
        if !bool::from(key.checksum_digits().ct_eq(check)) {
            return Err(SecretKeyError::ChecksumMismatch.into());
        }
        Ok(key)
    }

    fn digits(&self) -> Zeroizing<[u8; TOTAL_DIGITS]> {
        let mut out = Zeroizing::new([0_u8; TOTAL_DIGITS]);
        // Bit i of the 260-bit string: zero for the padding, else key bits.
        let bit = |i: u32| -> u8 {
            if i < PAD_BITS {
                return 0;
            }
            let pos = i.saturating_sub(PAD_BITS);
            let byte = usize::try_from(pos >> 3).unwrap_or(usize::MAX);
            self.0.get(byte).map_or(0, |b| (b >> ((pos & 7) ^ 7)) & 1)
        };
        for (n, slot) in out.iter_mut().take(KEY_DIGITS).enumerate() {
            let start = u32::try_from(n).unwrap_or(0).saturating_mul(5);
            *slot = (0..5_u32).fold(0, |acc, k| (acc << 1) | bit(start.saturating_add(k)));
        }
        for (slot, &d) in out
            .iter_mut()
            .skip(KEY_DIGITS)
            .zip(self.checksum_digits().iter())
        {
            *slot = d;
        }
        out
    }

    fn checksum_digits(&self) -> [u8; 2] {
        let hash = Sha256::new()
            .chain_update(LABEL_CHECKSUM)
            .chain_update(self.0)
            .finalize();
        let first = hash.first().copied().unwrap_or(0);
        let second = hash.get(1).copied().unwrap_or(0);
        let ten_bits = (u16::from(first) << 2) | (u16::from(second) >> 6);
        [
            u8::try_from((ten_bits >> 5) & 0x1F).unwrap_or(0),
            u8::try_from(ten_bits & 0x1F).unwrap_or(0),
        ]
    }

    fn derive(&self, salt: &[u8], label: &[u8]) -> Result<SymmetricKey> {
        let mut key = SymmetricKey::zeroed();
        Hkdf::<Sha256>::new(Some(salt), &self.0)
            .expand(label, key.as_mut_bytes())
            .map_err(|_| Error::KeyDerivation)?;
        Ok(key)
    }

    /// The key that wraps a copy of the key set with method 4.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyDerivation`] if HKDF fails.
    pub fn wrapping_key(&self, account_id: &AccountId) -> Result<SymmetricKey> {
        self.derive(account_id.as_bytes(), LABEL_WRAP)
    }

    /// The token presented to the server to start recovery. Bound to the
    /// account's canonical email address rather than its ID, because a
    /// device recovering an account does not know the ID until the server
    /// accepts the token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyDerivation`] if HKDF fails.
    pub fn auth_token(&self, email: &ClientIdentity) -> Result<SymmetricKey> {
        self.derive(email.as_bytes(), LABEL_AUTH)
    }

    /// `SHA-256(auth_token)`: what the server stores to check the token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyDerivation`] if HKDF fails.
    pub fn auth_verifier(&self, email: &ClientIdentity) -> Result<[u8; 32]> {
        Ok(auth_verifier_for(&self.auth_token(email)?))
    }
}

impl core::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryKey(<redacted>)")
    }
}

/// `SHA-256(token)` for a presented recovery token.
#[must_use]
pub fn auth_verifier_for(token: &SymmetricKey) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Server-side check of a presented recovery token against the stored
/// verifier, in constant time.
#[must_use]
pub fn check_auth_token(stored_verifier: &[u8; 32], presented: &[u8]) -> bool {
    let digest: [u8; 32] = Sha256::digest(presented).into();
    presented.len() == KEY_LEN && bool::from(digest.ct_eq(stored_verifier))
}

/// An emergency key: wraps a copy of the key set with method 5, and is
/// sealed to a trusted contact in an [`EmergencyGrant`]. Erased on drop.
pub struct EmergencyKey(SymmetricKey);

impl EmergencyKey {
    /// Generates a new emergency key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomUnavailable`] if the generator fails.
    pub fn generate() -> Result<Self> {
        Ok(Self(SymmetricKey::from_bytes(random::bytes()?)))
    }

    /// The key that wraps the key set with method 5.
    #[must_use]
    pub const fn wrapping_key(&self) -> &SymmetricKey {
        &self.0
    }
}

impl core::fmt::Debug for EmergencyKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EmergencyKey(<redacted>)")
    }
}

/// An emergency key sealed to a trusted contact and signed by the account
/// owner (spec section 11.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencyGrant {
    /// The account that granted access.
    pub owner: AccountId,
    /// The owner's key set version.
    pub owner_key_set_version: u32,
    /// The trusted contact.
    pub contact: AccountId,
    /// The contact's key set version.
    pub contact_key_set_version: u32,
    /// Days the server must wait after a request before releasing the grant.
    pub wait_days: u16,
}

impl EmergencyGrant {
    fn header(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(GRANT_HEADER_LEN);
        out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(self.owner.as_bytes());
        out.extend_from_slice(&self.owner_key_set_version.to_be_bytes());
        out.extend_from_slice(self.contact.as_bytes());
        out.extend_from_slice(&self.contact_key_set_version.to_be_bytes());
        out.extend_from_slice(&self.wait_days.to_be_bytes());
        out
    }

    fn decode_header(bytes: &[u8]) -> Result<Self> {
        let take = |range: core::ops::Range<usize>| bytes.get(range).ok_or(Error::MalformedMessage);
        if bytes.len() != GRANT_HEADER_LEN || take(0..2)? != FORMAT_VERSION.to_be_bytes() {
            return Err(Error::MalformedMessage);
        }
        let bad = |_| Error::MalformedMessage;
        Ok(Self {
            owner: AccountId::from_bytes(take(2..18)?.try_into().map_err(bad)?),
            owner_key_set_version: u32::from_be_bytes(take(18..22)?.try_into().map_err(bad)?),
            contact: AccountId::from_bytes(take(22..38)?.try_into().map_err(bad)?),
            contact_key_set_version: u32::from_be_bytes(take(38..42)?.try_into().map_err(bad)?),
            wait_days: u16::from_be_bytes(take(42..44)?.try_into().map_err(bad)?),
        })
    }

    /// Seals `key` to `contact` and signs it as `owner`.
    ///
    /// `contact` must be a bundle the owner verified through key
    /// transparency or a safety number (spec section 9).
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if `wait_days` is over
    /// [`MAX_WAIT_DAYS`], or [`Error::InvalidPublicKey`],
    /// [`Error::RandomUnavailable`], [`Error::Encryption`] or
    /// [`Error::Signing`].
    pub fn seal(
        key: &EmergencyKey,
        owner: &KeySet,
        owner_account: &AccountId,
        owner_key_set_version: u32,
        contact: &PublicKeyBundle,
        wait_days: u16,
    ) -> Result<Vec<u8>> {
        if wait_days > MAX_WAIT_DAYS {
            return Err(Error::MalformedMessage);
        }
        let grant = Self {
            owner: *owner_account,
            owner_key_set_version,
            contact: contact.account_id,
            contact_key_set_version: contact.key_set_version,
            wait_days,
        };
        let header = grant.header();
        let (enc, ss) = contact.xwing.encapsulate()?;
        let wrap = grant_key(&ss, contact.xwing.as_bytes(), &header, &enc)?;
        let nonce: [u8; NONCE_LEN] = random::bytes()?;
        let sealed = aead::seal_with_nonce(&wrap, &nonce, key.0.as_bytes(), &header)?;

        let mut out = Vec::with_capacity(EMERGENCY_GRANT_LEN);
        out.extend_from_slice(&header);
        out.extend_from_slice(&enc);
        out.extend_from_slice(&sealed);
        let signature = owner.identity().sign(LABEL_GRANT, &out)?;
        out.extend_from_slice(signature.as_bytes());
        Ok(out)
    }

    /// Reads the grant's header without verifying it, for the server's
    /// routing and waiting-period checks.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`].
    pub fn inspect(grant: &[u8]) -> Result<Self> {
        if grant.len() != EMERGENCY_GRANT_LEN {
            return Err(Error::MalformedMessage);
        }
        Self::decode_header(
            grant
                .get(..GRANT_HEADER_LEN)
                .ok_or(Error::MalformedMessage)?,
        )
    }

    /// Opens a grant released to this contact. Checks the owner's signature
    /// before decrypting.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`], [`Error::WrongRecipient`],
    /// [`Error::WrongSender`], [`Error::InvalidSignature`] or
    /// [`Error::Decryption`].
    pub fn open(
        grant: &[u8],
        contact: &KeySet,
        contact_account: &AccountId,
        contact_key_set_version: u32,
        owner: &PublicKeyBundle,
    ) -> Result<(Self, EmergencyKey)> {
        let parsed = Self::inspect(grant)?;
        if parsed.contact != *contact_account
            || parsed.contact_key_set_version != contact_key_set_version
        {
            return Err(Error::WrongRecipient);
        }
        if parsed.owner != owner.account_id || parsed.owner_key_set_version != owner.key_set_version
        {
            return Err(Error::WrongSender);
        }
        let signed_len = EMERGENCY_GRANT_LEN.saturating_sub(HYBRID_SIGNATURE_LEN);
        let (signed, signature) = grant.split_at(signed_len);
        owner.identity.verify(
            LABEL_GRANT,
            signed,
            &crate::signature::HybridSignature::from_bytes(signature)?,
        )?;

        let (header, rest) = signed.split_at(GRANT_HEADER_LEN);
        let (enc, sealed) = rest.split_at(XWING_CIPHERTEXT_LEN);
        let enc: [u8; XWING_CIPHERTEXT_LEN] =
            enc.try_into().map_err(|_| Error::MalformedMessage)?;
        let ss = contact.xwing_secret().decapsulate(&enc);
        let wrap = grant_key(&ss, contact.xwing_public_key().as_bytes(), header, &enc)?;
        let plaintext = aead::open(&wrap, sealed, header)?;
        let bytes: [u8; KEY_LEN] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| Error::Decryption)?;
        Ok((parsed, EmergencyKey(SymmetricKey::from_bytes(bytes))))
    }
}

fn grant_key(
    ss: &[u8; 32],
    recipient_public: &[u8],
    header: &[u8],
    enc: &[u8],
) -> Result<SymmetricKey> {
    let salt = Sha256::digest(recipient_public);
    let mut info = Vec::with_capacity(
        LABEL_GRANT
            .len()
            .saturating_add(header.len())
            .saturating_add(enc.len()),
    );
    info.extend_from_slice(LABEL_GRANT);
    info.extend_from_slice(header);
    info.extend_from_slice(enc);
    let mut key = SymmetricKey::zeroed();
    Hkdf::<Sha256>::new(Some(&salt), ss)
        .expand(&info, key.as_mut_bytes())
        .map_err(|_| Error::KeyDerivation)?;
    Ok(key)
}

/// Header length, checked at compile time.
const _: () = assert!(GRANT_HEADER_LEN == 2 + 2 * (ACCOUNT_ID_LEN + 4) + 2);

/// Grant length, checked at compile time.
const _: () = assert!(
    EMERGENCY_GRANT_LEN
        == GRANT_HEADER_LEN
            + XWING_CIPHERTEXT_LEN
            + NONCE_LEN
            + KEY_LEN
            + 16
            + HYBRID_SIGNATURE_LEN
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyset::UnlockMethod;

    #[test]
    fn display_round_trip() {
        for _ in 0..100 {
            let key = RecoveryKey::generate().unwrap();
            let shown = key.to_display_string();
            assert!(shown.starts_with("BR1-"));
            assert_eq!(shown.split('-').count(), 10);
            let back = RecoveryKey::parse(&shown).unwrap();
            assert_eq!(back.0, key.0);
            let messy = shown.to_lowercase().replace('-', " ");
            assert_eq!(RecoveryKey::parse(&messy).unwrap().0, key.0);
        }
        for bytes in [[0_u8; 32], [0xFF; 32]] {
            let key = RecoveryKey(bytes);
            assert_eq!(
                RecoveryKey::parse(&key.to_display_string()).unwrap().0,
                bytes
            );
        }
    }

    #[test]
    fn parse_rejects_mistakes() {
        let shown = RecoveryKey::generate().unwrap().to_display_string();
        let mut chars: Vec<char> = shown.chars().collect();
        chars[5] = if chars[5] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(matches!(
            RecoveryKey::parse(&typo),
            Err(Error::InvalidSecretKey(SecretKeyError::ChecksumMismatch))
        ));
        assert!(RecoveryKey::parse("").is_err());
        assert!(RecoveryKey::parse(&shown.replace("BR1", "B1")).is_err());
        assert!(RecoveryKey::parse(&shown[..shown.len() - 1]).is_err());
        // The first digit may only be 0 or 1: four padding bits are zero.
        let high = format!("BR1-2{}", &shown[5..]);
        assert!(matches!(
            RecoveryKey::parse(&high),
            Err(Error::InvalidSecretKey(SecretKeyError::OutOfRange))
        ));
    }

    #[test]
    fn derived_values_are_independent_and_account_bound() {
        let key = RecoveryKey::generate().unwrap();
        let a = AccountId::from_bytes([1; 16]);
        let b = AccountId::from_bytes([2; 16]);
        let alice = ClientIdentity::new("alice@example.com").unwrap();
        let bob = ClientIdentity::new("bob@example.com").unwrap();
        assert_ne!(key.wrapping_key(&a).unwrap(), key.wrapping_key(&b).unwrap());
        assert_ne!(
            key.wrapping_key(&a).unwrap(),
            key.auth_token(&alice).unwrap()
        );

        let token = key.auth_token(&alice).unwrap();
        let verifier = key.auth_verifier(&alice).unwrap();
        assert!(check_auth_token(&verifier, token.as_bytes()));
        assert!(!check_auth_token(
            &verifier,
            key.auth_token(&bob).unwrap().as_bytes()
        ));
        assert!(!check_auth_token(&verifier, &[]));
    }

    #[test]
    fn recovery_key_unwraps_the_key_set() {
        let keys = KeySet::generate().unwrap();
        let account = AccountId::from_bytes([3; 16]);
        let rk = RecoveryKey::generate().unwrap();
        let wrapped = keys
            .wrap(
                &rk.wrapping_key(&account).unwrap(),
                &account,
                1,
                UnlockMethod::Recovery,
            )
            .unwrap();
        let typed = RecoveryKey::parse(&rk.to_display_string()).unwrap();
        let (back, _) = KeySet::unwrap(
            &wrapped,
            &typed.wrapping_key(&account).unwrap(),
            &account,
            UnlockMethod::Recovery,
            1,
        )
        .unwrap();
        assert_eq!(back.account_key(), keys.account_key());
    }

    struct Person {
        keys: KeySet,
        id: AccountId,
        bundle: PublicKeyBundle,
    }

    fn person(tag: u8) -> Person {
        let keys = KeySet::generate().unwrap();
        let id = AccountId::from_bytes([tag; 16]);
        let bundle =
            PublicKeyBundle::verify_signed(&keys.signed_public_bundle(&id, 1).unwrap()).unwrap();
        Person { keys, id, bundle }
    }

    #[test]
    fn emergency_grant_round_trip() {
        let owner = person(1);
        let contact = person(2);
        let ek = EmergencyKey::generate().unwrap();
        let wrapped = owner
            .keys
            .wrap(
                ek.wrapping_key(),
                &owner.id,
                1,
                UnlockMethod::TrustedContact,
            )
            .unwrap();

        let grant =
            EmergencyGrant::seal(&ek, &owner.keys, &owner.id, 1, &contact.bundle, 7).unwrap();
        assert_eq!(grant.len(), EMERGENCY_GRANT_LEN);
        let info = EmergencyGrant::inspect(&grant).unwrap();
        assert_eq!(info.wait_days, 7);
        assert_eq!(info.contact, contact.id);

        let (_, released) =
            EmergencyGrant::open(&grant, &contact.keys, &contact.id, 1, &owner.bundle).unwrap();
        let (back, _) = KeySet::unwrap(
            &wrapped,
            released.wrapping_key(),
            &owner.id,
            UnlockMethod::TrustedContact,
            1,
        )
        .unwrap();
        assert_eq!(back.account_key(), owner.keys.account_key());
    }

    #[test]
    fn emergency_grant_is_bound_to_contact_and_owner() {
        let owner = person(1);
        let contact = person(2);
        let mallory = person(9);
        let ek = EmergencyKey::generate().unwrap();
        let grant =
            EmergencyGrant::seal(&ek, &owner.keys, &owner.id, 1, &contact.bundle, 3).unwrap();

        assert_eq!(
            EmergencyGrant::open(&grant, &mallory.keys, &mallory.id, 1, &owner.bundle).unwrap_err(),
            Error::WrongRecipient
        );
        assert_eq!(
            EmergencyGrant::open(&grant, &contact.keys, &contact.id, 1, &mallory.bundle)
                .unwrap_err(),
            Error::WrongSender
        );
        // Changing the waiting period invalidates the owner's signature.
        let mut shorter = grant.clone();
        shorter[43] = 0;
        assert_eq!(
            EmergencyGrant::open(&shorter, &contact.keys, &contact.id, 1, &owner.bundle)
                .unwrap_err(),
            Error::InvalidSignature
        );
        // A forged grant claiming to be from the owner.
        let forged =
            EmergencyGrant::seal(&ek, &mallory.keys, &owner.id, 1, &contact.bundle, 0).unwrap();
        assert_eq!(
            EmergencyGrant::open(&forged, &contact.keys, &contact.id, 1, &owner.bundle)
                .unwrap_err(),
            Error::InvalidSignature
        );
    }

    #[test]
    fn waiting_period_is_limited() {
        let owner = person(1);
        let contact = person(2);
        let ek = EmergencyKey::generate().unwrap();
        assert_eq!(
            EmergencyGrant::seal(
                &ek,
                &owner.keys,
                &owner.id,
                1,
                &contact.bundle,
                MAX_WAIT_DAYS + 1
            )
            .unwrap_err(),
            Error::MalformedMessage
        );
        assert!(EmergencyGrant::inspect(&[0; 10]).is_err());
    }
}
