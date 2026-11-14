//! Account key sets: generation, wrapping and the signed public key bundle
//! (spec section 5).

use zeroize::Zeroizing;

use crate::aead::{self, NONCE_LEN};
use crate::error::{Error, Result};
use crate::key::{KEY_LEN, SymmetricKey};
use crate::random;
use crate::signature::{HybridSignature, IdentityPublicKey, IdentitySecretKey};
use crate::xwing::{XWING_PUBLIC_LEN, XWingPublicKey, XWingSecretKey};

/// Length of an account ID in bytes.
pub const ACCOUNT_ID_LEN: usize = 16;

/// Length of a wrapped key set in bytes.
pub const WRAPPED_KEY_SET_LEN: usize = 175;

/// Length of an unsigned public key bundle in bytes.
pub const PUBLIC_BUNDLE_LEN: usize = 3222;

/// Length of a signed public key bundle in bytes.
pub const SIGNED_PUBLIC_BUNDLE_LEN: usize = 6595;

const FORMAT_VERSION: u16 = 1;
const PLAINTEXT_LEN: usize = 128;
const HEADER_LEN: usize = 7;
const LABEL_KEY_SET: &[u8] = b"BlackBoxus v1 key-set";
const LABEL_BUNDLE: &[u8] = b"BlackBoxus v1 public-key-bundle";

/// A stable, random account identifier. Not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountId([u8; ACCOUNT_ID_LEN]);

impl AccountId {
    /// Generates a new account ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomUnavailable`] if the generator fails.
    pub fn generate() -> Result<Self> {
        random::bytes().map(Self)
    }

    /// Wraps account ID bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ACCOUNT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// The account ID bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ACCOUNT_ID_LEN] {
        &self.0
    }
}

/// How a wrapped key set is unlocked (spec section 5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnlockMethod {
    /// Account Unlock Key from the master password and Secret Key.
    MasterPassword,
    /// Key derived from a passkey's WebAuthn PRF output.
    Passkey,
    /// Device key held in the platform secure element.
    Device,
    /// Recovery key.
    Recovery,
    /// Emergency key released to a trusted contact.
    TrustedContact,
}

impl UnlockMethod {
    const fn code(self) -> u8 {
        match self {
            Self::MasterPassword => 1,
            Self::Passkey => 2,
            Self::Device => 3,
            Self::Recovery => 4,
            Self::TrustedContact => 5,
        }
    }
}

/// A user's key set. Every secret is erased on drop.
pub struct KeySet {
    account_key: SymmetricKey,
    xwing: XWingSecretKey,
    identity: IdentitySecretKey,
}

impl KeySet {
    /// Generates a new key set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomUnavailable`] if the generator fails.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            account_key: SymmetricKey::from_bytes(random::bytes()?),
            xwing: XWingSecretKey::generate()?,
            identity: IdentitySecretKey::generate()?,
        })
    }

    #[doc(hidden)]
    /// Builds a key set from fixed seeds. For test vectors only: real key
    /// sets must come from [`KeySet::generate`].
    #[must_use]
    pub fn from_seeds_for_test_vectors(seeds: [[u8; KEY_LEN]; 4]) -> Self {
        let [account, xwing, ed, ml] = seeds;
        Self {
            account_key: SymmetricKey::from_bytes(account),
            xwing: XWingSecretKey::from_seed(xwing),
            identity: IdentitySecretKey::from_seeds(ed, ml),
        }
    }

    /// The account key.
    #[must_use]
    pub const fn account_key(&self) -> &SymmetricKey {
        &self.account_key
    }

    /// The identity signing keys.
    #[must_use]
    pub const fn identity(&self) -> &IdentitySecretKey {
        &self.identity
    }

    /// The X-Wing secret key, for opening vault shares.
    pub(crate) const fn xwing_secret(&self) -> &XWingSecretKey {
        &self.xwing
    }

    /// The X-Wing public key.
    #[must_use]
    pub fn xwing_public_key(&self) -> XWingPublicKey {
        self.xwing.public_key()
    }

    fn plaintext(&self) -> Zeroizing<[u8; PLAINTEXT_LEN]> {
        let mut out = Zeroizing::new([0_u8; PLAINTEXT_LEN]);
        let parts: [&[u8; KEY_LEN]; 4] = [
            self.account_key.as_bytes(),
            self.xwing.seed(),
            self.identity.ed25519_seed(),
            self.identity.ml_dsa_seed(),
        ];
        for (chunk, part) in out.chunks_exact_mut(KEY_LEN).zip(parts) {
            chunk.copy_from_slice(part);
        }
        out
    }

    fn from_plaintext(plaintext: &[u8]) -> Result<Self> {
        let mut seeds = Zeroizing::new([[0_u8; KEY_LEN]; 4]);
        if plaintext.len() != PLAINTEXT_LEN {
            return Err(Error::Decryption);
        }
        for (seed, chunk) in seeds.iter_mut().zip(plaintext.chunks_exact(KEY_LEN)) {
            seed.copy_from_slice(chunk);
        }
        let [account, xwing, ed, ml] = *seeds;
        Ok(Self {
            account_key: SymmetricKey::from_bytes(account),
            xwing: XWingSecretKey::from_seed(xwing),
            identity: IdentitySecretKey::from_seeds(ed, ml),
        })
    }

    /// Wraps the key set under `wrapping_key` (spec section 5.4).
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomUnavailable`] or [`Error::Encryption`].
    pub fn wrap(
        &self,
        wrapping_key: &SymmetricKey,
        account_id: &AccountId,
        key_set_version: u32,
        method: UnlockMethod,
    ) -> Result<Vec<u8>> {
        let nonce: [u8; NONCE_LEN] = random::bytes()?;
        self.wrap_with_nonce(wrapping_key, account_id, key_set_version, method, &nonce)
    }

    #[doc(hidden)]
    /// Deterministic wrapping for test vectors only. Never reuse a nonce.
    pub fn wrap_with_nonce(
        &self,
        wrapping_key: &SymmetricKey,
        account_id: &AccountId,
        key_set_version: u32,
        method: UnlockMethod,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let header = header(key_set_version, method);
        let aad = wrap_aad(account_id, key_set_version, method);
        let sealed = aead::seal_with_nonce(wrapping_key, nonce, self.plaintext().as_slice(), &aad)?;
        let mut out = Vec::with_capacity(WRAPPED_KEY_SET_LEN);
        out.extend_from_slice(&header);
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Unwraps a key set (spec section 5.4).
    ///
    /// `account_id` must come from the client's own records, never from the
    /// server. `min_version` is the highest key set version this client has
    /// seen before for the account; older versions are rejected.
    ///
    /// Returns the key set and its version.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] for a wrong length, version or
    /// method, [`Error::KeySetRollback`] for an older key set, or
    /// [`Error::Decryption`] if the wrapping key is wrong or the data was
    /// tampered with.
    pub fn unwrap(
        wrapped: &[u8],
        wrapping_key: &SymmetricKey,
        account_id: &AccountId,
        method: UnlockMethod,
        min_version: u32,
    ) -> Result<(Self, u32)> {
        if wrapped.len() != WRAPPED_KEY_SET_LEN {
            return Err(Error::MalformedMessage);
        }
        let (head, sealed) = wrapped.split_at(HEADER_LEN);
        let (format, rest) = head.split_at(2);
        let (version_bytes, method_byte) = rest.split_at(4);

        if format != FORMAT_VERSION.to_be_bytes() || method_byte != [method.code()] {
            return Err(Error::MalformedMessage);
        }
        let key_set_version = u32::from_be_bytes(
            version_bytes
                .try_into()
                .map_err(|_| Error::MalformedMessage)?,
        );
        if key_set_version < min_version {
            return Err(Error::KeySetRollback);
        }

        let aad = wrap_aad(account_id, key_set_version, method);
        let plaintext = aead::open(wrapping_key, sealed, &aad)?;
        Ok((Self::from_plaintext(&plaintext)?, key_set_version))
    }

    /// Builds and self-signs the public key bundle (spec section 5.5).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signing`] or [`Error::RandomUnavailable`].
    pub fn signed_public_bundle(
        &self,
        account_id: &AccountId,
        key_set_version: u32,
    ) -> Result<Vec<u8>> {
        let bundle = PublicKeyBundle {
            account_id: *account_id,
            key_set_version,
            xwing: self.xwing.public_key(),
            identity: self.identity.public_key(),
        };
        let bytes = bundle.encode();
        let signature = self.identity.sign(LABEL_BUNDLE, &bytes)?;
        let mut out = Vec::with_capacity(SIGNED_PUBLIC_BUNDLE_LEN);
        out.extend_from_slice(&bytes);
        out.extend_from_slice(signature.as_bytes());
        Ok(out)
    }
}

impl core::fmt::Debug for KeySet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KeySet(<redacted>)")
    }
}

fn header(key_set_version: u32, method: UnlockMethod) -> [u8; HEADER_LEN] {
    let mut out = [0_u8; HEADER_LEN];
    let (format, rest) = out.split_at_mut(2);
    format.copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    let (version, method_byte) = rest.split_at_mut(4);
    version.copy_from_slice(&key_set_version.to_be_bytes());
    method_byte.copy_from_slice(&[method.code()]);
    out
}

fn wrap_aad(account_id: &AccountId, key_set_version: u32, method: UnlockMethod) -> Vec<u8> {
    let mut aad = Vec::with_capacity(LABEL_KEY_SET.len().saturating_add(23));
    aad.extend_from_slice(LABEL_KEY_SET);
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(account_id.as_bytes());
    aad.extend_from_slice(&key_set_version.to_be_bytes());
    aad.push(method.code());
    aad
}

/// A verified public key bundle (spec section 5.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyBundle {
    /// The account this bundle belongs to.
    pub account_id: AccountId,
    /// The key set version.
    pub key_set_version: u32,
    /// The X-Wing public key, for sharing vault keys with this account.
    pub xwing: XWingPublicKey,
    /// The identity public key, for verifying this account's signatures.
    pub identity: IdentityPublicKey,
}

impl PublicKeyBundle {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_BUNDLE_LEN);
        out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(self.account_id.as_bytes());
        out.extend_from_slice(&self.key_set_version.to_be_bytes());
        out.extend_from_slice(self.xwing.as_bytes());
        out.extend_from_slice(&self.identity.to_bytes());
        out
    }

    /// Parses a signed bundle and checks its self-signature.
    ///
    /// This proves the publisher holds the bundle's secret keys. It does
    /// **not** prove who that is: check the bundle against key transparency
    /// or an out-of-band fingerprint before trusting it for sharing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] or [`Error::InvalidSignature`].
    pub fn verify_signed(signed: &[u8]) -> Result<Self> {
        if signed.len() != SIGNED_PUBLIC_BUNDLE_LEN {
            return Err(Error::MalformedMessage);
        }
        let (bundle, signature) = signed.split_at(PUBLIC_BUNDLE_LEN);
        let (format, rest) = bundle.split_at(2);
        if format != FORMAT_VERSION.to_be_bytes() {
            return Err(Error::MalformedMessage);
        }
        let (account_id, rest) = rest.split_at(ACCOUNT_ID_LEN);
        let (version, rest) = rest.split_at(4);
        let (xwing, identity) = rest.split_at(XWING_PUBLIC_LEN);

        let parsed = Self {
            account_id: AccountId(account_id.try_into().map_err(|_| Error::MalformedMessage)?),
            key_set_version: u32::from_be_bytes(
                version.try_into().map_err(|_| Error::MalformedMessage)?,
            ),
            xwing: XWingPublicKey::from_bytes(
                xwing.try_into().map_err(|_| Error::MalformedMessage)?,
            ),
            identity: IdentityPublicKey::from_bytes(identity)?,
        };
        parsed.identity.verify(
            LABEL_BUNDLE,
            bundle,
            &HybridSignature::from_bytes(signature)?,
        )?;
        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::TAG_LEN;
    use crate::signature::{HYBRID_SIGNATURE_LEN, IDENTITY_PUBLIC_LEN};

    fn fixtures() -> (KeySet, AccountId, SymmetricKey) {
        (
            KeySet::generate().unwrap(),
            AccountId::from_bytes([4; ACCOUNT_ID_LEN]),
            SymmetricKey::from_bytes([9; KEY_LEN]),
        )
    }

    #[test]
    fn wrap_and_unwrap_round_trip() {
        let (ks, id, wk) = fixtures();
        let wrapped = ks.wrap(&wk, &id, 3, UnlockMethod::MasterPassword).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_KEY_SET_LEN);
        let (back, version) =
            KeySet::unwrap(&wrapped, &wk, &id, UnlockMethod::MasterPassword, 1).unwrap();
        assert_eq!(version, 3);
        assert_eq!(back.account_key(), ks.account_key());
        assert_eq!(back.xwing_public_key(), ks.xwing_public_key());
        assert_eq!(back.identity().public_key(), ks.identity().public_key());
    }

    #[test]
    fn unwrap_rejects_wrong_key_account_or_method() {
        let (ks, id, wk) = fixtures();
        let wrapped = ks.wrap(&wk, &id, 1, UnlockMethod::MasterPassword).unwrap();

        let wrong_key = SymmetricKey::from_bytes([8; KEY_LEN]);
        assert_eq!(
            KeySet::unwrap(&wrapped, &wrong_key, &id, UnlockMethod::MasterPassword, 1).unwrap_err(),
            Error::Decryption
        );
        let other_id = AccountId::from_bytes([5; ACCOUNT_ID_LEN]);
        assert_eq!(
            KeySet::unwrap(&wrapped, &wk, &other_id, UnlockMethod::MasterPassword, 1).unwrap_err(),
            Error::Decryption
        );
        assert_eq!(
            KeySet::unwrap(&wrapped, &wk, &id, UnlockMethod::Passkey, 1).unwrap_err(),
            Error::MalformedMessage
        );
    }

    #[test]
    fn unwrap_rejects_rollback_and_tampered_headers() {
        let (ks, id, wk) = fixtures();
        let wrapped = ks.wrap(&wk, &id, 2, UnlockMethod::MasterPassword).unwrap();
        assert_eq!(
            KeySet::unwrap(&wrapped, &wk, &id, UnlockMethod::MasterPassword, 3).unwrap_err(),
            Error::KeySetRollback
        );

        // A server that edits the version or method header cannot get the
        // result accepted: the header is also bound into the AAD.
        let mut bumped = wrapped.clone();
        bumped[5] = 9; // version 2 -> 9
        assert_eq!(
            KeySet::unwrap(&bumped, &wk, &id, UnlockMethod::MasterPassword, 1).unwrap_err(),
            Error::Decryption
        );
        let mut as_passkey = wrapped.clone();
        as_passkey[6] = UnlockMethod::Passkey.code();
        assert_eq!(
            KeySet::unwrap(&as_passkey, &wk, &id, UnlockMethod::Passkey, 1).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn unwrap_rejects_wrong_lengths() {
        let (ks, id, wk) = fixtures();
        let mut wrapped = ks.wrap(&wk, &id, 1, UnlockMethod::Device).unwrap();
        wrapped.push(0);
        assert_eq!(
            KeySet::unwrap(&wrapped, &wk, &id, UnlockMethod::Device, 1).unwrap_err(),
            Error::MalformedMessage
        );
        assert!(KeySet::unwrap(&[], &wk, &id, UnlockMethod::Device, 1).is_err());
    }

    #[test]
    fn signed_bundle_verifies_and_round_trips() {
        let (ks, id, _) = fixtures();
        let signed = ks.signed_public_bundle(&id, 7).unwrap();
        assert_eq!(signed.len(), SIGNED_PUBLIC_BUNDLE_LEN);
        let bundle = PublicKeyBundle::verify_signed(&signed).unwrap();
        assert_eq!(bundle.account_id, id);
        assert_eq!(bundle.key_set_version, 7);
        assert_eq!(bundle.xwing, ks.xwing_public_key());
        assert_eq!(bundle.identity, ks.identity().public_key());
    }

    #[test]
    fn signed_bundle_rejects_any_change() {
        let (ks, id, _) = fixtures();
        let signed = ks.signed_public_bundle(&id, 1).unwrap();
        // Flip one byte in each region: header, account ID, version, X-Wing
        // key, identity key, and signature.
        for pos in [0, 5, 19, 100, 2000, 3300, 6000] {
            let mut bad = signed.clone();
            bad[pos] ^= 1;
            assert!(PublicKeyBundle::verify_signed(&bad).is_err(), "pos {pos}");
        }
        assert!(PublicKeyBundle::verify_signed(&signed[..100]).is_err());
    }

    #[test]
    fn bundle_signed_by_another_key_set_is_rejected() {
        let (ks, id, _) = fixtures();
        let attacker = KeySet::generate().unwrap();
        let mut forged = ks.signed_public_bundle(&id, 1).unwrap();
        // Keep the victim's public keys but sign with the attacker's identity.
        let sig = attacker
            .identity()
            .sign(LABEL_BUNDLE, &forged[..PUBLIC_BUNDLE_LEN])
            .unwrap();
        forged[PUBLIC_BUNDLE_LEN..].copy_from_slice(sig.as_bytes());
        assert_eq!(
            PublicKeyBundle::verify_signed(&forged).unwrap_err(),
            Error::InvalidSignature
        );
    }

    #[test]
    fn sizes_match_the_spec() {
        assert_eq!(
            HEADER_LEN + NONCE_LEN + PLAINTEXT_LEN + TAG_LEN,
            WRAPPED_KEY_SET_LEN
        );
        assert_eq!(
            2 + ACCOUNT_ID_LEN + 4 + XWING_PUBLIC_LEN + IDENTITY_PUBLIC_LEN,
            PUBLIC_BUNDLE_LEN
        );
        assert_eq!(
            PUBLIC_BUNDLE_LEN + HYBRID_SIGNATURE_LEN,
            SIGNED_PUBLIC_BUNDLE_LEN
        );
    }
}
