//! Vault keys: creation, wrapping for the owner, and sharing with other
//! accounts (spec section 7).

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::aead::{self, NONCE_LEN};
use crate::error::{Error, Result};
use crate::item::{ID_LEN, VaultId};
use crate::key::{KEY_LEN, SymmetricKey};
use crate::keyset::{ACCOUNT_ID_LEN, AccountId, KeySet, PublicKeyBundle};
use crate::random;
use crate::signature::{HYBRID_SIGNATURE_LEN, HybridSignature, IdentityPublicKey};
use crate::xwing::XWING_CIPHERTEXT_LEN;

const FORMAT_VERSION: u16 = 1;
const LABEL_VAULT_KEY: &[u8] = b"BlackBoxus v1 vault-key";
const LABEL_SHARE: &[u8] = b"BlackBoxus v1 vault-share";

/// Length of a vault key wrapped for its owner, in bytes.
pub const OWNER_WRAPPED_VAULT_KEY_LEN: usize = 94;

/// Length of the header of a vault share, in bytes.
const SHARE_HEADER_LEN: usize = 62;

/// Length of a vault share, in bytes.
pub const VAULT_SHARE_LEN: usize = 4627;

/// A vault's encryption key, with its version. Erased on drop.
#[derive(Debug)]
pub struct VaultKey {
    /// The key.
    pub key: SymmetricKey,
    /// The key version, starting at 1. It increases each time the key is
    /// replaced, for example after removing a member.
    pub version: u32,
}

impl VaultKey {
    /// Generates a new vault key with the given version.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomUnavailable`] if the generator fails.
    pub fn generate(version: u32) -> Result<Self> {
        Ok(Self {
            key: SymmetricKey::from_bytes(random::bytes()?),
            version,
        })
    }

    /// Wraps the key under the owner's account key (spec section 7.3).
    ///
    /// # Errors
    ///
    /// Returns [`Error::RandomUnavailable`] or [`Error::Encryption`].
    pub fn wrap_for_owner(
        &self,
        owner: &KeySet,
        owner_account: &AccountId,
        vault_id: &VaultId,
    ) -> Result<Vec<u8>> {
        let nonce: [u8; NONCE_LEN] = random::bytes()?;
        self.wrap_for_owner_with_nonce(owner, owner_account, vault_id, &nonce)
    }

    #[doc(hidden)]
    /// Deterministic wrapping for test vectors only. Never reuse a nonce.
    ///
    /// # Errors
    ///
    /// As [`VaultKey::wrap_for_owner`].
    pub fn wrap_for_owner_with_nonce(
        &self,
        owner: &KeySet,
        owner_account: &AccountId,
        vault_id: &VaultId,
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let aad = owner_aad(owner_account, vault_id, self.version);
        let sealed = aead::seal_with_nonce(owner.account_key(), nonce, self.key.as_bytes(), &aad)?;
        let mut out = Vec::with_capacity(OWNER_WRAPPED_VAULT_KEY_LEN);
        out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(vault_id.as_bytes());
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&sealed);
        Ok(out)
    }

    /// Unwraps a key produced by [`VaultKey::wrap_for_owner`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`], [`Error::WrongItem`] if it is for
    /// another vault, or [`Error::Decryption`].
    pub fn unwrap_for_owner(
        wrapped: &[u8],
        owner: &KeySet,
        owner_account: &AccountId,
        vault_id: &VaultId,
    ) -> Result<Self> {
        if wrapped.len() != OWNER_WRAPPED_VAULT_KEY_LEN {
            return Err(Error::MalformedMessage);
        }
        let mut r = Reader(wrapped);
        if r.u16()? != FORMAT_VERSION {
            return Err(Error::MalformedMessage);
        }
        if VaultId::from_bytes(r.array()?) != *vault_id {
            return Err(Error::WrongItem);
        }
        let version = r.u32()?;
        let plaintext = aead::open(
            owner.account_key(),
            r.rest(),
            &owner_aad(owner_account, vault_id, version),
        )?;
        Ok(Self {
            key: key_from(&plaintext)?,
            version,
        })
    }

    /// Shares the key with another account (spec section 7.4).
    ///
    /// `recipient` must be a bundle the sender has verified belongs to the
    /// intended person (key transparency or fingerprint check, section 9).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`], [`Error::RandomUnavailable`],
    /// [`Error::Encryption`] or [`Error::Signing`].
    pub fn share(
        &self,
        vault_id: &VaultId,
        sender: &KeySet,
        sender_account: &AccountId,
        sender_key_set_version: u32,
        recipient: &PublicKeyBundle,
    ) -> Result<Vec<u8>> {
        let (enc, shared_secret) = recipient.xwing.encapsulate()?;
        let nonce: [u8; NONCE_LEN] = random::bytes()?;
        self.share_with(
            vault_id,
            sender,
            sender_account,
            sender_key_set_version,
            recipient,
            &enc,
            &shared_secret,
            &nonce,
        )
    }

    #[doc(hidden)]
    /// Deterministic sharing (except for the signature) for test vectors
    /// only. Never reuse randomness.
    ///
    /// # Errors
    ///
    /// As [`VaultKey::share`].
    #[expect(clippy::too_many_arguments, reason = "test-vector helper")]
    pub fn share_deterministic(
        &self,
        vault_id: &VaultId,
        sender: &KeySet,
        sender_account: &AccountId,
        sender_key_set_version: u32,
        recipient: &PublicKeyBundle,
        kem_randomness: &[u8; 64],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let (enc, shared_secret) = recipient.xwing.encapsulate_deterministic(kem_randomness)?;
        self.share_with(
            vault_id,
            sender,
            sender_account,
            sender_key_set_version,
            recipient,
            &enc,
            &shared_secret,
            nonce,
        )
    }

    #[expect(clippy::too_many_arguments, reason = "internal helper")]
    fn share_with(
        &self,
        vault_id: &VaultId,
        sender: &KeySet,
        sender_account: &AccountId,
        sender_key_set_version: u32,
        recipient: &PublicKeyBundle,
        enc: &[u8; XWING_CIPHERTEXT_LEN],
        shared_secret: &[u8; 32],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let header = ShareHeader {
            vault_id: *vault_id,
            vault_key_version: self.version,
            sender: *sender_account,
            sender_key_set_version,
            recipient: recipient.account_id,
            recipient_key_set_version: recipient.key_set_version,
        }
        .encode();

        let wrap_key = share_key(shared_secret, recipient.xwing.as_bytes(), &header, enc)?;
        let sealed = aead::seal_with_nonce(&wrap_key, nonce, self.key.as_bytes(), &header)?;

        let mut out = Vec::with_capacity(VAULT_SHARE_LEN);
        out.extend_from_slice(&header);
        out.extend_from_slice(enc);
        out.extend_from_slice(&sealed);
        let signature = sender.identity().sign(LABEL_SHARE, &out)?;
        out.extend_from_slice(signature.as_bytes());
        Ok(out)
    }

    /// Opens a vault share addressed to this account (spec section 7.5).
    ///
    /// `sender` must be the sender's public key bundle, verified through key
    /// transparency (section 9). The signature is checked before anything
    /// is decrypted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`], [`Error::WrongRecipient`] if the
    /// share is addressed to another account or key set,
    /// [`Error::WrongSender`] if it names a different sender than `sender`,
    /// [`Error::InvalidSignature`], or [`Error::Decryption`].
    pub fn open_share(
        share: &[u8],
        recipient: &KeySet,
        recipient_account: &AccountId,
        recipient_key_set_version: u32,
        sender: &PublicKeyBundle,
    ) -> Result<(VaultId, Self)> {
        if share.len() != VAULT_SHARE_LEN {
            return Err(Error::MalformedMessage);
        }
        let (signed, signature) =
            share.split_at(VAULT_SHARE_LEN.saturating_sub(HYBRID_SIGNATURE_LEN));
        let (header_bytes, rest) = signed.split_at(SHARE_HEADER_LEN);
        let (enc, sealed) = rest.split_at(XWING_CIPHERTEXT_LEN);
        let header = ShareHeader::decode(header_bytes)?;

        if header.recipient != *recipient_account
            || header.recipient_key_set_version != recipient_key_set_version
        {
            return Err(Error::WrongRecipient);
        }
        if header.sender != sender.account_id
            || header.sender_key_set_version != sender.key_set_version
        {
            return Err(Error::WrongSender);
        }
        verify(&sender.identity, signed, signature)?;

        let enc: [u8; XWING_CIPHERTEXT_LEN] =
            enc.try_into().map_err(|_| Error::MalformedMessage)?;
        let shared_secret = recipient.xwing_secret().decapsulate(&enc);
        let own_public = recipient.xwing_public_key();
        let wrap_key = share_key(&shared_secret, own_public.as_bytes(), header_bytes, &enc)?;
        let plaintext = aead::open(&wrap_key, sealed, header_bytes)?;
        Ok((
            header.vault_id,
            Self {
                key: key_from(&plaintext)?,
                version: header.vault_key_version,
            },
        ))
    }
}

/// The public header of a vault share, readable without any key. The
/// server uses it to route shares; clients must still verify and open the
/// share with [`VaultKey::open_share`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareInfo {
    /// The shared vault.
    pub vault_id: VaultId,
    /// The vault key version.
    pub vault_key_version: u32,
    /// The sender.
    pub sender: AccountId,
    /// The sender's key set version.
    pub sender_key_set_version: u32,
    /// The recipient.
    pub recipient: AccountId,
    /// The recipient's key set version.
    pub recipient_key_set_version: u32,
}

impl ShareInfo {
    /// Reads a share's header without verifying anything.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] for a bad length or header.
    pub fn inspect(share: &[u8]) -> Result<Self> {
        if share.len() != VAULT_SHARE_LEN {
            return Err(Error::MalformedMessage);
        }
        let header = share
            .get(..SHARE_HEADER_LEN)
            .ok_or(Error::MalformedMessage)?;
        let h = ShareHeader::decode(header)?;
        Ok(Self {
            vault_id: h.vault_id,
            vault_key_version: h.vault_key_version,
            sender: h.sender,
            sender_key_set_version: h.sender_key_set_version,
            recipient: h.recipient,
            recipient_key_set_version: h.recipient_key_set_version,
        })
    }
}

fn verify(identity: &IdentityPublicKey, message: &[u8], signature: &[u8]) -> Result<()> {
    identity.verify(
        LABEL_SHARE,
        message,
        &HybridSignature::from_bytes(signature)?,
    )
}

fn key_from(plaintext: &[u8]) -> Result<SymmetricKey> {
    let bytes: [u8; KEY_LEN] = plaintext.try_into().map_err(|_| Error::Decryption)?;
    Ok(SymmetricKey::from_bytes(bytes))
}

fn owner_aad(owner_account: &AccountId, vault_id: &VaultId, version: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(LABEL_VAULT_KEY.len().saturating_add(38));
    aad.extend_from_slice(LABEL_VAULT_KEY);
    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(owner_account.as_bytes());
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(&version.to_be_bytes());
    aad
}

/// `HKDF-SHA-256(salt = SHA-256(recipient_pk), IKM = ss,
///  info = label ‖ header ‖ enc)`.
fn share_key(
    shared_secret: &[u8; 32],
    recipient_public: &[u8],
    header: &[u8],
    enc: &[u8],
) -> Result<SymmetricKey> {
    let salt = Sha256::digest(recipient_public);
    let mut info = Vec::with_capacity(
        LABEL_SHARE
            .len()
            .saturating_add(header.len())
            .saturating_add(enc.len()),
    );
    info.extend_from_slice(LABEL_SHARE);
    info.extend_from_slice(header);
    info.extend_from_slice(enc);
    let mut key = SymmetricKey::zeroed();
    Hkdf::<Sha256>::new(Some(&salt), shared_secret)
        .expand(&info, key.as_mut_bytes())
        .map_err(|_| Error::KeyDerivation)?;
    Ok(key)
}

struct ShareHeader {
    vault_id: VaultId,
    vault_key_version: u32,
    sender: AccountId,
    sender_key_set_version: u32,
    recipient: AccountId,
    recipient_key_set_version: u32,
}

impl ShareHeader {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SHARE_HEADER_LEN);
        out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(self.vault_id.as_bytes());
        out.extend_from_slice(&self.vault_key_version.to_be_bytes());
        out.extend_from_slice(self.sender.as_bytes());
        out.extend_from_slice(&self.sender_key_set_version.to_be_bytes());
        out.extend_from_slice(self.recipient.as_bytes());
        out.extend_from_slice(&self.recipient_key_set_version.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        if r.u16()? != FORMAT_VERSION {
            return Err(Error::MalformedMessage);
        }
        let header = Self {
            vault_id: VaultId::from_bytes(r.array::<ID_LEN>()?),
            vault_key_version: r.u32()?,
            sender: AccountId::from_bytes(r.array::<ACCOUNT_ID_LEN>()?),
            sender_key_set_version: r.u32()?,
            recipient: AccountId::from_bytes(r.array::<ACCOUNT_ID_LEN>()?),
            recipient_key_set_version: r.u32()?,
        };
        if !r.rest().is_empty() {
            return Err(Error::MalformedMessage);
        }
        Ok(header)
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

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    const fn rest(&self) -> &'a [u8] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::TAG_LEN;

    struct Person {
        keys: KeySet,
        id: AccountId,
        bundle: PublicKeyBundle,
    }

    fn person(tag: u8) -> Person {
        let keys = KeySet::generate().unwrap();
        let id = AccountId::from_bytes([tag; ACCOUNT_ID_LEN]);
        let bundle =
            PublicKeyBundle::verify_signed(&keys.signed_public_bundle(&id, 1).unwrap()).unwrap();
        Person { keys, id, bundle }
    }

    fn vault() -> VaultId {
        VaultId::from_bytes([0xAA; ID_LEN])
    }

    #[test]
    fn sizes_match_the_spec() {
        assert_eq!(
            2 + ID_LEN + 4 + NONCE_LEN + KEY_LEN + TAG_LEN,
            OWNER_WRAPPED_VAULT_KEY_LEN
        );
        assert_eq!(2 + ID_LEN + 4 + 2 * (ACCOUNT_ID_LEN + 4), SHARE_HEADER_LEN);
        assert_eq!(
            SHARE_HEADER_LEN
                + XWING_CIPHERTEXT_LEN
                + NONCE_LEN
                + KEY_LEN
                + TAG_LEN
                + HYBRID_SIGNATURE_LEN,
            VAULT_SHARE_LEN
        );
    }

    #[test]
    fn owner_wrap_round_trip() {
        let alice = person(1);
        let vk = VaultKey::generate(1).unwrap();
        let wrapped = vk.wrap_for_owner(&alice.keys, &alice.id, &vault()).unwrap();
        assert_eq!(wrapped.len(), OWNER_WRAPPED_VAULT_KEY_LEN);
        let back = VaultKey::unwrap_for_owner(&wrapped, &alice.keys, &alice.id, &vault()).unwrap();
        assert_eq!(back.key, vk.key);
        assert_eq!(back.version, 1);
    }

    #[test]
    fn owner_wrap_is_bound_to_account_vault_and_version() {
        let alice = person(1);
        let bob = person(2);
        let vk = VaultKey::generate(1).unwrap();
        let wrapped = vk.wrap_for_owner(&alice.keys, &alice.id, &vault()).unwrap();

        assert!(VaultKey::unwrap_for_owner(&wrapped, &bob.keys, &bob.id, &vault()).is_err());
        assert!(VaultKey::unwrap_for_owner(&wrapped, &alice.keys, &bob.id, &vault()).is_err());
        let other_vault = VaultId::from_bytes([0xBB; ID_LEN]);
        assert_eq!(
            VaultKey::unwrap_for_owner(&wrapped, &alice.keys, &alice.id, &other_vault).unwrap_err(),
            Error::WrongItem
        );
        let mut bumped = wrapped.clone();
        bumped[21] = 9;
        assert_eq!(
            VaultKey::unwrap_for_owner(&bumped, &alice.keys, &alice.id, &vault()).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn share_round_trip() {
        let alice = person(1);
        let bob = person(2);
        let vk = VaultKey::generate(3).unwrap();
        let share = vk
            .share(&vault(), &alice.keys, &alice.id, 1, &bob.bundle)
            .unwrap();
        assert_eq!(share.len(), VAULT_SHARE_LEN);

        let (vault_id, received) =
            VaultKey::open_share(&share, &bob.keys, &bob.id, 1, &alice.bundle).unwrap();
        assert_eq!(vault_id, vault());
        assert_eq!(received.key, vk.key);
        assert_eq!(received.version, 3);
    }

    #[test]
    fn share_is_only_for_its_recipient() {
        let alice = person(1);
        let bob = person(2);
        let carol = person(3);
        let vk = VaultKey::generate(1).unwrap();
        let share = vk
            .share(&vault(), &alice.keys, &alice.id, 1, &bob.bundle)
            .unwrap();

        assert_eq!(
            VaultKey::open_share(&share, &carol.keys, &carol.id, 1, &alice.bundle).unwrap_err(),
            Error::WrongRecipient
        );
        assert_eq!(
            VaultKey::open_share(&share, &bob.keys, &bob.id, 2, &alice.bundle).unwrap_err(),
            Error::WrongRecipient
        );
        // Carol's keys under Bob's identity cannot decrypt it either.
        assert!(VaultKey::open_share(&share, &carol.keys, &bob.id, 1, &alice.bundle).is_err());
    }

    #[test]
    fn share_must_come_from_the_claimed_sender() {
        let alice = person(1);
        let bob = person(2);
        let mallory = person(9);
        let vk = VaultKey::generate(1).unwrap();

        // Mallory shares a vault she controls, but the recipient expects Alice.
        let fake = vk
            .share(&vault(), &mallory.keys, &mallory.id, 1, &bob.bundle)
            .unwrap();
        assert_eq!(
            VaultKey::open_share(&fake, &bob.keys, &bob.id, 1, &alice.bundle).unwrap_err(),
            Error::WrongSender
        );

        // Mallory claims to be Alice in the header but cannot sign as her.
        let mut forged = vk
            .share(&vault(), &mallory.keys, &alice.id, 1, &bob.bundle)
            .unwrap();
        assert_eq!(
            VaultKey::open_share(&forged, &bob.keys, &bob.id, 1, &alice.bundle).unwrap_err(),
            Error::InvalidSignature
        );
        forged.truncate(10);
        assert_eq!(
            VaultKey::open_share(&forged, &bob.keys, &bob.id, 1, &alice.bundle).unwrap_err(),
            Error::MalformedMessage
        );
    }

    #[test]
    fn any_modification_is_rejected() {
        let alice = person(1);
        let bob = person(2);
        let vk = VaultKey::generate(1).unwrap();
        let share = vk
            .share(&vault(), &alice.keys, &alice.id, 1, &bob.bundle)
            .unwrap();
        // Header fields, KEM ciphertext, nonce, sealed key, signature.
        for pos in [3, 19, 30, 1000, 1190, 1210, 1240, 4000] {
            let mut bad = share.clone();
            bad[pos] ^= 1;
            assert!(
                VaultKey::open_share(&bad, &bob.keys, &bob.id, 1, &alice.bundle).is_err(),
                "pos {pos}"
            );
        }
    }

    #[test]
    fn re_signing_a_modified_share_still_fails_to_decrypt() {
        // Even a sender who re-signs cannot change the vault ID or version
        // without the recipient's decryption failing, because the header is
        // bound into the key derivation and the associated data.
        let alice = person(1);
        let bob = person(2);
        let vk = VaultKey::generate(1).unwrap();
        let mut share = vk
            .share(&vault(), &alice.keys, &alice.id, 1, &bob.bundle)
            .unwrap();
        share[2] ^= 1; // vault ID
        let signed_len = VAULT_SHARE_LEN - HYBRID_SIGNATURE_LEN;
        let sig = alice
            .keys
            .identity()
            .sign(LABEL_SHARE, &share[..signed_len])
            .unwrap();
        share[signed_len..].copy_from_slice(sig.as_bytes());
        assert_eq!(
            VaultKey::open_share(&share, &bob.keys, &bob.id, 1, &alice.bundle).unwrap_err(),
            Error::Decryption
        );
    }
}
