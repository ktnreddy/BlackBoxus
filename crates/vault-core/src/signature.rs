//! Hybrid Ed25519 + ML-DSA-65 identity signatures (spec section 5.5).
//!
//! A signature is valid only if both halves verify.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use libcrux_ml_dsa::ml_dsa_65;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::random;

/// Length of an Ed25519 public key in bytes.
pub const ED25519_PUBLIC_LEN: usize = 32;
/// Length of an Ed25519 signature in bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// Length of an ML-DSA-65 public key in bytes.
pub const ML_DSA_65_PUBLIC_LEN: usize = 1952;
/// Length of an ML-DSA-65 signature in bytes.
pub const ML_DSA_65_SIGNATURE_LEN: usize = 3309;
/// Length of an identity public key: Ed25519 key followed by ML-DSA-65 key.
pub const IDENTITY_PUBLIC_LEN: usize = 1984;
/// Length of a hybrid signature: Ed25519 signature followed by ML-DSA-65.
pub const HYBRID_SIGNATURE_LEN: usize = 3373;
/// Maximum length of a signing context.
pub const MAX_CONTEXT_LEN: usize = 255;

/// Identity signing keys, stored as two 32-byte seeds. Erased on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IdentitySecretKey {
    ed25519_seed: [u8; 32],
    ml_dsa_seed: [u8; 32],
}

impl IdentitySecretKey {
    /// Generates new identity keys.
    pub(crate) fn generate() -> Result<Self> {
        Ok(Self {
            ed25519_seed: random::bytes()?,
            ml_dsa_seed: random::bytes()?,
        })
    }

    /// Builds keys from seeds.
    pub(crate) const fn from_seeds(ed25519_seed: [u8; 32], ml_dsa_seed: [u8; 32]) -> Self {
        Self {
            ed25519_seed,
            ml_dsa_seed,
        }
    }

    /// The Ed25519 seed.
    pub(crate) const fn ed25519_seed(&self) -> &[u8; 32] {
        &self.ed25519_seed
    }

    /// The ML-DSA-65 seed.
    pub(crate) const fn ml_dsa_seed(&self) -> &[u8; 32] {
        &self.ml_dsa_seed
    }

    /// Derives the public identity key.
    #[must_use]
    pub fn public_key(&self) -> IdentityPublicKey {
        let ed = SigningKey::from_bytes(&self.ed25519_seed)
            .verifying_key()
            .to_bytes();
        let mut key_pair = ml_dsa_65::generate_key_pair(self.ml_dsa_seed);
        let mut ml = [0_u8; ML_DSA_65_PUBLIC_LEN];
        ml.copy_from_slice(key_pair.verification_key.as_slice());
        key_pair.signing_key.as_mut_slice().zeroize();
        IdentityPublicKey {
            ed25519: ed,
            ml_dsa: ml,
        }
    }

    /// Signs `message` under `context` (at most 255 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidContext`] if the context is too long,
    /// [`Error::RandomUnavailable`] if randomness is unavailable, or
    /// [`Error::Signing`] if ML-DSA signing fails.
    pub fn sign(&self, context: &[u8], message: &[u8]) -> Result<HybridSignature> {
        let context_len = u8::try_from(context.len()).map_err(|_| Error::InvalidContext)?;

        let mut ed_input = Vec::with_capacity(
            1_usize
                .saturating_add(context.len())
                .saturating_add(message.len()),
        );
        ed_input.push(context_len);
        ed_input.extend_from_slice(context);
        ed_input.extend_from_slice(message);
        let ed_sig = SigningKey::from_bytes(&self.ed25519_seed)
            .sign(&ed_input)
            .to_bytes();

        let mut key_pair = ml_dsa_65::generate_key_pair(self.ml_dsa_seed);
        let result = ml_dsa_65::sign(&key_pair.signing_key, message, context, random::bytes()?);
        key_pair.signing_key.as_mut_slice().zeroize();
        let ml_sig = result.map_err(|_| Error::Signing)?;

        let mut out = [0_u8; HYBRID_SIGNATURE_LEN];
        let (a, b) = out.split_at_mut(ED25519_SIGNATURE_LEN);
        a.copy_from_slice(&ed_sig);
        b.copy_from_slice(ml_sig.as_slice());
        Ok(HybridSignature(out))
    }
}

impl core::fmt::Debug for IdentitySecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IdentitySecretKey(<redacted>)")
    }
}

/// A public identity key: Ed25519 and ML-DSA-65 verification keys.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityPublicKey {
    ed25519: [u8; ED25519_PUBLIC_LEN],
    ml_dsa: [u8; ML_DSA_65_PUBLIC_LEN],
}

impl IdentityPublicKey {
    /// Parses `ed25519 ‖ ml_dsa` public key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if the length is wrong.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != IDENTITY_PUBLIC_LEN {
            return Err(Error::MalformedMessage);
        }
        let (ed, ml) = bytes.split_at(ED25519_PUBLIC_LEN);
        Ok(Self {
            ed25519: ed.try_into().map_err(|_| Error::MalformedMessage)?,
            ml_dsa: ml.try_into().map_err(|_| Error::MalformedMessage)?,
        })
    }

    /// Encodes as `ed25519 ‖ ml_dsa`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(IDENTITY_PUBLIC_LEN);
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&self.ml_dsa);
        out
    }

    /// Verifies a hybrid signature. Both halves must be valid, and Ed25519 is
    /// checked with strict verification.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSignature`] if either half fails, or
    /// [`Error::InvalidContext`] if the context is too long.
    pub fn verify(
        &self,
        context: &[u8],
        message: &[u8],
        signature: &HybridSignature,
    ) -> Result<()> {
        let context_len = u8::try_from(context.len()).map_err(|_| Error::InvalidContext)?;
        let (ed_sig, ml_sig) = signature.0.split_at(ED25519_SIGNATURE_LEN);

        let ed_key =
            VerifyingKey::from_bytes(&self.ed25519).map_err(|_| Error::InvalidSignature)?;
        let ed_sig: [u8; ED25519_SIGNATURE_LEN] =
            ed_sig.try_into().map_err(|_| Error::InvalidSignature)?;
        let mut ed_input = Vec::with_capacity(
            1_usize
                .saturating_add(context.len())
                .saturating_add(message.len()),
        );
        ed_input.push(context_len);
        ed_input.extend_from_slice(context);
        ed_input.extend_from_slice(message);
        let ed_ok = ed_key
            .verify_strict(&ed_input, &ed25519_dalek::Signature::from_bytes(&ed_sig))
            .is_ok();

        let ml_sig: [u8; ML_DSA_65_SIGNATURE_LEN] =
            ml_sig.try_into().map_err(|_| Error::InvalidSignature)?;
        let ml_ok = ml_dsa_65::verify(
            &ml_dsa_65::MLDSA65VerificationKey::new(self.ml_dsa),
            message,
            context,
            &ml_dsa_65::MLDSA65Signature::new(ml_sig),
        )
        .is_ok();

        // Evaluate both before deciding, so failure timing does not reveal
        // which half was wrong.
        if ed_ok & ml_ok {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

impl core::fmt::Debug for IdentityPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IdentityPublicKey(..)")
    }
}

/// A hybrid signature: Ed25519 signature followed by ML-DSA-65 signature.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridSignature([u8; HYBRID_SIGNATURE_LEN]);

impl HybridSignature {
    /// Parses signature bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if the length is wrong.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| Error::MalformedMessage)
    }

    /// The signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HYBRID_SIGNATURE_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HybridSignature(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: &[u8] = b"BlackBoxus v1 test";

    #[test]
    fn sign_and_verify() {
        let sk = IdentitySecretKey::generate().unwrap();
        let pk = sk.public_key();
        let sig = sk.sign(CTX, b"hello").unwrap();
        assert!(pk.verify(CTX, b"hello", &sig).is_ok());
    }

    #[test]
    fn rejects_wrong_message_context_or_key() {
        let sk = IdentitySecretKey::generate().unwrap();
        let pk = sk.public_key();
        let sig = sk.sign(CTX, b"hello").unwrap();
        assert!(pk.verify(CTX, b"hellp", &sig).is_err());
        assert!(pk.verify(b"other context", b"hello", &sig).is_err());
        let other = IdentitySecretKey::generate().unwrap().public_key();
        assert!(other.verify(CTX, b"hello", &sig).is_err());
    }

    #[test]
    fn both_halves_are_required() {
        let sk = IdentitySecretKey::generate().unwrap();
        let pk = sk.public_key();
        let sig = sk.sign(CTX, b"hello").unwrap();

        // Corrupt only the Ed25519 half, then only the ML-DSA half.
        for pos in [0, ED25519_SIGNATURE_LEN + 10] {
            let mut bytes = *sig.as_bytes();
            bytes[pos] ^= 1;
            let bad = HybridSignature::from_bytes(&bytes).unwrap();
            assert_eq!(pk.verify(CTX, b"hello", &bad), Err(Error::InvalidSignature));
        }

        // A valid half from one signature cannot be combined with the other
        // half of a signature over a different message.
        let other = sk.sign(CTX, b"bye").unwrap();
        let mut mixed = *sig.as_bytes();
        mixed[ED25519_SIGNATURE_LEN..].copy_from_slice(&other.as_bytes()[ED25519_SIGNATURE_LEN..]);
        let mixed = HybridSignature::from_bytes(&mixed).unwrap();
        assert!(pk.verify(CTX, b"hello", &mixed).is_err());
    }

    #[test]
    fn context_length_is_limited() {
        let sk = IdentitySecretKey::generate().unwrap();
        let long = [0_u8; MAX_CONTEXT_LEN + 1];
        assert_eq!(sk.sign(&long, b"m").unwrap_err(), Error::InvalidContext);
        assert!(sk.sign(&long[..MAX_CONTEXT_LEN], b"m").is_ok());
    }

    #[test]
    fn public_key_round_trips() {
        let pk = IdentitySecretKey::generate().unwrap().public_key();
        assert_eq!(IdentityPublicKey::from_bytes(&pk.to_bytes()).unwrap(), pk);
        assert!(IdentityPublicKey::from_bytes(&[0; 10]).is_err());
    }

    #[test]
    fn ml_dsa_signature_verifies_with_independent_implementation() {
        use ml_dsa::{MlDsa65, Signature, VerifyingKey};
        let sk = IdentitySecretKey::generate().unwrap();
        let pk = sk.public_key();
        let sig = sk.sign(CTX, b"cross-check").unwrap();

        let vk = VerifyingKey::<MlDsa65>::decode(&pk.ml_dsa.into());
        let ml_sig =
            Signature::<MlDsa65>::try_from(&sig.as_bytes()[ED25519_SIGNATURE_LEN..]).unwrap();
        assert!(vk.verify_with_context(b"cross-check", CTX, &ml_sig));
        assert!(!vk.verify_with_context(b"cross-check", b"other", &ml_sig));
    }

    #[test]
    fn ml_dsa_key_matches_independent_implementation() {
        use ml_dsa::{Keypair, MlDsa65, SigningKey};
        for i in 0..5_u8 {
            let seed = [i.wrapping_add(11); 32];
            let ours = IdentitySecretKey::from_seeds([0; 32], seed).public_key();
            let theirs = SigningKey::<MlDsa65>::from_seed(&seed.into())
                .verifying_key()
                .encode();
            assert_eq!(ours.ml_dsa.as_slice(), theirs.as_slice());
        }
    }
}
