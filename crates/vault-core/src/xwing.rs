//! X-Wing key generation (X25519 + ML-KEM-768), per
//! draft-connolly-cfrg-xwing-kem, Section 5.2 (spec section 5.3).
//!
//! Encapsulation and decapsulation are added with vault sharing (section 7).

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::Result;
use crate::random;

/// Length of an X-Wing secret key (seed) in bytes.
pub const XWING_SECRET_LEN: usize = 32;

/// Length of an X-Wing public key in bytes.
pub const XWING_PUBLIC_LEN: usize = 1216;

const ML_KEM_PUBLIC_LEN: usize = 1184;

/// An X-Wing secret key, stored as its 32-byte seed. Erased on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct XWingSecretKey([u8; XWING_SECRET_LEN]);

impl XWingSecretKey {
    /// Generates a new secret key.
    pub(crate) fn generate() -> Result<Self> {
        random::bytes().map(Self)
    }

    /// Wraps a seed.
    pub(crate) const fn from_seed(seed: [u8; XWING_SECRET_LEN]) -> Self {
        Self(seed)
    }

    /// The seed bytes.
    pub(crate) const fn seed(&self) -> &[u8; XWING_SECRET_LEN] {
        &self.0
    }

    /// Derives the public key.
    #[must_use]
    pub fn public_key(&self) -> XWingPublicKey {
        let mut expanded = Zeroizing::new([0_u8; 96]);
        libcrux_sha3::shake256_ema(expanded.as_mut_slice(), &self.0);

        let (dz, sk_x) = expanded.split_at(64);
        let mut ml_kem_seed = Zeroizing::new([0_u8; 64]);
        ml_kem_seed.copy_from_slice(dz);
        let mut x25519_secret = Zeroizing::new([0_u8; 32]);
        x25519_secret.copy_from_slice(sk_x);

        let key_pair = libcrux_ml_kem::mlkem768::generate_key_pair(*ml_kem_seed);
        let pk_x = x25519_dalek::x25519(*x25519_secret, x25519_dalek::X25519_BASEPOINT_BYTES);

        let mut out = [0_u8; XWING_PUBLIC_LEN];
        let (m, x) = out.split_at_mut(ML_KEM_PUBLIC_LEN);
        m.copy_from_slice(key_pair.pk());
        x.copy_from_slice(&pk_x);

        // The expanded ML-KEM secret key is not needed: erase it (best effort,
        // since the library does not erase it itself).
        let (secret, _) = key_pair.into_parts();
        let mut raw: [u8; 2400] = secret.into();
        raw.zeroize();
        XWingPublicKey(out)
    }
}

impl core::fmt::Debug for XWingSecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("XWingSecretKey(<redacted>)")
    }
}

/// An X-Wing public key: `pk_M ‖ pk_X`.
#[derive(Clone, PartialEq, Eq)]
pub struct XWingPublicKey([u8; XWING_PUBLIC_LEN]);

impl XWingPublicKey {
    /// Wraps public key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; XWING_PUBLIC_LEN]) -> Self {
        Self(bytes)
    }

    /// The public key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; XWING_PUBLIC_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for XWingPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("XWingPublicKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x_wing::{DecapsulationKey, KeyExport, kem::Decapsulator};

    #[test]
    fn matches_independent_implementation() {
        for i in 0..20_u8 {
            let seed = [i.wrapping_mul(37).wrapping_add(1); XWING_SECRET_LEN];
            let ours = XWingSecretKey::from_seed(seed).public_key();
            let theirs = DecapsulationKey::from(seed).encapsulation_key().to_bytes();
            assert_eq!(ours.as_bytes().as_slice(), theirs.as_slice(), "seed {i}");
        }
    }

    #[test]
    fn different_seeds_give_different_keys() {
        let a = XWingSecretKey::generate().unwrap().public_key();
        let b = XWingSecretKey::generate().unwrap().public_key();
        assert_ne!(a, b);
    }
}
