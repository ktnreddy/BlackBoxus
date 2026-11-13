//! X-Wing (X25519 + ML-KEM-768), per draft-connolly-cfrg-xwing-kem
//! (spec sections 5.3 and 7.4).

use libcrux_ml_kem::mlkem768;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::random;

/// Length of an X-Wing secret key (seed) in bytes.
pub const XWING_SECRET_LEN: usize = 32;

/// Length of an X-Wing public key in bytes.
pub const XWING_PUBLIC_LEN: usize = 1216;

/// Length of an X-Wing ciphertext in bytes.
pub const XWING_CIPHERTEXT_LEN: usize = 1120;

/// Length of an X-Wing shared secret in bytes.
pub const XWING_SHARED_SECRET_LEN: usize = 32;

const ML_KEM_PUBLIC_LEN: usize = 1184;
const ML_KEM_SECRET_LEN: usize = 2400;
const ML_KEM_CIPHERTEXT_LEN: usize = 1088;

/// The X-Wing combiner label, `\.//^\`.
const XWING_LABEL: &[u8; 6] = br"\.//^\";

/// A shared secret, erased on drop.
pub(crate) type SharedSecret = Zeroizing<[u8; XWING_SHARED_SECRET_LEN]>;

/// An X-Wing secret key, stored as its 32-byte seed. Erased on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct XWingSecretKey([u8; XWING_SECRET_LEN]);

/// The expanded form of a secret key. Every secret part is erased on drop.
struct Expanded {
    ml_kem_secret: Zeroizing<[u8; ML_KEM_SECRET_LEN]>,
    ml_kem_public: [u8; ML_KEM_PUBLIC_LEN],
    x25519_secret: Zeroizing<[u8; 32]>,
    x25519_public: [u8; 32],
}

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

    /// Expands the seed (draft section 5.2).
    fn expand(&self) -> Expanded {
        let mut expanded = Zeroizing::new([0_u8; 96]);
        libcrux_sha3::shake256_ema(expanded.as_mut_slice(), &self.0);

        let (dz, sk_x) = expanded.split_at(64);
        let mut ml_kem_seed = Zeroizing::new([0_u8; 64]);
        ml_kem_seed.copy_from_slice(dz);
        let mut x25519_secret = Zeroizing::new([0_u8; 32]);
        x25519_secret.copy_from_slice(sk_x);

        let key_pair = mlkem768::generate_key_pair(*ml_kem_seed);
        let mut ml_kem_public = [0_u8; ML_KEM_PUBLIC_LEN];
        ml_kem_public.copy_from_slice(key_pair.pk());
        let (secret, _) = key_pair.into_parts();
        let ml_kem_secret = Zeroizing::new(secret.into());

        let x25519_public =
            x25519_dalek::x25519(*x25519_secret, x25519_dalek::X25519_BASEPOINT_BYTES);
        Expanded {
            ml_kem_secret,
            ml_kem_public,
            x25519_secret,
            x25519_public,
        }
    }

    /// Derives the public key.
    #[must_use]
    pub fn public_key(&self) -> XWingPublicKey {
        let e = self.expand();
        let mut out = [0_u8; XWING_PUBLIC_LEN];
        let (m, x) = out.split_at_mut(ML_KEM_PUBLIC_LEN);
        m.copy_from_slice(&e.ml_kem_public);
        x.copy_from_slice(&e.x25519_public);
        XWingPublicKey(out)
    }

    /// Recovers the shared secret from a ciphertext (draft section 5.4).
    ///
    /// Never fails: a modified ciphertext yields an unrelated secret, which
    /// the caller's authenticated decryption then rejects.
    pub(crate) fn decapsulate(&self, ciphertext: &[u8; XWING_CIPHERTEXT_LEN]) -> SharedSecret {
        let e = self.expand();
        let (ct_m, ct_x) = ciphertext.split_at(ML_KEM_CIPHERTEXT_LEN);
        let mut ct_m_array = [0_u8; ML_KEM_CIPHERTEXT_LEN];
        ct_m_array.copy_from_slice(ct_m);
        let mut ct_x_array = [0_u8; 32];
        ct_x_array.copy_from_slice(ct_x);

        let secret = mlkem768::MlKem768PrivateKey::from(*e.ml_kem_secret);
        let mut ss_m =
            mlkem768::decapsulate(&secret, &mlkem768::MlKem768Ciphertext::from(ct_m_array));
        let mut raw: [u8; ML_KEM_SECRET_LEN] = secret.into();
        raw.zeroize();

        let ss_x = Zeroizing::new(x25519_dalek::x25519(*e.x25519_secret, ct_x_array));
        let ss = combine(&ss_m, &ss_x, &ct_x_array, &e.x25519_public);
        ss_m.zeroize();
        ss
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

    /// Creates a shared secret and the ciphertext that carries it to the
    /// key's owner (draft section 5.3).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPublicKey`] if the ML-KEM half fails the FIPS
    /// 203 input check, or [`Error::RandomUnavailable`].
    pub(crate) fn encapsulate(&self) -> Result<([u8; XWING_CIPHERTEXT_LEN], SharedSecret)> {
        let randomness = Zeroizing::new(random::bytes::<64>()?);
        self.encapsulate_deterministic(&randomness)
    }

    /// Encapsulation with caller-supplied randomness: the first 32 bytes for
    /// ML-KEM, the last 32 for the ephemeral X25519 key. Test vectors only.
    pub(crate) fn encapsulate_deterministic(
        &self,
        randomness: &[u8; 64],
    ) -> Result<([u8; XWING_CIPHERTEXT_LEN], SharedSecret)> {
        let (pk_m, pk_x) = self.0.split_at(ML_KEM_PUBLIC_LEN);
        let mut pk_m_array = [0_u8; ML_KEM_PUBLIC_LEN];
        pk_m_array.copy_from_slice(pk_m);
        let mut pk_x_array = [0_u8; 32];
        pk_x_array.copy_from_slice(pk_x);

        let pk_m = mlkem768::MlKem768PublicKey::from(pk_m_array);
        if !mlkem768::validate_public_key(&pk_m) {
            return Err(Error::InvalidPublicKey);
        }

        let (rand_m, rand_x) = randomness.split_at(32);
        let mut rand_m_array = Zeroizing::new([0_u8; 32]);
        rand_m_array.copy_from_slice(rand_m);
        let mut ek_x = Zeroizing::new([0_u8; 32]);
        ek_x.copy_from_slice(rand_x);

        let (ct_m, mut ss_m) = mlkem768::encapsulate(&pk_m, *rand_m_array);
        let ct_x = x25519_dalek::x25519(*ek_x, x25519_dalek::X25519_BASEPOINT_BYTES);
        let ss_x = Zeroizing::new(x25519_dalek::x25519(*ek_x, pk_x_array));
        let ss = combine(&ss_m, &ss_x, &ct_x, &pk_x_array);
        ss_m.zeroize();

        let mut ct = [0_u8; XWING_CIPHERTEXT_LEN];
        let (m, x) = ct.split_at_mut(ML_KEM_CIPHERTEXT_LEN);
        m.copy_from_slice(ct_m.as_slice());
        x.copy_from_slice(&ct_x);
        Ok((ct, ss))
    }
}

impl core::fmt::Debug for XWingPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("XWingPublicKey(..)")
    }
}

/// `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)` (draft section 5.3).
fn combine(ss_m: &[u8; 32], ss_x: &[u8; 32], ct_x: &[u8; 32], pk_x: &[u8; 32]) -> SharedSecret {
    let mut input = Zeroizing::new([0_u8; 134]);
    for (dst, src) in input.iter_mut().zip(
        ss_m.iter()
            .chain(ss_x)
            .chain(ct_x)
            .chain(pk_x)
            .chain(XWING_LABEL),
    ) {
        *dst = *src;
    }
    Zeroizing::new(libcrux_sha3::sha256(input.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x_wing::kem::{Decapsulate, Decapsulator};
    use x_wing::{Ciphertext, DecapsulationKey, KeyExport};

    #[test]
    fn public_key_matches_independent_implementation() {
        for i in 0..20_u8 {
            let seed = [i.wrapping_mul(37).wrapping_add(1); XWING_SECRET_LEN];
            let ours = XWingSecretKey::from_seed(seed).public_key();
            let theirs = DecapsulationKey::from(seed).encapsulation_key().to_bytes();
            assert_eq!(ours.as_bytes().as_slice(), theirs.as_slice(), "seed {i}");
        }
    }

    #[test]
    fn encapsulation_matches_independent_implementation() {
        for i in 0..10_u8 {
            let seed = [i.wrapping_add(3); XWING_SECRET_LEN];
            let randomness = [i.wrapping_mul(13).wrapping_add(7); 64];
            let pk = XWingSecretKey::from_seed(seed).public_key();
            let (ct, ss) = pk.encapsulate_deterministic(&randomness).unwrap();

            let theirs = DecapsulationKey::from(seed);
            let (their_ct, their_ss) = theirs
                .encapsulation_key()
                .encapsulate_deterministic(&randomness.into());
            assert_eq!(ct.as_slice(), their_ct.as_slice(), "ciphertext {i}");
            assert_eq!(ss.as_slice(), their_ss.as_slice(), "secret {i}");

            // And they decapsulate our ciphertext to the same secret.
            let parsed = Ciphertext::try_from(ct.as_slice()).unwrap();
            assert_eq!(theirs.decapsulate(&parsed).as_slice(), ss.as_slice());
        }
    }

    #[test]
    fn decapsulation_recovers_the_secret() {
        let sk = XWingSecretKey::generate().unwrap();
        let (ct, ss) = sk.public_key().encapsulate().unwrap();
        assert_eq!(*sk.decapsulate(&ct), *ss);
    }

    #[test]
    fn wrong_key_or_modified_ciphertext_gives_a_different_secret() {
        let sk = XWingSecretKey::generate().unwrap();
        let (ct, ss) = sk.public_key().encapsulate().unwrap();
        let other = XWingSecretKey::generate().unwrap();
        assert_ne!(*other.decapsulate(&ct), *ss);
        for pos in [0, 500, 1087, 1088, 1119] {
            let mut bad = ct;
            bad[pos] ^= 1;
            assert_ne!(*sk.decapsulate(&bad), *ss, "pos {pos}");
        }
    }

    #[test]
    fn rejects_invalid_ml_kem_public_key() {
        // Coefficients of 0xFFF exceed the ML-KEM modulus.
        let bad = XWingPublicKey::from_bytes([0xFF; XWING_PUBLIC_LEN]);
        assert_eq!(bad.encapsulate().unwrap_err(), Error::InvalidPublicKey);
    }

    #[test]
    fn different_seeds_give_different_keys() {
        let a = XWingSecretKey::generate().unwrap().public_key();
        let b = XWingSecretKey::generate().unwrap().public_key();
        assert_ne!(a, b);
    }
}
