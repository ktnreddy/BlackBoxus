//! Authenticated encryption with XChaCha20-Poly1305 (spec section 2).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::key::SymmetricKey;
use crate::random;

/// Nonce length in bytes.
pub const NONCE_LEN: usize = 24;

/// Authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Encrypts `plaintext` with a fresh random nonce. Returns
/// `nonce ‖ ciphertext ‖ tag`.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "kept for future single-key encryption")
)]
pub(crate) fn seal(key: &SymmetricKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let nonce: [u8; NONCE_LEN] = random::bytes()?;
    seal_with_nonce(key, &nonce, plaintext, aad)
}

/// Encrypts with a caller-supplied nonce. Only for test vectors and for
/// [`seal`]; a nonce must never be reused with the same key.
pub(crate) fn seal_with_nonce(
    key: &SymmetricKey,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| Error::Encryption)?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Encryption)?;
    let mut out = Vec::with_capacity(NONCE_LEN.saturating_add(ciphertext.len()));
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts `nonce ‖ ciphertext ‖ tag`. The plaintext is erased when the
/// returned buffer is dropped.
pub(crate) fn open(key: &SymmetricKey, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN.saturating_add(TAG_LEN) {
        return Err(Error::Decryption);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::Decryption)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| Error::Decryption)?;
    cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> SymmetricKey {
        SymmetricKey::from_bytes([b; 32])
    }

    #[test]
    fn round_trip() {
        let sealed = seal(&key(1), b"secret", b"context").unwrap();
        assert_eq!(sealed.len(), NONCE_LEN + 6 + TAG_LEN);
        let opened = open(&key(1), &sealed, b"context").unwrap();
        assert_eq!(opened.as_slice(), b"secret");
    }

    #[test]
    fn nonces_are_fresh() {
        let a = seal(&key(1), b"secret", b"").unwrap();
        let b = seal(&key(1), b"secret", b"").unwrap();
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_aad_or_tampering_fails() {
        let sealed = seal(&key(1), b"secret", b"context").unwrap();
        assert_eq!(open(&key(2), &sealed, b"context"), Err(Error::Decryption));
        assert_eq!(open(&key(1), &sealed, b"other"), Err(Error::Decryption));
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 1;
            assert_eq!(open(&key(1), &bad, b"context"), Err(Error::Decryption));
        }
    }

    #[test]
    fn short_input_fails_cleanly() {
        for len in 0..NONCE_LEN + TAG_LEN {
            assert_eq!(open(&key(1), &vec![0; len], b""), Err(Error::Decryption));
        }
    }
}
