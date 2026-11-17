//! The browser extension's messages and their encryption (spec section 14).
//!
//! The extension and the app agree a key once, when the user approves the
//! browser in the app: an ephemeral P-256 key exchange, confirmed by a
//! six-digit code both sides show. Every later request and answer is sealed
//! with AES-256-GCM under that key, so nothing but the paired extension can
//! ask for a login, and only it can read the answer. P-256 and AES-GCM are
//! used because the extension has only the browser's Web Crypto API.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The largest message the app reads from the extension.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// The largest message Chrome accepts from a native host.
pub const MAX_REPLY_BYTES: usize = 1024 * 1024;

/// Length of a pairing ID.
pub const PAIRING_ID_LEN: usize = 16;

/// Length of an uncompressed P-256 public key.
const PUBLIC_KEY_LEN: usize = 65;

/// Length of an AES-GCM nonce.
const NONCE_LEN: usize = 12;

const LABEL_PAIR: &[u8] = b"BlackBoxus v1 browser-pair";
const LABEL_REQUEST: &[u8] = b"BlackBoxus v1 browser-request";
const LABEL_RESPONSE: &[u8] = b"BlackBoxus v1 browser-response";

/// Something in a message was not as the protocol says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

/// A message from the extension.
#[derive(Debug, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase", deny_unknown_fields)]
pub enum Incoming {
    /// Asks to pair: the extension's pairing ID and ephemeral public key.
    Pair {
        /// Pairing ID, base64url.
        id: String,
        /// P-256 public key, uncompressed, base64url.
        key: String,
        /// The browser's name, to show the user.
        browser: String,
    },
    /// A sealed request from a paired extension.
    Req {
        /// Pairing ID, base64url.
        id: String,
        /// Nonce, base64url.
        n: String,
        /// Ciphertext, base64url.
        c: String,
    },
}

/// A message to the extension.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum Outgoing {
    /// The app's ephemeral public key, answering [`Incoming::Pair`].
    Pair {
        /// P-256 public key, uncompressed, base64url.
        key: String,
    },
    /// The user approved the pairing.
    Paired,
    /// A sealed answer.
    Res {
        /// Nonce, base64url.
        n: String,
        /// Ciphertext, base64url.
        c: String,
    },
    /// The request failed before anything could be sealed.
    Error {
        /// `disabled`, `denied`, `unpaired`, `busy` or `malformed`.
        code: &'static str,
    },
}

/// What a sealed request asks for.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Whether the app is unlocked.
    Status,
    /// The logins saved for a page.
    Logins {
        /// The page's address.
        url: String,
    },
    /// One login's username, password and current one-time code, to fill
    /// into a page.
    Fill {
        /// The page's address.
        url: String,
        /// Vault ID, base64url.
        vault: String,
        /// Item ID, base64url.
        item: String,
    },
}

/// A pairing being set up: the key both sides now share, and the code to
/// show the user so they can check both sides agree.
pub struct Pairing {
    /// The app's ephemeral public key, to send to the extension.
    pub app_key: [u8; PUBLIC_KEY_LEN],
    /// The shared key, kept if the user approves.
    pub key: Zeroizing<[u8; 32]>,
    /// Six digits, shown by the app and by the extension.
    pub code: String,
}

/// Answers a pairing request (spec section 14.3).
///
/// # Errors
///
/// Returns [`Malformed`] if the ID or key is invalid, or randomness fails.
pub fn pair(id: &[u8], extension_key: &[u8]) -> Result<Pairing, Malformed> {
    if id.len() != PAIRING_ID_LEN {
        return Err(Malformed);
    }
    let theirs = p256::PublicKey::from_sec1_bytes(extension_key).map_err(|_| Malformed)?;
    let secret = loop {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut_slice()).map_err(|_| Malformed)?;
        // A value outside the scalar range is vanishingly rare; draw again.
        if let Ok(s) = p256::SecretKey::from_slice(bytes.as_slice()) {
            break s;
        }
    };
    let app_key = encoded(&secret.public_key())?;
    let theirs_encoded = encoded(&theirs)?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), theirs.as_affine());
    let (key, code) = derive(id, &theirs_encoded, &app_key, shared.raw_secret_bytes())?;
    Ok(Pairing { app_key, key, code })
}

/// A public key, uncompressed, as Web Crypto exports it.
fn encoded(key: &p256::PublicKey) -> Result<[u8; PUBLIC_KEY_LEN], Malformed> {
    (*key.to_sec1_bytes()).try_into().map_err(|_| Malformed)
}

/// The shared key and confirmation code from an exchange.
fn derive(
    id: &[u8],
    extension_key: &[u8],
    app_key: &[u8],
    shared: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, String), Malformed> {
    let transcript: [u8; 32] = Sha256::new()
        .chain_update(LABEL_PAIR)
        .chain_update(id)
        .chain_update(extension_key)
        .chain_update(app_key)
        .finalize()
        .into();
    let mut okm = Zeroizing::new([0_u8; 36]);
    Hkdf::<Sha256>::new(Some(&transcript), shared)
        .expand(LABEL_PAIR, okm.as_mut_slice())
        .map_err(|_| Malformed)?;
    let mut key = Zeroizing::new([0_u8; 32]);
    let (k, c) = okm.split_at(32);
    key.copy_from_slice(k);
    let code_bytes: [u8; 4] = c.try_into().map_err(|_| Malformed)?;
    let code = u32::from_be_bytes(code_bytes) % 1_000_000;
    Ok((key, format!("{code:06}")))
}

/// Which way a sealed message goes; each has its own associated data.
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    /// From the extension.
    Request,
    /// To the extension.
    Response,
}

fn aad(id: &[u8], direction: Direction) -> Vec<u8> {
    let label = match direction {
        Direction::Request => LABEL_REQUEST,
        Direction::Response => LABEL_RESPONSE,
    };
    [label, id].concat()
}

/// Seals a message: returns the nonce and ciphertext.
///
/// # Errors
///
/// Returns [`Malformed`] if randomness or encryption fails.
pub fn seal(
    key: &[u8; 32],
    id: &[u8],
    direction: Direction,
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), Malformed> {
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|_| Malformed)?;
    Ok((
        nonce,
        seal_with_nonce(key, id, direction, &nonce, plaintext)?,
    ))
}

fn seal_with_nonce(
    key: &[u8; 32],
    id: &[u8],
    direction: Direction,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, Malformed> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Malformed)?;
    cipher
        .encrypt(
            &(*nonce).into(),
            Payload {
                msg: plaintext,
                aad: &aad(id, direction),
            },
        )
        .map_err(|_| Malformed)
}

/// Opens a sealed message.
///
/// # Errors
///
/// Returns [`Malformed`] if it was not sealed with this key, ID and
/// direction.
pub fn open(
    key: &[u8; 32],
    id: &[u8],
    direction: Direction,
    nonce: &[u8],
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Malformed> {
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Malformed)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Malformed)?;
    cipher
        .decrypt(
            &nonce.into(),
            Payload {
                msg: sealed,
                aad: &aad(id, direction),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Malformed)
}

/// Reads one length-prefixed message (a little-endian `u32`, then the
/// bytes), as native messaging frames them. Returns `None` at the end of
/// the stream.
///
/// # Errors
///
/// Returns an error if reading fails or the message is longer than `max`.
pub fn read_frame(reader: &mut impl std::io::Read, max: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0_u8; 4];
    match reader.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = usize::try_from(u32::from_le_bytes(len)).unwrap_or(usize::MAX);
    if len > max {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut body = vec![0_u8; len];
    reader.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Writes one length-prefixed message.
///
/// # Errors
///
/// Returns an error if writing fails or the message is longer than `max`.
pub fn write_frame(
    writer: &mut impl std::io::Write,
    body: &[u8],
    max: usize,
) -> std::io::Result<()> {
    if body.len() > max {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let len = u32::try_from(body.len()).map_err(|_| std::io::ErrorKind::InvalidData)?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(body)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    /// The extension's side of a pairing, as the Web Crypto code does it.
    fn extension_side(
        id: &[u8],
        secret: &p256::SecretKey,
        app_key: &[u8],
    ) -> (Zeroizing<[u8; 32]>, String) {
        let theirs = p256::PublicKey::from_sec1_bytes(app_key).unwrap();
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), theirs.as_affine());
        let mine = encoded(&secret.public_key()).unwrap();
        derive(id, &mine, app_key, shared.raw_secret_bytes()).unwrap()
    }

    #[test]
    fn both_sides_agree_on_key_and_code() {
        let id = [7_u8; 16];
        let ext = p256::SecretKey::from_slice(&[3_u8; 32]).unwrap();
        let ext_pub = encoded(&ext.public_key()).unwrap();
        let p = pair(&id, &ext_pub).unwrap();
        let (key, code) = extension_side(&id, &ext, &p.app_key);
        assert_eq!(*key, *p.key);
        assert_eq!(code, p.code);
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));

        // A second exchange gives a different key.
        let q = pair(&id, &ext_pub).unwrap();
        assert_ne!(*q.key, *p.key);

        assert!(pair(&id[..15], &ext_pub).is_err());
        assert!(pair(&id, &ext_pub[..64]).is_err());
        let mut bad = ext_pub;
        bad[64] ^= 1;
        assert!(pair(&id, &bad).is_err());
    }

    #[test]
    fn sealing_is_bound_to_key_id_and_direction() {
        let key = [9_u8; 32];
        let id = [1_u8; 16];
        let (n, c) = seal(&key, &id, Direction::Request, b"{\"op\":\"status\"}").unwrap();
        assert_eq!(
            open(&key, &id, Direction::Request, &n, &c)
                .unwrap()
                .as_slice(),
            b"{\"op\":\"status\"}"
        );
        assert!(open(&key, &id, Direction::Response, &n, &c).is_err());
        assert!(open(&key, &[2; 16], Direction::Request, &n, &c).is_err());
        assert!(open(&[8; 32], &id, Direction::Request, &n, &c).is_err());
        let mut tampered = c.clone();
        tampered[0] ^= 1;
        assert!(open(&key, &id, Direction::Request, &n, &tampered).is_err());
        assert!(open(&key, &id, Direction::Request, &n[..11], &c).is_err());
    }

    #[test]
    fn messages_parse_strictly() {
        let pair: Incoming =
            serde_json::from_str(r#"{"t":"pair","id":"a","key":"b","browser":"Chrome"}"#).unwrap();
        assert!(matches!(pair, Incoming::Pair { .. }));
        assert!(
            serde_json::from_str::<Incoming>(
                r#"{"t":"pair","id":"a","key":"b","browser":"x","more":1}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<Incoming>(r#"{"t":"nope"}"#).is_err());
        assert_eq!(
            serde_json::from_str::<Request>(r#"{"op":"logins","url":"https://a.example"}"#)
                .unwrap(),
            Request::Logins {
                url: "https://a.example".into()
            }
        );
        assert_eq!(
            serde_json::to_string(&Outgoing::Error { code: "denied" }).unwrap(),
            r#"{"t":"error","code":"denied"}"#
        );
    }

    #[test]
    fn vectors_match() {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../docs/spec/vectors/14-browser.json"
        ))
        .unwrap();
        let hex = |name: &str| -> Vec<u8> {
            let s = v[name].as_str().unwrap();
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let ext = p256::SecretKey::from_slice(&hex("extension_private_hex")).unwrap();
        let app = p256::SecretKey::from_slice(&hex("app_private_hex")).unwrap();
        let ext_pub = encoded(&ext.public_key()).unwrap();
        let app_pub = encoded(&app.public_key()).unwrap();
        assert_eq!(ext_pub.to_vec(), hex("extension_public_hex"));
        assert_eq!(app_pub.to_vec(), hex("app_public_hex"));
        let shared =
            p256::ecdh::diffie_hellman(app.to_nonzero_scalar(), ext.public_key().as_affine());
        assert_eq!(shared.raw_secret_bytes().to_vec(), hex("shared_hex"));
        let id = hex("id_hex");
        let (key, code) = derive(&id, &ext_pub, &app_pub, shared.raw_secret_bytes()).unwrap();
        assert_eq!(key.to_vec(), hex("key_hex"));
        assert_eq!(code, v["code"].as_str().unwrap());

        let nonce: [u8; 12] = hex("request_nonce_hex").try_into().unwrap();
        let plain = v["request_plaintext"].as_str().unwrap().as_bytes();
        let sealed = seal_with_nonce(&key, &id, Direction::Request, &nonce, plain).unwrap();
        assert_eq!(sealed, hex("request_sealed_hex"));
        assert_eq!(
            open(&key, &id, Direction::Request, &nonce, &sealed)
                .unwrap()
                .as_slice(),
            plain
        );
        let rnonce: [u8; 12] = hex("response_nonce_hex").try_into().unwrap();
        let rplain = v["response_plaintext"].as_str().unwrap().as_bytes();
        assert_eq!(
            seal_with_nonce(&key, &id, Direction::Response, &rnonce, rplain).unwrap(),
            hex("response_sealed_hex")
        );
    }

    #[test]
    fn frames() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello", 10).unwrap();
        assert_eq!(&buf[..4], &[5, 0, 0, 0]);
        let mut r = buf.as_slice();
        assert_eq!(read_frame(&mut r, 10).unwrap().unwrap(), b"hello");
        assert_eq!(read_frame(&mut r, 10).unwrap(), None);
        assert!(write_frame(&mut Vec::new(), &[0; 11], 10).is_err());
        let mut long = Vec::new();
        write_frame(&mut long, &[0; 11], 20).unwrap();
        assert!(read_frame(&mut long.as_slice(), 10).is_err());
    }
}
