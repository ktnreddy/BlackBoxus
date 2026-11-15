//! One-time codes for two-factor sign-in (TOTP, RFC 6238).
//!
//! The secret is stored in an item's one-time code field, either as an
//! `otpauth://totp/...` link (what sites show as a QR code) or as the
//! Base32 text sites offer for typing in. Codes are computed here in Rust
//! and only the current code reaches the window.

use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::AppError;

/// SHA-1 is what nearly every site uses for TOTP; it is safe in HMAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// A parsed TOTP secret.
#[derive(Clone)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
}

impl core::fmt::Debug for Totp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Totp")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .finish_non_exhaustive()
    }
}

/// The current code, for the window.
#[derive(Debug, Serialize)]
pub struct Code {
    /// The code, as digits.
    pub code: Zeroizing<String>,
    /// Seconds each code lasts.
    pub period: u64,
    /// Seconds until the next code.
    pub remaining: u64,
}

/// Decodes RFC 4648 Base32, ignoring case, spaces, dashes and padding.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "bit counts stay below 13 and values below 2^13"
)]
fn base32(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for c in text.chars().filter(|c| !matches!(c, ' ' | '-' | '=')) {
        let value = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => u32::from(c) - u32::from('A'),
            c @ '2'..='7' => u32::from(c) - u32::from('2') + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
        buffer &= (1 << bits) - 1;
    }
    (!out.is_empty()).then_some(out)
}

/// Decodes `%XX` escapes in a query value.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "the index only moves forward within the string"
)]
fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hex = value.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(if b == b'+' { b' ' } else { b });
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

impl Totp {
    /// Reads a secret from an `otpauth://totp/` link or plain Base32.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::InvalidTotp`] if it is neither, or uses settings
    /// outside what authenticator apps support.
    pub fn parse(text: &str) -> Result<Self, AppError> {
        let text = text.trim();
        let lower = text.to_ascii_lowercase();
        if !lower.starts_with("otpauth://") {
            return Ok(Self {
                secret: base32(text).ok_or(AppError::InvalidTotp)?,
                algorithm: Algorithm::Sha1,
                digits: 6,
                period: 30,
            });
        }
        if !lower.starts_with("otpauth://totp/") {
            // Counter-based codes (HOTP) need state that changes on every
            // use, which a synced item cannot hold safely.
            return Err(AppError::InvalidTotp);
        }
        let query = text.split_once('?').map_or("", |(_, q)| q);
        let mut totp = Self {
            secret: Zeroizing::new(Vec::new()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
        };
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = Zeroizing::new(percent_decode(value).ok_or(AppError::InvalidTotp)?);
            match key.to_ascii_lowercase().as_str() {
                "secret" => totp.secret = base32(&value).ok_or(AppError::InvalidTotp)?,
                "algorithm" => {
                    totp.algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(AppError::InvalidTotp),
                    }
                }
                "digits" => {
                    totp.digits = value.parse().map_err(|_| AppError::InvalidTotp)?;
                }
                "period" => {
                    totp.period = value.parse().map_err(|_| AppError::InvalidTotp)?;
                }
                _ => {}
            }
        }
        if totp.secret.is_empty()
            || !(6..=8).contains(&totp.digits)
            || !(10..=300).contains(&totp.period)
        {
            return Err(AppError::InvalidTotp);
        }
        Ok(totp)
    }

    fn hmac(&self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>, AppError> {
        fn run<M: Mac + KeyInit>(key: &[u8], message: &[u8]) -> Result<Vec<u8>, AppError> {
            let mut mac = <M as KeyInit>::new_from_slice(key).map_err(|_| AppError::InvalidTotp)?;
            mac.update(message);
            Ok(mac.finalize().into_bytes().to_vec())
        }
        Ok(Zeroizing::new(match self.algorithm {
            Algorithm::Sha1 => run::<Hmac<sha1::Sha1>>(&self.secret, message)?,
            Algorithm::Sha256 => run::<Hmac<sha2::Sha256>>(&self.secret, message)?,
            Algorithm::Sha512 => run::<Hmac<sha2::Sha512>>(&self.secret, message)?,
        }))
    }

    /// The code at `unix_seconds`.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "the period is 10 to 300, the offset at most 15 and digits 6 to 8"
    )]
    ///
    /// # Errors
    ///
    /// Returns [`AppError::InvalidTotp`] if the HMAC cannot be computed.
    pub fn code_at(&self, unix_seconds: u64) -> Result<Code, AppError> {
        let counter = unix_seconds / self.period;
        let mac = self.hmac(&counter.to_be_bytes())?;
        // Dynamic truncation (RFC 4226 section 5.3).
        let offset = usize::from(mac.last().ok_or(AppError::InvalidTotp)? & 0x0f);
        let bytes: [u8; 4] = mac
            .get(offset..offset + 4)
            .and_then(|b| b.try_into().ok())
            .ok_or(AppError::InvalidTotp)?;
        let value = u32::from_be_bytes(bytes) & 0x7fff_ffff;
        let modulus = 10_u32.pow(self.digits);
        let width = usize::try_from(self.digits).map_err(|_| AppError::InvalidTotp)?;
        Ok(Code {
            code: Zeroizing::new(format!("{:0width$}", value % modulus)),
            period: self.period,
            remaining: self.period - unix_seconds % self.period,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        reason = "test code"
    )]

    use super::*;

    /// RFC 6238 appendix B, with its 20-, 32- and 64-byte ASCII secrets.
    #[test]
    fn rfc_6238_vectors() -> Result<(), AppError> {
        let sha1 = base32("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").ok_or(AppError::Internal)?;
        assert_eq!(sha1.as_slice(), b"12345678901234567890");
        let link = |algorithm: &str, secret: &[u8]| {
            let mut b32 = String::new();
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let mut buffer: u32 = 0;
            let mut bits = 0;
            for &byte in secret {
                buffer = (buffer << 8) | u32::from(byte);
                bits += 8;
                while bits >= 5 {
                    bits -= 5;
                    b32.push(char::from(alphabet[((buffer >> bits) & 31) as usize]));
                }
                buffer &= (1 << bits) - 1;
            }
            if bits > 0 {
                b32.push(char::from(alphabet[((buffer << (5 - bits)) & 31) as usize]));
            }
            format!("otpauth://totp/x?secret={b32}&algorithm={algorithm}&digits=8")
        };
        let cases: [(u64, &str, &str, &str); 3] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        let one = Totp::parse(&link("SHA1", b"12345678901234567890"))?;
        let two = Totp::parse(&link("SHA256", b"12345678901234567890123456789012"))?;
        let five = Totp::parse(&link(
            "SHA512",
            b"1234567890123456789012345678901234567890123456789012345678901234",
        ))?;
        for (t, a, b, c) in cases {
            assert_eq!(one.code_at(t)?.code.as_str(), a);
            assert_eq!(two.code_at(t)?.code.as_str(), b);
            assert_eq!(five.code_at(t)?.code.as_str(), c);
        }
        Ok(())
    }

    #[test]
    fn plain_secrets_and_links() -> Result<(), AppError> {
        let plain = Totp::parse("jbsw y3dp ehpk 3pxp")?;
        let code = plain.code_at(59)?;
        assert_eq!(code.code.len(), 6);
        assert_eq!((code.period, code.remaining), (30, 1));
        let link = Totp::parse(
            "otpauth://totp/Mail%3Aalex%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Mail&period=60",
        )?;
        assert_eq!(link.period, 60);
        assert_eq!(
            link.code_at(59)?.code.as_str(),
            plain.code_at(1)?.code.as_str()
        );
        Ok(())
    }

    #[test]
    fn rejects_bad_secrets() {
        for bad in [
            "",
            "not base32!",
            "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=12",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
            "otpauth://totp/x?issuer=nothing",
        ] {
            assert!(Totp::parse(bad).is_err(), "{bad}");
        }
    }
}
