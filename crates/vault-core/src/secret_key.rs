//! The Secret Key: 128 random bits that never leave the user's devices
//! (spec section 3.2).

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Result, SecretKeyError};
use crate::random;

/// Length of the Secret Key in bytes.
pub const SECRET_KEY_LEN: usize = 16;

/// Crockford Base32 alphabet.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Format prefix shown in front of every Secret Key.
const PREFIX: &str = "B1";

/// Number of Base32 digits that encode the key (26 × 5 = 130 bits).
const KEY_DIGITS: usize = 26;

/// Number of Base32 digits that encode the 10-bit checksum.
const CHECK_DIGITS: usize = 2;

/// Total Base32 digits in a displayed Secret Key.
const TOTAL_DIGITS: usize = 28;

/// Digits per displayed group.
const GROUP_LEN: usize = 7;

/// Length of the display string: prefix, 28 digits and 4 hyphens.
const DISPLAY_LEN: usize = 34;

const CHECKSUM_LABEL: &[u8] = b"BlackBoxus v1 secret-key checksum";

/// A user's Secret Key.
///
/// The bytes are erased on drop and never printed by `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; SECRET_KEY_LEN]);

impl SecretKey {
    /// Generates a new Secret Key from the operating system's random number
    /// generator.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::RandomUnavailable`] if the generator fails.
    pub fn generate() -> Result<Self> {
        random::bytes().map(Self)
    }

    /// Wraps raw Secret Key bytes, for example when loading from secure
    /// storage.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.0
    }

    /// Formats the key for display, as `B1-XXXXXXX-XXXXXXX-XXXXXXX-XXXXXXX`.
    ///
    /// The returned string is erased when dropped.
    #[must_use]
    pub fn to_display_string(&self) -> Zeroizing<String> {
        let digits = self.digits();
        let mut out = Zeroizing::new(String::with_capacity(DISPLAY_LEN));
        out.push_str(PREFIX);
        for group in digits.chunks(GROUP_LEN) {
            out.push('-');
            for &d in group {
                out.push(char::from(alphabet_char(d)));
            }
        }
        out
    }

    /// Parses a Secret Key typed or pasted by a user.
    ///
    /// Spaces, tabs and hyphens are ignored, case does not matter, and the
    /// commonly confused letters `O`, `I` and `L` are accepted as `0`, `1`
    /// and `1`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidSecretKey`] describing what is wrong.
    pub fn parse(input: &str) -> Result<Self> {
        let mut cleaned: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(input.len()));
        cleaned.extend(
            input
                .bytes()
                .filter(|b| !matches!(b, b' ' | b'\t' | b'-'))
                .map(|b| b.to_ascii_uppercase()),
        );

        let body = cleaned
            .strip_prefix(PREFIX.as_bytes())
            .ok_or(SecretKeyError::MissingPrefix)?;
        if body.len() != TOTAL_DIGITS {
            return Err(SecretKeyError::WrongLength.into());
        }

        let mut digits = Zeroizing::new([0_u8; TOTAL_DIGITS]);
        for (slot, &c) in digits.iter_mut().zip(body) {
            *slot = decode_char(c).ok_or(SecretKeyError::InvalidCharacter)?;
        }

        let (key_digits, check_digits) = digits.split_at(KEY_DIGITS);

        let mut value: u128 = 0;
        for &d in key_digits {
            value = value
                .checked_mul(32)
                .and_then(|v| v.checked_add(u128::from(d)))
                .ok_or(SecretKeyError::OutOfRange)?;
        }
        let key = Self(value.to_be_bytes());
        value.zeroize();

        let expected = key.checksum_digits();
        if !bool::from(expected.ct_eq(check_digits)) {
            return Err(SecretKeyError::ChecksumMismatch.into());
        }
        Ok(key)
    }

    /// Returns the 28 Base32 digit values (key followed by checksum).
    fn digits(&self) -> Zeroizing<[u8; TOTAL_DIGITS]> {
        let mut value = u128::from_be_bytes(self.0);
        let mut out = Zeroizing::new([0_u8; TOTAL_DIGITS]);
        // Shifts 125, 120, ..., 0: most significant digit first.
        for (slot, shift) in out.iter_mut().zip((0..130_u32).step_by(5).rev()) {
            *slot = low_five_bits(value.checked_shr(shift).unwrap_or(0));
        }
        value.zeroize();
        let check = self.checksum_digits();
        for (slot, &d) in out.iter_mut().skip(KEY_DIGITS).zip(check.iter()) {
            *slot = d;
        }
        out
    }

    /// First 10 bits of SHA-256(label ‖ key), as two Base32 digits.
    fn checksum_digits(&self) -> [u8; CHECK_DIGITS] {
        let hash = Sha256::new()
            .chain_update(CHECKSUM_LABEL)
            .chain_update(self.0)
            .finalize();
        let first = hash.first().copied().unwrap_or(0);
        let second = hash.get(1).copied().unwrap_or(0);
        // 10 bits: all 8 bits of `first`, then the top 2 bits of `second`.
        let ten_bits = (u16::from(first) << 2) | (u16::from(second) >> 6);
        [
            low_five_bits(u128::from(ten_bits >> 5)),
            low_five_bits(u128::from(ten_bits)),
        ]
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SecretKey {}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

fn low_five_bits(v: u128) -> u8 {
    // The mask keeps the value below 32, so it always fits in a u8.
    u8::try_from(v & 0x1F).unwrap_or(0)
}

fn alphabet_char(digit: u8) -> u8 {
    ALPHABET.get(usize::from(digit)).copied().unwrap_or(b'0')
}

fn decode_char(c: u8) -> Option<u8> {
    let c = match c {
        b'O' => b'0',
        b'I' | b'L' => b'1',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|&a| a == c)
        .and_then(|i| u8::try_from(i).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    fn sample() -> SecretKey {
        SecretKey::from_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ])
    }

    #[test]
    fn display_format_has_expected_shape() {
        let s = sample().to_display_string();
        assert_eq!(s.len(), 2 + 4 * 8);
        assert!(s.starts_with("B1-"));
        let groups: Vec<&str> = s.split('-').collect();
        assert_eq!(groups.len(), 5);
        assert!(groups.iter().skip(1).all(|g| g.len() == GROUP_LEN));
    }

    #[test]
    fn round_trips_through_display_and_parse() {
        for _ in 0..200 {
            let key = SecretKey::generate().unwrap();
            let parsed = SecretKey::parse(&key.to_display_string()).unwrap();
            assert_eq!(key, parsed);
        }
    }

    #[test]
    fn extreme_values_round_trip() {
        for bytes in [[0_u8; 16], [0xFF_u8; 16]] {
            let key = SecretKey::from_bytes(bytes);
            let parsed = SecretKey::parse(&key.to_display_string()).unwrap();
            assert_eq!(key, parsed);
        }
    }

    #[test]
    fn parse_is_forgiving_about_formatting() {
        let key = sample();
        let shown = key.to_display_string();
        let messy = shown.to_lowercase().replace('-', " ");
        assert_eq!(SecretKey::parse(&messy).unwrap(), key);
        let no_separators: String = shown.chars().filter(|&c| c != '-').collect();
        assert_eq!(SecretKey::parse(&no_separators).unwrap(), key);
    }

    #[test]
    fn parse_accepts_confusable_letters() {
        let key = SecretKey::from_bytes([0_u8; 16]);
        let shown = key.to_display_string();
        // The all-zero key starts with many zeros after the prefix.
        let with_letter_o = shown.replacen("B1-0", "B1-O", 1);
        assert_eq!(SecretKey::parse(&with_letter_o).unwrap(), key);
    }

    #[test]
    fn rejects_typing_mistakes() {
        let shown = sample().to_display_string();
        let mut chars: Vec<char> = shown.chars().collect();
        // Change one digit in the second group.
        let pos = 5;
        chars[pos] = if chars[pos] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert_eq!(
            SecretKey::parse(&typo),
            Err(Error::InvalidSecretKey(SecretKeyError::ChecksumMismatch))
        );
    }

    #[test]
    fn rejects_malformed_input() {
        let cases = [
            ("", SecretKeyError::MissingPrefix),
            (
                "A1-0000000-0000000-0000000-0000000",
                SecretKeyError::MissingPrefix,
            ),
            ("B1-000000", SecretKeyError::WrongLength),
            (
                "B1-0000000-0000000-0000000-00000000",
                SecretKeyError::WrongLength,
            ),
            (
                "B1-0000000-0000000-0000000-000000U",
                SecretKeyError::InvalidCharacter,
            ),
            (
                "B1-8000000-0000000-0000000-0000000",
                SecretKeyError::OutOfRange,
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                SecretKey::parse(input),
                Err(Error::InvalidSecretKey(expected)),
                "input: {input:?}"
            );
        }
    }

    #[test]
    fn debug_is_redacted() {
        assert_eq!(format!("{:?}", sample()), "SecretKey(<redacted>)");
    }
}
