//! Master password normalisation and policy (spec section 3.3).

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

/// Maximum length of a normalised master password, in bytes.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Minimum number of characters for a new master password.
pub const MIN_NEW_PASSWORD_CHARS: usize = 12;

/// A normalised master password. Its bytes are erased on drop.
pub struct MasterPassword {
    bytes: Zeroizing<Vec<u8>>,
    chars: usize,
}

impl MasterPassword {
    /// Normalises a password to Unicode NFKC and encodes it as UTF-8.
    ///
    /// Leading and trailing spaces are kept: they are part of the password.
    ///
    /// # Errors
    ///
    /// Returns [`Error::PasswordEmpty`] or [`Error::PasswordTooLong`].
    pub fn new(input: &str) -> Result<Self> {
        let normalized: Zeroizing<String> = Zeroizing::new(input.nfkc().collect());
        let chars = normalized.chars().count();
        let bytes = Zeroizing::new(normalized.as_bytes().to_vec());

        if bytes.is_empty() {
            return Err(Error::PasswordEmpty);
        }
        if bytes.len() > MAX_PASSWORD_BYTES {
            return Err(Error::PasswordTooLong {
                max_bytes: MAX_PASSWORD_BYTES,
            });
        }
        Ok(Self { bytes, chars })
    }

    /// Normalises a password and also applies the policy for newly chosen
    /// passwords: at least [`MIN_NEW_PASSWORD_CHARS`] characters.
    ///
    /// Use this only when a password is created or changed. Unlocking with an
    /// existing password uses [`MasterPassword::new`].
    ///
    /// # Errors
    ///
    /// As [`MasterPassword::new`], plus [`Error::PasswordTooShort`].
    pub fn new_for_account_creation(input: &str) -> Result<Self> {
        let password = Self::new(input)?;
        if password.chars < MIN_NEW_PASSWORD_CHARS {
            return Err(Error::PasswordTooShort {
                min_chars: MIN_NEW_PASSWORD_CHARS,
            });
        }
        Ok(password)
    }

    /// The normalised UTF-8 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The number of Unicode scalar values after normalisation.
    #[must_use]
    pub const fn char_count(&self) -> usize {
        self.chars
    }
}

impl core::fmt::Debug for MasterPassword {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MasterPassword(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_to_nfkc() {
        // "é" as 'e' + combining acute accent, and as one precomposed character.
        let decomposed = MasterPassword::new("caf\u{0065}\u{0301}").unwrap();
        let composed = MasterPassword::new("caf\u{00E9}").unwrap();
        assert_eq!(decomposed.as_bytes(), composed.as_bytes());

        // Full-width letters become ASCII under NFKC.
        let full_width = MasterPassword::new("\u{FF21}\u{FF22}").unwrap();
        assert_eq!(full_width.as_bytes(), b"AB");
    }

    #[test]
    fn keeps_surrounding_spaces() {
        let p = MasterPassword::new("  secret  ").unwrap();
        assert_eq!(p.as_bytes(), b"  secret  ");
    }

    #[test]
    fn rejects_empty_and_overlong() {
        assert!(matches!(MasterPassword::new(""), Err(Error::PasswordEmpty)));
        let long = "a".repeat(MAX_PASSWORD_BYTES + 1);
        assert!(matches!(
            MasterPassword::new(&long),
            Err(Error::PasswordTooLong { .. })
        ));
        assert!(MasterPassword::new(&"a".repeat(MAX_PASSWORD_BYTES)).is_ok());
    }

    #[test]
    fn new_password_policy_counts_characters_not_bytes() {
        assert!(matches!(
            MasterPassword::new_for_account_creation("elevenchars"),
            Err(Error::PasswordTooShort { .. })
        ));
        assert!(MasterPassword::new_for_account_creation("twelve chars").is_ok());
        // Eleven multi-byte characters are still too short.
        assert!(MasterPassword::new_for_account_creation(&"é".repeat(11)).is_err());
        assert!(MasterPassword::new_for_account_creation(&"é".repeat(12)).is_ok());
    }

    #[test]
    fn existing_short_password_can_still_unlock() {
        assert!(MasterPassword::new("short").is_ok());
    }

    #[test]
    fn debug_is_redacted() {
        let p = MasterPassword::new("hunter2hunter2").unwrap();
        assert_eq!(format!("{p:?}"), "MasterPassword(<redacted>)");
    }
}
