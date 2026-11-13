//! Error type for `vault-core`.
//!
//! Error messages never contain secret values.

/// Errors returned by `vault-core`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The operating system's random number generator failed.
    #[error("the system random number generator failed")]
    RandomUnavailable,

    /// A Secret Key string could not be parsed.
    #[error("invalid Secret Key: {0}")]
    InvalidSecretKey(SecretKeyError),

    /// The master password is empty after normalisation.
    #[error("the master password is empty")]
    PasswordEmpty,

    /// The master password is longer than the maximum allowed length.
    #[error("the master password is longer than {max_bytes} bytes")]
    PasswordTooLong {
        /// Maximum allowed length in bytes after normalisation.
        max_bytes: usize,
    },

    /// A new master password is shorter than the minimum length.
    #[error("the master password must have at least {min_chars} characters")]
    PasswordTooShort {
        /// Minimum number of characters.
        min_chars: usize,
    },

    /// Argon2id parameters are outside the allowed range.
    #[error("key derivation parameter `{param}` is out of range")]
    KdfParamOutOfRange {
        /// Name of the offending parameter.
        param: &'static str,
    },

    /// Key derivation failed inside the underlying primitive.
    #[error("key derivation failed")]
    KeyDerivation,

    /// An email address or server origin is not valid.
    #[error("invalid email address or server address")]
    InvalidIdentity,

    /// A protocol message could not be parsed.
    #[error("malformed protocol message")]
    MalformedMessage,

    /// Authentication failed. Deliberately does not say why: the password,
    /// Secret Key, account or server may be wrong.
    #[error("authentication failed")]
    Authentication,

    /// Encryption failed inside the underlying primitive.
    #[error("encryption failed")]
    Encryption,

    /// Decryption failed: wrong key, or the data was modified.
    #[error("decryption failed")]
    Decryption,

    /// A signing context is longer than 255 bytes.
    #[error("signing context too long")]
    InvalidContext,

    /// Signing failed inside the underlying primitive.
    #[error("signing failed")]
    Signing,

    /// A signature did not verify.
    #[error("invalid signature")]
    InvalidSignature,

    /// The server offered an older key set than this device has already seen.
    #[error("key set is older than one already seen")]
    KeySetRollback,

    /// An item is larger than the format allows.
    #[error("item is too large")]
    ItemTooLarge,

    /// An item envelope belongs to a different vault or item than expected.
    #[error("item belongs to a different vault or item")]
    WrongItem,

    /// A public key failed validation.
    #[error("invalid public key")]
    InvalidPublicKey,

    /// A vault share is addressed to a different account or key set.
    #[error("vault share is addressed to someone else")]
    WrongRecipient,

    /// A vault share names a different sender than expected.
    #[error("vault share is from an unexpected sender")]
    WrongSender,
}

/// Why a Secret Key string was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SecretKeyError {
    /// The string does not start with the `B1` format prefix.
    #[error("it does not start with B1")]
    MissingPrefix,
    /// The string has the wrong number of characters.
    #[error("it has the wrong number of characters")]
    WrongLength,
    /// The string contains a character outside the Base32 alphabet.
    #[error("it contains an invalid character")]
    InvalidCharacter,
    /// The encoded value does not fit in 128 bits.
    #[error("it is not a valid key")]
    OutOfRange,
    /// The checksum does not match, which usually means a typing mistake.
    #[error("the checksum does not match; check for typing mistakes")]
    ChecksumMismatch,
}

impl From<SecretKeyError> for Error {
    fn from(e: SecretKeyError) -> Self {
        Self::InvalidSecretKey(e)
    }
}

/// Result type used throughout `vault-core`.
pub type Result<T> = core::result::Result<T, Error>;
