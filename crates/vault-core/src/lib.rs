//! # vault-core
//!
//! The cryptographic core of BlackBoxus. Every client (desktop, browser
//! extension, Android, iOS) links this one library, so all cryptography has a
//! single, reviewable implementation.
//!
//! ## Design rules
//!
//! - The server is untrusted. Everything it returns is authenticated here
//!   before use.
//! - Cipher suites are fixed by [`PROTOCOL_VERSION`]. There is no runtime
//!   negotiation and no legacy fallback, so nothing can be downgraded.
//! - Secret material is zeroized on drop and never logged.
//! - No `unsafe` code, and no panics on untrusted input.
//!
//! The protocol is specified in `docs/spec/` in the repository.
//!
//! ## Example: deriving account keys
//!
//! ```
//! use vault_core::{AccountSalt, KdfParams, MasterPassword, SecretKey, derive_account_keys};
//!
//! # fn main() -> vault_core::Result<()> {
//! let password = MasterPassword::new_for_account_creation("correct horse battery staple")?;
//! let secret_key = SecretKey::generate()?;
//! let salt = AccountSalt::generate()?;
//!
//! let keys = derive_account_keys(&password, &secret_key, &salt, &KdfParams::MIN)?;
//! # let _ = keys;
//! # Ok(())
//! # }
//! ```

mod aead;
pub mod device;
mod error;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
mod identity;
mod item;
mod kdf;
mod key;
mod keyset;
pub mod local;
pub mod log;
pub mod login;
mod password;
mod random;
pub mod recovery;
mod secret_key;
mod signature;
pub mod transparency;
mod vault;
mod xwing;

pub use error::{Error, Result, SecretKeyError};
pub use identity::{ClientIdentity, MAX_EMAIL_BYTES, MAX_ORIGIN_BYTES, ServerIdentity};
pub use item::{
    Field, FieldKind, ID_LEN, Item, ItemId, ItemType, MAX_ENVELOPE_LEN, MAX_FIELDS,
    MAX_LABEL_BYTES, MAX_VALUE_BYTES, MIN_ENVELOPE_LEN, OpenedItem, PADDING_BUCKETS, VaultId,
    open_item, seal_item, seal_item_deterministic,
};
pub use kdf::{AccountKeys, AccountSalt, KdfParams, SALT_LEN, derive_account_keys};
pub use key::{KEY_LEN, SymmetricKey};
pub use keyset::{
    ACCOUNT_ID_LEN, AccountId, KeySet, PUBLIC_BUNDLE_LEN, PublicKeyBundle,
    SIGNED_PUBLIC_BUNDLE_LEN, UnlockMethod, WRAPPED_KEY_SET_LEN,
};
pub use password::{MAX_PASSWORD_BYTES, MIN_NEW_PASSWORD_CHARS, MasterPassword};
pub use secret_key::{SECRET_KEY_LEN, SecretKey};
pub use signature::{
    HYBRID_SIGNATURE_LEN, HybridSignature, IDENTITY_PUBLIC_LEN, IdentityPublicKey,
    IdentitySecretKey, MAX_CONTEXT_LEN,
};
pub use vault::{OWNER_WRAPPED_VAULT_KEY_LEN, ShareInfo, VAULT_SHARE_LEN, VaultKey};
pub use xwing::{XWING_CIPHERTEXT_LEN, XWING_PUBLIC_LEN, XWingPublicKey};

/// The wire and storage protocol version implemented by this library.
///
/// Each version fixes one set of algorithms. Data tagged with any other
/// version is rejected rather than interpreted.
pub const PROTOCOL_VERSION: u16 = 1;

/// Returns `true` if `version` is a protocol version this library accepts.
#[must_use]
pub const fn is_supported_version(version: u16) -> bool {
    version == PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_current_version() {
        assert!(is_supported_version(PROTOCOL_VERSION));
        assert!(!is_supported_version(0));
        assert!(!is_supported_version(PROTOCOL_VERSION + 1));
    }
}
