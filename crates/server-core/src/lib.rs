//! # server-core
//!
//! Platform-independent server logic for BlackBoxus: login, request
//! validation, vault revision ordering, and storage of encrypted data.
//!
//! The server is treated as untrusted by every client. It never sees
//! plaintext vault data, master passwords or encryption keys, and clients
//! verify everything it returns.
//!
//! Hosting-specific code (Cloudflare Workers, D1, Durable Objects) lives in a
//! thin adapter crate, so the server can move to another platform by
//! rewriting only that adapter.

pub mod api;
mod error;
pub mod log;
pub mod login;
pub mod prelogin;
pub mod recovery;
pub mod transparency;

pub use error::{Error, Result};

/// Maximum size in bytes of a single item envelope (spec section 6.4).
pub const MAX_ITEM_CIPHERTEXT_BYTES: usize = vault_core::MAX_ENVELOPE_LEN;

/// Minimum size in bytes of a single item envelope (spec section 6.4).
pub const MIN_ITEM_CIPHERTEXT_BYTES: usize = vault_core::MIN_ENVELOPE_LEN;

/// Returns `true` if an item envelope of `len` bytes is within limits.
///
/// The server cannot decrypt envelopes; this only rejects sizes no honest
/// client produces.
#[must_use]
pub const fn item_size_allowed(len: usize) -> bool {
    len >= MIN_ITEM_CIPHERTEXT_BYTES && len <= MAX_ITEM_CIPHERTEXT_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_oversized_items() {
        assert!(!item_size_allowed(0));
        assert!(!item_size_allowed(MIN_ITEM_CIPHERTEXT_BYTES - 1));
        assert!(item_size_allowed(MIN_ITEM_CIPHERTEXT_BYTES));
        assert!(item_size_allowed(MAX_ITEM_CIPHERTEXT_BYTES));
        assert!(!item_size_allowed(MAX_ITEM_CIPHERTEXT_BYTES + 1));
    }
}
