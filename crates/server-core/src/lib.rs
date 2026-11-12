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

mod error;
pub mod login;
pub mod prelogin;

pub use error::{Error, Result};

/// Maximum size in bytes of a single encrypted item accepted by the server.
pub const MAX_ITEM_CIPHERTEXT_BYTES: usize = 64 * 1024;

/// Returns `true` if an encrypted item of `len` bytes is within limits.
#[must_use]
pub const fn item_size_allowed(len: usize) -> bool {
    len > 0 && len <= MAX_ITEM_CIPHERTEXT_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_oversized_items() {
        assert!(!item_size_allowed(0));
        assert!(item_size_allowed(1));
        assert!(item_size_allowed(MAX_ITEM_CIPHERTEXT_BYTES));
        assert!(!item_size_allowed(MAX_ITEM_CIPHERTEXT_BYTES + 1));
    }
}
