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
