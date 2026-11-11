//! Symmetric key type.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of every symmetric key in bytes (spec section 2.1).
pub const KEY_LEN: usize = 32;

/// A 256-bit symmetric key.
///
/// The bytes are erased when the key is dropped, are never printed by
/// `Debug`, and are compared in constant time.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; KEY_LEN]);

impl SymmetricKey {
    /// Wraps raw key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the raw key bytes.
    ///
    /// Callers must not copy these bytes into memory that is not erased.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// A zeroed key whose bytes are filled in place by a derivation, so the
    /// key material is never copied through temporary memory.
    pub(crate) const fn zeroed() -> Self {
        Self([0; KEY_LEN])
    }

    /// Mutable access to the key bytes, for in-place derivation.
    pub(crate) const fn as_mut_bytes(&mut self) -> &mut [u8; KEY_LEN] {
        &mut self.0
    }
}

impl PartialEq for SymmetricKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SymmetricKey {}

impl core::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SymmetricKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_reveal_key() {
        let key = SymmetricKey::from_bytes([0xAB; KEY_LEN]);
        let shown = format!("{key:?}");
        assert!(!shown.to_lowercase().contains("ab"));
        assert!(shown.contains("redacted"));
    }

    #[test]
    fn equality_compares_contents() {
        let a = SymmetricKey::from_bytes([1; KEY_LEN]);
        let b = SymmetricKey::from_bytes([1; KEY_LEN]);
        let c = SymmetricKey::from_bytes([2; KEY_LEN]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
