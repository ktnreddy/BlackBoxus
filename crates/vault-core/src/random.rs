//! Access to the operating system's cryptographically secure random number
//! generator (spec section 1.3).

use crate::error::{Error, Result};

/// Fills `dest` with random bytes from the operating system.
///
/// Fails instead of falling back to a weaker source.
pub(crate) fn fill(dest: &mut [u8]) -> Result<()> {
    getrandom::fill(dest).map_err(|_| Error::RandomUnavailable)
}

/// Returns `N` random bytes from the operating system.
pub(crate) fn bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0_u8; N];
    fill(&mut out)?;
    Ok(out)
}
