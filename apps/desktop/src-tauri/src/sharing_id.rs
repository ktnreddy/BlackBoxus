//! Sharing IDs: an account ID written for people to read out or paste.
//!
//! Vaults are shared by sharing ID rather than email address, so the
//! server never has to answer "does this address have an account?". The
//! ID is checked through key transparency and a safety number before
//! anything is shared.

use vault_core::AccountId;

use crate::error::AppError;

/// Crockford's Base32: no I, L, O or U, so it reads back reliably.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 128 bits in 5-bit characters.
const CHARS: usize = 26;

/// Formats an account ID as `XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX`.
pub fn encode(account: &AccountId) -> String {
    let mut value = u128::from_be_bytes(*account.as_bytes());
    let mut digits = [b'0'; CHARS];
    for slot in digits.iter_mut().rev() {
        let low = usize::try_from(value & 31).unwrap_or(0);
        *slot = ALPHABET.get(low).copied().unwrap_or(b'0');
        value >>= 5;
    }
    let mut out = String::with_capacity(CHARS.saturating_add(4));
    for (i, d) in digits.iter().enumerate() {
        if i >= 6 && (i.saturating_sub(6)).is_multiple_of(5) {
            out.push('-');
        }
        out.push(char::from(*d));
    }
    out
}

/// Reads a sharing ID. Case, spaces and dashes do not matter, and the
/// letters O, I and L are read as 0, 1 and 1.
///
/// # Errors
///
/// Returns [`AppError::InvalidSharingId`] if it is not a sharing ID.
pub fn decode(text: &str) -> Result<AccountId, AppError> {
    let mut value: u128 = 0;
    let mut count = 0_usize;
    for c in text.chars().filter(|c| !matches!(c, ' ' | '-' | '\t')) {
        let c = match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        let digit = ALPHABET
            .iter()
            .position(|&a| char::from(a) == c)
            .ok_or(AppError::InvalidSharingId)?;
        // The first character holds only the top 3 bits.
        if count == 0 && digit > 7 {
            return Err(AppError::InvalidSharingId);
        }
        value = value.checked_shl(5).ok_or(AppError::InvalidSharingId)?
            | u128::try_from(digit).map_err(|_| AppError::InvalidSharingId)?;
        count = count.saturating_add(1);
    }
    if count != CHARS {
        return Err(AppError::InvalidSharingId);
    }
    Ok(AccountId::from_bytes(value.to_be_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() -> Result<(), AppError> {
        for bytes in [[0_u8; 16], [255; 16], [7; 16], *b"0123456789abcdef"] {
            let id = AccountId::from_bytes(bytes);
            let text = encode(&id);
            assert_eq!(text.len(), 30);
            assert_eq!(decode(&text)?, id);
            assert_eq!(decode(&text.to_lowercase().replace('-', " "))?, id);
        }
        Ok(())
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(decode("hello"), Err(AppError::InvalidSharingId));
        assert_eq!(decode(&"Z".repeat(26)), Err(AppError::InvalidSharingId));
        assert_eq!(decode(&"0".repeat(27)), Err(AppError::InvalidSharingId));
    }
}
