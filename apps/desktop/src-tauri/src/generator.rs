//! Generates passwords and passphrases with the operating system's random
//! number generator, without bias.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::AppError;

// Letters and digits that look alike (l, I, O, 0, 1) are left out, so
// passwords are easy to read and type.
const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &str = "23456789";
const SYMBOLS: &str = "!#$%&*+-=?@^_~";
const MIN_LENGTH: usize = 8;
const MAX_LENGTH: usize = 64;
const MIN_WORDS: usize = 3;
const MAX_WORDS: usize = 10;

/// The EFF Large Wordlist for passphrases, 7,776 words, by the Electronic
/// Frontier Foundation (CC BY 3.0 US):
/// <https://www.eff.org/dice>.
const WORDLIST: &str = include_str!("../eff_large_wordlist.txt");

/// What to generate.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Options {
    /// Random characters.
    Random {
        /// Number of characters.
        length: usize,
        /// Include digits.
        digits: bool,
        /// Include symbols.
        symbols: bool,
    },
    /// Random words from the EFF list.
    Passphrase {
        /// Number of words.
        words: usize,
        /// Separator between words.
        separator: String,
        /// Capitalise one word.
        capitalise: bool,
        /// Add a digit to one word.
        number: bool,
    },
}

/// A generated password and its strength.
#[derive(Debug, Serialize)]
pub struct Generated {
    /// The password.
    pub password: Zeroizing<String>,
    /// Entropy in bits, rounded down.
    pub bits: u32,
    /// One or two words for the meter.
    pub label: &'static str,
}

/// A uniformly random index below `n`.
fn below(n: usize) -> Result<usize, AppError> {
    let n = u32::try_from(n).map_err(|_| AppError::Internal)?;
    let limit = u32::MAX
        .checked_rem(n)
        .and_then(|r| u32::MAX.checked_sub(r))
        .ok_or(AppError::Internal)?;
    loop {
        let v = getrandom::u32().map_err(|_| AppError::Internal)?;
        if v < limit {
            let index = v.checked_rem(n).ok_or(AppError::Internal)?;
            return usize::try_from(index).map_err(|_| AppError::Internal);
        }
    }
}

fn pick<T: Copy>(set: &[T]) -> Result<T, AppError> {
    set.get(below(set.len())?)
        .copied()
        .ok_or(AppError::Internal)
}

fn bits(choices: usize, count: usize) -> u32 {
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "small, positive values; the result is shown rounded down"
    )]
    let b = (count as f64 * (choices as f64).log2()).floor() as u32;
    b
}

fn label(bits: u32) -> &'static str {
    match bits {
        0..=39 => "Weak",
        40..=59 => "Fair",
        60..=79 => "Strong",
        _ => "Very strong",
    }
}

fn random(length: usize, digits: bool, symbols: bool) -> Result<Generated, AppError> {
    let length = length.clamp(MIN_LENGTH, MAX_LENGTH);
    let mut sets: Vec<Vec<char>> = vec![LOWER.chars().collect(), UPPER.chars().collect()];
    if digits {
        sets.push(DIGITS.chars().collect());
    }
    if symbols {
        sets.push(SYMBOLS.chars().collect());
    }
    let all: Vec<char> = sets.iter().flatten().copied().collect();
    // Draw until every set is represented: rejection keeps the result
    // uniform over all passwords that meet the rule.
    loop {
        let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(length));
        for _ in 0..length {
            chars.push(pick(&all)?);
        }
        if sets.iter().all(|s| chars.iter().any(|c| s.contains(c))) {
            let b = bits(all.len(), length);
            return Ok(Generated {
                password: Zeroizing::new(chars.iter().collect()),
                bits: b,
                label: label(b),
            });
        }
    }
}

fn passphrase(
    words: usize,
    separator: &str,
    capitalise: bool,
    number: bool,
) -> Result<Generated, AppError> {
    let count = words.clamp(MIN_WORDS, MAX_WORDS);
    let list: Vec<&str> = WORDLIST.lines().filter(|w| !w.is_empty()).collect();
    let separator: String = separator.chars().take(3).collect();
    let mut chosen: Vec<Zeroizing<String>> = Vec::with_capacity(count);
    for _ in 0..count {
        chosen.push(Zeroizing::new(pick(&list)?.to_owned()));
    }
    let mut b = bits(list.len(), count);
    if capitalise {
        let i = below(count)?;
        if let Some(word) = chosen.get_mut(i) {
            let mut chars = word.chars();
            let first = chars.next().map(|c| c.to_uppercase().collect::<String>());
            **word = format!("{}{}", first.unwrap_or_default(), chars.as_str());
        }
        b = b.saturating_add(bits(count, 1));
    }
    if number {
        let i = below(count)?;
        let digit = below(10)?;
        if let Some(word) = chosen.get_mut(i) {
            word.push_str(&digit.to_string());
        }
        b = b.saturating_add(bits(count.saturating_mul(10), 1));
    }
    let joined: Vec<&str> = chosen.iter().map(|w| w.as_str()).collect();
    Ok(Generated {
        password: Zeroizing::new(joined.join(&separator)),
        bits: b,
        label: label(b),
    })
}

/// Generates a password or passphrase.
///
/// # Errors
///
/// Returns [`AppError::Internal`] if the random number generator fails.
pub fn generate(options: &Options) -> Result<Generated, AppError> {
    match options {
        Options::Random {
            length,
            digits,
            symbols,
        } => random(*length, *digits, *symbols),
        Options::Passphrase {
            words,
            separator,
            capitalise,
            number,
        } => passphrase(*words, separator, *capitalise, *number),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wordlist_is_complete() {
        let list: Vec<&str> = WORDLIST.lines().collect();
        assert_eq!(list.len(), 7776);
        assert_eq!(list.first(), Some(&"abacus"));
        assert_eq!(list.last(), Some(&"zoom"));
    }

    #[test]
    fn random_meets_the_options() -> Result<(), AppError> {
        for _ in 0..50 {
            let g = random(20, true, true)?;
            assert_eq!(g.password.chars().count(), 20);
            assert!(g.password.chars().any(|c| DIGITS.contains(c)));
            assert!(g.password.chars().any(|c| SYMBOLS.contains(c)));
            assert!(g.password.chars().any(|c| UPPER.contains(c)));
        }
        let plain = random(3, false, false)?;
        assert_eq!(plain.password.chars().count(), MIN_LENGTH);
        assert!(plain.password.chars().all(char::is_alphabetic));
        Ok(())
    }

    #[test]
    fn passphrases() -> Result<(), AppError> {
        let g = passphrase(5, "-", true, true)?;
        assert!(g.password.chars().any(|c| c.is_ascii_digit()));
        assert!(g.password.chars().any(char::is_uppercase));
        // 5 words of about 12.9 bits each, plus the capital and the digit.
        assert_eq!(bits(7776, 5), 64);
        assert!(g.bits >= 70);
        assert_eq!(g.label, "Strong");
        let plain = passphrase(4, " ", false, false)?;
        assert!(plain.password.split(' ').count() >= 4);
        Ok(())
    }
}
