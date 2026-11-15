//! Rates a new master password with zxcvbn, which estimates how many
//! guesses an attacker would need.

use serde::Serialize;
use vault_core::MIN_NEW_PASSWORD_CHARS;

/// Lowest zxcvbn score accepted for a new master password (0 to 4).
pub const MIN_SCORE: u8 = 3;

/// zxcvbn's run time grows quickly with length; anything longer than this
/// is rated on its first part, which only underestimates it.
const MAX_RATED_CHARS: usize = 128;

/// How strong a password is, for the meter on the sign-up screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rating {
    /// 0 (very weak) to 4 (very strong).
    pub score: u8,
    /// One or two words for the meter.
    pub label: &'static str,
    /// Whether it is good enough for a new account.
    pub acceptable: bool,
    /// The characters typed, counted the way the length rule counts them.
    pub chars: usize,
    /// The minimum number of characters.
    pub min_chars: usize,
    /// Advice, if any.
    pub hint: Option<String>,
}

/// Rates `password`. `context` holds words an attacker would try first,
/// such as the email address.
pub fn rate(password: &str, context: &[&str]) -> Rating {
    let chars = password.chars().count();
    let rated: String = password.chars().take(MAX_RATED_CHARS).collect();
    let entropy = zxcvbn::zxcvbn(&rated, context);
    let score = u8::from(entropy.score());
    let hint = entropy.feedback().and_then(|f| {
        f.warning()
            .map(|w| w.to_string())
            .or_else(|| f.suggestions().first().map(ToString::to_string))
    });
    let label = match (chars, score) {
        (0, _) => "",
        (_, 0 | 1) => "Weak",
        (_, 2) => "Fair",
        (_, 3) => "Strong",
        _ => "Very strong",
    };
    Rating {
        score,
        label,
        acceptable: chars >= MIN_NEW_PASSWORD_CHARS && score >= MIN_SCORE,
        chars,
        min_chars: MIN_NEW_PASSWORD_CHARS,
        hint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_and_strong() {
        let weak = rate("password1234", &[]);
        assert!(!weak.acceptable);
        assert_eq!(weak.label, "Weak");

        let strong = rate("lantern-orbit-velvet-quarry", &[]);
        assert!(strong.acceptable);
        assert_eq!(strong.chars, 27);
    }

    #[test]
    fn the_email_address_counts_against_it() {
        let rating = rate("alexandra.rivers1", &["alexandra.rivers", "example.com"]);
        assert!(!rating.acceptable);
    }

    #[test]
    fn short_is_never_acceptable() {
        assert!(!rate("Zq8#v!Lp", &[]).acceptable);
    }
}
