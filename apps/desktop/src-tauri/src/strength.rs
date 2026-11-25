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
    /// Roughly how long an offline attack against a slow password hash
    /// would take, such as "centuries". Empty when nothing is typed.
    pub guess_time: String,
}

/// Rates `password`. `context` holds words an attacker would try first,
/// such as the email address.
pub fn rate(password: &str, context: &[&str]) -> Rating {
    let chars = password.chars().count();
    let rated: String = password.chars().take(MAX_RATED_CHARS).collect();
    let entropy = zxcvbn::zxcvbn(&rated, context);
    let short = chars < MIN_NEW_PASSWORD_CHARS;
    // A password too short to use is never shown as strong, whatever
    // zxcvbn thinks of it: the meter would contradict the rule.
    let score = if short && chars > 0 {
        u8::from(entropy.score()).min(1)
    } else {
        u8::from(entropy.score())
    };
    let hint = entropy.feedback().and_then(|f| {
        f.warning()
            .map(|w| w.to_string())
            .or_else(|| f.suggestions().first().map(ToString::to_string))
    });
    let label = match (chars, score) {
        (0, _) => "",
        _ if short => "Too short",
        (_, 0 | 1) => "Weak",
        (_, 2) => "Fair",
        (_, 3) => "Strong",
        _ => "Very strong",
    };
    let guess_time = if chars == 0 {
        String::new()
    } else {
        entropy
            .crack_times()
            .offline_slow_hashing_1e4_per_second()
            .to_string()
    };
    Rating {
        score,
        guess_time,
        label,
        acceptable: !short && score >= MIN_SCORE,
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
        assert!(!strong.guess_time.is_empty());
        assert!(rate("", &[]).guess_time.is_empty());
    }

    #[test]
    fn the_email_address_counts_against_it() {
        let rating = rate("alexandra.rivers1", &["alexandra.rivers", "example.com"]);
        assert!(!rating.acceptable);
    }

    #[test]
    fn short_is_never_acceptable() {
        let short = rate("Zq8#v!Lp9%sW", &[]);
        assert_eq!(short.chars, 12);
        let short = rate("Zq8#v!Lp9%s", &[]);
        assert!(!short.acceptable);
        assert_eq!(short.label, "Too short");
        assert!(short.score <= 1);
    }
}
