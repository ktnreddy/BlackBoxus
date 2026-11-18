//! Checks a new master password against the passwords exposed in known
//! data breaches (spec section 3.4), using Have I Been Pwned's range API.
//!
//! Only the first 5 hexadecimal characters of the password's SHA-1 hash
//! leave the device. The service answers with every hash suffix that
//! shares that prefix (hundreds of them, padded with fake entries so the
//! answer's size gives nothing away), and the match is made here.

use std::fmt::Write as _;
use std::io::Read;
use std::time::Duration;

use sha1::{Digest, Sha1};
use zeroize::Zeroizing;

/// The range API. The prefix is appended to it.
const RANGE_URL: &str = "https://api.pwnedpasswords.com/range/";

/// Largest answer read. A real one is around 30 to 40 KB.
const MAX_BODY: u64 = 1 << 20;

/// What the check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The password appears in known breaches this many times.
    Breached(u64),
    /// It does not appear in any known breach.
    NotFound,
    /// The service could not be reached or gave an unreadable answer.
    Unknown,
}

/// Checks `password` against the live service.
pub fn check(password: &str) -> Outcome {
    check_with(password, fetch_range)
}

/// Checks `password`, asking `fetch` for the suffixes that share a prefix.
/// `fetch` gets the 5-character prefix and returns the answer's text, or
/// `None` if it could not get one.
pub fn check_with(password: &str, fetch: impl FnOnce(&str) -> Option<String>) -> Outcome {
    let hash = sha1_hex(password);
    let (prefix, suffix) = hash.split_at(5);
    match fetch(prefix) {
        Some(body) => find(&body, suffix),
        None => Outcome::Unknown,
    }
}

/// The upper-case hexadecimal SHA-1 hash of `password`, wiped after use.
fn sha1_hex(password: &str) -> Zeroizing<String> {
    let digest: Zeroizing<[u8; 20]> = Zeroizing::new(Sha1::digest(password.as_bytes()).into());
    let mut hex = Zeroizing::new(String::with_capacity(40));
    for byte in digest.iter() {
        // Writing to a String cannot fail.
        let _ = write!(hex, "{byte:02X}");
    }
    hex
}

/// Looks for `suffix` in a range answer: one `SUFFIX:COUNT` per line.
/// Padding entries have a count of 0 and never match.
fn find(body: &str, suffix: &str) -> Outcome {
    let mut any = false;
    for line in body.lines() {
        let Some((candidate, count)) = line.trim().split_once(':') else {
            continue;
        };
        any = true;
        if candidate.len() == 35 && candidate.eq_ignore_ascii_case(suffix) {
            return match count.trim().parse::<u64>() {
                Ok(0) => Outcome::NotFound,
                Ok(n) => Outcome::Breached(n),
                Err(_) => Outcome::Unknown,
            };
        }
    }
    // A real answer always lists many suffixes; an empty one is broken.
    if any {
        Outcome::NotFound
    } else {
        Outcome::Unknown
    }
}

/// Fetches one range from the service, or `None` if that fails.
fn fetch_range(prefix: &str) -> Option<String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(8)))
        .timeout_connect(Some(Duration::from_secs(5)))
        .user_agent(concat!("BlackBoxus/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let mut answer = agent
        .get(&format!("{RANGE_URL}{prefix}"))
        .header("Add-Padding", "true")
        .call()
        .ok()?;
    let mut body = String::new();
    answer
        .body_mut()
        .as_reader()
        .take(MAX_BODY)
        .read_to_string(&mut body)
        .ok()?;
    Some(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    const PREFIX: &str = "5BAA6";
    const SUFFIX: &str = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    #[test]
    fn hashes_like_the_service() {
        assert_eq!(sha1_hex("password").as_str(), format!("{PREFIX}{SUFFIX}"));
    }

    #[test]
    fn only_the_prefix_is_sent() {
        let mut asked = String::new();
        let outcome = check_with("password", |prefix| {
            asked = prefix.to_owned();
            Some(format!(
                "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{SUFFIX}:52256179\r\n"
            ))
        });
        assert_eq!(asked, PREFIX);
        assert_eq!(outcome, Outcome::Breached(52_256_179));
    }

    #[test]
    fn lower_case_answers_match_too() {
        let body = format!("{}:3\n", SUFFIX.to_ascii_lowercase());
        assert_eq!(check_with("password", |_| Some(body)), Outcome::Breached(3));
    }

    #[test]
    fn padding_and_other_suffixes_do_not_match() {
        let body = format!(
            "0018A45C4D1DEF81644B54AB7F969B88D65:4\r\n{SUFFIX}:0\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0\r\n"
        );
        assert_eq!(check_with("password", |_| Some(body)), Outcome::NotFound);
        let other = "0018A45C4D1DEF81644B54AB7F969B88D65:4\r\n".to_owned();
        assert_eq!(check_with("password", |_| Some(other)), Outcome::NotFound);
    }

    #[test]
    fn no_answer_or_a_broken_one_is_unknown() {
        assert_eq!(check_with("password", |_| None), Outcome::Unknown);
        assert_eq!(
            check_with("password", |_| Some(String::new())),
            Outcome::Unknown
        );
        assert_eq!(
            check_with("password", |_| Some("<html>error</html>".into())),
            Outcome::Unknown
        );
        let bad_count = format!("{SUFFIX}:lots\n");
        assert_eq!(
            check_with("password", |_| Some(bad_count)),
            Outcome::Unknown
        );
    }
}
