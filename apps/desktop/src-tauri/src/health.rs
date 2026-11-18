//! The Security tab's password check: which saved logins have weak,
//! reused or leaked passwords. It runs entirely on this device. The
//! passwords stay in Rust; the window only gets which items need fixing.

use std::collections::HashMap;

use serde::Serialize;
use sha2::{Digest, Sha256};
use vault_core::FieldKind;
use zeroize::Zeroizing;

use crate::breach::Outcome;
use crate::error::AppError;
use crate::state::Session;

/// At most this many different passwords are checked for leaks in one go,
/// so a huge vault doesn't send thousands of requests.
const MAX_LEAK_CHECKS: usize = 1000;

/// One login's password, copied out of the vaults for checking.
pub struct Login {
    vault: String,
    vault_name: String,
    item: String,
    title: String,
    subtitle: String,
    password: Zeroizing<String>,
    /// The website's host name, if it has one.
    site: Option<String>,
    /// It already has a one-time code.
    has_code: bool,
}

/// Websites that offer one-time codes, from the 2FA Directory (see
/// totp_sites.LICENSE). Kept in the app so no lookup leaves the device.
const TOTP_SITES: &str = include_str!("totp_sites.txt");

/// Whether `host` (or a domain it belongs to) offers one-time codes.
pub fn offers_codes(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let mut part = host.as_str();
    loop {
        if TOTP_SITES.lines().any(|d| d == part) {
            return true;
        }
        match part.split_once('.') {
            // Stop before a bare suffix like "com" or "co.uk".
            Some((_, rest)) if rest.contains('.') => part = rest,
            _ => return false,
        }
    }
}

/// A login whose website offers one-time codes it doesn't have yet.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TwoStep {
    pub vault: String,
    pub vault_name: String,
    pub item: String,
    pub title: String,
    pub subtitle: String,
    /// The website's host name.
    pub site: String,
}

/// What is wrong with one login, if anything.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub vault: String,
    pub vault_name: String,
    pub item: String,
    pub title: String,
    pub subtitle: String,
    /// Short or easy to guess.
    pub weak: bool,
    /// How many other logins use the same password.
    pub reused: usize,
    /// How many times it appears in known breaches, if checked and found.
    pub leaked: Option<u64>,
}

/// The result of a check.
#[derive(Debug, Clone, Serialize)]
pub struct Health {
    /// Logins with a password.
    pub logins: usize,
    /// Only the logins that need attention, worst first.
    pub findings: Vec<Finding>,
    /// Whether the leak check ran (it needs a connection).
    pub leaks_checked: bool,
    /// 0 to 100: the share of logins with nothing wrong.
    pub score: u8,
    /// Logins that could add a one-time code (advice; not in the score).
    pub two_step: Vec<TwoStep>,
}

/// Copies every login's password out of the open vaults.
pub fn collect(session: &Session) -> Vec<Login> {
    let mut logins = Vec::new();
    for vault in session.vaults.summaries(&session.unlocked) {
        let Some(id) = wire::unb64_array(&vault.id).map(vault_core::VaultId::from_bytes) else {
            continue;
        };
        let Ok(items) = session.vaults.items(&id) else {
            continue;
        };
        for (item_id, item) in items {
            let Some(password) = item
                .fields
                .iter()
                .find(|f| f.kind == FieldKind::Password && !f.value.is_empty())
            else {
                continue;
            };
            let summary = crate::items::summary(&item_id, &item);
            logins.push(Login {
                vault: vault.id.clone(),
                vault_name: vault.name.clone(),
                item: summary.id,
                title: summary.title,
                subtitle: summary.subtitle,
                password: Zeroizing::new(password.value.as_str().to_owned()),
                site: summary.site,
                has_code: summary.has_code,
            });
        }
    }
    logins
}

/// Checks `logins`. `leaks` is asked about each different password, if
/// given; the real one sends 5 characters of its SHA-1 hash.
pub fn analyse(logins: &[Login], leaks: Option<&dyn Fn(&str) -> Outcome>) -> Health {
    // Group by a hash of the password, so equal passwords are counted
    // without keeping a second copy of each.
    let mut groups: HashMap<[u8; 32], usize> = HashMap::new();
    let keys: Vec<[u8; 32]> = logins
        .iter()
        .map(|l| Sha256::digest(l.password.as_bytes()).into())
        .collect();
    for key in &keys {
        let count = groups.entry(*key).or_default();
        *count = count.saturating_add(1);
    }

    let mut leaked: HashMap<[u8; 32], Option<u64>> = HashMap::new();
    let mut leaks_checked = false;
    if let Some(check) = leaks {
        leaks_checked = true;
        for (login, key) in logins.iter().zip(&keys) {
            if leaked.contains_key(key) {
                continue;
            }
            if leaked.len() >= MAX_LEAK_CHECKS {
                break;
            }
            match check(&login.password) {
                Outcome::Breached(n) => {
                    leaked.insert(*key, Some(n));
                }
                Outcome::NotFound => {
                    leaked.insert(*key, None);
                }
                Outcome::Unknown => {
                    // Offline or the service is down: say so rather than
                    // report everything as safe.
                    leaks_checked = false;
                    break;
                }
            }
        }
    }

    let mut findings: Vec<Finding> = logins
        .iter()
        .zip(&keys)
        .filter_map(|(login, key)| {
            let weak = crate::strength::rate(&login.password, &[&login.title]).score < 3;
            let reused = groups.get(key).copied().unwrap_or(1).saturating_sub(1);
            let leaked = if leaks_checked {
                leaked.get(key).copied().flatten()
            } else {
                None
            };
            (weak || reused > 0 || leaked.is_some()).then(|| Finding {
                vault: login.vault.clone(),
                vault_name: login.vault_name.clone(),
                item: login.item.clone(),
                title: login.title.clone(),
                subtitle: login.subtitle.clone(),
                weak,
                reused,
                leaked,
            })
        })
        .collect();
    findings.sort_by_key(|f| {
        (
            f.leaked.is_none(),
            f.reused == 0,
            !f.weak,
            f.title.to_lowercase(),
        )
    });

    let total = logins.len();
    let fine = total.saturating_sub(findings.len());
    let score = fine
        .saturating_mul(100)
        .checked_div(total)
        .map_or(100, |s| u8::try_from(s).unwrap_or(100));
    let mut two_step: Vec<TwoStep> = logins
        .iter()
        .filter(|l| !l.has_code)
        .filter_map(|l| {
            let site = l.site.as_deref().filter(|s| offers_codes(s))?;
            Some(TwoStep {
                vault: l.vault.clone(),
                vault_name: l.vault_name.clone(),
                item: l.item.clone(),
                title: l.title.clone(),
                subtitle: l.subtitle.clone(),
                site: site.to_owned(),
            })
        })
        .collect();
    two_step.sort_by_cached_key(|t| t.title.to_lowercase());
    Health {
        logins: total,
        findings,
        leaks_checked,
        score,
        two_step,
    }
}

/// Runs the check on the open vaults.
///
/// # Errors
///
/// Returns [`AppError::Locked`] when the vaults are locked.
pub fn run(state: &crate::state::AppState, check_leaks: bool) -> Result<Health, AppError> {
    let logins = state.with_session(|s| Ok(collect(s)))?;
    let real: &dyn Fn(&str) -> Outcome = &crate::breach::check;
    Ok(analyse(&logins, check_leaks.then_some(real)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login(title: &str, password: &str) -> Login {
        Login {
            vault: "v".into(),
            vault_name: "Personal".into(),
            item: title.into(),
            title: title.into(),
            subtitle: String::new(),
            password: Zeroizing::new(password.into()),
            site: None,
            has_code: false,
        }
    }

    #[test]
    fn sites_that_offer_codes_are_suggested() {
        assert!(offers_codes("github.com"));
        assert!(offers_codes("Gist.GitHub.com"));
        assert!(!offers_codes("example.invalid"));
        assert!(!offers_codes("com"));
        let mut with = login("GitHub", "x8#Lq2!vR9@mT4zW");
        with.site = Some("github.com".into());
        let mut done = login("GitLab", "Qm7$wE2^rT9&yU4i");
        done.site = Some("gitlab.com".into());
        done.has_code = true;
        let health = analyse(&[with, done], None);
        assert_eq!(health.two_step.len(), 1);
        assert_eq!(health.two_step[0].site, "github.com");
        assert_eq!(health.score, 100);
    }

    #[test]
    fn finds_weak_and_reused_passwords() {
        let logins = [
            login("Mail", "correct-Horse-battery-staple-91"),
            login("Shop", "correct-Horse-battery-staple-91"),
            login("Bank", "password1"),
            login("News", "x8#Lq2!vR9@mT4zW"),
        ];
        let health = analyse(&logins, None);
        assert_eq!(health.logins, 4);
        assert!(!health.leaks_checked);
        let titles: Vec<_> = health.findings.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(titles, ["Mail", "Shop", "Bank"]);
        assert_eq!(health.findings[0].reused, 1);
        assert!(health.findings[2].weak);
        assert_eq!(health.score, 25);
    }

    #[test]
    fn leaked_passwords_come_first_and_are_checked_once() {
        let logins = [
            login("A", "x8#Lq2!vR9@mT4zW"),
            login("B", "Tr0ub4dor&3-horse-staple"),
            login("C", "Tr0ub4dor&3-horse-staple"),
        ];
        let asked = std::cell::Cell::new(0);
        let check = |p: &str| {
            asked.set(asked.get() + 1);
            if p.starts_with("Tr0ub") {
                Outcome::Breached(42)
            } else {
                Outcome::NotFound
            }
        };
        let health = analyse(&logins, Some(&check));
        assert_eq!(asked.get(), 2);
        assert!(health.leaks_checked);
        assert_eq!(health.findings.len(), 2);
        assert!(health.findings.iter().all(|f| f.leaked == Some(42)));
    }

    #[test]
    fn an_unreachable_service_is_not_reported_as_safe() {
        let logins = [login("A", "x8#Lq2!vR9@mT4zW")];
        let check = |_: &str| Outcome::Unknown;
        let health = analyse(&logins, Some(&check));
        assert!(!health.leaks_checked);
        assert!(health.findings.is_empty());
    }

    #[test]
    fn no_logins_scores_full_marks() {
        let health = analyse(&[], None);
        assert_eq!(health.score, 100);
        assert!(health.findings.is_empty());
    }
}
