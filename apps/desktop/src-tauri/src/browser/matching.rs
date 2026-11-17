//! Which saved logins belong to a page (spec section 14.5).
//!
//! A login matches a page on the same site: the same registrable domain
//! (the part a person or company registers, found with the Public Suffix
//! List), so `accounts.example.com` and `www.example.com` share logins but
//! `alice.github.io` and `mallory.github.io` do not. Addresses without a
//! registrable domain, such as IP addresses and `localhost`, must match
//! exactly, port included. A login saved for `https` is never offered to
//! an `http` page.

use url::{Host, Url};

/// Where a page or saved login is, for matching.
#[derive(Debug, PartialEq, Eq)]
struct Site {
    https: bool,
    host: String,
    port: Option<u16>,
    /// The registrable domain, if the host has one.
    domain: Option<String>,
}

/// Reads a page address. Only `https` and `http` pages can be filled.
fn page_site(url: &str) -> Option<Site> {
    let url = Url::parse(url).ok()?;
    site(&url)
}

/// Reads an address saved in a login, which people often type without a
/// scheme.
fn saved_site(text: &str) -> Option<Site> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let url = Url::parse(text)
        .ok()
        .filter(|u| u.has_host())
        .or_else(|| Url::parse(&format!("https://{text}")).ok())?;
    site(&url)
}

fn site(url: &Url) -> Option<Site> {
    let https = match url.scheme() {
        "https" => true,
        "http" => false,
        _ => return None,
    };
    let host = url.host()?;
    let domain = match &host {
        Host::Domain(name) => {
            let domain = psl::domain_str(name).map(str::to_owned);
            // A public suffix itself, like `co.uk` or `github.io`, is no
            // one's site. A single label like `localhost` is matched
            // exactly instead.
            if domain.is_none() && name.contains('.') {
                return None;
            }
            domain
        }
        Host::Ipv4(_) | Host::Ipv6(_) => None,
    };
    Some(Site {
        https,
        host: host.to_string(),
        port: url.port(),
        domain,
    })
}

/// Whether a login saved for `saved` may be offered on `page`.
pub fn matches(saved: &str, page: &str) -> bool {
    let (Some(saved), Some(page)) = (saved_site(saved), page_site(page)) else {
        return false;
    };
    if saved.https && !page.https {
        return false;
    }
    match (&saved.domain, &page.domain) {
        (Some(a), Some(b)) => a == b && (saved.port.is_none() || saved.port == page.port),
        _ => saved.host == page.host && saved.port == page.port,
    }
}

/// The origin of a page (`scheme://host:port`), which the extension checks
/// before filling, or `None` if it cannot be filled.
pub fn fillable_origin(page: &str) -> Option<String> {
    let url = Url::parse(page).ok()?;
    page_site(page)?;
    Some(url.origin().ascii_serialization())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_site_matches() {
        assert!(matches(
            "https://example.com",
            "https://www.example.com/login"
        ));
        assert!(matches("example.com", "https://accounts.example.com/"));
        assert!(matches("www.example.com/signin", "https://example.com"));
        assert!(matches("http://example.com", "https://example.com"));
        assert!(matches(
            "https://shop.example.co.uk",
            "https://example.co.uk"
        ));
    }

    #[test]
    fn other_sites_do_not() {
        assert!(!matches("https://example.com", "https://example.org"));
        assert!(!matches(
            "https://example.com",
            "https://example.com.evil.net"
        ));
        assert!(!matches("https://example.com", "https://notexample.com"));
        // Different registrations under a shared suffix are different sites.
        assert!(!matches(
            "https://alice.github.io",
            "https://mallory.github.io"
        ));
        assert!(!matches("https://a.blogspot.com", "https://b.blogspot.com"));
        assert!(!matches("https://co.uk", "https://co.uk"));
    }

    #[test]
    fn no_downgrade_to_http() {
        assert!(!matches("https://example.com", "http://example.com"));
        assert!(matches("http://example.com", "http://example.com"));
    }

    #[test]
    fn addresses_without_a_domain_match_exactly() {
        assert!(matches("http://192.168.1.1", "http://192.168.1.1/admin"));
        assert!(!matches("http://192.168.1.1", "http://192.168.1.2"));
        assert!(!matches("http://192.168.1.1:8080", "http://192.168.1.1"));
        assert!(matches("http://localhost:3000", "http://localhost:3000/x"));
        assert!(!matches("http://localhost:3000", "http://localhost:3001"));
        assert!(matches("http://[::1]:8080", "http://[::1]:8080/"));
    }

    #[test]
    fn ports_when_saved() {
        assert!(matches(
            "https://example.com:8443",
            "https://example.com:8443/"
        ));
        assert!(!matches("https://example.com:8443", "https://example.com/"));
        assert!(matches("https://example.com", "https://example.com:8443/"));
    }

    #[test]
    fn only_web_pages() {
        assert!(!matches("example.com", "file:///C:/example.com"));
        assert!(!matches("example.com", "chrome://settings"));
        assert!(!matches("javascript:alert(1)", "https://example.com"));
        assert!(!matches("", "https://example.com"));
        assert!(!matches("example.com", "not a url"));
    }

    #[test]
    fn international_names() {
        assert!(matches(
            "https://bücher.example",
            "https://xn--bcher-kva.example/"
        ));
    }

    #[test]
    fn origins() {
        assert_eq!(
            fillable_origin("https://www.example.com/login?x=1").as_deref(),
            Some("https://www.example.com")
        );
        assert_eq!(
            fillable_origin("http://localhost:3000/").as_deref(),
            Some("http://localhost:3000")
        );
        assert_eq!(fillable_origin("file:///tmp/x"), None);
    }
}
