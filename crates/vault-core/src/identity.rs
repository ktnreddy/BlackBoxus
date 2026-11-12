//! Canonical client and server identities (spec section 4.3).

use unicode_normalization::UnicodeNormalization;

use crate::error::{Error, Result};

/// Maximum length of a canonical email address, in bytes.
pub const MAX_EMAIL_BYTES: usize = 254;

/// Maximum length of a server origin, in bytes.
pub const MAX_ORIGIN_BYTES: usize = 255;

/// A user's canonical email address, used as the OPAQUE client identity and
/// credential identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientIdentity(String);

impl ClientIdentity {
    /// Canonicalises an email address: trims white space, normalises to NFKC
    /// and converts to lower case.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidIdentity`] if the result is not a plausible
    /// email address or is too long.
    pub fn new(email: &str) -> Result<Self> {
        let canonical: String = email.trim().nfkc().collect::<String>().to_lowercase();
        if canonical.len() > MAX_EMAIL_BYTES {
            return Err(Error::InvalidIdentity);
        }
        let mut parts = canonical.split('@');
        let valid = matches!(
            (parts.next(), parts.next(), parts.next()),
            (Some(local), Some(domain), None) if !local.is_empty() && !domain.is_empty()
        );
        if !valid || canonical.chars().any(char::is_whitespace) {
            return Err(Error::InvalidIdentity);
        }
        Ok(Self(canonical))
    }

    /// The canonical address.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The canonical address as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// The server's canonical origin, used as the OPAQUE server identity.
///
/// It comes from the client's own configuration, never from the server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerIdentity(String);

impl ServerIdentity {
    /// Validates and canonicalises a server origin such as
    /// `https://api.example.org`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidIdentity`] if the origin is not `https` (or
    /// plain `http` to `localhost` / `127.0.0.1`), or contains a path,
    /// query, fragment or credentials.
    pub fn new(origin: &str) -> Result<Self> {
        let lower = origin.trim().to_ascii_lowercase();
        if lower.is_empty() || lower.len() > MAX_ORIGIN_BYTES || !lower.is_ascii() {
            return Err(Error::InvalidIdentity);
        }

        let (scheme, authority) = lower.split_once("://").ok_or(Error::InvalidIdentity)?;
        let host = match authority.rsplit_once(':') {
            Some((host, port)) => {
                if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Error::InvalidIdentity);
                }
                host
            }
            None => authority,
        };

        let host_ok = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        let scheme_ok = match scheme {
            "https" => true,
            "http" => host == "localhost" || host == "127.0.0.1",
            _ => false,
        };
        if !host_ok || !scheme_ok {
            return Err(Error::InvalidIdentity);
        }
        Ok(Self(lower))
    }

    /// The canonical origin.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The canonical origin as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_is_canonicalised() {
        let id = ClientIdentity::new("  Alice.Example@Mail.COM \n").unwrap();
        assert_eq!(id.as_str(), "alice.example@mail.com");
        // Full-width characters become ASCII under NFKC.
        let wide = ClientIdentity::new("\u{FF41}@b.c").unwrap();
        assert_eq!(wide.as_str(), "a@b.c");
    }

    #[test]
    fn rejects_invalid_emails() {
        for bad in ["", "no-at-sign", "@domain", "local@", "a@b@c", "a b@c.d"] {
            assert!(ClientIdentity::new(bad).is_err(), "{bad:?}");
        }
        let long = format!("{}@example.com", "a".repeat(250));
        assert!(ClientIdentity::new(&long).is_err());
    }

    #[test]
    fn origin_is_canonicalised() {
        let id = ServerIdentity::new("HTTPS://API.Example.org").unwrap();
        assert_eq!(id.as_str(), "https://api.example.org");
        assert!(ServerIdentity::new("https://api.example.org:8443").is_ok());
        assert!(ServerIdentity::new("http://localhost:8787").is_ok());
        assert!(ServerIdentity::new("http://127.0.0.1").is_ok());
    }

    #[test]
    fn rejects_unsafe_or_malformed_origins() {
        for bad in [
            "",
            "api.example.org",
            "http://api.example.org",
            "ftp://api.example.org",
            "https://api.example.org/",
            "https://api.example.org/path",
            "https://user@api.example.org",
            "https://api.example.org:",
            "https://api.example.org:80a",
            "https://",
        ] {
            assert!(ServerIdentity::new(bad).is_err(), "{bad:?}");
        }
    }
}
