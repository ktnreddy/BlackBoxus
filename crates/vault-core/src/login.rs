//! OPAQUE login and registration, client side (spec section 4).
//!
//! The matching server side lives in `server-core` and uses the same
//! [`Suite`], identities and context defined here.

use hkdf::Hkdf;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::identity::{ClientIdentity, ServerIdentity};
use crate::key::SymmetricKey;

/// Parses an OPAQUE value and rejects input with trailing or missing bytes,
/// so every value has exactly one accepted encoding.
macro_rules! parse_exact {
    ($ty:ty, $bytes:expr, $err:expr) => {{
        let bytes: &[u8] = $bytes;
        match <$ty>::deserialize(bytes) {
            Ok(v) if v.serialize().len() == bytes.len() => Ok(v),
            _ => Err($err),
        }
    }};
}

/// Context string bound into every login (spec section 4.2).
pub const LOGIN_CONTEXT: &[u8] = b"BlackBoxus v1 login";

const LABEL_SESSION_TOKEN: &[u8] = b"BlackBoxus v1 session-token";

/// Length of a session token in bytes.
pub const SESSION_TOKEN_LEN: usize = 32;

/// The OPAQUE cipher suite for protocol version 1: ristretto255 OPRF, 3DH
/// over ristretto255 with SHA-512, and no extra key stretching because the
/// password input is already stretched by Argon2id.
#[derive(Debug, Clone, Copy)]
pub struct Suite;

impl opaque_ke::CipherSuite for Suite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2_10::Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

/// Builds the OPAQUE identifiers for a client and server.
#[must_use]
pub fn identifiers<'a>(client: &'a ClientIdentity, server: &'a ServerIdentity) -> Identifiers<'a> {
    Identifiers {
        client: Some(client.as_bytes()),
        server: Some(server.as_bytes()),
    }
}

/// A session token derived from the OPAQUE session key (spec section 4.6).
///
/// Erased on drop, compared in constant time, and never printed by `Debug`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionToken([u8; SESSION_TOKEN_LEN]);

impl SessionToken {
    /// Derives the token from an OPAQUE session key. Both client and server
    /// compute this independently; the token is never sent during login.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyDerivation`] if HKDF fails.
    pub fn from_session_key(session_key: &[u8]) -> Result<Self> {
        let mut token = Self([0; SESSION_TOKEN_LEN]);
        Hkdf::<Sha256>::new(None, session_key)
            .expand(LABEL_SESSION_TOKEN, &mut token.0)
            .map_err(|_| Error::KeyDerivation)?;
        Ok(token)
    }

    /// Restores a token that the client kept in secure local storage, for
    /// example sealed under a device key (spec section 10.4).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SESSION_TOKEN_LEN]) -> Self {
        Self(bytes)
    }

    /// The token bytes, for use as a bearer token.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_TOKEN_LEN] {
        &self.0
    }

    /// `SHA-256(token)`: the only form in which a server may store it.
    #[must_use]
    pub fn storage_hash(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }
}

impl PartialEq for SessionToken {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for SessionToken {}

impl core::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

/// Client state between the two registration messages.
pub struct RegistrationState(ClientRegistration<Suite>);

impl core::fmt::Debug for RegistrationState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RegistrationState(<redacted>)")
    }
}

/// Starts OPAQUE registration. Returns the state to keep and the request to
/// send to the server.
///
/// # Errors
///
/// Returns [`Error::Authentication`] if OPAQUE fails.
pub fn start_registration(opaque_password: &SymmetricKey) -> Result<(RegistrationState, Vec<u8>)> {
    let start = ClientRegistration::<Suite>::start(&mut OsRng, opaque_password.as_bytes())
        .map_err(|_| Error::Authentication)?;
    let request = start.message.serialize().to_vec();
    Ok((RegistrationState(start.state), request))
}

impl RegistrationState {
    /// Completes registration using the server's response. Returns the upload
    /// to send to the server. The OPAQUE export key is discarded.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if the response cannot be parsed,
    /// or [`Error::Authentication`] if OPAQUE rejects it.
    pub fn finish(
        self,
        opaque_password: &SymmetricKey,
        response: &[u8],
        client: &ClientIdentity,
        server: &ServerIdentity,
    ) -> Result<Vec<u8>> {
        let response = parse_exact!(
            RegistrationResponse<Suite>,
            response,
            Error::MalformedMessage
        )?;
        let finish = self
            .0
            .finish(
                &mut OsRng,
                opaque_password.as_bytes(),
                response,
                ClientRegistrationFinishParameters::new(identifiers(client, server), None),
            )
            .map_err(|_| Error::Authentication)?;
        Ok(finish.message.serialize().to_vec())
    }
}

/// Client state between the login messages.
pub struct LoginState(ClientLogin<Suite>);

impl core::fmt::Debug for LoginState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LoginState(<redacted>)")
    }
}

/// Starts an OPAQUE login. Returns the state to keep and `KE1` to send.
///
/// # Errors
///
/// Returns [`Error::Authentication`] if OPAQUE fails.
pub fn start_login(opaque_password: &SymmetricKey) -> Result<(LoginState, Vec<u8>)> {
    let start = ClientLogin::<Suite>::start(&mut OsRng, opaque_password.as_bytes())
        .map_err(|_| Error::Authentication)?;
    let ke1 = start.message.serialize().to_vec();
    Ok((LoginState(start.state), ke1))
}

/// The result of a successful client-side login.
#[derive(Debug)]
pub struct LoginFinish {
    /// `KE3`, to send to the server.
    pub ke3: Vec<u8>,
    /// The session token to present on later requests.
    pub session_token: SessionToken,
}

impl LoginState {
    /// Completes the login using the server's `KE2`.
    ///
    /// A wrong password, wrong Secret Key, unknown account or impostor server
    /// all produce the same [`Error::Authentication`], by design.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if `KE2` cannot be parsed, or
    /// [`Error::Authentication`] if the login fails.
    pub fn finish(
        self,
        opaque_password: &SymmetricKey,
        ke2: &[u8],
        client: &ClientIdentity,
        server: &ServerIdentity,
    ) -> Result<LoginFinish> {
        let ke2 = parse_exact!(CredentialResponse<Suite>, ke2, Error::MalformedMessage)?;
        let finish = self
            .0
            .finish(
                &mut OsRng,
                opaque_password.as_bytes(),
                ke2,
                ClientLoginFinishParameters::new(
                    Some(LOGIN_CONTEXT),
                    identifiers(client, server),
                    None,
                ),
            )
            .map_err(|_| Error::Authentication)?;
        let mut session_key = finish.session_key;
        let session_token = SessionToken::from_session_key(session_key.as_slice());
        session_key.as_mut_slice().zeroize();
        let session_token = session_token?;
        Ok(LoginFinish {
            ke3: finish.message.serialize().to_vec(),
            session_token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_token_debug_is_redacted() {
        let token = SessionToken::from_session_key(&[1; 64]).unwrap();
        assert_eq!(format!("{token:?}"), "SessionToken(<redacted>)");
    }

    #[test]
    fn session_token_depends_on_session_key() {
        let a = SessionToken::from_session_key(&[1; 64]).unwrap();
        let b = SessionToken::from_session_key(&[1; 64]).unwrap();
        let c = SessionToken::from_session_key(&[2; 64]).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a.storage_hash(), *a.as_bytes());
    }

    #[test]
    fn rejects_malformed_server_messages() {
        let opw = SymmetricKey::from_bytes([3; 32]);
        let client = ClientIdentity::new("a@b.c").unwrap();
        let server = ServerIdentity::new("https://api.example.org").unwrap();

        let (state, _) = start_registration(&opw).unwrap();
        assert_eq!(
            state.finish(&opw, &[0; 3], &client, &server).unwrap_err(),
            Error::MalformedMessage
        );

        let (state, _) = start_login(&opw).unwrap();
        assert_eq!(
            state.finish(&opw, &[0; 3], &client, &server).unwrap_err(),
            Error::MalformedMessage
        );
    }
}
