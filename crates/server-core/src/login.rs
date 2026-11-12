//! OPAQUE registration and login, server side (spec section 4).

use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand_core::OsRng;
use vault_core::login::{LOGIN_CONTEXT, SessionToken, Suite, identifiers};
use vault_core::{ClientIdentity, ServerIdentity};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

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

/// The server's OPAQUE secrets: OPRF seed and long-term key pair
/// (spec section 4.7).
///
/// Load it from the hosting platform's secret store. Never log it or commit
/// it to source control.
pub struct OpaqueServer(ServerSetup<Suite>);

impl OpaqueServer {
    /// Generates new server secrets. Do this once per deployment.
    #[must_use]
    pub fn generate() -> Self {
        Self(ServerSetup::<Suite>::new(&mut OsRng))
    }

    /// Serialises the secrets for storage in a secret store.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = self.0.serialize();
        let out = Zeroizing::new(bytes.to_vec());
        bytes.as_mut_slice().zeroize();
        out
    }

    /// Loads secrets produced by [`OpaqueServer::to_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfiguration`] if the bytes are not valid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        parse_exact!(ServerSetup<Suite>, bytes, Error::InvalidConfiguration).map(Self)
    }

    /// Answers a client's registration request.
    ///
    /// The caller must have checked that this registration is allowed: a new
    /// account, or an authenticated change for the same account.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] or [`Error::Authentication`].
    pub fn registration_response(
        &self,
        request: &[u8],
        client: &ClientIdentity,
    ) -> Result<Vec<u8>> {
        let request = parse_exact!(RegistrationRequest<Suite>, request, Error::MalformedMessage)?;
        let start = ServerRegistration::<Suite>::start(&self.0, request, client.as_bytes())
            .map_err(|_| Error::Authentication)?;
        Ok(start.message.serialize().to_vec())
    }

    /// Starts a login. Pass `None` as `record` when the account does not
    /// exist: a fake response is produced so the reply looks the same.
    ///
    /// Returns the state to keep (server-side only, for at most 60 seconds,
    /// used once) and `KE2` to send to the client.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if `KE1` or the record cannot be
    /// parsed, or [`Error::Authentication`] if OPAQUE fails.
    pub fn start_login(
        &self,
        record: Option<&[u8]>,
        ke1: &[u8],
        client: &ClientIdentity,
        server: &ServerIdentity,
    ) -> Result<(ServerLoginState, Vec<u8>)> {
        let password_file = match record {
            Some(r) => Some(parse_exact!(
                ServerRegistration<Suite>,
                r,
                Error::MalformedMessage
            )?),
            None => None,
        };
        let ke1 = parse_exact!(CredentialRequest<Suite>, ke1, Error::MalformedMessage)?;
        let start = ServerLogin::start(
            &mut OsRng,
            &self.0,
            password_file,
            ke1,
            client.as_bytes(),
            ServerLoginParameters {
                context: Some(LOGIN_CONTEXT),
                identifiers: identifiers(client, server),
            },
        )
        .map_err(|_| Error::Authentication)?;
        Ok((
            ServerLoginState(start.state),
            start.message.serialize().to_vec(),
        ))
    }
}

impl core::fmt::Debug for OpaqueServer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OpaqueServer(<redacted>)")
    }
}

/// Validates a client's registration upload and returns the record to store
/// for the account.
///
/// # Errors
///
/// Returns [`Error::MalformedMessage`] if the upload cannot be parsed.
pub fn finish_registration(upload: &[u8]) -> Result<Vec<u8>> {
    let upload = parse_exact!(RegistrationUpload<Suite>, upload, Error::MalformedMessage)?;
    Ok(ServerRegistration::finish(upload).serialize().to_vec())
}

/// Server state between `KE2` and `KE3`.
pub struct ServerLoginState(ServerLogin<Suite>);

impl ServerLoginState {
    /// Serialises the state so it can be held briefly in server-side storage
    /// between requests.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = self.0.serialize();
        let out = Zeroizing::new(bytes.to_vec());
        bytes.as_mut_slice().zeroize();
        out
    }

    /// Restores state produced by [`ServerLoginState::to_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if the bytes are not valid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        parse_exact!(ServerLogin<Suite>, bytes, Error::MalformedMessage).map(Self)
    }

    /// Verifies the client's `KE3` and returns the session token. Store only
    /// [`SessionToken::storage_hash`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] or [`Error::Authentication`].
    pub fn finish(
        self,
        ke3: &[u8],
        client: &ClientIdentity,
        server: &ServerIdentity,
    ) -> Result<SessionToken> {
        let ke3 = parse_exact!(CredentialFinalization<Suite>, ke3, Error::MalformedMessage)?;
        let finish = self
            .0
            .finish(
                ke3,
                ServerLoginParameters {
                    context: Some(LOGIN_CONTEXT),
                    identifiers: identifiers(client, server),
                },
            )
            .map_err(|_| Error::Authentication)?;
        let mut session_key = finish.session_key;
        let token = SessionToken::from_session_key(session_key.as_slice());
        session_key.as_mut_slice().zeroize();
        Ok(token?)
    }
}

impl core::fmt::Debug for ServerLoginState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ServerLoginState(<redacted>)")
    }
}
