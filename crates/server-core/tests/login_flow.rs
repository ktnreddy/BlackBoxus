//! End-to-end registration and login between the `vault-core` client and the
//! `server-core` server (spec section 4).

#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

use server_core::login::{OpaqueServer, ServerLoginState, finish_registration};
use vault_core::login::{start_login, start_registration};
use vault_core::{
    AccountSalt, ClientIdentity, Error as ClientError, KdfParams, MasterPassword, SecretKey,
    ServerIdentity, SymmetricKey, derive_account_keys,
};

fn ids() -> (ClientIdentity, ServerIdentity) {
    (
        ClientIdentity::new("Alice@Example.com").unwrap(),
        ServerIdentity::new("https://api.blackboxus.test").unwrap(),
    )
}

/// Derives OPW the way a real client does, with minimum Argon2id cost to keep
/// tests fast.
fn opaque_password(password: &str, secret_key: &SecretKey, salt: &AccountSalt) -> SymmetricKey {
    let password = MasterPassword::new(password).unwrap();
    derive_account_keys(&password, secret_key, salt, &KdfParams::MIN)
        .unwrap()
        .opaque_password
}

fn register(server: &OpaqueServer, opw: &SymmetricKey) -> Vec<u8> {
    let (client, server_id) = ids();
    let (state, request) = start_registration(opw).unwrap();
    let response = server.registration_response(&request, &client).unwrap();
    let upload = state.finish(opw, &response, &client, &server_id).unwrap();
    finish_registration(&upload).unwrap()
}

struct Account {
    server: OpaqueServer,
    record: Vec<u8>,
    secret_key: SecretKey,
    salt: AccountSalt,
}

fn create_account() -> Account {
    let server = OpaqueServer::generate();
    let secret_key = SecretKey::generate().unwrap();
    let salt = AccountSalt::generate().unwrap();
    let opw = opaque_password("correct horse battery staple", &secret_key, &salt);
    let record = register(&server, &opw);
    Account {
        server,
        record,
        secret_key,
        salt,
    }
}

#[test]
fn registration_then_login_agrees_on_session_token() {
    let account = create_account();
    let (client, server_id) = ids();
    let opw = opaque_password(
        "correct horse battery staple",
        &account.secret_key,
        &account.salt,
    );

    let (client_state, ke1) = start_login(&opw).unwrap();
    let (server_state, ke2) = account
        .server
        .start_login(Some(&account.record), &ke1, &client, &server_id)
        .unwrap();
    let done = client_state
        .finish(&opw, &ke2, &client, &server_id)
        .unwrap();
    let server_token = server_state.finish(&done.ke3, &client, &server_id).unwrap();

    assert_eq!(done.session_token, server_token);
    assert_eq!(
        done.session_token.storage_hash(),
        server_token.storage_hash()
    );
}

#[test]
fn server_state_survives_serialisation() {
    let account = create_account();
    let (client, server_id) = ids();
    let opw = opaque_password(
        "correct horse battery staple",
        &account.secret_key,
        &account.salt,
    );

    let (client_state, ke1) = start_login(&opw).unwrap();
    let (server_state, ke2) = account
        .server
        .start_login(Some(&account.record), &ke1, &client, &server_id)
        .unwrap();
    let stored = server_state.to_bytes();
    let restored = ServerLoginState::from_bytes(&stored).unwrap();

    let done = client_state
        .finish(&opw, &ke2, &client, &server_id)
        .unwrap();
    assert_eq!(
        restored.finish(&done.ke3, &client, &server_id).unwrap(),
        done.session_token
    );
}

#[test]
fn server_secrets_survive_serialisation() {
    let account = create_account();
    let reloaded = OpaqueServer::from_bytes(&account.server.to_bytes()).unwrap();
    let (client, server_id) = ids();
    let opw = opaque_password(
        "correct horse battery staple",
        &account.secret_key,
        &account.salt,
    );

    let (client_state, ke1) = start_login(&opw).unwrap();
    let (_, ke2) = reloaded
        .start_login(Some(&account.record), &ke1, &client, &server_id)
        .unwrap();
    assert!(client_state.finish(&opw, &ke2, &client, &server_id).is_ok());
}

#[test]
fn wrong_password_fails_at_client() {
    let account = create_account();
    let (client, server_id) = ids();
    let wrong = opaque_password(
        "correct horse battery stapler",
        &account.secret_key,
        &account.salt,
    );

    let (client_state, ke1) = start_login(&wrong).unwrap();
    let (_, ke2) = account
        .server
        .start_login(Some(&account.record), &ke1, &client, &server_id)
        .unwrap();
    assert_eq!(
        client_state
            .finish(&wrong, &ke2, &client, &server_id)
            .unwrap_err(),
        ClientError::Authentication
    );
}

#[test]
fn wrong_secret_key_fails_at_client() {
    let account = create_account();
    let (client, server_id) = ids();
    let other_key = SecretKey::generate().unwrap();
    let wrong = opaque_password("correct horse battery staple", &other_key, &account.salt);

    let (client_state, ke1) = start_login(&wrong).unwrap();
    let (_, ke2) = account
        .server
        .start_login(Some(&account.record), &ke1, &client, &server_id)
        .unwrap();
    assert_eq!(
        client_state
            .finish(&wrong, &ke2, &client, &server_id)
            .unwrap_err(),
        ClientError::Authentication
    );
}

#[test]
fn impostor_server_identity_fails() {
    let account = create_account();
    let (client, real_server) = ids();
    let impostor = ServerIdentity::new("https://evil.example").unwrap();
    let opw = opaque_password(
        "correct horse battery staple",
        &account.secret_key,
        &account.salt,
    );

    let (client_state, ke1) = start_login(&opw).unwrap();
    let (_, ke2) = account
        .server
        .start_login(Some(&account.record), &ke1, &client, &impostor)
        .unwrap();
    assert_eq!(
        client_state
            .finish(&opw, &ke2, &client, &real_server)
            .unwrap_err(),
        ClientError::Authentication
    );
}

#[test]
fn unknown_account_gets_fake_response_that_fails_like_a_wrong_password() {
    let server = OpaqueServer::generate();
    let (client, server_id) = ids();
    let opw = SymmetricKey::from_bytes([7; 32]);

    let (client_state, ke1) = start_login(&opw).unwrap();
    let (_, ke2) = server.start_login(None, &ke1, &client, &server_id).unwrap();
    assert_eq!(
        client_state
            .finish(&opw, &ke2, &client, &server_id)
            .unwrap_err(),
        ClientError::Authentication
    );
}

#[test]
fn fake_and_real_responses_have_the_same_size() {
    let account = create_account();
    let (client, server_id) = ids();
    let opw = SymmetricKey::from_bytes([7; 32]);
    let (_, ke1) = start_login(&opw).unwrap();

    let (_, real) = account
        .server
        .start_login(Some(&account.record), &ke1, &client, &server_id)
        .unwrap();
    let (_, fake) = account
        .server
        .start_login(None, &ke1, &client, &server_id)
        .unwrap();
    assert_eq!(real.len(), fake.len());
}

#[test]
fn tampered_ke2_is_rejected() {
    let account = create_account();
    let (client, server_id) = ids();
    let opw = opaque_password(
        "correct horse battery staple",
        &account.secret_key,
        &account.salt,
    );

    let (client_state, ke1) = start_login(&opw).unwrap();
    let (_, mut ke2) = account
        .server
        .start_login(Some(&account.record), &ke1, &client, &server_id)
        .unwrap();
    let last = ke2.len() - 1;
    ke2[last] ^= 0x01;
    assert!(
        client_state
            .finish(&opw, &ke2, &client, &server_id)
            .is_err()
    );
}

#[test]
fn ke3_from_another_session_is_rejected() {
    let account = create_account();
    let (client, server_id) = ids();
    let opw = opaque_password(
        "correct horse battery staple",
        &account.secret_key,
        &account.salt,
    );

    // First session completes normally.
    let (c1, ke1_a) = start_login(&opw).unwrap();
    let (_, ke2_a) = account
        .server
        .start_login(Some(&account.record), &ke1_a, &client, &server_id)
        .unwrap();
    let done_a = c1.finish(&opw, &ke2_a, &client, &server_id).unwrap();

    // A second session must not accept the first session's KE3.
    let (_, ke1_b) = start_login(&opw).unwrap();
    let (server_b, _) = account
        .server
        .start_login(Some(&account.record), &ke1_b, &client, &server_id)
        .unwrap();
    assert!(server_b.finish(&done_a.ke3, &client, &server_id).is_err());
}

#[test]
fn malformed_messages_are_rejected_without_panicking() {
    let server = OpaqueServer::generate();
    let (client, server_id) = ids();
    for junk in [&[][..], &[0_u8; 1][..], &[0xFF_u8; 500][..]] {
        assert!(server.registration_response(junk, &client).is_err());
        assert!(finish_registration(junk).is_err());
        assert!(server.start_login(None, junk, &client, &server_id).is_err());
        assert!(ServerLoginState::from_bytes(junk).is_err());
        assert!(OpaqueServer::from_bytes(junk).is_err());
    }
}

#[test]
fn messages_with_trailing_bytes_are_rejected() {
    let account = create_account();
    let (client, server_id) = ids();
    let opw = opaque_password(
        "correct horse battery staple",
        &account.secret_key,
        &account.salt,
    );

    let (_, mut ke1) = start_login(&opw).unwrap();
    let (state, _) = account
        .server
        .start_login(Some(&account.record), &ke1, &client, &server_id)
        .unwrap();
    let mut stored = state.to_bytes().to_vec();
    stored.push(0);
    assert!(ServerLoginState::from_bytes(&stored).is_err());

    ke1.push(0);
    assert!(
        account
            .server
            .start_login(Some(&account.record), &ke1, &client, &server_id)
            .is_err()
    );

    let mut record = account.record.clone();
    record.push(0);
    let (_, ke1) = start_login(&opw).unwrap();
    assert!(
        account
            .server
            .start_login(Some(&record), &ke1, &client, &server_id)
            .is_err()
    );
}

#[test]
fn client_rejects_ke2_with_trailing_bytes() {
    let account = create_account();
    let (client, server_id) = ids();
    let opw = opaque_password(
        "correct horse battery staple",
        &account.secret_key,
        &account.salt,
    );

    let (client_state, ke1) = start_login(&opw).unwrap();
    let (_, mut ke2) = account
        .server
        .start_login(Some(&account.record), &ke1, &client, &server_id)
        .unwrap();
    ke2.push(0);
    assert_eq!(
        client_state
            .finish(&opw, &ke2, &client, &server_id)
            .unwrap_err(),
        ClientError::MalformedMessage
    );
}
