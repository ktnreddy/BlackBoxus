//! End-to-end use of the server API handlers (spec section 12): a client
//! creates an account, signs in, adds a second device and looks up keys,
//! against a simple in-memory adapter.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::collections::HashMap;

use server_core::Error;
use server_core::api::{
    AccountRecord, Api, EnrolmentTransfer, LOGIN_TTL_MS, NewAccount, PendingLogin, Session,
    accept_enrolment, session_token_hash, take_enrolment,
};
use server_core::login::OpaqueServer;
use server_core::prelogin::FakeSaltKey;
use server_core::transparency::KtLog;
use vault_core::device::{EnrolmentOffer, EnrolmentPayload};
use vault_core::login::{SessionToken, start_login, start_registration};
use vault_core::transparency::{KeyLookup, TreeHead, verify_key_lookup};
use vault_core::{
    AccountId, AccountSalt, ClientIdentity, IdentityPublicKey, IdentitySecretKey, KdfParams,
    KeySet, MasterPassword, SecretKey, ServerIdentity, UnlockMethod, derive_account_keys,
};

const ORIGIN: &str = "https://api.blackboxus.test";
const PASSWORD: &str = "correct horse battery staple";

/// The in-memory stand-in for the hosting adapter.
struct Server {
    api: Api,
    log_public: IdentityPublicKey,
    accounts: HashMap<ClientIdentity, AccountRecord>,
    leaves: HashMap<AccountId, (u64, Vec<u8>)>,
    log: KtLog,
    logins: HashMap<[u8; 16], PendingLogin>,
    sessions: HashMap<[u8; 32], Session>,
    enrolments: HashMap<[u8; 16], EnrolmentTransfer>,
}

impl Server {
    fn new() -> Self {
        let log_key = IdentitySecretKey::generate().unwrap();
        let log_public = log_key.public_key();
        Self {
            api: Api::new(
                OpaqueServer::generate(),
                FakeSaltKey::from_bytes(&[3; 32]).unwrap(),
                log_key,
                ServerIdentity::new(ORIGIN).unwrap(),
            ),
            log_public,
            accounts: HashMap::new(),
            leaves: HashMap::new(),
            log: KtLog::new(),
            logins: HashMap::new(),
            sessions: HashMap::new(),
            enrolments: HashMap::new(),
        }
    }

    fn prelogin(&self, email: &str) -> (AccountSalt, KdfParams) {
        let id = ClientIdentity::new(email).unwrap();
        self.api.prelogin(&id, self.accounts.get(&id)).unwrap()
    }

    fn register(&mut self, request: &NewAccount<'_>, now: u64) -> Result<(), Error> {
        let (record, leaf) = self.api.create_account(request, now)?;
        if self.accounts.contains_key(&record.identity)
            || self.leaves.contains_key(&record.account_id)
        {
            return Err(Error::Conflict);
        }
        let index = self.log.append(&leaf)?;
        self.leaves
            .insert(record.account_id, (index, leaf.to_vec()));
        self.accounts.insert(record.identity.clone(), record);
        Ok(())
    }

    fn login_start(&mut self, email: &str, ke1: &[u8], now: u64) -> ([u8; 16], Vec<u8>) {
        let id = ClientIdentity::new(email).unwrap();
        let (pending, ke2) = self
            .api
            .start_login(&id, self.accounts.get(&id), ke1, now)
            .unwrap();
        let login_id = pending.login_id;
        self.logins.insert(login_id, pending);
        (login_id, ke2)
    }

    fn login_finish(&mut self, login_id: [u8; 16], ke3: &[u8], now: u64) -> Result<(), Error> {
        let pending = self.logins.remove(&login_id).ok_or(Error::Authentication)?;
        let session = self.api.finish_login(pending, ke3, now)?;
        self.sessions.insert(session.token_hash, session);
        Ok(())
    }

    fn authenticate(&mut self, token: &[u8], now: u64) -> Result<AccountId, Error> {
        let hash = session_token_hash(token)?;
        match self.api.authenticate(token, self.sessions.get(&hash), now) {
            Ok(s) => {
                let id = s.account_id;
                self.sessions.insert(hash, s);
                Ok(id)
            }
            Err(e) => {
                self.sessions.remove(&hash);
                Err(e)
            }
        }
    }

    fn logout(&mut self, token: &[u8], now: u64) {
        self.authenticate(token, now).unwrap();
        self.sessions.remove(&session_token_hash(token).unwrap());
    }

    fn key_lookup(&self, account_id: &AccountId, seen: Option<u64>, now: u64) -> Vec<u8> {
        let account = self
            .accounts
            .values()
            .find(|a| a.account_id == *account_id)
            .unwrap();
        let (index, leaf) = &self.leaves[account_id];
        let r = self
            .api
            .key_lookup(&self.log, account, leaf, *index, seen, now)
            .unwrap();
        pack(&r)
    }
}

/// Packs a lookup response so the client side below has to unpack it, as
/// it would from JSON in the real API.
fn pack(r: &server_core::api::KeyLookupResponse) -> Vec<u8> {
    let mut out = Vec::new();
    for part in [&r.signed_bundle, &r.leaf, &r.signed_tree_head] {
        out.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(&r.leaf_index.to_be_bytes());
    for proof in [&r.inclusion_proof, &r.consistency_proof] {
        out.extend_from_slice(&u32::try_from(proof.len()).unwrap().to_be_bytes());
        for h in proof {
            out.extend_from_slice(h);
        }
    }
    out
}

fn verify_lookup(packed: &[u8], log_key: &IdentityPublicKey, last: Option<&TreeHead>) -> TreeHead {
    let mut at = 0;
    let mut take = |n: usize| {
        let s = &packed[at..at + n];
        at += n;
        s.to_vec()
    };
    let mut blob = || {
        let n = u32::from_be_bytes(take(4).try_into().unwrap()) as usize;
        take(n)
    };
    let (bundle, leaf, sth) = (blob(), blob(), blob());
    let index = u64::from_be_bytes(take(8).try_into().unwrap());
    let mut hashes = || {
        let n = u32::from_be_bytes(take(4).try_into().unwrap()) as usize;
        (0..n)
            .map(|_| <[u8; 32]>::try_from(take(32)).unwrap())
            .collect::<Vec<_>>()
    };
    let (inclusion, consistency) = (hashes(), hashes());
    verify_key_lookup(
        &KeyLookup {
            signed_bundle: &bundle,
            leaf: &leaf,
            leaf_index: index,
            inclusion_proof: &inclusion,
            signed_tree_head: &sth,
            consistency_proof: &consistency,
        },
        log_key,
        last,
    )
    .unwrap()
    .1
}

/// A client's local state after creating an account.
struct Client {
    email: String,
    account_id: AccountId,
    secret_key: SecretKey,
}

fn opaque_password(
    secret_key: &SecretKey,
    salt: &AccountSalt,
    kdf: &KdfParams,
) -> vault_core::SymmetricKey {
    derive_account_keys(
        &MasterPassword::new(PASSWORD).unwrap(),
        secret_key,
        salt,
        kdf,
    )
    .unwrap()
    .opaque_password
}

fn create_account(server: &mut Server, email: &str, now: u64) -> Client {
    let identity = ClientIdentity::new(email).unwrap();
    let server_id = ServerIdentity::new(ORIGIN).unwrap();
    let secret_key = SecretKey::generate().unwrap();
    let salt = AccountSalt::generate().unwrap();
    let kdf = KdfParams::MIN;
    let account_keys = derive_account_keys(
        &MasterPassword::new(PASSWORD).unwrap(),
        &secret_key,
        &salt,
        &kdf,
    )
    .unwrap();
    let (state, request) = start_registration(&account_keys.opaque_password).unwrap();
    let response = server
        .api
        .registration_response(&identity, &request)
        .unwrap();
    let upload = state
        .finish(
            &account_keys.opaque_password,
            &response,
            &identity,
            &server_id,
        )
        .unwrap();

    let account_id = AccountId::generate().unwrap();
    let keys = KeySet::generate().unwrap();
    let bundle = keys.signed_public_bundle(&account_id, 1).unwrap();
    let wrapped = keys
        .wrap(
            &account_keys.account_unlock_key,
            &account_id,
            1,
            UnlockMethod::MasterPassword,
        )
        .unwrap();
    server
        .register(
            &NewAccount {
                email,
                salt,
                kdf,
                registration_upload: &upload,
                signed_bundle: &bundle,
                wrapped_key_set: &wrapped,
            },
            now,
        )
        .unwrap();
    Client {
        email: email.to_owned(),
        account_id,
        secret_key,
    }
}

/// Signs in the way a client does: prelogin, derive, OPAQUE.
fn sign_in(
    server: &mut Server,
    email: &str,
    secret_key: &SecretKey,
    now: u64,
) -> Result<SessionToken, Error> {
    let identity = ClientIdentity::new(email).unwrap();
    let server_id = ServerIdentity::new(ORIGIN).unwrap();
    let (salt, kdf) = server.prelogin(email);
    let opw = opaque_password(secret_key, &salt, &kdf);
    let (state, ke1) = start_login(&opw).unwrap();
    let (login_id, ke2) = server.login_start(email, &ke1, now);
    let done = state
        .finish(&opw, &ke2, &identity, &server_id)
        .map_err(|_| Error::Authentication)?;
    server.login_finish(login_id, &done.ke3, now)?;
    Ok(done.session_token)
}

#[test]
fn account_lifecycle() {
    let mut server = Server::new();
    let alice = create_account(&mut server, "alice@example.com", 1_000);
    let bob = create_account(&mut server, "bob@example.com", 2_000);

    // Prelogin answers are the same shape for real and unknown accounts,
    // and stable for unknown ones.
    let real = server.prelogin("Alice@Example.com");
    assert_eq!(real.1, KdfParams::MIN);
    assert_eq!(
        server.prelogin("nobody@example.com"),
        server.prelogin("nobody@example.com")
    );

    // Signing in with the right password and Secret Key.
    let token = sign_in(&mut server, "alice@example.com", &alice.secret_key, 10_000).unwrap();
    assert_eq!(
        server.authenticate(token.as_bytes(), 20_000).unwrap(),
        alice.account_id
    );

    // The wrong Secret Key, or an unknown address, fails the same way.
    let wrong = SecretKey::generate().unwrap();
    assert_eq!(
        sign_in(&mut server, "alice@example.com", &wrong, 10_000).unwrap_err(),
        Error::Authentication
    );
    assert_eq!(
        sign_in(&mut server, "nobody@example.com", &wrong, 10_000).unwrap_err(),
        Error::Authentication
    );

    // Alice looks up Bob's keys and verifies them through key transparency.
    let head = verify_lookup(
        &server.key_lookup(&bob.account_id, None, 30_000),
        &server.log_public,
        None,
    );
    assert_eq!(head.tree_size, 2);
    let carol = create_account(&mut server, "carol@example.com", 40_000);
    let head = verify_lookup(
        &server.key_lookup(&carol.account_id, Some(head.tree_size), 50_000),
        &server.log_public,
        Some(&head),
    );
    assert_eq!(head.tree_size, 3);

    // Alice adds a second device with a QR code.
    let offer = EnrolmentOffer::generate().unwrap();
    let payload = EnrolmentPayload {
        account_id: alice.account_id,
        email: ClientIdentity::new(&alice.email).unwrap(),
        server: ServerIdentity::new(ORIGIN).unwrap(),
        secret_key: alice.secret_key.clone(),
        signed_tree_head: None,
    };
    server.authenticate(token.as_bytes(), 60_000).unwrap();
    let transfer = accept_enrolment(&offer.seal(&payload).unwrap(), 60_000).unwrap();
    server.enrolments.insert(*offer.session_id(), transfer);
    let picked = take_enrolment(server.enrolments.remove(offer.session_id()), 70_000).unwrap();
    assert!(take_enrolment(server.enrolments.remove(offer.session_id()), 70_000).is_err());
    let received = offer.open(&picked).unwrap();
    let token2 = sign_in(
        &mut server,
        received.email.as_str(),
        &received.secret_key,
        80_000,
    )
    .unwrap();
    assert_ne!(token, token2);

    // Signing out ends only that session.
    server.logout(token.as_bytes(), 90_000);
    assert_eq!(
        server.authenticate(token.as_bytes(), 90_001).unwrap_err(),
        Error::Authentication
    );
    assert!(server.authenticate(token2.as_bytes(), 90_001).is_ok());
}

#[test]
fn duplicate_accounts_and_bad_uploads_are_rejected() {
    let mut server = Server::new();
    let alice = create_account(&mut server, "alice@example.com", 0);
    let record = server.accounts[&ClientIdentity::new("alice@example.com").unwrap()].clone();

    // Same email address again.
    let identity = ClientIdentity::new("alice@example.com").unwrap();
    let (state, request) = start_registration(&opaque_password(
        &alice.secret_key,
        &record.salt,
        &record.kdf,
    ))
    .unwrap();
    let response = server
        .api
        .registration_response(&identity, &request)
        .unwrap();
    let upload = state
        .finish(
            &opaque_password(&alice.secret_key, &record.salt, &record.kdf),
            &response,
            &identity,
            &ServerIdentity::new(ORIGIN).unwrap(),
        )
        .unwrap();
    let mut request = NewAccount {
        email: "ALICE@example.com",
        salt: record.salt,
        kdf: record.kdf,
        registration_upload: &upload,
        signed_bundle: &record.signed_bundle,
        wrapped_key_set: &record.wrapped_key_set,
    };
    assert_eq!(server.register(&request, 1).unwrap_err(), Error::Conflict);

    // A tampered bundle, a wrapped key set for another method, weak KDF
    // parameters and junk OPAQUE uploads are refused before storage.
    request.email = "new@example.com";
    let mut bundle = record.signed_bundle.clone();
    bundle[100] ^= 1;
    request.signed_bundle = &bundle;
    assert_eq!(
        server.register(&request, 1).unwrap_err(),
        Error::MalformedMessage
    );
    request.signed_bundle = &record.signed_bundle;

    let mut wrapped = record.wrapped_key_set.clone();
    wrapped[6] = 3;
    request.wrapped_key_set = &wrapped;
    assert_eq!(
        server.register(&request, 1).unwrap_err(),
        Error::MalformedMessage
    );
    request.wrapped_key_set = &record.wrapped_key_set;

    request.kdf = KdfParams {
        memory_kib: 1024,
        ..KdfParams::MIN
    };
    assert_eq!(
        server.register(&request, 1).unwrap_err(),
        Error::MalformedMessage
    );
    request.kdf = record.kdf;

    request.registration_upload = &upload[..upload.len() - 1];
    assert_eq!(
        server.register(&request, 1).unwrap_err(),
        Error::MalformedMessage
    );
    request.registration_upload = &upload;

    // The bundle's account ID is already taken.
    assert_eq!(server.register(&request, 1).unwrap_err(), Error::Conflict);
}

#[test]
fn logins_are_single_use_and_expire() {
    let mut server = Server::new();
    let alice = create_account(&mut server, "alice@example.com", 0);
    let identity = ClientIdentity::new("alice@example.com").unwrap();
    let server_id = ServerIdentity::new(ORIGIN).unwrap();
    let (salt, kdf) = server.prelogin("alice@example.com");
    let opw = opaque_password(&alice.secret_key, &salt, &kdf);

    // Expired.
    let (state, ke1) = start_login(&opw).unwrap();
    let (login_id, ke2) = server.login_start("alice@example.com", &ke1, 0);
    let done = state.finish(&opw, &ke2, &identity, &server_id).unwrap();
    assert_eq!(
        server
            .login_finish(login_id, &done.ke3, LOGIN_TTL_MS)
            .unwrap_err(),
        Error::Authentication
    );
    // Replayed: the pending login was deleted on first use.
    assert_eq!(
        server.login_finish(login_id, &done.ke3, 1).unwrap_err(),
        Error::Authentication
    );
}
