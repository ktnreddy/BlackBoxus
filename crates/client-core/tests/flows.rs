//! Every client flow against an in-memory server that speaks the real JSON
//! API, built from `server-core`'s handlers and `server-worker`'s routing,
//! exactly as the Cloudflare Worker uses them.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::collections::{BTreeMap, HashMap, HashSet};

use client_core::enrolment::{fetch_request, offer_request, offer_sent, receive};
use client_core::keys::KeyDirectory;
use client_core::login::{Login, Unlocked};
use client_core::signup::{NewAccount, Signup};
use client_core::{ClientError, Request, Response};
use server_core::api::{
    AccountRecord, Api, EnrolmentTransfer, NewAccount as ServerNewAccount, PendingLogin, Session,
    accept_enrolment, require_fresh_session, session_token_hash, take_enrolment,
};
use server_core::login::OpaqueServer;
use server_core::prelogin::FakeSaltKey;
use server_core::recovery::{
    NewPassword, RecoveryRecord, accept_recovery_key, recovery_finish, recovery_start,
};
use server_core::transparency::KtLog;
use server_core::vaults::{
    self as server_vaults, ItemWrite, VaultRules, accept_append, accept_owner_key, touched_item,
};
use server_worker::http::{self, ApiError, Route};
use vault_core::device::EnrolmentOffer;
use vault_core::log::Checkpoint;
use vault_core::{
    AccountId, AccountSalt, ClientIdentity, IdentityPublicKey, IdentitySecretKey, KdfParams,
    SecretKey, ServerIdentity,
};
use vault_core::{ItemId, VaultId};

const ORIGIN: &str = "https://api.blackboxus.test";
const PASSWORD: &str = "correct horse battery staple";

/// An in-memory stand-in for the Worker: same routes, JSON and handlers.
struct Server {
    api: Api,
    log_key: IdentityPublicKey,
    accounts: Vec<AccountRecord>,
    leaves: HashMap<AccountId, (u64, Vec<u8>)>,
    log: KtLog,
    logins: HashMap<[u8; 16], PendingLogin>,
    sessions: HashMap<[u8; 32], Session>,
    enrolments: HashMap<[u8; 16], EnrolmentTransfer>,
    now: u64,
    /// When set, tamper with key lookups to simulate a malicious server.
    swap_bundles: bool,
    vaults: Vaults,
    recovery: HashMap<AccountId, RecoveryRecord>,
}

/// An item's revision, envelope (none if deleted) and log sequence.
type StoredItem = (u64, Option<Vec<u8>>, u64);

/// Vault storage, as in migrations 0002 and 0003.
#[derive(Default)]
struct Vaults {
    logs: HashMap<VaultId, Vec<(Vec<u8>, Checkpoint)>>,
    rules: HashMap<VaultId, VaultRules>,
    items: HashMap<VaultId, BTreeMap<ItemId, StoredItem>>,
    access: HashSet<(VaultId, AccountId)>,
    keys: HashMap<(VaultId, AccountId), BTreeMap<u32, Vec<u8>>>,
    shares: Vec<(AccountId, Vec<u8>)>,
    /// When set, answer log reads with the vault's first entry again.
    replay_first: bool,
}

impl Server {
    fn new() -> Self {
        let log_secret = IdentitySecretKey::generate().unwrap();
        Self {
            log_key: log_secret.public_key(),
            api: Api::new(
                OpaqueServer::generate(),
                FakeSaltKey::from_bytes(&[4; 32]).unwrap(),
                log_secret,
                ServerIdentity::new(ORIGIN).unwrap(),
            ),
            accounts: Vec::new(),
            leaves: HashMap::new(),
            log: KtLog::new(),
            logins: HashMap::new(),
            sessions: HashMap::new(),
            enrolments: HashMap::new(),
            now: 1_000,
            swap_bundles: false,
            vaults: Vaults::default(),
            recovery: HashMap::new(),
        }
    }

    fn send(&mut self, req: &Request) -> Response {
        self.now += 10;
        let (status, body) = match self.handle(req) {
            Ok(body) => (200, body),
            Err(e) => (e.status(), e.body()),
        };
        Response {
            status,
            retry_after: None,
            body: body.into_bytes(),
        }
    }

    fn session(&self, req: &Request) -> Result<Session, ApiError> {
        let token = http::bearer_token(req.authorization.as_deref())?;
        let hash = session_token_hash(&token)?;
        Ok(self
            .api
            .authenticate(&token, self.sessions.get(&hash), self.now)?)
    }

    fn by_email(&self, email: &ClientIdentity) -> Option<&AccountRecord> {
        self.accounts.iter().find(|a| a.identity == *email)
    }

    fn handle(&mut self, req: &Request) -> Result<String, ApiError> {
        let (path, query) = req.path.split_once('?').unwrap_or((&req.path, ""));
        let body = req.body.clone().unwrap_or_default();
        let json = |v: &dyn erased::Json| Ok(v.to_json());
        match http::route(req.method.as_str(), path)? {
            Route::Prelogin => {
                let r: http::PreloginRequest = http::parse_json(body.as_bytes())?;
                let id = ClientIdentity::new(&r.email).unwrap();
                let (salt, kdf) = self.api.prelogin(&id, self.by_email(&id))?;
                json(&http::PreloginResponse {
                    salt: http::b64(salt.as_bytes()),
                    kdf: kdf.into(),
                })
            }
            Route::RegisterStart => {
                let r: http::RegisterStartRequest = http::parse_json(body.as_bytes())?;
                let id = ClientIdentity::new(&r.email).unwrap();
                let response = self
                    .api
                    .registration_response(&id, &http::unb64(&r.request, 1024)?)?;
                json(&http::RegisterStartResponse {
                    response: http::b64(&response),
                })
            }
            Route::RegisterFinish => {
                let r: http::RegisterFinishRequest = http::parse_json(body.as_bytes())?;
                let upload = http::unb64(&r.upload, 1024)?;
                let bundle = http::unb64(&r.signed_bundle, 8192)?;
                let wrapped = http::unb64(&r.wrapped_key_set, 175)?;
                let (record, leaf) = self.api.create_account(
                    &ServerNewAccount {
                        email: &r.email,
                        salt: AccountSalt::from_bytes(http::unb64_array(&r.salt)?),
                        kdf: KdfParams::from(r.kdf),
                        registration_upload: &upload,
                        signed_bundle: &bundle,
                        wrapped_key_set: &wrapped,
                    },
                    self.now,
                )?;
                if self.by_email(&record.identity).is_some() {
                    return Err(ApiError::Core(server_core::Error::Conflict));
                }
                let index = self.log.append(&leaf)?;
                self.leaves
                    .insert(record.account_id, (index, leaf.to_vec()));
                let account_id = http::b64(record.account_id.as_bytes());
                self.accounts.push(record);
                json(&http::RegisterFinishResponse { account_id })
            }
            Route::LoginStart => {
                let r: http::LoginStartRequest = http::parse_json(body.as_bytes())?;
                let id = ClientIdentity::new(&r.email).unwrap();
                let account = self.by_email(&id).cloned();
                let (pending, ke2) = self.api.start_login(
                    &id,
                    account.as_ref(),
                    &http::unb64(&r.ke1, 1024)?,
                    self.now,
                )?;
                let login_id = http::b64(&pending.login_id);
                self.logins.insert(pending.login_id, pending);
                json(&http::LoginStartResponse {
                    login_id,
                    ke2: http::b64(&ke2),
                })
            }
            Route::LoginFinish => {
                let r: http::LoginFinishRequest = http::parse_json(body.as_bytes())?;
                let id: [u8; 16] = http::unb64_array(&r.login_id)?;
                let pending = self
                    .logins
                    .remove(&id)
                    .ok_or(ApiError::Core(server_core::Error::Authentication))?;
                let session =
                    self.api
                        .finish_login(pending, &http::unb64(&r.ke3, 1024)?, self.now)?;
                self.sessions.insert(session.token_hash, session);
                Ok("{}".into())
            }
            Route::Logout => {
                let s = self.session(req)?;
                self.sessions.remove(&s.token_hash);
                Ok("{}".into())
            }
            Route::KeySet => {
                let s = self.session(req)?;
                let a = self
                    .accounts
                    .iter()
                    .find(|a| a.account_id == s.account_id)
                    .unwrap();
                let mut wrapped = vec![http::WrappedJson {
                    method: 1,
                    data: http::b64(&a.wrapped_key_set),
                }];
                if let Some(r) = self.recovery.get(&a.account_id) {
                    wrapped.push(http::WrappedJson {
                        method: 4,
                        data: http::b64(&r.wrapped_key_set),
                    });
                }
                json(&http::KeySetResponse {
                    account_id: http::b64(a.account_id.as_bytes()),
                    key_set_version: a.key_set_version,
                    wrapped,
                })
            }
            Route::RecoveryPut => {
                let s = self.session(req)?;
                require_fresh_session(&s, self.now)?;
                let r: http::RecoveryPutRequest = http::parse_json(body.as_bytes())?;
                let a = self
                    .accounts
                    .iter()
                    .find(|a| a.account_id == s.account_id)
                    .unwrap();
                let record = accept_recovery_key(
                    a,
                    &http::unb64(&r.verifier, 32)?,
                    &http::unb64(&r.wrapped_key_set, 175)?,
                )?;
                self.recovery.insert(s.account_id, record);
                Ok("{}".into())
            }
            Route::RecoveryDelete => {
                let s = self.session(req)?;
                require_fresh_session(&s, self.now)?;
                self.recovery.remove(&s.account_id);
                Ok("{}".into())
            }
            Route::RecoveryStart => {
                let r: http::RecoveryStartRequest = http::parse_json(body.as_bytes())?;
                let id = ClientIdentity::new(&r.email).unwrap();
                let found = self
                    .by_email(&id)
                    .and_then(|a| Some((a, self.recovery.get(&a.account_id)?)));
                let (account_id, wrapped) =
                    recovery_start(found, &http::unb64(&r.auth_token, 32)?)?;
                json(&http::RecoveryStartResponse {
                    account_id: http::b64(account_id.as_bytes()),
                    wrapped_key_set: http::b64(&wrapped),
                })
            }
            Route::RecoveryFinish => {
                let r: http::RecoveryFinishRequest = http::parse_json(body.as_bytes())?;
                let id = ClientIdentity::new(&r.email).unwrap();
                let found = self
                    .by_email(&id)
                    .and_then(|a| Some((a, self.recovery.get(&a.account_id)?)));
                let upload = http::unb64(&r.upload, 1024)?;
                let wrapped = http::unb64(&r.wrapped_key_set, 175)?;
                let record = recovery_finish(
                    found,
                    &http::unb64(&r.auth_token, 32)?,
                    &NewPassword {
                        registration_upload: &upload,
                        salt: AccountSalt::from_bytes(http::unb64_array(&r.salt)?),
                        kdf: KdfParams::from(r.kdf),
                        wrapped_key_set: &wrapped,
                    },
                )?;
                self.sessions
                    .retain(|_, s| s.account_id != record.account_id);
                let a = self
                    .accounts
                    .iter_mut()
                    .find(|a| a.account_id == record.account_id)
                    .unwrap();
                *a = record;
                Ok("{}".into())
            }
            Route::AccountKeys(id) => {
                self.session(req)?;
                let seen = http::parse_seen(Some(query))?;
                let mut account = self
                    .accounts
                    .iter()
                    .find(|a| a.account_id == id)
                    .ok_or(ApiError::NotFound)?
                    .clone();
                if self.swap_bundles {
                    // A malicious server substituting another account's keys.
                    let other = self.accounts.iter().find(|a| a.account_id != id).unwrap();
                    account.signed_bundle = other.signed_bundle.clone();
                }
                let (index, leaf) = &self.leaves[&id];
                let r = self
                    .api
                    .key_lookup(&self.log, &account, leaf, *index, seen, self.now)?;
                json(&http::lookup_json(r))
            }
            Route::EnrolmentPut(id) => {
                self.session(req)?;
                let r: http::EnrolmentPutRequest = http::parse_json(body.as_bytes())?;
                let t = accept_enrolment(&http::unb64(&r.sealed, 8192)?, self.now)?;
                if self.enrolments.contains_key(&id) {
                    return Err(ApiError::Core(server_core::Error::Conflict));
                }
                self.enrolments.insert(id, t);
                Ok("{}".into())
            }
            Route::EnrolmentGet(id) => {
                let sealed = take_enrolment(self.enrolments.remove(&id), self.now)?;
                json(&http::EnrolmentGetResponse {
                    sealed: http::b64(&sealed),
                })
            }
            Route::Vaults => {
                let s = self.session(req)?;
                let vaults = self
                    .vaults
                    .access
                    .iter()
                    .filter(|(_, a)| *a == s.account_id)
                    .map(|(v, _)| http::VaultSummary {
                        vault_id: http::b64(v.as_bytes()),
                        head_seq: self.vaults.logs[v].len() as u64 - 1,
                    })
                    .collect();
                json(&http::VaultListResponse { vaults })
            }
            Route::LogAppend(v) => {
                let s = self.session(req)?;
                let r: http::LogAppendRequest = http::parse_json(body.as_bytes())?;
                let entry = http::unb64(&r.entry, 4096)?;
                let envelope = r
                    .envelope
                    .as_deref()
                    .map(|e| http::unb64(e, 40_000))
                    .transpose()?;
                // The stored rules, with the item the entry changes.
                let item = touched_item(&entry)?
                    .and_then(|id| Some((id, self.vaults.items.get(&v)?.get(&id)?)));
                let rules = self.vaults.rules.get(&v).cloned().map(|r| match item {
                    Some((id, (revision, envelope, _))) => {
                        r.with_item(id, *revision, envelope.is_none())
                    }
                    None => r,
                });
                let a = accept_append(&v, rules, &s.account_id, &entry, envelope.as_deref())?;
                let seq = a.checkpoint.seq;
                self.vaults
                    .logs
                    .entry(v)
                    .or_default()
                    .push((entry, a.checkpoint));
                self.vaults.rules.insert(v, a.rules.clone());
                if a.creates_vault {
                    self.vaults.access.insert((v, s.account_id));
                }
                if let Some(added) = a.added {
                    self.vaults.access.insert((v, added));
                }
                if let Some(removed) = a.removed {
                    self.vaults.access.remove(&(v, removed));
                    self.vaults.keys.remove(&(v, removed));
                    self.vaults.shares.retain(|(r, share)| {
                        *r != removed
                            || vault_core::ShareInfo::inspect(share).unwrap().vault_id != v
                    });
                }
                let items = self.vaults.items.entry(v).or_default();
                match a.item {
                    Some(ItemWrite::Put {
                        item_id,
                        revision,
                        envelope,
                    }) => {
                        items.insert(item_id, (revision, Some(envelope), seq));
                    }
                    Some(ItemWrite::Delete { item_id, revision }) => {
                        items.insert(item_id, (revision, None, seq));
                    }
                    None => {}
                }
                json(&http::LogAppendResponse { seq })
            }
            Route::LogRead(v) => {
                let s = self.session(req)?;
                if !self.vaults.access.contains(&(v, s.account_id)) {
                    return Err(ApiError::Core(server_core::Error::NotAllowed));
                }
                let from = http::parse_number(Some(query), "from")?.unwrap_or(0) as usize;
                let mut entries: Vec<String> = self.vaults.logs[&v]
                    .iter()
                    .skip(from)
                    .map(|(e, _)| http::b64(e))
                    .collect();
                if self.vaults.replay_first {
                    entries = vec![http::b64(&self.vaults.logs[&v][0].0)];
                }
                // Pages of two, to exercise "more".
                let more = entries.len() > 2;
                entries.truncate(2);
                json(&http::LogResponse { entries, more })
            }
            Route::Items(v) => {
                let s = self.session(req)?;
                if !self.vaults.access.contains(&(v, s.account_id)) {
                    return Err(ApiError::Core(server_core::Error::NotAllowed));
                }
                let after = http::parse_number(Some(query), "after")?;
                let mut items: Vec<http::ItemJson> = self
                    .vaults
                    .items
                    .get(&v)
                    .into_iter()
                    .flatten()
                    .filter(|(_, (_, _, seq))| after.is_none_or(|a| *seq > a))
                    .map(|(id, (revision, envelope, seq))| http::ItemJson {
                        item_id: http::b64(id.as_bytes()),
                        revision: *revision,
                        envelope: envelope.as_deref().map(http::b64),
                        seq: *seq,
                    })
                    .collect();
                items.sort_by_key(|i| i.seq);
                json(&http::ItemsResponse { items, more: false })
            }
            Route::VaultKeyPut(v) => {
                let s = self.session(req)?;
                let r: http::VaultKeyPutRequest = http::parse_json(body.as_bytes())?;
                let wrapped = http::unb64(&r.wrapped, 94)?;
                let member = self
                    .vaults
                    .rules
                    .get(&v)
                    .is_some_and(|r| r.role(&s.account_id).is_some());
                let version = accept_owner_key(&v, member, &wrapped)?;
                self.vaults
                    .keys
                    .entry((v, s.account_id))
                    .or_default()
                    .insert(version, wrapped);
                Ok("{}".into())
            }
            Route::VaultKeys(v) => {
                let s = self.session(req)?;
                let keys = self
                    .vaults
                    .keys
                    .get(&(v, s.account_id))
                    .into_iter()
                    .flat_map(|m| m.values())
                    .map(|k| http::b64(k))
                    .collect();
                json(&http::VaultKeysResponse { keys })
            }
            Route::SharePost => {
                let s = self.session(req)?;
                let r: http::SharePostRequest = http::parse_json(body.as_bytes())?;
                let share = http::unb64(&r.share, 5000)?;
                let v = vault_core::ShareInfo::inspect(&share)
                    .map_err(|_| ApiError::Core(server_core::Error::MalformedMessage))?
                    .vault_id;
                let info =
                    server_vaults::accept_share(&share, &s.account_id, self.vaults.rules.get(&v))?;
                self.vaults.shares.push((info.recipient, share));
                Ok("{}".into())
            }
            Route::Shares => {
                let s = self.session(req)?;
                let shares = self
                    .vaults
                    .shares
                    .iter()
                    .filter(|(r, _)| *r == s.account_id)
                    .map(|(_, sh)| http::b64(sh))
                    .collect();
                json(&http::SharesResponse { shares })
            }
            Route::NotImplemented => Err(ApiError::NotImplemented),
        }
    }
}

mod erased {
    pub trait Json {
        fn to_json(&self) -> String;
    }
    impl<T: serde::Serialize> Json for T {
        fn to_json(&self) -> String {
            serde_json::to_string(self).unwrap()
        }
    }
}

fn server_id() -> ServerIdentity {
    ServerIdentity::new(ORIGIN).unwrap()
}

fn sign_up(server: &mut Server, email: &str) -> NewAccount {
    let (signup, req) = Signup::start(email, PASSWORD, &server_id(), KdfParams::MIN).unwrap();
    let (pending, req) = signup.register(&server.send(&req)).unwrap();
    pending.complete(&server.send(&req)).unwrap()
}

fn sign_in(
    server: &mut Server,
    email: &str,
    password: &str,
    secret_key: &SecretKey,
) -> Result<Unlocked, ClientError> {
    let (login, req) = Login::start(email, &server_id())?;
    let (started, req) = login.prelogin(&server.send(&req), password, secret_key)?;
    let (finishing, req) = started.key_exchange(&server.send(&req))?;
    let (unlocking, req) = finishing.finished(&server.send(&req))?;
    unlocking.unlock(&server.send(&req))
}

#[test]
fn sign_up_then_sign_in_unlocks_the_same_key_set() {
    let mut server = Server::new();
    let account = sign_up(&mut server, "alice@example.com");
    let kit = account.emergency_kit();
    assert_eq!(kit.email, "alice@example.com");
    assert_eq!(kit.server, ORIGIN);
    assert!(kit.secret_key.starts_with("B1-"));

    let unlocked = sign_in(
        &mut server,
        "Alice@Example.com",
        PASSWORD,
        &account.secret_key,
    )
    .unwrap();
    assert_eq!(*unlocked.session.account_id(), account.account_id);
    assert_eq!(unlocked.key_set_version, 1);
    assert_eq!(
        unlocked
            .key_set
            .signed_public_bundle(&account.account_id, 1)
            .map(|b| vault_core::PublicKeyBundle::verify_signed(&b)
                .unwrap()
                .identity),
        account
            .key_set
            .signed_public_bundle(&account.account_id, 1)
            .map(|b| vault_core::PublicKeyBundle::verify_signed(&b)
                .unwrap()
                .identity),
    );

    // Signing out ends the session.
    let req = unlocked.session.logout_request();
    assert_eq!(server.send(&req).status, 200);
    let directory = KeyDirectory::new(server.log_key.clone(), None);
    let lookup = directory.lookup_request(&account.account_id, &unlocked.session);
    assert_eq!(server.send(&lookup).status, 401);
}

#[test]
fn wrong_credentials_and_unknown_addresses_fail_the_same_way() {
    let mut server = Server::new();
    let account = sign_up(&mut server, "alice@example.com");
    let wrong_key = SecretKey::generate().unwrap();
    assert_eq!(
        sign_in(
            &mut server,
            "alice@example.com",
            "wrong password!",
            &account.secret_key
        )
        .unwrap_err(),
        ClientError::WrongCredentials
    );
    assert_eq!(
        sign_in(&mut server, "alice@example.com", PASSWORD, &wrong_key).unwrap_err(),
        ClientError::WrongCredentials
    );
    assert_eq!(
        sign_in(&mut server, "nobody@example.com", PASSWORD, &wrong_key).unwrap_err(),
        ClientError::WrongCredentials
    );
}

#[test]
fn sign_up_rejects_weak_passwords_and_taken_addresses() {
    let mut server = Server::new();
    assert!(matches!(
        Signup::start("alice@example.com", "short", &server_id(), KdfParams::MIN),
        Err(ClientError::Crypto(_))
    ));
    sign_up(&mut server, "alice@example.com");
    let (signup, req) =
        Signup::start("ALICE@example.com", PASSWORD, &server_id(), KdfParams::MIN).unwrap();
    let (pending, req) = signup.register(&server.send(&req)).unwrap();
    assert_eq!(
        pending.complete(&server.send(&req)).unwrap_err(),
        ClientError::Server {
            status: 409,
            code: "conflict".into()
        }
    );
}

#[test]
fn a_malicious_server_cannot_weaken_key_derivation() {
    let mut server = Server::new();
    let account = sign_up(&mut server, "alice@example.com");
    let (login, _) = Login::start("alice@example.com", &server_id()).unwrap();
    let weak = Response {
        status: 200,
        retry_after: None,
        body: br#"{"salt":"AAAAAAAAAAAAAAAAAAAAAA","kdf":{"m":8,"t":1,"p":1}}"#.to_vec(),
    };
    assert!(matches!(
        login.prelogin(&weak, PASSWORD, &account.secret_key),
        Err(ClientError::Crypto(
            vault_core::Error::KdfParamOutOfRange { .. }
        ))
    ));
}

#[test]
fn key_lookups_are_verified_and_substitution_is_caught() {
    let mut server = Server::new();
    let alice = sign_up(&mut server, "alice@example.com");
    let bob = sign_up(&mut server, "bob@example.com");
    let session = sign_in(
        &mut server,
        "alice@example.com",
        PASSWORD,
        &alice.secret_key,
    )
    .unwrap()
    .session;

    let mut directory = KeyDirectory::new(server.log_key.clone(), None);
    let req = directory.lookup_request(&bob.account_id, &session);
    let bundle = directory
        .verify(&bob.account_id, &server.send(&req))
        .unwrap();
    assert_eq!(bundle.bundle.account_id, bob.account_id);
    assert_eq!(directory.tree_head().unwrap().tree_size, 2);

    // The log grows; the next lookup carries a consistency proof.
    let carol = sign_up(&mut server, "carol@example.com");
    let req = directory.lookup_request(&carol.account_id, &session);
    assert!(req.path.ends_with("?seen=2"));
    directory
        .verify(&carol.account_id, &server.send(&req))
        .unwrap();
    assert_eq!(directory.tree_head().unwrap().tree_size, 3);

    // A server handing out someone else's keys is caught, and the stored
    // tree head is not changed by a failed lookup.
    server.swap_bundles = true;
    let req = directory.lookup_request(&bob.account_id, &session);
    assert!(
        directory
            .verify(&bob.account_id, &server.send(&req))
            .is_err()
    );
    assert_eq!(directory.tree_head().unwrap().tree_size, 3);

    // A tree head signed by another log key is rejected.
    server.swap_bundles = false;
    let mut impostor = KeyDirectory::new(IdentitySecretKey::generate().unwrap().public_key(), None);
    let req = impostor.lookup_request(&bob.account_id, &session);
    assert_eq!(
        impostor
            .verify(&bob.account_id, &server.send(&req))
            .unwrap_err(),
        ClientError::Crypto(vault_core::Error::InvalidSignature)
    );
}

#[test]
fn adding_a_device_by_qr_code() {
    let mut server = Server::new();
    let alice = sign_up(&mut server, "alice@example.com");
    let session = sign_in(
        &mut server,
        "alice@example.com",
        PASSWORD,
        &alice.secret_key,
    )
    .unwrap()
    .session;

    // Old device.
    let offer = EnrolmentOffer::generate().unwrap();
    let req = offer_request(
        &offer,
        &session,
        &alice.identity,
        &alice.server,
        &alice.secret_key,
        None,
    )
    .unwrap();
    offer_sent(&server.send(&req)).unwrap();

    // New device scans the QR code.
    let scanned = EnrolmentOffer::from_qr_text(&offer.to_qr_text()).unwrap();
    let payload = receive(&scanned, &server.send(&fetch_request(&scanned))).unwrap();
    assert_eq!(payload.account_id, alice.account_id);
    let second = sign_in(
        &mut server,
        payload.email.as_str(),
        PASSWORD,
        &payload.secret_key,
    )
    .unwrap();
    assert_eq!(*second.session.account_id(), alice.account_id);

    // The transfer can be taken only once.
    assert_eq!(
        receive(&scanned, &server.send(&fetch_request(&scanned))).unwrap_err(),
        ClientError::Server {
            status: 403,
            code: "not_allowed".into()
        }
    );
}

// ---------------------------------------------------------------------------
// Vaults

use client_core::keys::VerifiedKeys;
use client_core::vaults::{
    VaultReplica, accept_share, create_vault, list_request, receive_list, receive_shares,
    shares_request, written,
};
use vault_core::log::Role;
use vault_core::{Field, FieldKind, Item, ItemType};

fn lookup(server: &mut Server, unlocked: &Unlocked, account: &AccountId) -> VerifiedKeys {
    let mut directory = KeyDirectory::new(server.log_key.clone(), None);
    let req = directory.lookup_request(account, &unlocked.session);
    directory.verify(account, &server.send(&req)).unwrap()
}

/// A full sync, as an app would run it.
fn sync(
    server: &mut Server,
    replica: &mut VaultReplica,
    unlocked: &Unlocked,
) -> Result<(), ClientError> {
    while replica.receive_log(&server.send(&replica.log_request(unlocked)))? {}
    for author in replica.missing_authors()? {
        let keys = lookup(server, unlocked, &author);
        replica.add_author(&keys);
    }
    replica.verify()?;
    replica.receive_keys(unlocked, &server.send(&replica.keys_request(unlocked)))?;
    while replica.receive_items(&server.send(&replica.items_request(unlocked)))? {}
    Ok(())
}

fn login_item(title: &str, password: &str) -> Item {
    Item {
        item_type: ItemType::Login,
        created_ms: 1,
        modified_ms: 1,
        fields: vec![
            Field::new(FieldKind::Title, title),
            Field::new(FieldKind::Password, password),
        ],
    }
}

fn titles(replica: &VaultReplica) -> Vec<String> {
    let mut t: Vec<String> = replica
        .items()
        .unwrap()
        .into_iter()
        .map(|(_, item)| item.fields[0].value.to_string())
        .collect();
    t.sort();
    t
}

fn new_vault(server: &mut Server, unlocked: &Unlocked) -> VaultReplica {
    let own = lookup(server, unlocked, unlocked.session.account_id());
    let (mut replica, [log, key]) = create_vault(unlocked, &own, 1).unwrap();
    written(&server.send(&log)).unwrap();
    written(&server.send(&key)).unwrap();
    sync(server, &mut replica, unlocked).unwrap();
    replica
}

#[test]
fn create_write_sync_and_keep_a_local_copy() {
    let mut server = Server::new();
    let alice = sign_up(&mut server, "alice@example.com");
    let unlocked = sign_in(
        &mut server,
        "alice@example.com",
        PASSWORD,
        &alice.secret_key,
    )
    .unwrap();
    let mut vault = new_vault(&mut server, &unlocked);
    assert_eq!(
        receive_list(&server.send(&list_request(&unlocked))).unwrap(),
        vec![*vault.vault_id()]
    );

    let mut ids = Vec::new();
    for (title, pw) in [("bank", "b4nk"), ("mail", "m41l"), ("work", "w0rk")] {
        let (id, req) = vault
            .put_item(&unlocked, None, &login_item(title, pw), 2)
            .unwrap();
        written(&server.send(&req)).unwrap();
        sync(&mut server, &mut vault, &unlocked).unwrap();
        ids.push(id);
    }
    assert_eq!(titles(&vault), ["bank", "mail", "work"]);

    // Edit one item and delete another; a second device sees the same.
    let req = vault
        .put_item(&unlocked, Some(ids[0]), &login_item("bank (new)", "n3w"), 3)
        .unwrap()
        .1;
    written(&server.send(&req)).unwrap();
    sync(&mut server, &mut vault, &unlocked).unwrap();
    let req = vault.delete_item(&unlocked, &ids[1], 4).unwrap();
    written(&server.send(&req)).unwrap();
    sync(&mut server, &mut vault, &unlocked).unwrap();
    assert_eq!(titles(&vault), ["bank (new)", "work"]);
    let mut second = VaultReplica::new(*vault.vault_id());
    sync(&mut server, &mut second, &unlocked).unwrap();
    assert_eq!(titles(&second), ["bank (new)", "work"]);
    assert_eq!(second.checkpoint(), vault.checkpoint());

    // The encrypted local copy restores offline, and only for this account
    // and vault.
    let saved = vault.save(&unlocked).unwrap();
    let mut restored = VaultReplica::load(*vault.vault_id(), &unlocked, &saved).unwrap();
    restored
        .receive_keys(&unlocked, &server.send(&restored.keys_request(&unlocked)))
        .unwrap();
    assert_eq!(titles(&restored), ["bank (new)", "work"]);
    assert!(VaultReplica::load(VaultId::from_bytes([9; 16]), &unlocked, &saved).is_err());
    let mut tampered = saved.clone();
    tampered[40] ^= 1;
    assert!(VaultReplica::load(*vault.vault_id(), &unlocked, &tampered).is_err());
}

#[test]
fn offline_unlock_and_an_offline_local_copy() {
    use client_core::Session;
    use client_core::login::OfflineRecord;
    use vault_core::login::SessionToken;

    let mut server = Server::new();
    let alice = sign_up(&mut server, "alice@example.com");
    let (login, req) = Login::start("alice@example.com", &server_id()).unwrap();
    let (started, req) = login
        .prelogin(&server.send(&req), PASSWORD, &alice.secret_key)
        .unwrap();
    let (finishing, req) = started.key_exchange(&server.send(&req)).unwrap();
    let (unlocking, req) = finishing.finished(&server.send(&req)).unwrap();
    let (unlocked, record) = unlocking.unlock_keeping_record(&server.send(&req)).unwrap();
    let mut vault = new_vault(&mut server, &unlocked);
    let (_, req) = vault
        .put_item(&unlocked, None, &login_item("bank", "b4nk"), 2)
        .unwrap();
    written(&server.send(&req)).unwrap();
    sync(&mut server, &mut vault, &unlocked).unwrap();
    let saved = vault.save(&unlocked).unwrap();

    // Later, with no server: the record and the local copy are enough.
    let record = OfflineRecord::from_json(&record.to_json().unwrap()).unwrap();
    assert_eq!(
        record
            .unlock("wrong password", &alice.secret_key)
            .unwrap_err(),
        ClientError::WrongCredentials
    );
    let offline = record.unlock(PASSWORD, &alice.secret_key).unwrap();
    assert_eq!(offline.account_id, alice.account_id);
    let without_session = Unlocked {
        session: Session::restore(SessionToken::from_bytes([0; 32]), offline.account_id),
        key_set: offline.key_set,
        key_set_version: offline.key_set_version,
    };
    let restored = VaultReplica::load(*vault.vault_id(), &without_session, &saved).unwrap();
    assert_eq!(titles(&restored), ["bank"]);
}

#[test]
fn a_batch_of_new_items_verifies_in_one_sync() {
    let mut server = Server::new();
    let alice = sign_up(&mut server, "alice@example.com");
    let unlocked = sign_in(
        &mut server,
        "alice@example.com",
        PASSWORD,
        &alice.secret_key,
    )
    .unwrap();
    let mut vault = new_vault(&mut server, &unlocked);
    let items: Vec<Item> = (0..25)
        .map(|i| login_item(&format!("site {i:02}"), "pw"))
        .collect();
    let requests = vault.put_new_items(&unlocked, &items, 2).unwrap();
    assert_eq!(requests.len(), 25);
    for (_, request) in &requests {
        written(&server.send(request)).unwrap();
    }
    sync(&mut server, &mut vault, &unlocked).unwrap();
    assert_eq!(titles(&vault).len(), 25);
    assert_eq!(titles(&vault)[24], "site 24");

    // A batch built before another write lands is refused, not forked.
    let stale = vault
        .put_new_items(&unlocked, &[login_item("x", "1")], 3)
        .unwrap();
    let (_, other) = vault
        .put_item(&unlocked, None, &login_item("y", "2"), 3)
        .unwrap();
    written(&server.send(&other)).unwrap();
    assert!(written(&server.send(&stale[0].1)).is_err());
    sync(&mut server, &mut vault, &unlocked).unwrap();
    assert_eq!(titles(&vault).len(), 26);
}

#[test]
fn two_devices_writing_at_once_conflict_instead_of_forking() {
    let mut server = Server::new();
    let alice = sign_up(&mut server, "alice@example.com");
    let unlocked = sign_in(
        &mut server,
        "alice@example.com",
        PASSWORD,
        &alice.secret_key,
    )
    .unwrap();
    let vault = new_vault(&mut server, &unlocked);
    let (_, first) = vault
        .put_item(&unlocked, None, &login_item("a", "1"), 2)
        .unwrap();
    let (_, second) = vault
        .put_item(&unlocked, None, &login_item("b", "2"), 2)
        .unwrap();
    written(&server.send(&first)).unwrap();
    assert_eq!(
        written(&server.send(&second)).unwrap_err(),
        ClientError::Server {
            status: 409,
            code: "conflict".into()
        }
    );
}

/// Accepts every share waiting for `who`.
fn accept_all(server: &mut Server, who: &Unlocked) {
    let shares = receive_shares(&server.send(&shares_request(who))).unwrap();
    for (info, share) in &shares {
        let sender = lookup(server, who, &info.sender);
        let (_, req) = accept_share(who, share, &sender).unwrap();
        written(&server.send(&req)).unwrap();
    }
}

#[test]
fn changing_roles_removing_members_and_replacing_the_key() {
    let mut server = Server::new();
    let accounts: Vec<(NewAccount, Unlocked)> = ["alice", "bob", "carol"]
        .iter()
        .map(|name| {
            let email = format!("{name}@example.com");
            let account = sign_up(&mut server, &email);
            let unlocked = sign_in(&mut server, &email, PASSWORD, &account.secret_key).unwrap();
            (account, unlocked)
        })
        .collect();
    let (a, b, c) = (&accounts[0].1, &accounts[1].1, &accounts[2].1);
    let (bob_id, carol_id) = (accounts[1].0.account_id, accounts[2].0.account_id);

    let mut vault = new_vault(&mut server, a);
    for (account, who) in [(bob_id, b), (carol_id, c)] {
        let keys = lookup(&mut server, a, &account);
        for req in vault.share_with(a, &keys, Role::Editor, 2).unwrap() {
            written(&server.send(&req)).unwrap();
        }
        sync(&mut server, &mut vault, a).unwrap();
        accept_all(&mut server, who);
    }
    let req = vault
        .put_item(a, None, &login_item("old", "0ld"), 3)
        .unwrap()
        .1;
    written(&server.send(&req)).unwrap();
    sync(&mut server, &mut vault, a).unwrap();

    // Carol becomes a viewer.
    let req = vault.change_role(a, &carol_id, Role::Viewer, 4).unwrap();
    written(&server.send(&req)).unwrap();
    sync(&mut server, &mut vault, a).unwrap();
    assert_eq!(vault.state().unwrap().members[&carol_id].role, Role::Viewer);

    // Removing Bob needs every other member's keys, and only the right ones.
    let carol_keys = lookup(&mut server, a, &carol_id);
    let bob_keys = lookup(&mut server, a, &bob_id);
    assert!(vault.remove_member(a, &bob_id, &[], 5).is_err());
    assert!(
        vault
            .remove_member(a, &bob_id, std::slice::from_ref(&bob_keys), 5)
            .is_err()
    );
    for req in vault
        .remove_member(a, &bob_id, std::slice::from_ref(&carol_keys), 5)
        .unwrap()
    {
        written(&server.send(&req)).unwrap();
    }
    sync(&mut server, &mut vault, a).unwrap();
    let state = vault.state().unwrap();
    assert_eq!(state.vault_key_version, 2);
    assert!(!state.members.contains_key(&bob_id));

    // Old items are re-encrypted under the new key.
    let reqs = vault.reencrypt_items(a, 6).unwrap();
    assert_eq!(reqs.len(), 1);
    for req in &reqs {
        written(&server.send(req)).unwrap();
    }
    sync(&mut server, &mut vault, a).unwrap();
    assert!(vault.reencrypt_items(a, 7).unwrap().is_empty());
    let req = vault
        .put_item(a, None, &login_item("new", "n3w"), 8)
        .unwrap()
        .1;
    written(&server.send(&req)).unwrap();
    sync(&mut server, &mut vault, a).unwrap();

    // Carol gets the new key and reads everything.
    accept_all(&mut server, c);
    let mut carols = VaultReplica::new(*vault.vault_id());
    sync(&mut server, &mut carols, c).unwrap();
    assert_eq!(titles(&carols), ["new", "old"]);

    // Bob has no copy of the new key, so he can no longer open the items.
    let mut bobs = VaultReplica::new(*vault.vault_id());
    let bob_result = sync(&mut server, &mut bobs, b).and_then(|()| bobs.items());
    assert!(bob_result.is_err());

    // Carol leaves on her own; writes stop until Alice replaces the key.
    let req = carols.leave(c, 9).unwrap();
    written(&server.send(&req)).unwrap();
    sync(&mut server, &mut vault, a).unwrap();
    assert!(vault.state().unwrap().rotation_required);
    assert!(
        vault
            .put_item(a, None, &login_item("blocked", "x"), 10)
            .is_err()
    );
    for req in vault.rotate_key(a, &[], 10).unwrap() {
        written(&server.send(&req)).unwrap();
    }
    sync(&mut server, &mut vault, a).unwrap();
    assert_eq!(vault.state().unwrap().vault_key_version, 3);
    assert!(
        vault
            .put_item(a, None, &login_item("ok again", "x"), 11)
            .is_ok()
    );
    let _ = bob_keys;
}

#[test]
fn sharing_a_vault_and_enforcing_roles() {
    let mut server = Server::new();
    let alice = sign_up(&mut server, "alice@example.com");
    let bob = sign_up(&mut server, "bob@example.com");
    let carol = sign_up(&mut server, "carol@example.com");
    let a = sign_in(
        &mut server,
        "alice@example.com",
        PASSWORD,
        &alice.secret_key,
    )
    .unwrap();
    let b = sign_in(&mut server, "bob@example.com", PASSWORD, &bob.secret_key).unwrap();
    let c = sign_in(
        &mut server,
        "carol@example.com",
        PASSWORD,
        &carol.secret_key,
    )
    .unwrap();

    let mut vault = new_vault(&mut server, &a);
    let req = vault
        .put_item(&a, None, &login_item("shared", "s3cret"), 2)
        .unwrap()
        .1;
    written(&server.send(&req)).unwrap();
    sync(&mut server, &mut vault, &a).unwrap();

    // Carol cannot read a vault nobody shared with her.
    let mut nosy = VaultReplica::new(*vault.vault_id());
    assert!(matches!(
        sync(&mut server, &mut nosy, &c),
        Err(ClientError::Server { status: 403, .. })
    ));

    // Alice shares with Bob as editor and Carol as viewer.
    for (who, account, role) in [
        (&b, bob.account_id, Role::Editor),
        (&c, carol.account_id, Role::Viewer),
    ] {
        let keys = lookup(&mut server, &a, &account);
        for req in vault.share_with(&a, &keys, role, 3).unwrap() {
            written(&server.send(&req)).unwrap();
        }
        sync(&mut server, &mut vault, &a).unwrap();
        let shares = receive_shares(&server.send(&shares_request(who))).unwrap();
        let (info, share) = &shares[0];
        let sender = lookup(&mut server, who, &info.sender);
        let (vault_id, req) = accept_share(who, share, &sender).unwrap();
        assert_eq!(vault_id, *vault.vault_id());
        written(&server.send(&req)).unwrap();
    }

    // Bob reads and writes.
    let mut bobs = VaultReplica::new(*vault.vault_id());
    sync(&mut server, &mut bobs, &b).unwrap();
    assert_eq!(titles(&bobs), ["shared"]);
    let req = bobs
        .put_item(&b, None, &login_item("from bob", "b0b"), 4)
        .unwrap()
        .1;
    written(&server.send(&req)).unwrap();
    sync(&mut server, &mut vault, &a).unwrap();
    assert_eq!(titles(&vault), ["from bob", "shared"]);

    // Carol, a viewer, can read but the server refuses her write.
    let mut carols = VaultReplica::new(*vault.vault_id());
    sync(&mut server, &mut carols, &c).unwrap();
    assert_eq!(titles(&carols), ["from bob", "shared"]);
    let before = vault.checkpoint();
    let req = carols
        .put_item(&c, None, &login_item("from carol", "c4r0l"), 5)
        .unwrap()
        .1;
    assert_eq!(server.send(&req).status, 403);

    // A server that stored it anyway would not fool anyone: every client
    // rejects the log from that point and keeps its last good state.
    let r: http::LogAppendRequest = serde_json::from_str(req.body.as_deref().unwrap()).unwrap();
    let entry = http::unb64(&r.entry, 4096).unwrap();
    let hash = vault_core::log::entry_hash(&entry);
    let log = server.vaults.logs.get_mut(vault.vault_id()).unwrap();
    let seq = log.len() as u64;
    log.push((entry, Checkpoint { seq, hash }));
    assert_eq!(
        sync(&mut server, &mut vault, &a).unwrap_err(),
        ClientError::Crypto(vault_core::Error::LogMismatch)
    );
    assert_eq!(vault.checkpoint(), before);
    assert_eq!(titles(&vault), ["from bob", "shared"]);
}

#[test]
fn a_server_replaying_old_entries_is_caught() {
    let mut server = Server::new();
    let alice = sign_up(&mut server, "alice@example.com");
    let unlocked = sign_in(
        &mut server,
        "alice@example.com",
        PASSWORD,
        &alice.secret_key,
    )
    .unwrap();
    let mut vault = new_vault(&mut server, &unlocked);
    let req = vault
        .put_item(&unlocked, None, &login_item("a", "1"), 2)
        .unwrap()
        .1;
    written(&server.send(&req)).unwrap();
    let before = vault.checkpoint();
    server.vaults.replay_first = true;
    assert!(sync(&mut server, &mut vault, &unlocked).is_err());
    assert_eq!(vault.checkpoint(), before);
    server.vaults.replay_first = false;
    sync(&mut server, &mut vault, &unlocked).unwrap();
    assert_eq!(titles(&vault), ["a"]);
}

#[test]
fn recovering_a_forgotten_password() {
    use client_core::recovery::{
        Recovery, has_recovery_key, new_recovery_key, recovery_status_request, remove_recovery_key,
    };
    use vault_core::recovery::RecoveryKey;
    const NEW_PASSWORD: &str = "a different long passphrase";
    const NEWER_PASSWORD: &str = "yet another long passphrase";

    let mut server = Server::new();
    let alice = sign_up(&mut server, "alice@example.com");
    let unlocked = sign_in(
        &mut server,
        "alice@example.com",
        PASSWORD,
        &alice.secret_key,
    )
    .unwrap();
    let mut vault = new_vault(&mut server, &unlocked);
    let req = vault
        .put_item(&unlocked, None, &login_item("a", "1"), 2)
        .unwrap()
        .1;
    written(&server.send(&req)).unwrap();

    // Setting up a recovery key needs a fresh session.
    assert!(!has_recovery_key(&server.send(&recovery_status_request(&unlocked))).unwrap());
    let (key, req) = new_recovery_key(&unlocked, "alice@example.com").unwrap();
    written(&server.send(&req)).unwrap();
    assert!(has_recovery_key(&server.send(&recovery_status_request(&unlocked))).unwrap());
    let typed = key.to_display_string().to_lowercase().replace('-', " ");
    drop(key);
    server.now += 300_000;
    let (_, req) = new_recovery_key(&unlocked, "alice@example.com").unwrap();
    assert_eq!(server.send(&req).status, 403);
    assert_eq!(server.send(&remove_recovery_key(&unlocked)).status, 403);

    // A wrong key, or the right key for another address, is refused the
    // same way as an unknown address.
    let other = RecoveryKey::generate().unwrap().to_display_string();
    for (email, key) in [
        ("alice@example.com", other.as_str()),
        ("bob@example.com", typed.as_str()),
    ] {
        let (r, req) = Recovery::start(email, key, &server_id()).unwrap();
        assert_eq!(
            r.open(&server.send(&req)).unwrap_err(),
            ClientError::SignedOut
        );
    }
    assert!(Recovery::start("alice@example.com", "BR1-nonsense", &server_id()).is_err());

    // On a new device, without the Secret Key: a new one is made.
    let (r, req) = Recovery::start("Alice@Example.com", &typed, &server_id()).unwrap();
    let recovered = r.open(&server.send(&req)).unwrap();
    assert_eq!(recovered.account_id(), unlocked.session.account_id());
    let (setting, req) = recovered
        .choose_password(NEW_PASSWORD, None, KdfParams::MIN)
        .unwrap();
    let (finishing, req) = setting.register(&server.send(&req)).unwrap();
    let account = finishing.complete(&server.send(&req)).unwrap();
    assert!(account.new_secret_key);
    assert_eq!(account.emergency_kit().email, "alice@example.com");

    // Every old session ended, and the old password and Secret Key no
    // longer work.
    assert_eq!(
        sync(&mut server, &mut vault, &unlocked).unwrap_err(),
        ClientError::SignedOut
    );
    assert!(
        sign_in(
            &mut server,
            "alice@example.com",
            PASSWORD,
            &alice.secret_key
        )
        .is_err()
    );
    assert!(
        sign_in(
            &mut server,
            "alice@example.com",
            NEW_PASSWORD,
            &alice.secret_key
        )
        .is_err()
    );

    // The new password opens the same key set, and the vault is intact.
    let again = sign_in(
        &mut server,
        "alice@example.com",
        NEW_PASSWORD,
        &account.secret_key,
    )
    .unwrap();
    assert_eq!(again.key_set_version, unlocked.key_set_version);
    let mut copy = VaultReplica::new(*vault.vault_id());
    sync(&mut server, &mut copy, &again).unwrap();
    assert_eq!(titles(&copy), ["a"]);

    // On a device that has the Secret Key, it is kept.
    let (r, req) = Recovery::start("alice@example.com", &typed, &server_id()).unwrap();
    let (setting, req) = r
        .open(&server.send(&req))
        .unwrap()
        .choose_password(
            NEWER_PASSWORD,
            Some(account.secret_key.clone()),
            KdfParams::MIN,
        )
        .unwrap();
    let (finishing, req) = setting.register(&server.send(&req)).unwrap();
    let kept = finishing.complete(&server.send(&req)).unwrap();
    assert!(!kept.new_secret_key);
    sign_in(
        &mut server,
        "alice@example.com",
        NEWER_PASSWORD,
        &account.secret_key,
    )
    .unwrap();

    // Removing the key, with a fresh session, stops it working.
    let fresh = sign_in(
        &mut server,
        "alice@example.com",
        NEWER_PASSWORD,
        &account.secret_key,
    )
    .unwrap();
    written(&server.send(&remove_recovery_key(&fresh))).unwrap();
    let (r, req) = Recovery::start("alice@example.com", &typed, &server_id()).unwrap();
    assert_eq!(
        r.open(&server.send(&req)).unwrap_err(),
        ClientError::SignedOut
    );
}

#[test]
fn naming_a_vault() {
    use vault_core::VAULT_DETAILS_ITEM;

    let mut server = Server::new();
    let accounts: Vec<(NewAccount, Unlocked)> = ["alice", "bob", "carol", "dave"]
        .iter()
        .map(|name| {
            let email = format!("{name}@example.com");
            let account = sign_up(&mut server, &email);
            let unlocked = sign_in(&mut server, &email, PASSWORD, &account.secret_key).unwrap();
            (account, unlocked)
        })
        .collect();
    let a = &accounts[0].1;
    let ids: Vec<AccountId> = accounts.iter().map(|(n, _)| n.account_id).collect();
    let share = |server: &mut Server, vault: &mut VaultReplica, who: usize, now: u64| {
        let keys = lookup(server, a, &ids[who]);
        for req in vault.share_with(a, &keys, Role::Editor, now).unwrap() {
            written(&server.send(&req)).unwrap();
        }
        sync(server, vault, a).unwrap();
        accept_all(server, &accounts[who].1);
    };

    // A new vault has no name until one is given.
    let mut vault = new_vault(&mut server, a);
    assert_eq!(vault.name().unwrap(), None);
    let req = vault.rename(a, "Family", 2).unwrap();
    written(&server.send(&req)).unwrap();
    sync(&mut server, &mut vault, a).unwrap();
    let req = vault
        .put_item(a, None, &login_item("Wi-Fi", "pw"), 3)
        .unwrap()
        .1;
    written(&server.send(&req)).unwrap();
    sync(&mut server, &mut vault, a).unwrap();
    assert_eq!(vault.name().unwrap().as_deref(), Some("Family"));
    // The details are not listed as an item.
    assert_eq!(titles(&vault), ["Wi-Fi"]);

    // They cannot be deleted, overwritten by an item, or put elsewhere.
    assert_eq!(
        vault.delete_item(a, &VAULT_DETAILS_ITEM, 4).unwrap_err(),
        ClientError::NotAllowed
    );
    assert_eq!(
        vault
            .put_item(a, Some(VAULT_DETAILS_ITEM), &login_item("x", "y"), 4)
            .unwrap_err(),
        ClientError::NotAllowed
    );
    let details = vault.details().unwrap().unwrap();
    assert_eq!(
        vault.put_item(a, None, &details, 4).unwrap_err(),
        ClientError::NotAllowed
    );
    assert_eq!(
        vault
            .put_new_items(a, std::slice::from_ref(&details), 4)
            .unwrap_err(),
        ClientError::NotAllowed
    );

    // Members see the name, and editors can change it.
    share(&mut server, &mut vault, 1, 5);
    let b = &accounts[1].1;
    let mut bobs = VaultReplica::new(*vault.vault_id());
    sync(&mut server, &mut bobs, b).unwrap();
    assert_eq!(bobs.name().unwrap().as_deref(), Some("Family"));
    let req = bobs.rename(b, "Home", 6).unwrap();
    written(&server.send(&req)).unwrap();
    sync(&mut server, &mut vault, a).unwrap();
    assert_eq!(vault.name().unwrap().as_deref(), Some("Home"));

    // After a key replacement the details are re-encrypted too, so someone
    // added later can read the name.
    share(&mut server, &mut vault, 2, 7);
    let keep = lookup(&mut server, a, &ids[1]);
    for req in vault
        .remove_member(a, &ids[2], std::slice::from_ref(&keep), 8)
        .unwrap()
    {
        written(&server.send(&req)).unwrap();
    }
    sync(&mut server, &mut vault, a).unwrap();
    let reqs = vault.reencrypt_items(a, 9).unwrap();
    assert_eq!(reqs.len(), 2);
    for req in &reqs {
        written(&server.send(req)).unwrap();
    }
    sync(&mut server, &mut vault, a).unwrap();
    share(&mut server, &mut vault, 3, 10);
    let mut daves = VaultReplica::new(*vault.vault_id());
    sync(&mut server, &mut daves, &accounts[3].1).unwrap();
    assert_eq!(daves.name().unwrap().as_deref(), Some("Home"));
    assert_eq!(titles(&daves), ["Wi-Fi"]);
}
