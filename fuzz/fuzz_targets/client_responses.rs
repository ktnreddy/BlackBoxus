//! Answers from a possibly malicious server, arriving at the client flows
//! in `client-core`.
#![no_main]
use std::sync::OnceLock;

use arbitrary::Arbitrary;
use client_core::keys::{KeyDirectory, VerifiedKeys};
use client_core::login::{Login, Unlocked};
use client_core::{Response, Session, enrolment};
use libfuzzer_sys::fuzz_target;
use vault_core::device::EnrolmentOffer;
use vault_core::login::SessionToken;
use vault_core::{AccountId, KeySet, PublicKeyBundle, SecretKey};

#[derive(Arbitrary, Debug)]
struct Input {
    status: u16,
    retry_after: Option<u64>,
    body: Vec<u8>,
}

fn secret_key() -> &'static SecretKey {
    static K: OnceLock<SecretKey> = OnceLock::new();
    K.get_or_init(|| SecretKey::generate().expect("secret key"))
}

/// A signed-in account and its own published keys, for self-monitoring.
fn me() -> &'static (Unlocked, VerifiedKeys) {
    static ME: OnceLock<(Unlocked, VerifiedKeys)> = OnceLock::new();
    ME.get_or_init(|| {
        let account = AccountId::from_bytes([9; 16]);
        let key_set = KeySet::generate().expect("key set");
        let signed = key_set.signed_public_bundle(&account, 1).expect("bundle");
        let bundle = PublicKeyBundle::verify_signed(&signed).expect("verify");
        (
            Unlocked {
                session: Session::restore(SessionToken::from_bytes([1; 32]), account),
                key_set,
                key_set_version: 1,
            },
            VerifiedKeys { bundle, signed },
        )
    })
}

fuzz_target!(|i: Input| {
    let f = blackboxus_fuzz::fixture();
    let response = Response {
        status: i.status,
        retry_after: i.retry_after,
        body: i.body,
    };

    // Answers carrying Argon2id parameters are skipped here, so the fuzzer
    // never spends its time in a deliberately slow key derivation.
    if !response.body.windows(4).any(|w| w == b"\"m\":") {
        let (login, _) = Login::start("fuzz@example.com", &f.server).expect("start");
        let _ = login.prelogin(&response, "correct horse battery staple", secret_key());
    }

    let mut directory = KeyDirectory::new(f.log_key.clone(), None);
    assert!(
        directory.verify(&f.account, &response).is_err(),
        "forged key lookup accepted"
    );
    assert!(directory.tree_head().is_none());
    let (unlocked, own) = me();
    assert!(
        directory.check_own_keys(unlocked, own, &response).is_err(),
        "forged self-monitoring answer accepted"
    );
    let _ = client_core::emergency::status(unlocked.session.account_id(), &response);
    assert!(
        client_core::emergency::open_release(unlocked, own, &response).is_err(),
        "forged emergency grant opened"
    );
    assert!(directory.tree_head().is_none());

    let offer = EnrolmentOffer::generate().expect("offer");
    assert!(
        enrolment::receive(&offer, &response).is_err(),
        "forged transfer accepted"
    );
});
