//! Answers from a possibly malicious server, arriving at the client flows
//! in `client-core`.
#![no_main]
use std::sync::OnceLock;

use arbitrary::Arbitrary;
use client_core::keys::KeyDirectory;
use client_core::login::Login;
use client_core::{Response, enrolment};
use libfuzzer_sys::fuzz_target;
use vault_core::SecretKey;
use vault_core::device::EnrolmentOffer;

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

    let offer = EnrolmentOffer::generate().expect("offer");
    assert!(
        enrolment::receive(&offer, &response).is_err(),
        "forged transfer accepted"
    );
});
