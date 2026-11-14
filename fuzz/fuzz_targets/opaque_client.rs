//! OPAQUE messages from a possibly malicious server, arriving at the client
//! (spec section 4).
#![no_main]
use libfuzzer_sys::fuzz_target;
use vault_core::login::{start_login, start_registration};

fuzz_target!(|data: &[u8]| {
    let f = blackboxus_fuzz::fixture();
    let (registration, _) = start_registration(&f.key).expect("start");
    // Any well-formed response is acceptable here; it must just not crash.
    let _ = registration.finish(&f.key, data, &f.client, &f.server);
    let (login, _) = start_login(&f.key).expect("start");
    assert!(
        login.finish(&f.key, data, &f.client, &f.server).is_err(),
        "forged KE2 accepted"
    );
});
