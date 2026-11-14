//! OPAQUE messages arriving at the server (spec section 4).
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use server_core::login::{ServerLoginState, finish_registration};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    message: &'a [u8],
    state: &'a [u8],
}

fuzz_target!(|i: Input<'_>| {
    let f = blackboxus_fuzz::fixture();
    let _ = f.api.registration_response(&f.client, i.message);
    let _ = finish_registration(i.message);
    let _ = f.api.start_login(&f.client, None, i.message, 0);
    if let Ok(state) = ServerLoginState::from_bytes(i.state) {
        let _ = state.finish(i.message, &f.client, &f.server);
    }
});
