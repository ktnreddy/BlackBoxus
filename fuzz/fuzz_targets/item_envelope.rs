//! Item envelopes from the server (spec section 6.5).
#![no_main]
use libfuzzer_sys::fuzz_target;
use vault_core::open_item;

fuzz_target!(|data: &[u8]| {
    let f = blackboxus_fuzz::fixture();
    assert!(
        open_item(data, &f.key, &f.vault_id, None).is_err(),
        "forged envelope opened"
    );
});
