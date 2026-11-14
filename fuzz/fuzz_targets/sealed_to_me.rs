//! Data sealed to this account by another user: vault shares (7.5) and
//! emergency grants (11.4).
#![no_main]
use libfuzzer_sys::fuzz_target;
use vault_core::VaultKey;
use vault_core::recovery::EmergencyGrant;

fuzz_target!(|data: &[u8]| {
    let f = blackboxus_fuzz::fixture();
    assert!(
        VaultKey::open_share(data, &f.keys, &f.account, 1, &f.peer).is_err(),
        "forged share opened"
    );
    assert!(
        EmergencyGrant::open(data, &f.keys, &f.account, 1, &f.peer).is_err(),
        "forged grant opened"
    );
});
