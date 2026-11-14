//! Any change to a valid signed or encrypted object must be detected
//! (spec sections 5–11). Starts from a genuine object and flips bits.
#![no_main]
use libfuzzer_sys::fuzz_target;
use vault_core::recovery::EmergencyGrant;
use vault_core::transparency::TreeHead;
use vault_core::{KeySet, PublicKeyBundle, UnlockMethod, VaultKey, open_item};

fuzz_target!(|data: &[u8]| {
    let f = blackboxus_fuzz::fixture();
    let s = &f.samples;
    let changed = |sample: &[u8]| blackboxus_fuzz::tamper(sample, data);

    if let Some(v) = changed(&s.envelope) {
        assert!(
            open_item(&v, &f.key, &f.vault_id, None).is_err(),
            "tampered envelope opened"
        );
    }
    if let Some(v) = changed(&s.share) {
        assert!(
            VaultKey::open_share(&v, &f.keys, &f.account, 1, &f.peer).is_err(),
            "tampered share opened"
        );
    }
    if let Some(v) = changed(&s.grant) {
        assert!(
            EmergencyGrant::open(&v, &f.keys, &f.account, 1, &f.peer).is_err(),
            "tampered grant opened"
        );
    }
    if let Some(v) = changed(&s.bundle) {
        assert!(
            PublicKeyBundle::verify_signed(&v).is_err(),
            "tampered bundle verified"
        );
    }
    if let Some(v) = changed(&s.tree_head) {
        assert!(
            TreeHead::verify_signed(&v, &f.log_key).is_err(),
            "tampered tree head verified"
        );
    }
    if let Some(v) = changed(&s.wrapped_key_set) {
        assert!(
            KeySet::unwrap(&v, &f.key, &f.account, UnlockMethod::MasterPassword, 1).is_err(),
            "tampered key set unwrapped"
        );
    }
    if let Some(v) = changed(&s.enrolment) {
        assert!(
            s.offer.open(&v).is_err(),
            "tampered enrolment transfer opened"
        );
    }
});
