//! Signed objects from the server: public key bundles (5.5), tree heads
//! (9.3), log leaves (9.2), revision log entries (8.3), emergency grant
//! headers (11.4) and wrapped key sets (5.4).
#![no_main]
use libfuzzer_sys::fuzz_target;
use vault_core::log::LogEntry;
use vault_core::recovery::EmergencyGrant;
use vault_core::transparency::{KtLeaf, TreeHead};
use vault_core::{KeySet, PublicKeyBundle, UnlockMethod};

fuzz_target!(|data: &[u8]| {
    let f = blackboxus_fuzz::fixture();
    assert!(
        PublicKeyBundle::verify_signed(data).is_err(),
        "forged bundle verified"
    );
    assert!(
        TreeHead::verify_signed(data, &f.log_key).is_err(),
        "forged tree head verified"
    );
    if let Ok(leaf) = KtLeaf::decode(data) {
        assert_eq!(leaf.encode().as_slice(), data);
    }
    let _ = LogEntry::parse(data);
    let _ = EmergencyGrant::inspect(data);
    assert!(
        KeySet::unwrap(data, &f.key, &f.account, UnlockMethod::MasterPassword, 1).is_err(),
        "forged key set unwrapped"
    );
});
