//! Log appends arriving at the server with their envelopes, wrapped vault
//! keys and shares (spec section 12.7), checked against stored vault rules
//! that are themselves read from storage or rebuilt from a log.
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use server_core::vaults::{
    VaultRules, accept_append, accept_owner_key, accept_share, touched_item,
};
use vault_core::ItemId;

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    rules: Option<&'a [u8]>,
    item: Option<([u8; 16], u64, bool)>,
    log: Vec<&'a [u8]>,
    may_read: bool,
    entry: &'a [u8],
    envelope: Option<&'a [u8]>,
}

fuzz_target!(|i: Input<'_>| {
    let f = blackboxus_fuzz::fixture();
    let _ = touched_item(i.entry);
    let entries: Vec<Vec<u8>> = i.log.iter().map(|e| e.to_vec()).collect();
    if let Ok(rebuilt) = VaultRules::rebuild(&f.vault_id, &entries) {
        // Whatever replays must survive storage unchanged.
        let stored = rebuilt.encode();
        assert_eq!(
            VaultRules::decode(&f.vault_id, &stored).map(|r| r.encode()),
            Ok(stored)
        );
    }
    let rules = i
        .rules
        .and_then(|bytes| VaultRules::decode(&f.vault_id, bytes).ok())
        .map(|r| match i.item {
            Some((id, revision, deleted)) => r.with_item(ItemId::from_bytes(id), revision, deleted),
            None => r,
        });
    let _ = accept_share(i.entry, &f.account, rules.as_ref());
    let _ = accept_append(&f.vault_id, rules, &f.account, i.entry, i.envelope);
    let _ = accept_owner_key(&f.vault_id, i.may_read, i.entry);
});
