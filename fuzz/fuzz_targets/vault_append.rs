//! Log appends arriving at the server with their envelopes, wrapped vault
//! keys and shares (spec section 12.7).
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use server_core::vaults::{accept_append, accept_owner_key, accept_share};
use vault_core::log::Checkpoint;

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    head: Option<(u64, [u8; 32])>,
    may_read: bool,
    entry: &'a [u8],
    envelope: Option<&'a [u8]>,
}

fuzz_target!(|i: Input<'_>| {
    let f = blackboxus_fuzz::fixture();
    let head = i.head.map(|(seq, hash)| Checkpoint { seq, hash });
    let _ = accept_append(
        &f.vault_id,
        head.as_ref(),
        i.may_read,
        &f.account,
        i.entry,
        i.envelope,
    );
    let _ = accept_owner_key(&f.vault_id, i.may_read, i.entry);
    let _ = accept_share(i.entry, &f.account, i.may_read);
});
