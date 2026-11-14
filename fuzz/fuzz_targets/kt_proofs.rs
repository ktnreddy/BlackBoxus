//! Key transparency proofs from the server (spec section 9.3).
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use vault_core::transparency::{verify_consistency, verify_inclusion};

#[derive(Arbitrary, Debug)]
struct Input {
    index: u64,
    size: u64,
    old_size: u64,
    leaf: [u8; 32],
    root: [u8; 32],
    old_root: [u8; 32],
    proof: Vec<[u8; 32]>,
}

fuzz_target!(|i: Input| {
    let _ = verify_inclusion(i.index, i.size, &i.leaf, &i.proof, &i.root);
    let _ = verify_consistency(i.old_size, i.size, &i.old_root, &i.root, &i.proof);
});
