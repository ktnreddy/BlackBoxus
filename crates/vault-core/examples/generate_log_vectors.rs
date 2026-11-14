//! Generates the test vectors in `docs/spec/vectors/08-revision-log.json`.
//!
//! Run with: `cargo run -p vault-core --example generate_log_vectors`
//!
//! The output must be checked against an independent implementation before
//! it is committed.

#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "developer tool, not shipped code"
)]

use std::collections::HashMap;
use std::fmt::Write as _;

use vault_core::log::{LogEntry, Operation, bundle_hash, entry_hash, verify_log};
use vault_core::{AccountId, ItemId, KeySet, VaultId};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn seq<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start.wrapping_add(u8::try_from(i % 256).unwrap()))
}

fn main() {
    let alice = KeySet::from_seeds_for_test_vectors([seq(0x00), seq(0x20), seq(0x40), seq(0x60)]);
    let alice_id = AccountId::from_bytes(seq(0xA0));
    let bundle = alice.signed_public_bundle(&alice_id, 1).unwrap();
    let vault_id = VaultId::from_bytes(seq(0xC0));
    let item_id = ItemId::from_bytes(seq(0xD0));
    let envelope_hash: [u8; 32] = seq(0xE0);

    let first = LogEntry {
        vault_id,
        seq: 0,
        prev_hash: [0; 32],
        author: alice_id,
        author_key_set_version: 1,
        timestamp_ms: 1_762_000_000_000,
        operation: Operation::CreateVault {
            bundle_hash: bundle_hash(&bundle),
        },
    };
    let first_signed = first.sign(&alice).unwrap();
    let second = LogEntry {
        vault_id,
        seq: 1,
        prev_hash: entry_hash(&first_signed),
        author: alice_id,
        author_key_set_version: 1,
        timestamp_ms: 1_762_000_060_000,
        operation: Operation::PutItem {
            item_id,
            revision: 1,
            vault_key_version: 1,
            envelope_hash,
        },
    };
    let second_signed = second.sign(&alice).unwrap();

    let mut bundles = HashMap::new();
    bundles.insert((alice_id, 1), bundle.clone());
    let entries = vec![first_signed.clone(), second_signed.clone()];
    let state = verify_log(&vault_id, &entries, &bundles, None).unwrap();
    assert_eq!(state.head.seq, 1);

    let identity = alice.identity().public_key().to_bytes();
    let unsigned = |s: &[u8]| hex(&s[..s.len() - 3373]);

    println!("{{");
    println!("  \"vault_id_hex\": \"{}\",", hex(vault_id.as_bytes()));
    println!(
        "  \"author_account_id_hex\": \"{}\",",
        hex(alice_id.as_bytes())
    );
    println!(
        "  \"author_ed25519_public_key_hex\": \"{}\",",
        hex(&identity[..32])
    );
    println!(
        "  \"author_ml_dsa_public_key_hex\": \"{}\",",
        hex(&identity[32..])
    );
    println!("  \"author_signed_bundle_hex\": \"{}\",", hex(&bundle));
    println!("  \"item_id_hex\": \"{}\",", hex(item_id.as_bytes()));
    println!("  \"envelope_hash_hex\": \"{}\",", hex(&envelope_hash));
    println!("  \"entry0_timestamp_ms\": {},", first.timestamp_ms);
    println!("  \"entry1_timestamp_ms\": {},", second.timestamp_ms);
    println!(
        "  \"entry0_unsigned_hex\": \"{}\",",
        unsigned(&first_signed)
    );
    println!(
        "  \"entry1_unsigned_hex\": \"{}\",",
        unsigned(&second_signed)
    );
    println!(
        "  \"entry0_signed_sample_hex\": \"{}\",",
        hex(&first_signed)
    );
    println!(
        "  \"entry1_signed_sample_hex\": \"{}\",",
        hex(&second_signed)
    );
    println!("  \"head_seq\": {},", state.head.seq);
    println!("  \"head_hash_hex\": \"{}\"", hex(&state.head.hash));
    println!("}}");
}
