//! Generates the test vectors in `docs/spec/vectors/09-key-transparency.json`.
//!
//! Run with: `cargo run -p server-core --example generate_kt_vectors`
//!
//! The output must be checked against an independent implementation before
//! it is committed.

#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs,
    reason = "developer tool, not shipped code"
)]

use std::fmt::Write as _;

use server_core::transparency::KtLog;
use vault_core::transparency::{KtLeaf, fingerprint};
use vault_core::{AccountId, IdentitySecretKey, KeySet};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn seq<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start.wrapping_add(u8::try_from(i % 256).unwrap()))
}

fn list(hashes: &[[u8; 32]]) -> String {
    let items: Vec<String> = hashes.iter().map(|h| format!("\"{}\"", hex(h))).collect();
    format!("[{}]", items.join(", "))
}

fn main() {
    let leaves: Vec<[u8; 62]> = (0..7_u8)
        .map(|i| {
            KtLeaf {
                account_id: AccountId::from_bytes([i + 1; 16]),
                key_set_version: 1,
                bundle_hash: seq(i * 32),
                timestamp_ms: 1_762_000_000_000 + u64::from(i),
            }
            .encode()
        })
        .collect();
    let log = KtLog::from_leaves(leaves.iter().map(|l| l.as_slice())).unwrap();

    let roots: Vec<[u8; 32]> = (0..=7).map(|n| log.root(n).unwrap()).collect();
    let inclusion = log.inclusion_proof(5, 7).unwrap();
    let consistency = log.consistency_proof(3, 7).unwrap();

    let log_key = IdentitySecretKey::from_seed_bytes(&seq::<64>(0x40)).unwrap();
    let sth = log.signed_tree_head(&log_key, 1_762_000_100_000).unwrap();
    let log_public = log_key.public_key().to_bytes();

    let keys = KeySet::from_seeds_for_test_vectors([seq(0x00), seq(0x20), seq(0x40), seq(0x60)]);
    let account = AccountId::from_bytes(seq(0xA0));
    let bundle = keys.signed_public_bundle(&account, 1).unwrap();

    let leaf_list: Vec<String> = leaves.iter().map(|l| format!("\"{}\"", hex(l))).collect();
    println!("{{");
    println!("  \"leaves_hex\": [{}],", leaf_list.join(", "));
    println!("  \"roots_by_size_hex\": {},", list(&roots));
    println!(
        "  \"inclusion\": {{ \"leaf_index\": 5, \"tree_size\": 7, \"proof_hex\": {} }},",
        list(&inclusion)
    );
    println!(
        "  \"consistency\": {{ \"first_size\": 3, \"second_size\": 7, \"proof_hex\": {} }},",
        list(&consistency)
    );
    println!(
        "  \"log_ed25519_public_key_hex\": \"{}\",",
        hex(&log_public[..32])
    );
    println!(
        "  \"log_ml_dsa_public_key_hex\": \"{}\",",
        hex(&log_public[32..])
    );
    println!("  \"signed_tree_head_sample_hex\": \"{}\",", hex(&sth));
    println!(
        "  \"fingerprint_account_id_hex\": \"{}\",",
        hex(account.as_bytes())
    );
    println!("  \"fingerprint_signed_bundle_hex\": \"{}\",", hex(&bundle));
    println!("  \"fingerprint\": \"{}\"", fingerprint(&account, &bundle));
    println!("}}");
}
