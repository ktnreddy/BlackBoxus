//! Generates the test vectors in `docs/spec/vectors/05-key-sets.json`.
//!
//! Run with: `cargo run -p vault-core --example generate_key_set_vectors`
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

use std::fmt::Write as _;

use vault_core::{AccountId, KeySet, SymmetricKey, UnlockMethod};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn seq(start: u8) -> [u8; 32] {
    core::array::from_fn(|i| start.wrapping_add(u8::try_from(i).unwrap()))
}

fn main() {
    let seeds = [seq(0x00), seq(0x20), seq(0x40), seq(0x60)];
    let key_set = KeySet::from_seeds_for_test_vectors(seeds);
    let account_id =
        AccountId::from_bytes(core::array::from_fn(|i| 0xA0 + u8::try_from(i).unwrap()));
    let wrapping_key = SymmetricKey::from_bytes(seq(0x80));
    let nonce: [u8; 24] = core::array::from_fn(|i| 0xC0 + u8::try_from(i).unwrap());
    let version = 1_u32;

    let wrapped = key_set
        .wrap_with_nonce(
            &wrapping_key,
            &account_id,
            version,
            UnlockMethod::MasterPassword,
            &nonce,
        )
        .unwrap();
    let signed = key_set.signed_public_bundle(&account_id, version).unwrap();
    let xwing_pk = key_set.xwing_public_key();
    let identity_pk = key_set.identity().public_key().to_bytes();

    println!("{{");
    println!("  \"account_key_hex\": \"{}\",", hex(&seeds[0]));
    println!("  \"xwing_seed_hex\": \"{}\",", hex(&seeds[1]));
    println!("  \"ed25519_seed_hex\": \"{}\",", hex(&seeds[2]));
    println!("  \"ml_dsa_seed_hex\": \"{}\",", hex(&seeds[3]));
    println!("  \"account_id_hex\": \"{}\",", hex(account_id.as_bytes()));
    println!("  \"key_set_version\": {version},");
    println!("  \"method\": 1,");
    println!(
        "  \"wrapping_key_hex\": \"{}\",",
        hex(wrapping_key.as_bytes())
    );
    println!("  \"nonce_hex\": \"{}\",", hex(&nonce));
    println!("  \"wrapped_hex\": \"{}\",", hex(&wrapped));
    println!(
        "  \"xwing_public_key_hex\": \"{}\",",
        hex(xwing_pk.as_bytes())
    );
    println!(
        "  \"ed25519_public_key_hex\": \"{}\",",
        hex(&identity_pk[..32])
    );
    println!(
        "  \"ml_dsa_public_key_hex\": \"{}\",",
        hex(&identity_pk[32..])
    );
    println!(
        "  \"public_bundle_hex\": \"{}\",",
        hex(&signed[..vault_core::PUBLIC_BUNDLE_LEN])
    );
    println!(
        "  \"signed_public_bundle_sample_hex\": \"{}\"",
        hex(&signed)
    );
    println!("}}");
}
