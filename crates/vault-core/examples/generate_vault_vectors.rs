//! Generates the test vectors in `docs/spec/vectors/07-vaults-and-sharing.json`.
//!
//! Run with: `cargo run -p vault-core --example generate_vault_vectors`
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

use vault_core::{AccountId, KeySet, PublicKeyBundle, SymmetricKey, VaultId, VaultKey};

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
    let alice_seeds = [seq(0x00), seq(0x20), seq(0x40), seq(0x60)];
    let bob_seeds = [seq(0x10), seq(0x30), seq(0x50), seq(0x70)];
    let alice = KeySet::from_seeds_for_test_vectors(alice_seeds);
    let bob = KeySet::from_seeds_for_test_vectors(bob_seeds);
    let alice_id = AccountId::from_bytes(seq(0xA0));
    let bob_id = AccountId::from_bytes(seq(0xB0));
    let bob_bundle =
        PublicKeyBundle::verify_signed(&bob.signed_public_bundle(&bob_id, 2).unwrap()).unwrap();
    let alice_signed = alice.signed_public_bundle(&alice_id, 1).unwrap();
    let alice_bundle = PublicKeyBundle::verify_signed(&alice_signed).unwrap();

    let vault_id = VaultId::from_bytes(seq(0xC0));
    let vault_key = VaultKey {
        key: SymmetricKey::from_bytes(seq(0xE0)),
        version: 5,
    };

    let owner_nonce = seq::<24>(0x80);
    let owner_wrapped = vault_key
        .wrap_for_owner_with_nonce(&alice, &alice_id, &vault_id, &owner_nonce)
        .unwrap();

    let kem_randomness = seq::<64>(0x90);
    let share_nonce = seq::<24>(0xD0);
    let share = vault_key
        .share_deterministic(
            &vault_id,
            &alice,
            &alice_id,
            1,
            &bob_bundle,
            &kem_randomness,
            &share_nonce,
        )
        .unwrap();

    let (opened_vault, opened) =
        VaultKey::open_share(&share, &bob, &bob_id, 2, &alice_bundle).unwrap();
    assert_eq!(opened_vault, vault_id);
    assert_eq!(opened.key, vault_key.key);

    let alice_identity = alice.identity().public_key().to_bytes();

    println!("{{");
    println!("  \"vault_id_hex\": \"{}\",", hex(vault_id.as_bytes()));
    println!(
        "  \"vault_key_hex\": \"{}\",",
        hex(vault_key.key.as_bytes())
    );
    println!("  \"vault_key_version\": {},", vault_key.version);
    println!(
        "  \"owner_account_id_hex\": \"{}\",",
        hex(alice_id.as_bytes())
    );
    println!("  \"owner_account_key_hex\": \"{}\",", hex(&alice_seeds[0]));
    println!("  \"owner_nonce_hex\": \"{}\",", hex(&owner_nonce));
    println!("  \"owner_wrapped_hex\": \"{}\",", hex(&owner_wrapped));
    println!(
        "  \"sender_account_id_hex\": \"{}\",",
        hex(alice_id.as_bytes())
    );
    println!("  \"sender_key_set_version\": 1,");
    println!(
        "  \"sender_ed25519_public_key_hex\": \"{}\",",
        hex(&alice_identity[..32])
    );
    println!(
        "  \"sender_ml_dsa_public_key_hex\": \"{}\",",
        hex(&alice_identity[32..])
    );
    println!(
        "  \"recipient_account_id_hex\": \"{}\",",
        hex(bob_id.as_bytes())
    );
    println!("  \"recipient_key_set_version\": 2,");
    println!(
        "  \"recipient_xwing_seed_hex\": \"{}\",",
        hex(&bob_seeds[1])
    );
    println!(
        "  \"recipient_xwing_public_key_hex\": \"{}\",",
        hex(bob_bundle.xwing.as_bytes())
    );
    println!("  \"kem_randomness_hex\": \"{}\",", hex(&kem_randomness));
    println!("  \"share_nonce_hex\": \"{}\",", hex(&share_nonce));
    println!(
        "  \"share_body_hex\": \"{}\",",
        hex(&share[..share.len() - 3373])
    );
    println!("  \"share_sample_hex\": \"{}\"", hex(&share));
    println!("}}");
}
