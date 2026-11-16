//! Generates the test vectors in `docs/spec/vectors/11-recovery.json`.
//!
//! Run with: `cargo run -p vault-core --example generate_recovery_vectors`
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

use vault_core::recovery::{EmergencyGrant, EmergencyKey, RecoveryKey};
use vault_core::{AccountId, KeySet, PublicKeyBundle};

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
    let rk_bytes = seq::<32>(0x30);
    let rk = RecoveryKey::from_bytes_for_test_vectors(rk_bytes);
    let account = AccountId::from_bytes(seq(0xA0));
    let email = vault_core::ClientIdentity::new("owner@example.com").unwrap();

    let owner = KeySet::from_seeds_for_test_vectors([seq(0x00), seq(0x20), seq(0x40), seq(0x60)]);
    let contact_seeds = [seq(0x10), seq(0x30), seq(0x50), seq(0x70)];
    let contact = KeySet::from_seeds_for_test_vectors(contact_seeds);
    let contact_id = AccountId::from_bytes(seq(0xB0));
    let contact_bundle =
        PublicKeyBundle::verify_signed(&contact.signed_public_bundle(&contact_id, 1).unwrap())
            .unwrap();
    let owner_signed = owner.signed_public_bundle(&account, 1).unwrap();
    let owner_bundle = PublicKeyBundle::verify_signed(&owner_signed).unwrap();

    let ek = EmergencyKey::generate().unwrap();
    let grant = EmergencyGrant::seal(&ek, &owner, &account, 1, &contact_bundle, 7).unwrap();
    let (_, released) =
        EmergencyGrant::open(&grant, &contact, &contact_id, 1, &owner_bundle).unwrap();
    assert_eq!(released.wrapping_key(), ek.wrapping_key());
    let identity = owner.identity().public_key().to_bytes();

    println!("{{");
    println!("  \"recovery_key_hex\": \"{}\",", hex(&rk_bytes));
    println!(
        "  \"recovery_key_display\": \"{}\",",
        rk.to_display_string().as_str()
    );
    println!("  \"account_id_hex\": \"{}\",", hex(account.as_bytes()));
    println!("  \"email\": \"{}\",", email.as_str());
    println!(
        "  \"wrapping_key_hex\": \"{}\",",
        hex(rk.wrapping_key(&account).unwrap().as_bytes())
    );
    println!(
        "  \"auth_token_hex\": \"{}\",",
        hex(rk.auth_token(&email).unwrap().as_bytes())
    );
    println!(
        "  \"auth_verifier_hex\": \"{}\",",
        hex(&rk.auth_verifier(&email).unwrap())
    );
    println!("  \"grant_sample_hex\": \"{}\",", hex(&grant));
    println!(
        "  \"grant_emergency_key_hex\": \"{}\",",
        hex(ek.wrapping_key().as_bytes())
    );
    println!(
        "  \"contact_account_id_hex\": \"{}\",",
        hex(contact_id.as_bytes())
    );
    println!(
        "  \"contact_xwing_seed_hex\": \"{}\",",
        hex(&contact_seeds[1])
    );
    println!(
        "  \"owner_ed25519_public_key_hex\": \"{}\",",
        hex(&identity[..32])
    );
    println!(
        "  \"owner_ml_dsa_public_key_hex\": \"{}\"",
        hex(&identity[32..])
    );
    println!("}}");
}
