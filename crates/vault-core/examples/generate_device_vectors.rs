//! Generates the test vectors in `docs/spec/vectors/10-devices.json`.
//!
//! Run with: `cargo run -p vault-core --example generate_device_vectors`
//!
//! The output must be checked against an independent implementation before
//! it is committed.

#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "developer tool, not shipped code"
)]

use std::fmt::Write as _;

use vault_core::device::{
    EnrolmentOffer, EnrolmentPayload, passkey_prf_input, passkey_wrapping_key,
};
use vault_core::{AccountId, ClientIdentity, SecretKey, ServerIdentity};

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
    let offer = EnrolmentOffer::from_parts_for_test_vectors(seq(0x10), seq(0x20));
    let account = AccountId::from_bytes(seq(0xA0));
    let secret_key = SecretKey::from_bytes(seq(0x50));
    let payload = EnrolmentPayload {
        account_id: account,
        email: ClientIdentity::new("alice@example.com").unwrap(),
        server: ServerIdentity::new("https://api.example.org").unwrap(),
        secret_key: SecretKey::from_bytes(*secret_key.as_bytes()),
        signed_tree_head: None,
    };
    let nonce = seq::<24>(0x70);
    let sealed = offer.seal_with_nonce(&payload, &nonce).unwrap();
    let opened = EnrolmentOffer::from_qr_text(&offer.to_qr_text())
        .unwrap()
        .open(&sealed)
        .unwrap();
    assert_eq!(opened.secret_key, secret_key);

    let prf_output = seq::<32>(0xC0);
    let credential_id = b"example-credential-id";
    let wrapping_key = passkey_wrapping_key(&prf_output, credential_id).unwrap();

    println!("{{");
    println!("  \"session_id_hex\": \"{}\",", hex(offer.session_id()));
    println!("  \"enrolment_secret_hex\": \"{}\",", hex(&seq::<32>(0x20)));
    println!("  \"qr_text\": \"{}\",", offer.to_qr_text().as_str());
    println!("  \"account_id_hex\": \"{}\",", hex(account.as_bytes()));
    println!("  \"email\": \"alice@example.com\",");
    println!("  \"server\": \"https://api.example.org\",");
    println!("  \"secret_key_hex\": \"{}\",", hex(secret_key.as_bytes()));
    println!("  \"nonce_hex\": \"{}\",", hex(&nonce));
    println!("  \"sealed_hex\": \"{}\",", hex(&sealed));
    println!(
        "  \"prf_input_hex\": \"{}\",",
        hex(&passkey_prf_input(&account))
    );
    println!("  \"prf_output_hex\": \"{}\",", hex(&prf_output));
    println!("  \"credential_id_hex\": \"{}\",", hex(credential_id));
    println!(
        "  \"passkey_wrapping_key_hex\": \"{}\"",
        hex(wrapping_key.as_bytes())
    );
    println!("}}");
}
