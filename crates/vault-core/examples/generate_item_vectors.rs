//! Generates the test vectors in `docs/spec/vectors/06-items.json`.
//!
//! Run with: `cargo run -p vault-core --example generate_item_vectors`
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

use vault_core::{
    Field, FieldKind, Item, ItemId, ItemType, SymmetricKey, VaultId, open_item,
    seal_item_deterministic,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn seq<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start.wrapping_add(u8::try_from(i % 256).unwrap()))
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_ascii_graphic() || c == ' ' => out.push(c),
            c => {
                let mut buf = [0_u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
    out
}

fn main() {
    let item = Item {
        item_type: ItemType::Login,
        created_ms: 1_762_000_000_000,
        modified_ms: 1_762_000_500_000,
        fields: vec![
            Field::new(FieldKind::Title, "Example \u{1F510}"),
            Field::labelled(FieldKind::Username, "Work email", "alice@example.com"),
            Field::new(FieldKind::Password, "correct horse battery staple"),
            Field::new(FieldKind::Url, "https://example.com/login"),
            Field::new(FieldKind::TotpSecret, "JBSWY3DPEHPK3PXP"),
        ],
    };
    let vault_key = SymmetricKey::from_bytes(seq(0x00));
    let item_key = SymmetricKey::from_bytes(seq(0x40));
    let vault_id = VaultId::from_bytes(seq(0x80));
    let item_id = ItemId::from_bytes(seq(0x90));
    let nonces = [seq::<24>(0xA0), seq::<24>(0xC0)];
    let revision = 3_u64;

    let envelope = seal_item_deterministic(
        &item, &vault_key, &vault_id, &item_id, revision, &item_key, &nonces,
    )
    .unwrap();
    let opened = open_item(&envelope, &vault_key, &vault_id, Some(&item_id)).unwrap();
    assert_eq!(opened.item, item);

    let fields: Vec<String> = item
        .fields
        .iter()
        .map(|f| {
            format!(
                "      {{ \"kind\": {}, \"label\": {}, \"value\": {} }}",
                field_code(f.kind),
                json_str(&f.label),
                json_str(&f.value)
            )
        })
        .collect();

    println!("{{");
    println!("  \"item\": {{");
    println!("    \"item_type\": 1,");
    println!("    \"created_ms\": {},", item.created_ms);
    println!("    \"modified_ms\": {},", item.modified_ms);
    println!("    \"fields\": [\n{}\n    ]", fields.join(",\n"));
    println!("  }},");
    println!("  \"vault_key_hex\": \"{}\",", hex(vault_key.as_bytes()));
    println!("  \"item_key_hex\": \"{}\",", hex(item_key.as_bytes()));
    println!("  \"vault_id_hex\": \"{}\",", hex(vault_id.as_bytes()));
    println!("  \"item_id_hex\": \"{}\",", hex(item_id.as_bytes()));
    println!("  \"revision\": {revision},");
    println!("  \"key_nonce_hex\": \"{}\",", hex(&nonces[0]));
    println!("  \"content_nonce_hex\": \"{}\",", hex(&nonces[1]));
    println!("  \"envelope_hex\": \"{}\"", hex(&envelope));
    println!("}}");
}

fn field_code(kind: FieldKind) -> u8 {
    match kind {
        FieldKind::Title => 1,
        FieldKind::Username => 2,
        FieldKind::Password => 3,
        FieldKind::Url => 4,
        FieldKind::TotpSecret => 6,
        _ => unreachable!("kind not used in these vectors"),
    }
}
