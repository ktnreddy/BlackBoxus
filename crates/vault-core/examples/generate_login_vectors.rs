//! Generates the test vectors in `docs/spec/vectors/04-login.json`.
//!
//! Run with: `cargo run -p vault-core --example generate_login_vectors`
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

use vault_core::login::SessionToken;
use vault_core::{ClientIdentity, ServerIdentity};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
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

fn list(items: &[String]) -> String {
    items.join(",\n")
}

fn main() {
    let emails = [
        "alice@example.com",
        "  Alice.Example@Mail.COM \n",
        "\u{FF41}\u{FF4C}\u{FF49}\u{FF43}\u{FF45}@example.com",
        "J\u{00D6}RG@B\u{00DC}RO.de",
    ];
    let email_items: Vec<String> = emails
        .iter()
        .map(|e| {
            let id = ClientIdentity::new(e).unwrap();
            format!(
                "    {{ \"input\": {}, \"canonical\": {} }}",
                json_str(e),
                json_str(id.as_str())
            )
        })
        .collect();

    let invalid_emails = ["", "no-at-sign", "a@b@c", "a b@c.d", "@example.com"];
    let invalid_email_items: Vec<String> = invalid_emails
        .iter()
        .map(|e| {
            assert!(ClientIdentity::new(e).is_err());
            format!("    {}", json_str(e))
        })
        .collect();

    let origins = [
        "https://api.example.org",
        "HTTPS://API.Example.org",
        "https://api.example.org:8443",
        "http://localhost:8787",
    ];
    let origin_items: Vec<String> = origins
        .iter()
        .map(|o| {
            let id = ServerIdentity::new(o).unwrap();
            format!(
                "    {{ \"input\": {}, \"canonical\": {} }}",
                json_str(o),
                json_str(id.as_str())
            )
        })
        .collect();

    let invalid_origins = [
        "http://api.example.org",
        "https://api.example.org/",
        "https://api.example.org/path",
        "https://user@api.example.org",
        "api.example.org",
    ];
    let invalid_origin_items: Vec<String> = invalid_origins
        .iter()
        .map(|o| {
            assert!(ServerIdentity::new(o).is_err());
            format!("    {}", json_str(o))
        })
        .collect();

    let session_keys: [Vec<u8>; 2] = [vec![0; 64], (0..64).collect()];
    let token_items: Vec<String> = session_keys
        .iter()
        .map(|k| {
            let token = SessionToken::from_session_key(k).unwrap();
            format!(
                "    {{ \"session_key_hex\": \"{}\", \"session_token_hex\": \"{}\", \"storage_hash_hex\": \"{}\" }}",
                hex(k),
                hex(token.as_bytes()),
                hex(&token.storage_hash())
            )
        })
        .collect();

    println!(
        "{{\n  \"client_identity\": [\n{}\n  ],\n  \"client_identity_invalid\": [\n{}\n  ],\n  \"server_identity\": [\n{}\n  ],\n  \"server_identity_invalid\": [\n{}\n  ],\n  \"session_token\": [\n{}\n  ]\n}}",
        list(&email_items),
        list(&invalid_email_items),
        list(&origin_items),
        list(&invalid_origin_items),
        list(&token_items),
    );
}
