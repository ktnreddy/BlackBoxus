//! Generates the test vectors in `docs/spec/vectors/03-account-creation.json`.
//!
//! Run with: `cargo run -p vault-core --example generate_vectors --release`
//!
//! The output must be checked against an independent implementation before
//! it is committed.

#![allow(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::type_complexity,
    clippy::write_with_newline,
    reason = "developer tool, not shipped code"
)]

use std::fmt::Write as _;

use vault_core::{AccountSalt, KdfParams, MasterPassword, SecretKey, derive_account_keys};

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

fn seq(start: u8) -> [u8; 16] {
    core::array::from_fn(|i| start.wrapping_add(u8::try_from(i).unwrap()))
}

fn main() {
    let kdf_cases: [(&str, &str, [u8; 16], [u8; 16], KdfParams); 3] = [
        (
            "ASCII passphrase, minimum parameters",
            "correct horse battery staple",
            seq(0x00),
            seq(0x10),
            KdfParams::MIN,
        ),
        (
            "Unicode password needing NFKC normalisation, default parameters",
            "p\u{0061}\u{0308}ssw\u{00F6}rd \u{FB01}sh \u{1F510}",
            seq(0xA0),
            seq(0xC0),
            KdfParams::DEFAULT,
        ),
        (
            "Leading and trailing spaces are kept",
            "  twelve chars  ",
            [0xFF; 16],
            [0x00; 16],
            KdfParams {
                memory_kib: 96 * 1024,
                iterations: 3,
                parallelism: 2,
            },
        ),
    ];

    let mut out = String::from("{\n  \"kdf\": [\n");
    for (i, (desc, password, sk, salt, params)) in kdf_cases.iter().enumerate() {
        let pw = MasterPassword::new(password).unwrap();
        let keys = derive_account_keys(
            &pw,
            &SecretKey::from_bytes(*sk),
            &AccountSalt::from_bytes(*salt),
            params,
        )
        .unwrap();
        let _ = write!(
            out,
            "    {{\n      \"description\": {},\n      \"password\": {},\n      \"password_nfkc_hex\": \"{}\",\n      \"secret_key_hex\": \"{}\",\n      \"salt_hex\": \"{}\",\n      \"memory_kib\": {},\n      \"iterations\": {},\n      \"parallelism\": {},\n      \"account_unlock_key_hex\": \"{}\",\n      \"opaque_password_hex\": \"{}\"\n    }}{}\n",
            json_str(desc),
            json_str(password),
            hex(pw.as_bytes()),
            hex(sk),
            hex(salt),
            params.memory_kib,
            params.iterations,
            params.parallelism,
            hex(keys.account_unlock_key.as_bytes()),
            hex(keys.opaque_password.as_bytes()),
            if i + 1 < kdf_cases.len() { "," } else { "" },
        );
    }
    out.push_str("  ],\n  \"secret_key_display\": [\n");

    let sk_cases = [[0x00_u8; 16], seq(0x00), [0xFF; 16]];
    for (i, sk) in sk_cases.iter().enumerate() {
        let display = SecretKey::from_bytes(*sk).to_display_string();
        let _ = write!(
            out,
            "    {{ \"secret_key_hex\": \"{}\", \"display\": \"{}\" }}{}\n",
            hex(sk),
            display.as_str(),
            if i + 1 < sk_cases.len() { "," } else { "" },
        );
    }
    out.push_str("  ]\n}\n");
    print!("{out}");
}
