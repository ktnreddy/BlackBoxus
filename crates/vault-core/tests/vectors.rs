//! Checks `vault-core` against the published test vectors in `docs/spec/vectors/`.

#![allow(clippy::unwrap_used, reason = "test helpers")]

use serde::Deserialize;
use vault_core::{AccountSalt, KdfParams, MasterPassword, SecretKey, derive_account_keys};

const ACCOUNT_CREATION: &str = include_str!("../../../docs/spec/vectors/03-account-creation.json");

#[derive(Deserialize)]
struct Vectors {
    kdf: Vec<KdfVector>,
    secret_key_display: Vec<DisplayVector>,
}

#[derive(Deserialize)]
struct KdfVector {
    description: String,
    password: String,
    password_nfkc_hex: String,
    secret_key_hex: String,
    salt_hex: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    account_unlock_key_hex: String,
    opaque_password_hex: String,
}

#[derive(Deserialize)]
struct DisplayVector {
    secret_key_hex: String,
    display: String,
}

fn bytes16(hex_str: &str) -> [u8; 16] {
    hex::decode(hex_str).unwrap().try_into().unwrap()
}

fn vectors() -> Vectors {
    serde_json::from_str(ACCOUNT_CREATION).unwrap()
}

#[test]
fn key_derivation_matches_vectors() {
    for v in vectors().kdf {
        let password = MasterPassword::new(&v.password).unwrap();
        assert_eq!(
            hex::encode(password.as_bytes()),
            v.password_nfkc_hex,
            "{}",
            v.description
        );

        let params = KdfParams {
            memory_kib: v.memory_kib,
            iterations: v.iterations,
            parallelism: v.parallelism,
        };
        let keys = derive_account_keys(
            &password,
            &SecretKey::from_bytes(bytes16(&v.secret_key_hex)),
            &AccountSalt::from_bytes(bytes16(&v.salt_hex)),
            &params,
        )
        .unwrap();

        assert_eq!(
            hex::encode(keys.account_unlock_key.as_bytes()),
            v.account_unlock_key_hex,
            "{}",
            v.description
        );
        assert_eq!(
            hex::encode(keys.opaque_password.as_bytes()),
            v.opaque_password_hex,
            "{}",
            v.description
        );
    }
}

#[test]
fn secret_key_display_matches_vectors() {
    for v in vectors().secret_key_display {
        let key = SecretKey::from_bytes(bytes16(&v.secret_key_hex));
        assert_eq!(key.to_display_string().as_str(), v.display);
        assert_eq!(SecretKey::parse(&v.display).unwrap(), key);
    }
}
