//! Checks `vault-core` against the published test vectors in `docs/spec/vectors/`.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

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

const LOGIN: &str = include_str!("../../../docs/spec/vectors/04-login.json");

#[derive(Deserialize)]
struct LoginVectors {
    client_identity: Vec<IdentityVector>,
    client_identity_invalid: Vec<String>,
    server_identity: Vec<IdentityVector>,
    server_identity_invalid: Vec<String>,
    session_token: Vec<TokenVector>,
}

#[derive(Deserialize)]
struct IdentityVector {
    input: String,
    canonical: String,
}

#[derive(Deserialize)]
struct TokenVector {
    session_key_hex: String,
    session_token_hex: String,
    storage_hash_hex: String,
}

#[test]
fn login_vectors_match() {
    let v: LoginVectors = serde_json::from_str(LOGIN).unwrap();

    for c in v.client_identity {
        assert_eq!(
            vault_core::ClientIdentity::new(&c.input).unwrap().as_str(),
            c.canonical
        );
    }
    for bad in v.client_identity_invalid {
        assert!(vault_core::ClientIdentity::new(&bad).is_err(), "{bad:?}");
    }
    for c in v.server_identity {
        assert_eq!(
            vault_core::ServerIdentity::new(&c.input).unwrap().as_str(),
            c.canonical
        );
    }
    for bad in v.server_identity_invalid {
        assert!(vault_core::ServerIdentity::new(&bad).is_err(), "{bad:?}");
    }
    for c in v.session_token {
        let key = hex::decode(&c.session_key_hex).unwrap();
        let token = vault_core::login::SessionToken::from_session_key(&key).unwrap();
        assert_eq!(hex::encode(token.as_bytes()), c.session_token_hex);
        assert_eq!(hex::encode(token.storage_hash()), c.storage_hash_hex);
    }
}

const KEY_SETS: &str = include_str!("../../../docs/spec/vectors/05-key-sets.json");

#[derive(Deserialize)]
struct KeySetVector {
    account_key_hex: String,
    account_id_hex: String,
    key_set_version: u32,
    wrapping_key_hex: String,
    wrapped_hex: String,
    xwing_public_key_hex: String,
    ed25519_public_key_hex: String,
    ml_dsa_public_key_hex: String,
    public_bundle_hex: String,
    signed_public_bundle_sample_hex: String,
}

#[test]
fn key_set_vectors_match() {
    use vault_core::{AccountId, KeySet, PublicKeyBundle, SymmetricKey, UnlockMethod};

    let v: KeySetVector = serde_json::from_str(KEY_SETS).unwrap();
    let account_id = AccountId::from_bytes(bytes16(&v.account_id_hex));
    let wrapping_key = SymmetricKey::from_bytes(
        hex::decode(&v.wrapping_key_hex)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    let wrapped = hex::decode(&v.wrapped_hex).unwrap();
    let (key_set, version) = KeySet::unwrap(
        &wrapped,
        &wrapping_key,
        &account_id,
        UnlockMethod::MasterPassword,
        1,
    )
    .unwrap();
    assert_eq!(version, v.key_set_version);
    assert_eq!(
        hex::encode(key_set.account_key().as_bytes()),
        v.account_key_hex
    );
    assert_eq!(
        hex::encode(key_set.xwing_public_key().as_bytes()),
        v.xwing_public_key_hex
    );
    let identity = key_set.identity().public_key().to_bytes();
    assert_eq!(hex::encode(&identity[..32]), v.ed25519_public_key_hex);
    assert_eq!(hex::encode(&identity[32..]), v.ml_dsa_public_key_hex);

    let signed = hex::decode(&v.signed_public_bundle_sample_hex).unwrap();
    assert_eq!(
        hex::encode(&signed[..vault_core::PUBLIC_BUNDLE_LEN]),
        v.public_bundle_hex
    );
    let bundle = PublicKeyBundle::verify_signed(&signed).unwrap();
    assert_eq!(bundle.account_id, account_id);
    assert_eq!(bundle.key_set_version, v.key_set_version);
}

const ITEMS: &str = include_str!("../../../docs/spec/vectors/06-items.json");

#[derive(Deserialize)]
struct ItemVector {
    item: ItemJson,
    vault_key_hex: String,
    vault_id_hex: String,
    item_id_hex: String,
    revision: u64,
    envelope_hex: String,
}

#[derive(Deserialize)]
struct ItemJson {
    created_ms: u64,
    modified_ms: u64,
    fields: Vec<FieldJson>,
}

#[derive(Deserialize)]
struct FieldJson {
    label: String,
    value: String,
}

#[test]
fn item_vectors_match() {
    use vault_core::{ItemId, SymmetricKey, VaultId, open_item};

    let v: ItemVector = serde_json::from_str(ITEMS).unwrap();
    let vault_key =
        SymmetricKey::from_bytes(hex::decode(&v.vault_key_hex).unwrap().try_into().unwrap());
    let vault_id = VaultId::from_bytes(bytes16(&v.vault_id_hex));
    let item_id = ItemId::from_bytes(bytes16(&v.item_id_hex));

    let envelope = hex::decode(&v.envelope_hex).unwrap();
    let opened = open_item(&envelope, &vault_key, &vault_id, Some(&item_id)).unwrap();
    assert_eq!(opened.revision, v.revision);
    assert_eq!(opened.item.created_ms, v.item.created_ms);
    assert_eq!(opened.item.modified_ms, v.item.modified_ms);
    assert_eq!(opened.item.fields.len(), v.item.fields.len());
    for (got, want) in opened.item.fields.iter().zip(&v.item.fields) {
        assert_eq!(got.label, want.label);
        assert_eq!(got.value.as_str(), want.value);
    }
}
