//! Shared fixtures for the fuzz targets: fixed keys and accounts created
//! once per process.

use std::sync::OnceLock;

use server_core::api::Api;
use server_core::login::OpaqueServer;
use server_core::prelogin::FakeSaltKey;
use vault_core::device::{EnrolmentOffer, EnrolmentPayload};
use vault_core::recovery::{EmergencyGrant, EmergencyKey};
use vault_core::transparency::TreeHead;
use vault_core::{
    AccountId, ClientIdentity, Field, FieldKind, IdentityPublicKey, IdentitySecretKey, Item,
    ItemId, ItemType, KeySet, PublicKeyBundle, SecretKey, ServerIdentity, SymmetricKey,
    UnlockMethod, VaultId, VaultKey, seal_item,
};

pub struct Fixture {
    pub key: SymmetricKey,
    pub vault_id: VaultId,
    pub account: AccountId,
    pub keys: KeySet,
    pub peer: PublicKeyBundle,
    pub log_key: IdentityPublicKey,
    pub client: ClientIdentity,
    pub server: ServerIdentity,
    pub api: Api,
    /// Valid objects, for targets that tamper with them.
    pub samples: Samples,
}

/// One valid instance of each signed or encrypted format.
pub struct Samples {
    pub envelope: Vec<u8>,
    pub share: Vec<u8>,
    pub grant: Vec<u8>,
    pub bundle: Vec<u8>,
    pub tree_head: Vec<u8>,
    pub wrapped_key_set: Vec<u8>,
    pub enrolment: Vec<u8>,
    pub offer: EnrolmentOffer,
}

pub fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let account = AccountId::from_bytes([1; 16]);
        let peer_id = AccountId::from_bytes([2; 16]);
        let peer_keys = KeySet::generate().expect("keys");
        let peer = PublicKeyBundle::verify_signed(
            &peer_keys.signed_public_bundle(&peer_id, 1).expect("bundle"),
        )
        .expect("verify");
        let server = ServerIdentity::new("https://api.blackboxus.workers.dev").expect("origin");
        let key = SymmetricKey::from_bytes([7; 32]);
        let vault_id = VaultId::from_bytes([3; 16]);
        let keys = KeySet::generate().expect("keys");
        let my_bundle = PublicKeyBundle::verify_signed(
            &keys.signed_public_bundle(&account, 1).expect("bundle"),
        )
        .expect("verify");
        let log_secret = IdentitySecretKey::generate().expect("log key");
        let client = ClientIdentity::new("fuzz@example.com").expect("email");
        let item = Item {
            item_type: ItemType::Login,
            created_ms: 1,
            modified_ms: 2,
            fields: vec![Field::new(FieldKind::Password, "hunter2")],
        };
        let offer = EnrolmentOffer::generate().expect("offer");
        let samples = Samples {
            envelope: seal_item(&item, &key, &vault_id, &ItemId::from_bytes([4; 16]), 1)
                .expect("envelope"),
            share: VaultKey::generate(1)
                .expect("vault key")
                .share(&vault_id, &peer_keys, &peer_id, 1, &my_bundle)
                .expect("share"),
            grant: EmergencyGrant::seal(
                &EmergencyKey::generate().expect("emergency key"),
                &peer_keys,
                &peer_id,
                1,
                &my_bundle,
                7,
            )
            .expect("grant"),
            bundle: keys.signed_public_bundle(&account, 1).expect("bundle"),
            tree_head: TreeHead {
                tree_size: 5,
                root_hash: [9; 32],
                timestamp_ms: 1,
            }
            .sign(&log_secret)
            .expect("tree head"),
            wrapped_key_set: keys
                .wrap(&key, &account, 1, UnlockMethod::MasterPassword)
                .expect("wrap"),
            enrolment: offer
                .seal(&EnrolmentPayload {
                    account_id: account,
                    email: client.clone(),
                    server: server.clone(),
                    secret_key: SecretKey::generate().expect("secret key"),
                    signed_tree_head: None,
                })
                .expect("enrolment"),
            offer,
        };
        Fixture {
            key,
            vault_id,
            account,
            keys,
            peer,
            log_key: log_secret.public_key(),
            client,
            api: Api::new(
                OpaqueServer::generate(),
                FakeSaltKey::from_bytes(&[5; 32]).expect("fake salt key"),
                IdentitySecretKey::generate().expect("log key"),
                server.clone(),
            ),
            server,
            samples,
        }
    })
}

/// XORs `data` into a copy of `sample`, wrapping around. Returns `None` if
/// the result equals the sample, so callers only see real modifications.
pub fn tamper(sample: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let mut out = sample.to_vec();
    let len = out.len();
    for (i, b) in data.iter().enumerate() {
        if let Some(o) = out.get_mut(i % len) {
            *o ^= b;
        }
    }
    (out != sample).then_some(out)
}
