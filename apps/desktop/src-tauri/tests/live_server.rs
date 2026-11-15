//! Account flows against a running server. Ignored by default; run with a
//! local server (see docs/deployment.md):
//!
//! ```sh
//! BLACKBOXUS_API_URL=http://127.0.0.1:8787 cargo test -p blackboxus-desktop -- --ignored
//! ```

use blackboxus_desktop::AppError;
use blackboxus_desktop::flows::{create_account, sign_in};
use blackboxus_desktop::http::{Https, ORIGIN};
use vault_core::{SecretKey, ServerIdentity};

const PASSWORD: &str = "lantern-orbit-velvet-quarry";

#[test]
#[ignore = "needs a running server"]
fn create_sign_in_and_reject_a_wrong_password() -> Result<(), AppError> {
    let transport = Https::new();
    let server = ServerIdentity::new(ORIGIN)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let email = format!("desktop-{nonce}@example.com");

    let (created, secret_key, kit) = create_account(&transport, &server, &email, PASSWORD)?;
    assert_eq!(kit.email, email);
    assert!(SecretKey::parse(&kit.secret_key)? == secret_key);

    let again = sign_in(&transport, &server, &email, &secret_key, PASSWORD)?;
    assert_eq!(again.session.account_id(), created.session.account_id());

    let wrong = sign_in(&transport, &server, &email, &secret_key, "not-the-password");
    assert_eq!(wrong.err(), Some(AppError::WrongCredentials));

    let taken = create_account(&transport, &server, &email, PASSWORD);
    assert_eq!(taken.err(), Some(AppError::EmailTaken));
    Ok(())
}

#[test]
#[ignore = "needs a running server and BLACKBOXUS_LOG_KEY"]
fn vaults_sync_write_and_survive_a_restart() -> Result<(), AppError> {
    use blackboxus_desktop::vaults::{VaultFiles, Vaults, log_key};
    use vault_core::{Field, FieldKind, Item, ItemType};

    let transport = Https::new();
    let server = ServerIdentity::new(ORIGIN)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let email = format!("vaults-{nonce}@example.com");
    let dir = std::env::temp_dir().join(format!("blackboxus-live-{nonce}"));
    let (unlocked, secret_key, _) = create_account(&transport, &server, &email, PASSWORD)?;

    // The first sync creates the account's first vault.
    let mut vaults = Vaults::new(VaultFiles::new(dir.clone()), log_key()?);
    vaults.sync(&transport, &unlocked)?;
    let list = vaults.summaries(&unlocked);
    assert_eq!(list.len(), 1);
    assert!(
        list.first()
            .is_some_and(|v| v.name == "Personal" && v.writable)
    );
    let id = vault_core::VaultId::from_bytes(
        wire::unb64_array(&list.first().map(|v| v.id.clone()).unwrap_or_default())
            .unwrap_or_default(),
    );

    let item = Item {
        item_type: ItemType::Login,
        created_ms: 1,
        modified_ms: 1,
        fields: vec![
            Field::new(FieldKind::Title, "Northwind Bank"),
            Field::new(FieldKind::Password, "Xq7#vL0o-Wd2!kO1"),
        ],
    };
    let item_id = vaults.put(&transport, &unlocked, id, None, &item)?;
    assert_eq!(vaults.item(&id, &item_id)?, item);

    // Another device signs in, syncs from its own empty folder and sees it.
    let other = sign_in(&transport, &server, &email, &secret_key, PASSWORD)?;
    let other_dir = dir.join("other");
    let mut elsewhere = Vaults::new(VaultFiles::new(other_dir), log_key()?);
    elsewhere.sync(&transport, &other)?;
    assert_eq!(elsewhere.item(&id, &item_id)?, item);

    // It edits the item; the first device picks the change up.
    let mut changed = item.clone();
    changed.modified_ms = 2;
    elsewhere.put(&transport, &other, id, Some(item_id), &changed)?;
    vaults.sync(&transport, &unlocked)?;
    assert_eq!(vaults.item(&id, &item_id)?, changed);

    // A restart loads the sealed local copy and syncs on from it.
    let mut restarted = Vaults::new(VaultFiles::new(dir.clone()), log_key()?);
    restarted.sync(&transport, &unlocked)?;
    assert_eq!(restarted.item(&id, &item_id)?, changed);

    restarted.delete(&transport, &unlocked, id, &item_id)?;
    assert_eq!(restarted.items(&id)?.len(), 0);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
#[ignore = "needs a running server and BLACKBOXUS_LOG_KEY"]
fn sharing_a_vault_after_checking_the_safety_number() -> Result<(), AppError> {
    use blackboxus_desktop::vaults::{VaultFiles, Vaults, log_key};
    use vault_core::log::Role;
    use vault_core::{Field, FieldKind, Item, ItemType, VaultId};

    let transport = Https::new();
    let server = ServerIdentity::new(ORIGIN)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("blackboxus-share-{nonce}"));
    let (alice, _, _) = create_account(
        &transport,
        &server,
        &format!("alice-{nonce}@example.com"),
        PASSWORD,
    )?;
    let (bob, _, _) = create_account(
        &transport,
        &server,
        &format!("bob-{nonce}@example.com"),
        PASSWORD,
    )?;
    let mut a = Vaults::new(VaultFiles::new(dir.join("a")), log_key()?);
    let mut b = Vaults::new(VaultFiles::new(dir.join("b")), log_key()?);
    a.sync(&transport, &alice)?;
    b.sync(&transport, &bob)?;

    let vault_text = a
        .summaries(&alice)
        .first()
        .map(|v| v.id.clone())
        .unwrap_or_default();
    let id = VaultId::from_bytes(wire::unb64_array(&vault_text).unwrap_or_default());
    let item = Item {
        item_type: ItemType::SecureNote,
        created_ms: 1,
        modified_ms: 1,
        fields: vec![
            Field::new(FieldKind::Title, "Wi-Fi at home"),
            Field::new(FieldKind::Notes, "Lantern-5G"),
        ],
    };
    let item_id = a.put(&transport, &alice, id, None, &item)?;

    // Bob gives Alice his sharing ID; both see the same safety number.
    let bob_id = b
        .members(
            &VaultId::from_bytes(
                wire::unb64_array(
                    &b.summaries(&bob)
                        .first()
                        .map(|v| v.id.clone())
                        .unwrap_or_default(),
                )
                .unwrap_or_default(),
            ),
            &bob,
        )?
        .into_iter()
        .find(|m| m.you)
        .map(|m| m.sharing_id)
        .unwrap_or_default();
    // Sharing needs a lookup first.
    assert_eq!(
        a.share(&transport, &alice, id, &bob_id, Role::Viewer).err(),
        Some(AppError::NotVerified)
    );
    let found = a.look_up(&transport, &alice, id, &bob_id)?;
    assert_eq!(found.safety_number.len(), 12);
    a.share(&transport, &alice, id, &bob_id, Role::Viewer)?;
    assert_eq!(a.members(&id, &alice)?.len(), 2);
    assert_eq!(
        a.look_up(&transport, &alice, id, &bob_id).err(),
        Some(AppError::AlreadyMember)
    );

    // Bob's next sync accepts the share and shows the vault, read-only.
    b.sync(&transport, &bob)?;
    let shared = b.summaries(&bob);
    assert_eq!(shared.len(), 2);
    assert!(
        shared
            .iter()
            .any(|v| v.id == vault_text && v.name == "Shared with you" && !v.writable)
    );
    assert_eq!(b.item(&id, &item_id)?, item);

    // Bob compares from his side and sees the same number.
    let alice_id = a
        .members(&id, &alice)?
        .into_iter()
        .find(|m| m.you)
        .map(|m| m.sharing_id)
        .unwrap_or_default();
    assert_eq!(
        b.compare(&transport, &bob, &alice_id)?.safety_number,
        found.safety_number
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
