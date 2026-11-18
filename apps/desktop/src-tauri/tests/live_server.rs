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

    let (created, _, secret_key, kit) = create_account(&transport, &server, &email, PASSWORD)?;
    assert_eq!(kit.email, email);
    assert!(SecretKey::parse(&kit.secret_key)? == secret_key);

    let (again, _) = sign_in(&transport, &server, &email, &secret_key, PASSWORD)?;
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
    let (unlocked, _, secret_key, _) = create_account(&transport, &server, &email, PASSWORD)?;

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
    let (other, _) = sign_in(&transport, &server, &email, &secret_key, PASSWORD)?;
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
    let (alice, _, _, _) = create_account(
        &transport,
        &server,
        &format!("alice-{nonce}@example.com"),
        PASSWORD,
    )?;
    let (bob, _, _, _) = create_account(
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
            .any(|v| v.id == vault_text && v.name == "Personal" && !v.writable)
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

#[test]
#[ignore = "needs a running server and BLACKBOXUS_LOG_KEY"]
fn importing_many_items_in_batches() -> Result<(), AppError> {
    use blackboxus_desktop::http::Transport;
    use blackboxus_desktop::vaults::{VaultFiles, Vaults, log_key};
    use client_core::vaults::written;
    use vault_core::{Field, FieldKind, Item, ItemType, VaultId};

    let transport = Https::new();
    let server = ServerIdentity::new(ORIGIN)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("blackboxus-import-{nonce}"));
    let (unlocked, _, _, _) = create_account(
        &transport,
        &server,
        &format!("import-{nonce}@example.com"),
        PASSWORD,
    )?;
    let mut vaults = Vaults::new(VaultFiles::new(dir.clone()), log_key()?);
    vaults.sync(&transport, &unlocked)?;
    let id = VaultId::from_bytes(
        wire::unb64_array(
            &vaults
                .summaries(&unlocked)
                .first()
                .map(|v| v.id.clone())
                .unwrap_or_default(),
        )
        .unwrap_or_default(),
    );
    let items: Vec<Item> = (0..120)
        .map(|i| Item {
            item_type: ItemType::Login,
            created_ms: 1,
            modified_ms: 1,
            fields: vec![
                Field::new(FieldKind::Title, &format!("site {i:03}")),
                Field::new(FieldKind::Password, "pw"),
            ],
        })
        .collect();
    let started = std::time::Instant::now();
    for batch in items.chunks(50) {
        for request in vaults.new_items_batch(&unlocked, &id, batch)? {
            written(&transport.send(&request)?)?;
        }
        vaults.sync_vault(&transport, &unlocked, id)?;
    }
    assert_eq!(vaults.items(&id)?.len(), 120);
    assert!(started.elapsed().as_secs() < 60);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
#[ignore = "needs a running server and BLACKBOXUS_LOG_KEY"]
fn offline_unlock_shows_the_last_synced_copy() -> Result<(), AppError> {
    use blackboxus_desktop::vaults::{VaultFiles, Vaults, log_key};
    use client_core::Session;
    use client_core::login::{OfflineRecord, Unlocked};
    use vault_core::login::SessionToken;
    use vault_core::{Field, FieldKind, Item, ItemType, VaultId};

    let transport = Https::new();
    let server = ServerIdentity::new(ORIGIN)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("blackboxus-offline-{nonce}"));
    let (unlocked, record, secret_key, _) = create_account(
        &transport,
        &server,
        &format!("offline-{nonce}@example.com"),
        PASSWORD,
    )?;
    let mut vaults = Vaults::new(VaultFiles::new(dir.clone()), log_key()?);
    vaults.sync(&transport, &unlocked)?;
    let id = VaultId::from_bytes(
        wire::unb64_array(
            &vaults
                .summaries(&unlocked)
                .first()
                .map(|v| v.id.clone())
                .unwrap_or_default(),
        )
        .unwrap_or_default(),
    );
    let item = Item {
        item_type: ItemType::Login,
        created_ms: 1,
        modified_ms: 1,
        fields: vec![
            Field::new(FieldKind::Title, "Northwind Bank"),
            Field::new(FieldKind::Password, "Xq7#vL0o"),
        ],
    };
    vaults.put(&transport, &unlocked, id, None, &item)?;

    // No server from here on.
    let record = OfflineRecord::from_json(&record.to_json()?)?;
    let opened = record.unlock(PASSWORD, &secret_key)?;
    let offline = Unlocked {
        session: Session::restore(SessionToken::from_bytes([0; 32]), opened.account_id),
        key_set: opened.key_set,
        key_set_version: opened.key_set_version,
    };
    let mut local = Vaults::new(VaultFiles::new(dir.clone()), log_key()?);
    local.load_local(&offline);
    assert_eq!(local.summaries(&offline).len(), 1);
    assert_eq!(
        local.items(&id)?.first().map(|(_, i)| i.clone()),
        Some(item)
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
#[ignore = "needs a running server and BLACKBOXUS_LOG_KEY"]
fn removing_and_leaving_replace_the_key() -> Result<(), AppError> {
    use blackboxus_desktop::vaults::{VaultFiles, Vaults, log_key};
    use vault_core::log::Role;
    use vault_core::{Field, FieldKind, Item, ItemType, VaultId};

    let transport = Https::new();
    let server = ServerIdentity::new(ORIGIN)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("blackboxus-members-{nonce}"));
    let mut people = Vec::new();
    for name in ["alice", "bob", "carol"] {
        let (unlocked, _, _, _) = create_account(
            &transport,
            &server,
            &format!("{name}-{nonce}@example.com"),
            PASSWORD,
        )?;
        let mut vaults = Vaults::new(VaultFiles::new(dir.join(name)), log_key()?);
        vaults.sync(&transport, &unlocked)?;
        people.push((unlocked, vaults));
    }
    let sharing_id = |p: &(client_core::login::Unlocked, Vaults)| -> Result<String, AppError> {
        let own = VaultId::from_bytes(
            wire::unb64_array(
                &p.1.summaries(&p.0)
                    .first()
                    .map(|v| v.id.clone())
                    .unwrap_or_default(),
            )
            .unwrap_or_default(),
        );
        Ok(p.1
            .members(&own, &p.0)?
            .into_iter()
            .find(|m| m.you)
            .map(|m| m.sharing_id)
            .unwrap_or_default())
    };
    let (bob_id, carol_id) = (sharing_id(&people[1])?, sharing_id(&people[2])?);
    let (alice, rest) = people.split_first_mut().ok_or(AppError::Internal)?;
    let id = VaultId::from_bytes(
        wire::unb64_array(
            &alice
                .1
                .summaries(&alice.0)
                .first()
                .map(|v| v.id.clone())
                .unwrap_or_default(),
        )
        .unwrap_or_default(),
    );
    let item = Item {
        item_type: ItemType::Login,
        created_ms: 1,
        modified_ms: 1,
        fields: vec![Field::new(FieldKind::Title, "Family Wi-Fi")],
    };
    alice.1.put(&transport, &alice.0, id, None, &item)?;
    for who in [&bob_id, &carol_id] {
        alice.1.look_up(&transport, &alice.0, id, who)?;
        alice.1.share(&transport, &alice.0, id, who, Role::Editor)?;
    }

    // Removing Bob replaces the key and re-encrypts the item.
    alice.1.remove_member(&transport, &alice.0, id, &bob_id)?;
    assert_eq!(alice.1.members(&id, &alice.0)?.len(), 2);
    // The server no longer lets Bob write to or download the vault, and his
    // app stops listing it.
    let bob = rest.get_mut(0).ok_or(AppError::Internal)?;
    assert!(bob.1.put(&transport, &bob.0, id, None, &item).is_err());
    bob.1.sync(&transport, &bob.0)?;
    assert!(
        bob.1
            .summaries(&bob.0)
            .iter()
            .all(|v| v.id != wire::b64(id.as_bytes()))
    );
    let carol = rest.get_mut(1).ok_or(AppError::Internal)?;
    carol.1.sync(&transport, &carol.0)?;
    assert_eq!(carol.1.item(&id, &alice.1.items(&id)?[0].0)?, item);

    // Carol leaves; Alice's next sync replaces the key again by itself.
    carol.1.leave(&transport, &carol.0, id)?;
    assert!(
        carol
            .1
            .summaries(&carol.0)
            .iter()
            .all(|v| v.id != wire::b64(id.as_bytes()))
    );
    alice.1.sync(&transport, &alice.0)?;
    assert_eq!(alice.1.members(&id, &alice.0)?.len(), 1);
    alice.1.put(&transport, &alice.0, id, None, &item)?;
    assert_eq!(alice.1.items(&id)?.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
#[ignore = "needs a running server"]
fn recovering_with_a_recovery_key() -> Result<(), AppError> {
    use blackboxus_desktop::flows::{recover, recovery_key_set, set_recovery_key};

    const NEW_PASSWORD: &str = "harbor-cinder-mosaic-thistle";
    let transport = Https::new();
    let server = ServerIdentity::new(ORIGIN)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let email = format!("recover-{nonce}@example.com");
    let (created, _, secret_key, _) = create_account(&transport, &server, &email, PASSWORD)?;
    let account = *created.session.account_id();
    assert!(!recovery_key_set(&transport, &created)?);

    // Making a key needs the right master password.
    assert_eq!(
        set_recovery_key(
            &transport,
            &server,
            &email,
            &secret_key,
            "wrong-password",
            &account
        )
        .err(),
        Some(AppError::WrongPassword)
    );
    let key = set_recovery_key(&transport, &server, &email, &secret_key, PASSWORD, &account)?;
    assert!(recovery_key_set(&transport, &created)?);
    let typed = key.to_display_string();

    // A mistyped or wrong key is refused before anything changes.
    assert!(matches!(
        recover(&transport, &server, &email, "BR1-ABC", NEW_PASSWORD, None),
        Err(AppError::InvalidRecoveryKey(_))
    ));
    let other = vault_core::recovery::RecoveryKey::generate()?.to_display_string();
    assert_eq!(
        recover(&transport, &server, &email, &other, NEW_PASSWORD, None).err(),
        Some(AppError::WrongRecoveryKey)
    );

    // Recovering on a new computer makes a new Secret Key; the old password
    // and session stop working.
    let recovered = recover(&transport, &server, &email, &typed, NEW_PASSWORD, None)?;
    assert!(recovered.new_secret_key);
    assert_eq!(recovered.account_id, account);
    assert_eq!(
        recovery_key_set(&transport, &created).err(),
        Some(AppError::SignedOut)
    );
    assert_eq!(
        sign_in(&transport, &server, &email, &secret_key, PASSWORD).err(),
        Some(AppError::WrongCredentials)
    );
    let (again, _) = sign_in(
        &transport,
        &server,
        &email,
        &recovered.secret_key,
        NEW_PASSWORD,
    )?;
    assert_eq!(again.session.account_id(), &account);

    // Removing the key, with that fresh session, stops it working. (Each
    // sign-in counts twice towards the per-address limit of 10 every 15
    // minutes, so this reuses the session instead of signing in again.)
    let request = client_core::recovery::remove_recovery_key(&again);
    client_core::vaults::written(&blackboxus_desktop::http::Transport::send(
        &transport, &request,
    )?)?;
    assert!(!recovery_key_set(&transport, &again)?);
    assert_eq!(
        recover(&transport, &server, &email, &typed, PASSWORD, None).err(),
        Some(AppError::WrongRecoveryKey)
    );
    Ok(())
}

#[test]
#[ignore = "needs a running server and BLACKBOXUS_LOG_KEY"]
fn creating_and_renaming_vaults() -> Result<(), AppError> {
    use blackboxus_desktop::vaults::{VaultFiles, Vaults, log_key};

    let transport = Https::new();
    let server = ServerIdentity::new(ORIGIN)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!("blackboxus-names-{nonce}"));
    let (unlocked, _, _, _) = create_account(
        &transport,
        &server,
        &format!("names-{nonce}@example.com"),
        PASSWORD,
    )?;
    let mut vaults = Vaults::new(VaultFiles::new(dir.clone()), log_key()?);
    vaults.sync(&transport, &unlocked)?;
    let names = |v: &Vaults| -> Vec<String> {
        v.summaries(&unlocked).into_iter().map(|s| s.name).collect()
    };
    // The first vault is named when it is made.
    assert_eq!(names(&vaults), ["Personal"]);

    let work = vaults.create(&transport, &unlocked, "  Work  ")?;
    assert_eq!(names(&vaults), ["Personal", "Work"]);
    assert_eq!(
        vaults.create(&transport, &unlocked, " ").err(),
        Some(AppError::InvalidVaultName)
    );
    vaults.rename(&transport, &unlocked, work, "Acme projects")?;
    assert_eq!(names(&vaults), ["Acme projects", "Personal"]);
    assert_eq!(vaults.items(&work)?.len(), 0);

    // Another computer sees the same names after a fresh sync.
    let mut other = Vaults::new(VaultFiles::new(dir.join("other")), log_key()?);
    other.sync(&transport, &unlocked)?;
    assert_eq!(names(&other), ["Acme projects", "Personal"]);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
#[ignore = "needs a running server"]
fn changing_the_master_password() -> Result<(), AppError> {
    use blackboxus_desktop::flows::{change_password, recovery_key_set};

    const NEW_PASSWORD: &str = "meadow-copper-signal-ember";
    let transport = Https::new();
    let server = ServerIdentity::new(ORIGIN)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let email = format!("change-{nonce}@example.com");
    let (created, _, secret_key, _) = create_account(&transport, &server, &email, PASSWORD)?;
    let account = *created.session.account_id();

    // The current password must be right.
    assert_eq!(
        change_password(
            &transport,
            &server,
            &email,
            &secret_key,
            "wrong-password",
            NEW_PASSWORD,
            &account
        )
        .err(),
        Some(AppError::WrongPassword)
    );

    let (fresh, offline) = change_password(
        &transport,
        &server,
        &email,
        &secret_key,
        PASSWORD,
        NEW_PASSWORD,
        &account,
    )?;
    // The old session ended; the one used for the change carries on.
    assert_eq!(
        recovery_key_set(&transport, &created).err(),
        Some(AppError::SignedOut)
    );
    assert!(!recovery_key_set(&transport, &fresh)?);
    // The offline record follows the new password.
    assert!(offline.unlock(PASSWORD, &secret_key).is_err());
    assert_eq!(
        offline.unlock(NEW_PASSWORD, &secret_key)?.account_id,
        account
    );

    assert_eq!(
        sign_in(&transport, &server, &email, &secret_key, PASSWORD).err(),
        Some(AppError::WrongCredentials)
    );
    let (again, _) = sign_in(&transport, &server, &email, &secret_key, NEW_PASSWORD)?;
    assert_eq!(again.session.account_id(), &account);
    assert_eq!(again.key_set_version, created.key_set_version);
    Ok(())
}

#[test]
#[ignore = "needs a running server and BLACKBOXUS_LOG_KEY"]
fn checking_our_own_keys_in_the_log() -> Result<(), AppError> {
    use blackboxus_desktop::vaults::{VaultFiles, Vaults, log_key};

    let transport = Https::new();
    let server = ServerIdentity::new(ORIGIN)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let email = format!("selfcheck-{nonce}@example.com");
    let dir = std::env::temp_dir().join(format!("blackboxus-live-{nonce}"));
    let (unlocked, _, _, _) = create_account(&transport, &server, &email, PASSWORD)?;
    let mut vaults = Vaults::new(VaultFiles::new(dir.clone()), log_key()?);

    // The real server lists only this account's own keys.
    assert!(!vaults.check_own_keys(&transport, &unlocked, 1_000)?);
    assert!(dir.join("self-check.json").exists());
    // Within a day it is not asked again; after a day it is.
    assert!(!vaults.check_own_keys(&transport, &unlocked, 2_000)?);
    assert!(!vaults.check_own_keys(&transport, &unlocked, 1_000 + 86_400_000)?);
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[test]
#[ignore = "needs a running server and BLACKBOXUS_LOG_KEY"]
fn naming_a_trusted_contact() -> Result<(), AppError> {
    use blackboxus_desktop::flows::set_trusted_contact;
    use blackboxus_desktop::http::Transport;
    use blackboxus_desktop::vaults::{VaultFiles, Vaults, log_key};
    use client_core::emergency::{
        GrantStage, access_requested, deny_request, open_release, release_request, request_access,
        status, status_request,
    };

    let transport = Https::new();
    let server = ServerIdentity::new(ORIGIN)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let owner_email = format!("owner-{nonce}@example.com");
    let (owner, _, owner_secret, _) = create_account(&transport, &server, &owner_email, PASSWORD)?;
    let (contact, _, _, _) = create_account(
        &transport,
        &server,
        &format!("contact-{nonce}@example.com"),
        PASSWORD,
    )?;
    let owner_id = *owner.session.account_id();
    let contact_id = *contact.session.account_id();
    let dir = std::env::temp_dir().join(format!("blackboxus-live-{nonce}"));
    let mut vaults = Vaults::new(VaultFiles::new(dir.clone()), log_key()?);

    let contact_text = blackboxus_desktop::sharing_id::encode(&contact_id);
    vaults.look_up_contact(&transport, &owner, &contact_text)?;
    let keys = vaults.take_contact(&contact_text)?;
    assert_eq!(
        set_trusted_contact(
            &transport,
            &server,
            &owner_email,
            &owner_secret,
            "wrong-password",
            &owner_id,
            &keys,
            1
        )
        .err(),
        Some(AppError::WrongPassword)
    );
    set_trusted_contact(
        &transport,
        &server,
        &owner_email,
        &owner_secret,
        PASSWORD,
        &owner_id,
        &keys,
        1,
    )?;
    let mine = status(&owner_id, &transport.send(&status_request(&owner))?)?;
    assert_eq!(mine.granted.as_ref().map(|g| g.contact), Some(contact_id));

    // The contact asks; the owner sees it and denies it; they ask again.
    let release_at = access_requested(&transport.send(&request_access(&contact, &owner_id))?)?;
    let theirs = status(&contact_id, &transport.send(&status_request(&contact))?)?;
    assert_eq!(theirs.received.len(), 1);
    assert_eq!(
        theirs.received[0].stage,
        GrantStage::Requested {
            requested_ms: release_at - 86_400_000,
            release_at_ms: release_at
        }
    );
    client_core::vaults::written(&transport.send(&deny_request(&owner, &contact_id))?)?;
    access_requested(&transport.send(&request_access(&contact, &owner_id))?)?;

    // A day has not passed, so nothing opens.
    let owner_keys = vaults.verified_keys(&transport, &contact, &owner_id)?;
    let early = transport.send(&release_request(&contact, &owner_id))?;
    assert_eq!(
        open_release(&contact, &owner_keys, &early).err(),
        Some(client_core::ClientError::Server {
            status: 403,
            code: "too_early".into()
        })
    );
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[test]
#[ignore = "needs a running server and BLACKBOXUS_LOG_KEY"]
fn hints_arrive_when_a_vault_changes() -> Result<(), AppError> {
    use std::time::{Duration, Instant};

    use blackboxus_desktop::http::Transport;
    use blackboxus_desktop::vaults::{VaultFiles, Vaults, log_key};
    use tungstenite::client::IntoClientRequest;
    use tungstenite::stream::MaybeTlsStream;

    let transport = Https::new();
    let server = ServerIdentity::new(ORIGIN)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let email = format!("hints-{nonce}@example.com");
    let (listener, _, secret_key, _) = create_account(&transport, &server, &email, PASSWORD)?;
    let (writer, _) = sign_in(&transport, &server, &email, &secret_key, PASSWORD)?;

    let url = transport.base().replace("http://", "ws://") + "/v1/notifications";
    let connect = |authorization: Option<String>| {
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|_| AppError::Offline)?;
        if let Some(a) = authorization {
            request
                .headers_mut()
                .insert("Authorization", a.parse().map_err(|_| AppError::Offline)?);
        }
        tungstenite::connect(request)
            .map(|(ws, _)| ws)
            .map_err(|e| match e {
                tungstenite::Error::Http(r) if r.status().as_u16() == 401 => AppError::SignedOut,
                _ => AppError::Offline,
            })
    };
    // Without a session nothing connects.
    assert_eq!(connect(None).err(), Some(AppError::SignedOut));
    let mut ws = connect(Some(listener.session.authorization()))?;
    if let MaybeTlsStream::Plain(s) = ws.get_ref() {
        let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    }

    // Another device makes the account's first vault: a hint names it.
    let dir = std::env::temp_dir().join(format!("blackboxus-live-{nonce}"));
    let mut vaults = Vaults::new(VaultFiles::new(dir.clone()), log_key()?);
    vaults.sync(&transport, &writer)?;
    let vault = vaults
        .summaries(&writer)
        .first()
        .map(|v| v.id.clone())
        .unwrap_or_default();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut seen = false;
    while Instant::now() < deadline && !seen {
        if let Ok(tungstenite::Message::Text(t)) = ws.read() {
            seen = t.as_str() == format!(r#"{{"t":"vault","id":"{vault}"}}"#);
        }
    }
    assert!(seen, "no hint for the new vault");

    // Signing out of the listening session closes its connection.
    client_core::vaults::written(&transport.send(&listener.session.logout_request())?)?;
    let closed = loop {
        match ws.read() {
            Ok(tungstenite::Message::Close(_)) | Err(_) => break true,
            Ok(_) if Instant::now() > deadline + Duration::from_secs(10) => break false,
            Ok(_) => {}
        }
    };
    assert!(closed, "connection stayed open after signing out");
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[test]
#[ignore = "needs a running server and BLACKBOXUS_LOG_KEY"]
fn changes_made_offline_sync_later_and_clashes_wait_for_the_user() -> Result<(), AppError> {
    use blackboxus_desktop::vaults::{Keep, VaultFiles, Vaults, log_key};
    use vault_core::{Field, FieldKind, Item, ItemType};

    let transport = Https::new();
    let server = ServerIdentity::new(ORIGIN)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let email = format!("offline-{nonce}@example.com");
    let dir = std::env::temp_dir().join(format!("blackboxus-offline-{nonce}"));
    let (phone, _, secret_key, _) = create_account(&transport, &server, &email, PASSWORD)?;
    let (laptop, _) = sign_in(&transport, &server, &email, &secret_key, PASSWORD)?;
    let login = |title: &str, at: u64| Item {
        item_type: ItemType::Login,
        created_ms: 1,
        modified_ms: at,
        fields: vec![Field::new(FieldKind::Title, title)],
    };

    let mut a = Vaults::new(VaultFiles::new(dir.join("phone")), log_key()?);
    a.sync(&transport, &phone)?;
    let id = vault_core::VaultId::from_bytes(
        wire::unb64_array(
            &a.summaries(&phone)
                .first()
                .map(|v| v.id.clone())
                .unwrap_or_default(),
        )
        .unwrap_or_default(),
    );
    let shared = a.put(&transport, &phone, id, None, &login("Netflix", 1))?;
    let mut b = Vaults::new(VaultFiles::new(dir.join("laptop")), log_key()?);
    b.sync(&transport, &laptop)?;

    // Offline on the phone: one new item, and an edit to the shared one.
    let added = a.put_offline(&phone, id, None, &login("IRCTC", 2))?;
    a.put_offline(&phone, id, Some(shared), &login("Netflix (phone)", 3))?;
    assert_eq!(a.pending(&phone)?.waiting, 2);
    assert_eq!(a.items(&id)?.len(), 2);

    // Meanwhile the laptop changes the shared item too.
    b.put(
        &transport,
        &laptop,
        id,
        Some(shared),
        &login("Netflix (laptop)", 4),
    )?;

    // Back online: the new item goes out, the clash waits.
    a.sync(&transport, &phone)?;
    let pending = a.pending(&phone)?;
    assert_eq!(pending.waiting, 0);
    assert_eq!(pending.conflicts.len(), 1);
    b.sync(&transport, &laptop)?;
    assert_eq!(b.item(&id, &added)?, login("IRCTC", 2));

    // Keeping both turns the phone's version into its own item.
    a.resolve(&transport, &phone, id, shared, Keep::Both)?;
    assert!(a.pending(&phone)?.conflicts.is_empty());
    assert_eq!(a.item(&id, &shared)?, login("Netflix (laptop)", 4));
    assert_eq!(a.items(&id)?.len(), 3);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
