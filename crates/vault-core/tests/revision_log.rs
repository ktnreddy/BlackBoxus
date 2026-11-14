//! Revision log scenarios (spec section 8): permissions, rollback and fork
//! detection, and tampering by a malicious server.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

use std::collections::HashMap;

use vault_core::log::{
    Checkpoint, LogEntry, Operation, Role, bundle_hash, entry_hash, envelope_hash, verify_log,
};
use vault_core::{
    ACCOUNT_ID_LEN, AccountId, Error, Field, FieldKind, ID_LEN, Item, ItemId, ItemType, KeySet,
    SymmetricKey, VaultId, seal_item,
};

struct Person {
    keys: KeySet,
    id: AccountId,
    bundle: Vec<u8>,
}

fn person(tag: u8) -> Person {
    let keys = KeySet::generate().unwrap();
    let id = AccountId::from_bytes([tag; ACCOUNT_ID_LEN]);
    let bundle = keys.signed_public_bundle(&id, 1).unwrap();
    Person { keys, id, bundle }
}

/// A test harness that writes correctly chained entries.
struct Vault {
    id: VaultId,
    entries: Vec<Vec<u8>>,
    bundles: HashMap<(AccountId, u32), Vec<u8>>,
}

impl Vault {
    fn create(owner: &Person) -> Self {
        let mut v = Self {
            id: VaultId::from_bytes([0x5A; ID_LEN]),
            entries: Vec::new(),
            bundles: HashMap::new(),
        };
        v.know(owner);
        v.push(
            owner,
            Operation::CreateVault {
                bundle_hash: bundle_hash(&owner.bundle),
            },
        );
        v
    }

    fn know(&mut self, p: &Person) {
        self.bundles.insert((p.id, 1), p.bundle.clone());
    }

    fn entry(&self, author: &Person, operation: Operation) -> Vec<u8> {
        let seq = self.entries.len() as u64;
        let prev_hash = self.entries.last().map_or([0; 32], |e| entry_hash(e));
        LogEntry {
            vault_id: self.id,
            seq,
            prev_hash,
            author: author.id,
            author_key_set_version: 1,
            timestamp_ms: 1_762_000_000_000 + seq,
            operation,
        }
        .sign(&author.keys)
        .unwrap()
    }

    fn push(&mut self, author: &Person, operation: Operation) {
        let e = self.entry(author, operation);
        self.entries.push(e);
    }

    fn verify(&self) -> Result<vault_core::log::VaultState, Error> {
        verify_log(&self.id, &self.entries, &self.bundles, None)
    }

    fn add(&mut self, owner: &Person, member: &Person, role: Role) {
        self.know(member);
        self.push(
            owner,
            Operation::AddMember {
                account_id: member.id,
                key_set_version: 1,
                bundle_hash: bundle_hash(&member.bundle),
                role,
            },
        );
    }
}

fn put(item: u8, revision: u64, key_version: u32, envelope: &[u8]) -> Operation {
    Operation::PutItem {
        item_id: ItemId::from_bytes([item; ID_LEN]),
        revision,
        vault_key_version: key_version,
        envelope_hash: envelope_hash(envelope),
    }
}

#[test]
fn happy_path_builds_the_expected_state() {
    let alice = person(1);
    let bob = person(2);
    let mut v = Vault::create(&alice);
    v.add(&alice, &bob, Role::Editor);

    let vault_key = SymmetricKey::from_bytes([7; 32]);
    let item = Item {
        item_type: ItemType::Login,
        created_ms: 1,
        modified_ms: 1,
        fields: vec![Field::new(FieldKind::Password, "s3cret")],
    };
    let item_id = ItemId::from_bytes([9; ID_LEN]);
    let env1 = seal_item(&item, &vault_key, &v.id, &item_id, 1).unwrap();
    let env2 = seal_item(&item, &vault_key, &v.id, &item_id, 2).unwrap();
    v.push(&alice, put(9, 1, 1, &env1));
    v.push(&bob, put(9, 2, 1, &env2));

    let state = v.verify().unwrap();
    assert_eq!(state.members.len(), 2);
    assert_eq!(state.members[&bob.id].role, Role::Editor);
    assert_eq!(state.head.seq, 3);
    assert_eq!(state.items[&item_id].last_author, bob.id);

    // Only the latest revision's exact envelope is accepted.
    assert_eq!(state.check_item(&item_id, 2, &env2).unwrap(), 1);
    assert_eq!(
        state.check_item(&item_id, 1, &env1).unwrap_err(),
        Error::LogMismatch
    );
    assert_eq!(
        state.check_item(&item_id, 2, &env1).unwrap_err(),
        Error::LogMismatch
    );

    v.push(
        &bob,
        Operation::DeleteItem {
            item_id,
            revision: 3,
        },
    );
    let state = v.verify().unwrap();
    assert!(state.items[&item_id].deleted);
    assert_eq!(
        state.check_item(&item_id, 2, &env2).unwrap_err(),
        Error::LogMismatch
    );
}

#[test]
fn viewers_cannot_write_and_editors_cannot_manage_members() {
    let alice = person(1);
    let bob = person(2);
    let carol = person(3);

    let mut v = Vault::create(&alice);
    v.add(&alice, &bob, Role::Viewer);
    v.push(&bob, put(1, 1, 1, b"envelope"));
    assert_eq!(v.verify().unwrap_err(), Error::LogMismatch);

    let mut v = Vault::create(&alice);
    v.add(&alice, &bob, Role::Editor);
    v.know(&carol);
    v.push(
        &bob,
        Operation::AddMember {
            account_id: carol.id,
            key_set_version: 1,
            bundle_hash: bundle_hash(&carol.bundle),
            role: Role::Owner,
        },
    );
    assert_eq!(v.verify().unwrap_err(), Error::LogMismatch);

    let mut v = Vault::create(&alice);
    v.add(&alice, &bob, Role::Editor);
    v.push(
        &bob,
        Operation::ChangeRole {
            account_id: bob.id,
            role: Role::Owner,
        },
    );
    assert_eq!(v.verify().unwrap_err(), Error::LogMismatch);
}

#[test]
fn outsiders_and_removed_members_cannot_write() {
    let alice = person(1);
    let bob = person(2);
    let mallory = person(9);

    let mut v = Vault::create(&alice);
    v.know(&mallory);
    v.push(&mallory, put(1, 1, 1, b"envelope"));
    assert_eq!(v.verify().unwrap_err(), Error::LogMismatch);

    let mut v = Vault::create(&alice);
    v.add(&alice, &bob, Role::Editor);
    v.push(&alice, Operation::RemoveMember { account_id: bob.id });
    v.push(&alice, Operation::RotateKey { new_version: 2 });
    v.push(&bob, put(1, 1, 2, b"envelope"));
    assert_eq!(v.verify().unwrap_err(), Error::LogMismatch);
}

#[test]
fn removal_requires_key_rotation_before_writing() {
    let alice = person(1);
    let bob = person(2);
    let mut v = Vault::create(&alice);
    v.add(&alice, &bob, Role::Editor);
    v.push(&alice, Operation::RemoveMember { account_id: bob.id });
    assert!(v.verify().unwrap().rotation_required);

    let mut blocked = Vault {
        id: v.id,
        entries: v.entries.clone(),
        bundles: v.bundles.clone(),
    };
    blocked.push(&alice, put(1, 1, 1, b"envelope"));
    assert_eq!(blocked.verify().unwrap_err(), Error::LogMismatch);

    v.push(&alice, Operation::RotateKey { new_version: 2 });
    let mut stale = Vault {
        id: v.id,
        entries: v.entries.clone(),
        bundles: v.bundles.clone(),
    };
    stale.push(&alice, put(1, 1, 1, b"envelope"));
    assert_eq!(stale.verify().unwrap_err(), Error::LogMismatch);

    v.push(&alice, put(1, 1, 2, b"envelope"));
    let state = v.verify().unwrap();
    assert_eq!(state.vault_key_version, 2);
    assert!(!state.rotation_required);
}

#[test]
fn members_may_leave_but_the_last_owner_may_not() {
    let alice = person(1);
    let bob = person(2);
    let mut v = Vault::create(&alice);
    v.add(&alice, &bob, Role::Viewer);
    v.push(&bob, Operation::RemoveMember { account_id: bob.id });
    assert!(!v.verify().unwrap().members.contains_key(&bob.id));

    let mut v = Vault::create(&alice);
    v.push(
        &alice,
        Operation::RemoveMember {
            account_id: alice.id,
        },
    );
    assert_eq!(v.verify().unwrap_err(), Error::LogMismatch);

    let mut v = Vault::create(&alice);
    v.push(
        &alice,
        Operation::ChangeRole {
            account_id: alice.id,
            role: Role::Viewer,
        },
    );
    assert_eq!(v.verify().unwrap_err(), Error::LogMismatch);
}

#[test]
fn revision_numbers_must_increase_by_one() {
    let alice = person(1);
    for bad in [0, 2] {
        let mut v = Vault::create(&alice);
        v.push(&alice, put(1, bad, 1, b"e"));
        assert_eq!(v.verify().unwrap_err(), Error::LogMismatch, "rev {bad}");
    }
    let mut v = Vault::create(&alice);
    v.push(&alice, put(1, 1, 1, b"e"));
    v.push(&alice, put(1, 1, 1, b"e"));
    assert_eq!(v.verify().unwrap_err(), Error::LogMismatch);

    let mut v = Vault::create(&alice);
    v.push(&alice, put(1, 1, 1, b"e"));
    v.push(
        &alice,
        Operation::DeleteItem {
            item_id: ItemId::from_bytes([1; ID_LEN]),
            revision: 2,
        },
    );
    v.push(&alice, put(1, 3, 1, b"e"));
    assert_eq!(v.verify().unwrap_err(), Error::LogMismatch);
}

#[test]
fn server_cannot_drop_reorder_or_edit_entries() {
    let alice = person(1);
    let mut v = Vault::create(&alice);
    for i in 1..=3 {
        v.push(&alice, put(i, 1, 1, b"e"));
    }
    assert!(v.verify().is_ok());

    let mut dropped = v.entries.clone();
    dropped.remove(2);
    assert!(verify_log(&v.id, &dropped, &v.bundles, None).is_err());

    let mut swapped = v.entries.clone();
    swapped.swap(1, 2);
    assert!(verify_log(&v.id, &swapped, &v.bundles, None).is_err());

    let mut edited = v.entries.clone();
    let last = edited.len() - 1;
    edited[last][120] ^= 1;
    assert!(verify_log(&v.id, &edited, &v.bundles, None).is_err());

    assert!(verify_log(&v.id, &[], &v.bundles, None).is_err());
    let other_vault = VaultId::from_bytes([1; ID_LEN]);
    assert_eq!(
        verify_log(&other_vault, &v.entries, &v.bundles, None).unwrap_err(),
        Error::LogMismatch
    );
}

#[test]
fn server_cannot_substitute_author_keys() {
    let alice = person(1);
    let mut v = Vault::create(&alice);
    v.push(&alice, put(1, 1, 1, b"e"));

    // A different, validly self-signed bundle for Alice's account.
    let impostor = KeySet::generate().unwrap();
    let fake_bundle = impostor.signed_public_bundle(&alice.id, 1).unwrap();
    let mut bundles = v.bundles.clone();
    bundles.insert((alice.id, 1), fake_bundle);
    assert_eq!(
        verify_log(&v.id, &v.entries, &bundles, None).unwrap_err(),
        Error::LogMismatch
    );

    // Missing bundle.
    assert!(verify_log(&v.id, &v.entries, &HashMap::new(), None).is_err());
}

#[test]
fn rollback_and_fork_are_detected() {
    let alice = person(1);
    let mut v = Vault::create(&alice);
    for i in 1..=3 {
        v.push(&alice, put(i, 1, 1, b"e"));
    }
    let head = v.verify().unwrap().head;
    assert_eq!(head.seq, 3);

    // The same log, or a longer one, is accepted.
    assert!(verify_log(&v.id, &v.entries, &v.bundles, Some(&head)).is_ok());
    let mut longer = Vault {
        id: v.id,
        entries: v.entries.clone(),
        bundles: v.bundles.clone(),
    };
    longer.push(&alice, put(4, 1, 1, b"e"));
    assert!(verify_log(&v.id, &longer.entries, &v.bundles, Some(&head)).is_ok());

    // Rollback: the server hides the latest entry.
    assert_eq!(
        verify_log(&v.id, &v.entries[..3], &v.bundles, Some(&head)).unwrap_err(),
        Error::LogRollback
    );

    // Fork: a different, validly signed entry at the same position.
    let mut fork = Vault {
        id: v.id,
        entries: v.entries[..3].to_vec(),
        bundles: v.bundles.clone(),
    };
    fork.push(&alice, put(8, 1, 1, b"other"));
    assert_eq!(
        verify_log(&v.id, &fork.entries, &v.bundles, Some(&head)).unwrap_err(),
        Error::LogFork
    );

    // A checkpoint whose hash does not match anything is also a fork.
    let bogus = Checkpoint {
        seq: 1,
        hash: [0xEE; 32],
    };
    assert_eq!(
        verify_log(&v.id, &v.entries, &v.bundles, Some(&bogus)).unwrap_err(),
        Error::LogFork
    );
}

#[test]
fn malformed_entries_are_rejected() {
    let alice = person(1);
    let v = Vault::create(&alice);
    for bad in [vec![], vec![0; 10], vec![0; 4000]] {
        assert!(verify_log(&v.id, &[bad], &v.bundles, None).is_err());
    }
    let mut extra = v.entries[0].clone();
    extra.insert(100, 0);
    assert!(verify_log(&v.id, &[extra], &v.bundles, None).is_err());
}
