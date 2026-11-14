//! End-to-end key transparency (spec section 9): a client looking up keys
//! from a server that may try to cheat.

#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

use server_core::transparency::KtLog;
use vault_core::log::bundle_hash;
use vault_core::transparency::{KeyLookup, KtLeaf, TreeHead, verify_key_lookup};
use vault_core::{AccountId, Error, IdentitySecretKey, KeySet};

struct Account {
    id: AccountId,
    bundle: Vec<u8>,
    leaf: Vec<u8>,
}

fn account(tag: u8) -> Account {
    let id = AccountId::from_bytes([tag; 16]);
    let bundle = KeySet::generate()
        .unwrap()
        .signed_public_bundle(&id, 1)
        .unwrap();
    let leaf = KtLeaf {
        account_id: id,
        key_set_version: 1,
        bundle_hash: bundle_hash(&bundle),
        timestamp_ms: u64::from(tag),
    }
    .encode()
    .to_vec();
    Account { id, bundle, leaf }
}

struct Server {
    log: KtLog,
    key: IdentitySecretKey,
}

impl Server {
    fn new() -> Self {
        Self {
            log: KtLog::new(),
            key: IdentitySecretKey::generate().unwrap(),
        }
    }

    fn publish(&mut self, a: &Account) -> u64 {
        self.log.append(&a.leaf).unwrap()
    }

    /// Answers a lookup the honest way.
    fn lookup(
        &self,
        a: &Account,
        index: u64,
        last: Option<&TreeHead>,
    ) -> (Vec<u8>, Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let size = self.log.size();
        let sth = self.log.signed_tree_head(&self.key, 1000).unwrap();
        let inclusion = self.log.inclusion_proof(index, size).unwrap();
        let consistency = last
            .map(|l| self.log.consistency_proof(l.tree_size, size).unwrap())
            .unwrap_or_default();
        let _ = a;
        (sth, inclusion, consistency)
    }
}

fn check(
    server: &Server,
    a: &Account,
    bundle: &[u8],
    index: u64,
    last: Option<&TreeHead>,
) -> Result<TreeHead, Error> {
    let (sth, inclusion, consistency) = server.lookup(a, index, last);
    verify_key_lookup(
        &KeyLookup {
            signed_bundle: bundle,
            leaf: &a.leaf,
            leaf_index: index,
            inclusion_proof: &inclusion,
            signed_tree_head: &sth,
            consistency_proof: &consistency,
        },
        &server.key.public_key(),
        last,
    )
    .map(|(_, head)| head)
}

#[test]
fn honest_lookups_verify_and_the_tree_head_advances() {
    let mut server = Server::new();
    let alice = account(1);
    let bob = account(2);
    let carol = account(3);
    let ia = server.publish(&alice);
    let ib = server.publish(&bob);

    let head1 = check(&server, &bob, &bob.bundle, ib, None).unwrap();
    assert_eq!(head1.tree_size, 2);

    server.publish(&carol);
    let head2 = check(&server, &alice, &alice.bundle, ia, Some(&head1)).unwrap();
    assert_eq!(head2.tree_size, 3);
}

#[test]
fn a_key_that_is_not_in_the_log_is_rejected() {
    let mut server = Server::new();
    let alice = account(1);
    let index = server.publish(&alice);

    // The server hands out a different bundle for Alice without logging it.
    let substitute = KeySet::generate()
        .unwrap()
        .signed_public_bundle(&alice.id, 1)
        .unwrap();
    assert_eq!(
        check(&server, &alice, &substitute, index, None).unwrap_err(),
        Error::LogMismatch
    );

    // Or claims an unlogged leaf for it: the inclusion proof fails.
    let unlogged = account(9);
    let (sth, inclusion, _) = server.lookup(&alice, index, None);
    let result = verify_key_lookup(
        &KeyLookup {
            signed_bundle: &unlogged.bundle,
            leaf: &unlogged.leaf,
            leaf_index: index,
            inclusion_proof: &inclusion,
            signed_tree_head: &sth,
            consistency_proof: &[],
        },
        &server.key.public_key(),
        None,
    );
    assert_eq!(result.unwrap_err(), Error::InvalidProof);
}

#[test]
fn a_tree_head_signed_by_another_key_is_rejected() {
    let mut server = Server::new();
    let alice = account(1);
    let index = server.publish(&alice);
    let (sth, inclusion, _) = server.lookup(&alice, index, None);
    let impostor = IdentitySecretKey::generate().unwrap().public_key();
    let result = verify_key_lookup(
        &KeyLookup {
            signed_bundle: &alice.bundle,
            leaf: &alice.leaf,
            leaf_index: index,
            inclusion_proof: &inclusion,
            signed_tree_head: &sth,
            consistency_proof: &[],
        },
        &impostor,
        None,
    );
    assert_eq!(result.unwrap_err(), Error::InvalidSignature);
}

#[test]
fn rollback_and_split_views_are_detected() {
    let mut server = Server::new();
    let accounts: Vec<Account> = (1..=6).map(account).collect();
    for a in &accounts[..4] {
        server.publish(a);
    }
    let head4 = check(&server, &accounts[0], &accounts[0].bundle, 0, None).unwrap();

    // Rollback: a server presenting a smaller tree than the client saw.
    let mut small = Server {
        log: KtLog::from_leaves(accounts[..3].iter().map(|a| a.leaf.as_slice())).unwrap(),
        key: IdentitySecretKey::from_seed_bytes(server.key.to_seed_bytes().as_slice()).unwrap(),
    };
    let (sth, inclusion, _) = small.lookup(&accounts[0], 0, None);
    let rollback = verify_key_lookup(
        &KeyLookup {
            signed_bundle: &accounts[0].bundle,
            leaf: &accounts[0].leaf,
            leaf_index: 0,
            inclusion_proof: &inclusion,
            signed_tree_head: &sth,
            consistency_proof: &[],
        },
        &small.key.public_key(),
        Some(&head4),
    );
    assert_eq!(rollback.unwrap_err(), Error::LogRollback);

    // Split view: a different history that replaced leaf 2, then grew.
    small.log = KtLog::from_leaves(
        [
            &accounts[0],
            &accounts[1],
            &accounts[5],
            &accounts[3],
            &accounts[4],
        ]
        .iter()
        .map(|a| a.leaf.as_slice()),
    )
    .unwrap();
    let (sth, inclusion, consistency) = small.lookup(&accounts[0], 0, Some(&head4));
    let fork = verify_key_lookup(
        &KeyLookup {
            signed_bundle: &accounts[0].bundle,
            leaf: &accounts[0].leaf,
            leaf_index: 0,
            inclusion_proof: &inclusion,
            signed_tree_head: &sth,
            consistency_proof: &consistency,
        },
        &small.key.public_key(),
        Some(&head4),
    );
    assert_eq!(fork.unwrap_err(), Error::InvalidProof);

    // The honest continuation is accepted.
    server.publish(&accounts[4]);
    assert!(check(&server, &accounts[0], &accounts[0].bundle, 0, Some(&head4)).is_ok());
}
