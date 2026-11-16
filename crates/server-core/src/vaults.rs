//! Server checks for vaults: log appends with their item envelopes, wrapped
//! vault keys and shares (spec sections 6–8 and 12.7).
//!
//! Clients verify every signature by replaying the log. The server also
//! applies the log's permission rules (spec section 8.3) to every append, so
//! a viewer or a removed member cannot add an entry that clients would
//! reject and so block the vault. Authors are authenticated by their
//! session, so the server does not need their signatures for this. It keeps
//! each log a single chain, makes envelopes match what their entry records,
//! and lets only current members read a vault (spec section 12.8).

use std::collections::BTreeMap;

use vault_core::log::{
    Checkpoint, ItemState, LogEntry, Member, Operation, Role, VaultState, envelope_hash,
};
use vault_core::{
    AccountId, ItemId, MAX_ENVELOPE_LEN, MIN_ENVELOPE_LEN, OWNER_WRAPPED_VAULT_KEY_LEN, ShareInfo,
    VaultId,
};

use crate::log::check_append;
use crate::{Error, Result};

/// Most log entries returned by one request.
pub const MAX_LOG_PAGE: usize = 200;

/// Most item envelopes returned by one request.
pub const MAX_ITEMS_PAGE: usize = 200;

/// Format version of [`VaultRules::encode`].
const RULES_FORMAT: u8 = 1;

/// Bytes per member in [`VaultRules::encode`].
const MEMBER_LEN: usize = 16 + 1 + 4 + 32;

/// What the server keeps of a vault's state to check appends: its head,
/// members, vault key version and whether a key replacement is due. Items
/// are not kept here; the adapter adds the one an entry touches with
/// [`VaultRules::with_item`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRules {
    state: VaultState,
}

impl VaultRules {
    /// Rebuilds the rules by replaying a whole log, for a vault stored
    /// before the server kept them or whose stored rules do not match its
    /// head. Signatures are not checked: every entry was accepted from its
    /// authenticated author.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if the log is empty or does not
    /// replay.
    pub fn rebuild(vault_id: &VaultId, entries: &[Vec<u8>]) -> Result<Self> {
        let mut state: Option<VaultState> = None;
        for signed in entries {
            let head = check_append(vault_id, state.as_ref().map(|s| &s.head), signed)
                .map_err(|_| Error::MalformedMessage)?;
            let (entry, _, _) = LogEntry::parse(signed).map_err(|_| Error::MalformedMessage)?;
            state = Some(
                match state {
                    None => VaultState::from_first_entry(&entry, head),
                    Some(s) => s.apply_entry(&entry, head),
                }
                .map_err(|_| Error::MalformedMessage)?,
            );
        }
        state
            .map(|state| Self { state })
            .ok_or(Error::MalformedMessage)
    }

    /// Reads rules stored with [`VaultRules::encode`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`].
    pub fn decode(vault_id: &VaultId, bytes: &[u8]) -> Result<Self> {
        let mut r = Reader(bytes);
        if r.array::<1>()? != [RULES_FORMAT] {
            return Err(Error::MalformedMessage);
        }
        let seq = u64::from_be_bytes(r.array()?);
        let hash = r.array()?;
        let vault_key_version = u32::from_be_bytes(r.array()?);
        let rotation_required = match r.array::<1>()? {
            [0] => false,
            [1] => true,
            _ => return Err(Error::MalformedMessage),
        };
        let count = u32::from_be_bytes(r.array()?);
        let mut members = BTreeMap::new();
        for _ in 0..count {
            let account = AccountId::from_bytes(r.array()?);
            let [code] = r.array::<1>()?;
            let member = Member {
                role: Role::from_code(code).ok_or(Error::MalformedMessage)?,
                key_set_version: u32::from_be_bytes(r.array()?),
                bundle_hash: r.array()?,
            };
            if members.insert(account, member).is_some() {
                return Err(Error::MalformedMessage);
            }
        }
        if !r.0.is_empty() || members.is_empty() {
            return Err(Error::MalformedMessage);
        }
        Ok(Self {
            state: VaultState {
                vault_id: *vault_id,
                members,
                items: BTreeMap::new(),
                vault_key_version,
                rotation_required,
                head: Checkpoint { seq, hash },
            },
        })
    }

    /// Encodes the rules for storage. Items are left out.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let s = &self.state;
        let mut out =
            Vec::with_capacity(50_usize.saturating_add(MEMBER_LEN.saturating_mul(s.members.len())));
        out.push(RULES_FORMAT);
        out.extend_from_slice(&s.head.seq.to_be_bytes());
        out.extend_from_slice(&s.head.hash);
        out.extend_from_slice(&s.vault_key_version.to_be_bytes());
        out.push(u8::from(s.rotation_required));
        let count = u32::try_from(s.members.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_be_bytes());
        for (account, member) in s
            .members
            .iter()
            .take(usize::try_from(count).unwrap_or(usize::MAX))
        {
            out.extend_from_slice(account.as_bytes());
            out.push(member.role.code());
            out.extend_from_slice(&member.key_set_version.to_be_bytes());
            out.extend_from_slice(&member.bundle_hash);
        }
        out
    }

    /// The log entry these rules are current at.
    #[must_use]
    pub const fn head(&self) -> &Checkpoint {
        &self.state.head
    }

    /// The role of `account`, or `None` if it is not a member.
    #[must_use]
    pub fn role(&self, account: &AccountId) -> Option<Role> {
        self.state.members.get(account).map(|m| m.role)
    }

    /// The current members.
    pub fn members(&self) -> impl Iterator<Item = &AccountId> {
        self.state.members.keys()
    }

    /// Adds what the server stores about one item: its current revision,
    /// and whether it is deleted. An append that changes an item must be
    /// checked with that item added.
    #[must_use]
    pub fn with_item(mut self, item_id: ItemId, revision: u64, deleted: bool) -> Self {
        self.state.items.insert(
            item_id,
            ItemState {
                revision,
                deleted,
                // Not used to check appends.
                vault_key_version: 0,
                envelope_hash: [0; 32],
                last_author: AccountId::from_bytes([0; 16]),
            },
        );
        self
    }
}

/// The item a log entry changes, if any, so the adapter can load it before
/// [`accept_append`].
///
/// # Errors
///
/// Returns [`Error::MalformedMessage`].
pub fn touched_item(entry: &[u8]) -> Result<Option<ItemId>> {
    let (parsed, _, _) = LogEntry::parse(entry).map_err(|_| Error::MalformedMessage)?;
    Ok(match parsed.operation {
        Operation::PutItem { item_id, .. } | Operation::DeleteItem { item_id, .. } => Some(item_id),
        _ => None,
    })
}

/// What a log append changes, besides the log itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemWrite {
    /// Store this envelope as the item's current revision.
    Put {
        /// The item.
        item_id: ItemId,
        /// Its new revision.
        revision: u64,
        /// The envelope.
        envelope: Vec<u8>,
    },
    /// Mark the item deleted and drop its envelope.
    Delete {
        /// The item.
        item_id: ItemId,
        /// Its new revision.
        revision: u64,
    },
}

/// An append the adapter must store atomically: the entry at
/// `checkpoint.seq`, the new rules, the item change if any, and the change
/// in who may read the vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedAppend {
    /// The log's new head.
    pub checkpoint: Checkpoint,
    /// `true` if this entry creates the vault; its author may now read it.
    pub creates_vault: bool,
    /// The item change.
    pub item: Option<ItemWrite>,
    /// The rules after this entry, to store in place of the old ones.
    pub rules: VaultRules,
    /// A new member, who may now read the vault.
    pub added: Option<AccountId>,
    /// A removed member, who may no longer read the vault. Their pending
    /// shares and wrapped keys for it should be dropped too.
    pub removed: Option<AccountId>,
}

/// `POST /v1/vaults/{vault_id}/log`.
///
/// - `rules`: the vault's current rules, or `None` if the vault does not
///   exist. They must be current at the log's head; for an item change,
///   they must include that item if the server has it
///   ([`VaultRules::with_item`]).
/// - `envelope`: required with a `PutItem` entry, forbidden otherwise.
///
/// The adapter MUST store the result atomically, keyed by `(vault, seq)`, so
/// of two concurrent appends only one succeeds.
///
/// # Errors
///
/// Returns [`Error::NotAllowed`] if the account did not author the entry or
/// the entry breaks the log's rules, for example a viewer changing an item
/// or someone who is not a member writing at all; [`Error::Conflict`] if
/// the entry does not extend the head; or [`Error::MalformedMessage`].
pub fn accept_append(
    vault_id: &VaultId,
    rules: Option<VaultRules>,
    account: &AccountId,
    entry: &[u8],
    envelope: Option<&[u8]>,
) -> Result<AcceptedAppend> {
    let checkpoint = check_append(vault_id, rules.as_ref().map(VaultRules::head), entry)?;
    let (parsed, _, _) = LogEntry::parse(entry).map_err(|_| Error::MalformedMessage)?;
    if parsed.author != *account {
        return Err(Error::NotAllowed);
    }
    let creates_vault = rules.is_none();
    if creates_vault != matches!(parsed.operation, Operation::CreateVault { .. }) {
        return Err(Error::MalformedMessage);
    }
    let mut state = match rules {
        None => VaultState::from_first_entry(&parsed, checkpoint),
        Some(r) => r.state.apply_entry(&parsed, checkpoint),
    }
    .map_err(|_| Error::NotAllowed)?;
    state.items.clear();

    let item = match (&parsed.operation, envelope) {
        (
            Operation::PutItem {
                item_id,
                revision,
                envelope_hash: expected,
                ..
            },
            Some(envelope),
        ) => {
            check_envelope(envelope, vault_id, item_id, *revision)?;
            if envelope_hash(envelope) != *expected {
                return Err(Error::MalformedMessage);
            }
            Some(ItemWrite::Put {
                item_id: *item_id,
                revision: *revision,
                envelope: envelope.to_vec(),
            })
        }
        (Operation::DeleteItem { item_id, revision }, None) => Some(ItemWrite::Delete {
            item_id: *item_id,
            revision: *revision,
        }),
        (Operation::PutItem { .. }, None) | (_, Some(_)) => return Err(Error::MalformedMessage),
        (_, None) => None,
    };
    let (added, removed) = match parsed.operation {
        Operation::AddMember { account_id, .. } => (Some(account_id), None),
        Operation::RemoveMember { account_id } => (None, Some(account_id)),
        _ => (None, None),
    };
    Ok(AcceptedAppend {
        checkpoint,
        creates_vault,
        item,
        rules: VaultRules { state },
        added,
        removed,
    })
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let (head, tail) = self.0.split_at_checked(N).ok_or(Error::MalformedMessage)?;
        self.0 = tail;
        head.try_into().map_err(|_| Error::MalformedMessage)
    }
}

/// Checks an envelope's length and the IDs in its header (spec section 6.5).
fn check_envelope(
    envelope: &[u8],
    vault_id: &VaultId,
    item_id: &ItemId,
    revision: u64,
) -> Result<()> {
    if !(MIN_ENVELOPE_LEN..=MAX_ENVELOPE_LEN).contains(&envelope.len()) {
        return Err(Error::MalformedMessage);
    }
    let mut expected = Vec::with_capacity(42);
    expected.extend_from_slice(&1_u16.to_be_bytes());
    expected.extend_from_slice(vault_id.as_bytes());
    expected.extend_from_slice(item_id.as_bytes());
    expected.extend_from_slice(&revision.to_be_bytes());
    if envelope.get(..expected.len()) != Some(expected.as_slice()) {
        return Err(Error::MalformedMessage);
    }
    Ok(())
}

/// `PUT /v1/vaults/{vault_id}/keys`: a vault key wrapped by a member for
/// themself (spec section 7.3). Returns the vault key version to store it
/// under, per account.
///
/// - `is_member`: whether the account is a current member of the vault.
///
/// # Errors
///
/// Returns [`Error::NotAllowed`] if the account is not a member, or
/// [`Error::MalformedMessage`].
pub fn accept_owner_key(vault_id: &VaultId, is_member: bool, wrapped: &[u8]) -> Result<u32> {
    if !is_member {
        return Err(Error::NotAllowed);
    }
    if wrapped.len() != OWNER_WRAPPED_VAULT_KEY_LEN
        || wrapped.get(..2) != Some(1_u16.to_be_bytes().as_slice())
        || wrapped.get(2..18) != Some(vault_id.as_bytes().as_slice())
    {
        return Err(Error::MalformedMessage);
    }
    wrapped
        .get(18..22)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map(u32::from_be_bytes)
        .ok_or(Error::MalformedMessage)
}

/// `POST /v1/shares` (spec section 7.4). Returns the share's header; the
/// adapter stores the share for its recipient.
///
/// - `rules`: the shared vault's rules, or `None` if it does not exist.
///
/// Only owners share vault keys, and only with current members: a member is
/// added to the log before their share is sent.
///
/// # Errors
///
/// Returns [`Error::NotAllowed`] if the account is not the sender or not an
/// owner, or the recipient is not a member; or [`Error::MalformedMessage`].
pub fn accept_share(
    share: &[u8],
    account: &AccountId,
    rules: Option<&VaultRules>,
) -> Result<ShareInfo> {
    let info = ShareInfo::inspect(share).map_err(|_| Error::MalformedMessage)?;
    let rules = rules.ok_or(Error::NotAllowed)?;
    if info.sender != *account
        || info.recipient == *account
        || rules.role(account) != Some(Role::Owner)
        || rules.role(&info.recipient).is_none()
    {
        return Err(Error::NotAllowed);
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code"
    )]

    use vault_core::{
        Field, FieldKind, Item, ItemType, KeySet, PublicKeyBundle, VaultKey, seal_item,
    };

    use super::*;

    const ALICE: AccountId = AccountId::from_bytes([1; 16]);
    const BOB: AccountId = AccountId::from_bytes([2; 16]);
    const CAROL: AccountId = AccountId::from_bytes([7; 16]);
    const VAULT: VaultId = VaultId::from_bytes([3; 16]);
    const ITEM: ItemId = ItemId::from_bytes([4; 16]);

    /// A vault being built entry by entry, the way the server sees it.
    struct Log {
        entries: Vec<Vec<u8>>,
        rules: Option<VaultRules>,
        /// Item revisions and deletion, as `vault_items` stores them.
        items: BTreeMap<ItemId, (u64, bool)>,
    }

    impl Log {
        fn new() -> Self {
            Self {
                entries: Vec::new(),
                rules: None,
                items: BTreeMap::new(),
            }
        }

        fn sign(&self, keys: &KeySet, author: AccountId, operation: Operation) -> Vec<u8> {
            let (seq, prev) = self
                .rules
                .as_ref()
                .map_or((0, [0; 32]), |r| (r.head().seq + 1, r.head().hash));
            LogEntry {
                vault_id: VAULT,
                seq,
                prev_hash: prev,
                author,
                author_key_set_version: 1,
                timestamp_ms: 0,
                operation,
            }
            .sign(keys)
            .unwrap()
        }

        /// What the adapter passes to [`accept_append`].
        fn rules_for(&self, entry: &[u8]) -> Option<VaultRules> {
            let rules = self.rules.clone()?;
            Some(match touched_item(entry).unwrap() {
                Some(id) => match self.items.get(&id) {
                    Some(&(revision, deleted)) => rules.with_item(id, revision, deleted),
                    None => rules,
                },
                None => rules,
            })
        }

        fn try_append(
            &self,
            keys: &KeySet,
            author: AccountId,
            operation: Operation,
            envelope: Option<&[u8]>,
        ) -> Result<(Vec<u8>, AcceptedAppend)> {
            let entry = self.sign(keys, author, operation);
            let accepted =
                accept_append(&VAULT, self.rules_for(&entry), &author, &entry, envelope)?;
            Ok((entry, accepted))
        }

        fn append(
            &mut self,
            keys: &KeySet,
            author: AccountId,
            operation: Operation,
            envelope: Option<&[u8]>,
        ) -> AcceptedAppend {
            let (entry, accepted) = self.try_append(keys, author, operation, envelope).unwrap();
            match &accepted.item {
                Some(ItemWrite::Put {
                    item_id, revision, ..
                }) => {
                    self.items.insert(*item_id, (*revision, false));
                }
                Some(ItemWrite::Delete { item_id, revision }) => {
                    self.items.insert(*item_id, (*revision, true));
                }
                None => {}
            }
            // The stored rules survive a round trip through storage.
            let stored = accepted.rules.encode();
            self.rules = Some(VaultRules::decode(&VAULT, &stored).unwrap());
            self.entries.push(entry);
            accepted
        }
    }

    fn create() -> Operation {
        Operation::CreateVault {
            bundle_hash: [9; 32],
        }
    }

    fn add(account: AccountId, role: Role) -> Operation {
        Operation::AddMember {
            account_id: account,
            key_set_version: 1,
            bundle_hash: [account.as_bytes()[0]; 32],
            role,
        }
    }

    fn sealed(revision: u64) -> (Operation, Vec<u8>) {
        let vault_key = VaultKey::generate(1).unwrap();
        let item = Item {
            item_type: ItemType::Login,
            created_ms: 1,
            modified_ms: 1,
            fields: vec![Field::new(FieldKind::Password, "pw")],
        };
        let envelope = seal_item(&item, &vault_key.key, &VAULT, &ITEM, revision).unwrap();
        (
            Operation::PutItem {
                item_id: ITEM,
                revision,
                vault_key_version: 1,
                envelope_hash: envelope_hash(&envelope),
            },
            envelope,
        )
    }

    #[test]
    fn creating_a_vault() {
        let keys = KeySet::generate().unwrap();
        let mut log = Log::new();
        let first = log.sign(&keys, ALICE, create());
        // Someone else cannot upload Alice's entry.
        assert_eq!(
            accept_append(&VAULT, None, &BOB, &first, None),
            Err(Error::NotAllowed)
        );
        let accepted = log.append(&keys, ALICE, create(), None);
        assert!(accepted.creates_vault);
        assert_eq!(accepted.checkpoint.seq, 0);
        assert_eq!((accepted.item, accepted.added), (None, None));
        assert_eq!(accepted.rules.role(&ALICE), Some(Role::Owner));

        // The first entry must create the vault.
        let item_first = Log::new().sign(
            &keys,
            ALICE,
            Operation::DeleteItem {
                item_id: ITEM,
                revision: 1,
            },
        );
        assert_eq!(
            accept_append(&VAULT, None, &ALICE, &item_first, None),
            Err(Error::MalformedMessage)
        );
    }

    #[test]
    fn putting_items() {
        let keys = KeySet::generate().unwrap();
        let mut log = Log::new();
        log.append(&keys, ALICE, create(), None);
        let (put, envelope) = sealed(1);

        let (entry, ok) = log
            .try_append(&keys, ALICE, put.clone(), Some(&envelope))
            .unwrap();
        assert_eq!(ok.checkpoint.seq, 1);
        assert_eq!(
            ok.item,
            Some(ItemWrite::Put {
                item_id: ITEM,
                revision: 1,
                envelope: envelope.clone()
            })
        );
        assert_eq!(
            log.try_append(&keys, ALICE, put.clone(), None).unwrap_err(),
            Error::MalformedMessage
        );
        let mut other = envelope.clone();
        let last = other.len() - 1;
        other[last] ^= 1;
        assert_eq!(
            log.try_append(&keys, ALICE, put.clone(), Some(&other))
                .unwrap_err(),
            Error::MalformedMessage
        );
        // An envelope for another item, with a matching hash, is refused too.
        let item = Item {
            item_type: ItemType::Login,
            created_ms: 1,
            modified_ms: 1,
            fields: vec![],
        };
        let wrong = seal_item(
            &item,
            &VaultKey::generate(1).unwrap().key,
            &VAULT,
            &ItemId::from_bytes([5; 16]),
            1,
        )
        .unwrap();
        let put_wrong = Operation::PutItem {
            item_id: ITEM,
            revision: 1,
            vault_key_version: 1,
            envelope_hash: envelope_hash(&wrong),
        };
        assert_eq!(
            log.try_append(&keys, ALICE, put_wrong, Some(&wrong))
                .unwrap_err(),
            Error::MalformedMessage
        );
        // The same entry again does not extend the new head.
        log.append(&keys, ALICE, put.clone(), Some(&envelope));
        assert_eq!(
            accept_append(
                &VAULT,
                log.rules_for(&entry),
                &ALICE,
                &entry,
                Some(&envelope)
            ),
            Err(Error::Conflict)
        );
        // Revisions must follow on from the stored one.
        assert_eq!(
            log.try_append(&keys, ALICE, put, Some(&envelope))
                .unwrap_err(),
            Error::NotAllowed
        );
        let (put2, envelope2) = sealed(2);
        log.append(&keys, ALICE, put2, Some(&envelope2));
        assert_eq!(log.items[&ITEM], (2, false));
    }

    #[test]
    fn roles_are_enforced() {
        let alice = KeySet::generate().unwrap();
        let bob = KeySet::generate().unwrap();
        let carol = KeySet::generate().unwrap();
        let mut log = Log::new();
        log.append(&alice, ALICE, create(), None);
        assert_eq!(
            log.append(&alice, ALICE, add(BOB, Role::Viewer), None)
                .added,
            Some(BOB)
        );

        // Someone who is not a member cannot write at all.
        let (put, envelope) = sealed(1);
        assert_eq!(
            log.try_append(&carol, CAROL, put.clone(), Some(&envelope))
                .unwrap_err(),
            Error::NotAllowed
        );
        // A viewer cannot change items or members.
        assert_eq!(
            log.try_append(&bob, BOB, put.clone(), Some(&envelope))
                .unwrap_err(),
            Error::NotAllowed
        );
        assert_eq!(
            log.try_append(&bob, BOB, add(CAROL, Role::Owner), None)
                .unwrap_err(),
            Error::NotAllowed
        );
        assert_eq!(
            log.try_append(
                &bob,
                BOB,
                Operation::ChangeRole {
                    account_id: BOB,
                    role: Role::Owner
                },
                None
            )
            .unwrap_err(),
            Error::NotAllowed
        );
        // Nor remove the owner, or replace the key.
        assert_eq!(
            log.try_append(
                &bob,
                BOB,
                Operation::RemoveMember { account_id: ALICE },
                None
            )
            .unwrap_err(),
            Error::NotAllowed
        );
        assert_eq!(
            log.try_append(&bob, BOB, Operation::RotateKey { new_version: 2 }, None)
                .unwrap_err(),
            Error::NotAllowed
        );

        // Promoted to editor, Bob can write items.
        log.append(
            &alice,
            ALICE,
            Operation::ChangeRole {
                account_id: BOB,
                role: Role::Editor,
            },
            None,
        );
        log.append(&bob, BOB, put, Some(&envelope));

        // The last owner cannot step down.
        assert_eq!(
            log.try_append(
                &alice,
                ALICE,
                Operation::ChangeRole {
                    account_id: ALICE,
                    role: Role::Viewer
                },
                None
            )
            .unwrap_err(),
            Error::NotAllowed
        );

        // Once removed, Bob cannot write, and items are frozen until the key
        // is replaced.
        let removed = log.append(
            &alice,
            ALICE,
            Operation::RemoveMember { account_id: BOB },
            None,
        );
        assert_eq!(removed.removed, Some(BOB));
        assert_eq!(removed.rules.role(&BOB), None);
        let (put2, envelope2) = sealed(2);
        assert_eq!(
            log.try_append(&bob, BOB, put2.clone(), Some(&envelope2))
                .unwrap_err(),
            Error::NotAllowed
        );
        assert_eq!(
            log.try_append(&alice, ALICE, put2, Some(&envelope2))
                .unwrap_err(),
            Error::NotAllowed
        );
        log.append(&alice, ALICE, Operation::RotateKey { new_version: 2 }, None);

        // A member may leave on their own.
        log.append(&alice, ALICE, add(CAROL, Role::Viewer), None);
        let left = log.append(
            &carol,
            CAROL,
            Operation::RemoveMember { account_id: CAROL },
            None,
        );
        assert_eq!(left.removed, Some(CAROL));
    }

    #[test]
    fn rebuilding_matches_stored_rules() {
        let alice = KeySet::generate().unwrap();
        let mut log = Log::new();
        log.append(&alice, ALICE, create(), None);
        log.append(&alice, ALICE, add(BOB, Role::Editor), None);
        let (put, envelope) = sealed(1);
        log.append(&alice, ALICE, put, Some(&envelope));
        log.append(
            &alice,
            ALICE,
            Operation::RemoveMember { account_id: BOB },
            None,
        );

        let rebuilt = VaultRules::rebuild(&VAULT, &log.entries).unwrap();
        assert_eq!(rebuilt.encode(), log.rules.as_ref().unwrap().encode());
        assert_eq!(rebuilt.members().collect::<Vec<_>>(), vec![&ALICE]);
        assert_eq!(
            VaultRules::rebuild(&VAULT, &[]),
            Err(Error::MalformedMessage)
        );
        assert_eq!(
            VaultRules::rebuild(&VAULT, &log.entries[1..]),
            Err(Error::MalformedMessage)
        );

        let stored = rebuilt.encode();
        assert!(VaultRules::decode(&VAULT, &stored[..stored.len() - 1]).is_err());
        let mut extra = stored.clone();
        extra.push(0);
        assert!(VaultRules::decode(&VAULT, &extra).is_err());
        let mut bad_role = stored;
        let role_at = bad_role.len() - MEMBER_LEN + 16;
        bad_role[role_at] = 9;
        assert!(VaultRules::decode(&VAULT, &bad_role).is_err());
    }

    #[test]
    fn owner_keys_and_shares() {
        let alice = KeySet::generate().unwrap();
        let bob = KeySet::generate().unwrap();
        let vault_key = VaultKey::generate(3).unwrap();
        let wrapped = vault_key.wrap_for_owner(&alice, &ALICE, &VAULT).unwrap();
        assert_eq!(accept_owner_key(&VAULT, true, &wrapped), Ok(3));
        assert_eq!(
            accept_owner_key(&VAULT, false, &wrapped),
            Err(Error::NotAllowed)
        );
        assert_eq!(
            accept_owner_key(&VaultId::from_bytes([8; 16]), true, &wrapped),
            Err(Error::MalformedMessage)
        );

        let mut log = Log::new();
        log.append(&alice, ALICE, create(), None);
        let bob_bundle =
            PublicKeyBundle::verify_signed(&bob.signed_public_bundle(&BOB, 1).unwrap()).unwrap();
        let share = vault_key
            .share(&VAULT, &alice, &ALICE, 1, &bob_bundle)
            .unwrap();
        // Bob must be added to the log first.
        assert_eq!(
            accept_share(&share, &ALICE, log.rules.as_ref()),
            Err(Error::NotAllowed)
        );
        log.append(&alice, ALICE, add(BOB, Role::Viewer), None);
        let info = accept_share(&share, &ALICE, log.rules.as_ref()).unwrap();
        assert_eq!((info.vault_id, info.recipient), (VAULT, BOB));
        assert_eq!(
            accept_share(&share, &BOB, log.rules.as_ref()),
            Err(Error::NotAllowed)
        );
        assert_eq!(accept_share(&share, &ALICE, None), Err(Error::NotAllowed));
        assert_eq!(
            accept_share(&share[1..], &ALICE, log.rules.as_ref()),
            Err(Error::MalformedMessage)
        );
        // Only owners share keys.
        let carol = PublicKeyBundle::verify_signed(
            &KeySet::generate()
                .unwrap()
                .signed_public_bundle(&CAROL, 1)
                .unwrap(),
        )
        .unwrap();
        log.append(&alice, ALICE, add(CAROL, Role::Editor), None);
        let from_bob = vault_key.share(&VAULT, &bob, &BOB, 1, &carol).unwrap();
        assert_eq!(
            accept_share(&from_bob, &BOB, log.rules.as_ref()),
            Err(Error::NotAllowed)
        );
    }
}
