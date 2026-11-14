//! Server checks for vaults: log appends with their item envelopes, wrapped
//! vault keys and shares (spec sections 6–8 and 12.7).
//!
//! The server cannot judge roles, which clients enforce by replaying the
//! signed log. It keeps each log a single chain, makes envelopes match what
//! their entry records, and limits who may read a vault (spec section 12.8).

use vault_core::log::{Checkpoint, LogEntry, Operation, envelope_hash};
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
/// `checkpoint.seq`, the item change if any, and, for a new vault, read
/// access for the creator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedAppend {
    /// The log's new head.
    pub checkpoint: Checkpoint,
    /// `true` if this entry creates the vault.
    pub creates_vault: bool,
    /// The item change.
    pub item: Option<ItemWrite>,
}

/// `POST /v1/vaults/{vault_id}/log`.
///
/// - `head`: the vault's last entry, or `None` if the vault does not exist.
/// - `may_read`: whether `account` may read this vault (ignored for a new
///   vault).
/// - `envelope`: required with a `PutItem` entry, forbidden otherwise.
///
/// The adapter MUST store the result atomically, keyed by `(vault, seq)`, so
/// of two concurrent appends only one succeeds.
///
/// # Errors
///
/// Returns [`Error::NotAllowed`] if the account may not write to this vault
/// or did not author the entry, [`Error::Conflict`] if the entry does not
/// extend the head, or [`Error::MalformedMessage`].
pub fn accept_append(
    vault_id: &VaultId,
    head: Option<&Checkpoint>,
    may_read: bool,
    account: &AccountId,
    entry: &[u8],
    envelope: Option<&[u8]>,
) -> Result<AcceptedAppend> {
    if head.is_some() && !may_read {
        return Err(Error::NotAllowed);
    }
    let checkpoint = check_append(vault_id, head, entry)?;
    let (parsed, _, _) = LogEntry::parse(entry).map_err(|_| Error::MalformedMessage)?;
    if parsed.author != *account {
        return Err(Error::NotAllowed);
    }
    let creates_vault = head.is_none();
    if creates_vault != matches!(parsed.operation, Operation::CreateVault { .. }) {
        return Err(Error::MalformedMessage);
    }
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
    Ok(AcceptedAppend {
        checkpoint,
        creates_vault,
        item,
    })
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
/// # Errors
///
/// Returns [`Error::NotAllowed`] if the account may not read the vault, or
/// [`Error::MalformedMessage`].
pub fn accept_owner_key(vault_id: &VaultId, may_read: bool, wrapped: &[u8]) -> Result<u32> {
    if !may_read {
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
/// adapter stores the share for its recipient and lets the recipient read
/// the vault.
///
/// - `sender_may_read`: whether `account` may read the shared vault.
///
/// # Errors
///
/// Returns [`Error::NotAllowed`] if the account is not the sender, may not
/// read the vault, or shares with itself; or [`Error::MalformedMessage`].
pub fn accept_share(share: &[u8], account: &AccountId, sender_may_read: bool) -> Result<ShareInfo> {
    let info = ShareInfo::inspect(share).map_err(|_| Error::MalformedMessage)?;
    if info.sender != *account || !sender_may_read || info.recipient == *account {
        return Err(Error::NotAllowed);
    }
    Ok(info)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use vault_core::log::entry_hash;
    use vault_core::{
        Field, FieldKind, Item, ItemType, KeySet, PublicKeyBundle, VaultKey, seal_item,
    };

    use super::*;

    const ALICE: AccountId = AccountId::from_bytes([1; 16]);
    const BOB: AccountId = AccountId::from_bytes([2; 16]);
    const VAULT: VaultId = VaultId::from_bytes([3; 16]);

    fn entry(
        keys: &KeySet,
        author: AccountId,
        seq: u64,
        prev: [u8; 32],
        operation: Operation,
    ) -> Vec<u8> {
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

    fn create(keys: &KeySet) -> Vec<u8> {
        entry(
            keys,
            ALICE,
            0,
            [0; 32],
            Operation::CreateVault {
                bundle_hash: [9; 32],
            },
        )
    }

    #[test]
    fn creating_a_vault() {
        let keys = KeySet::generate().unwrap();
        let first = create(&keys);
        let accepted = accept_append(&VAULT, None, false, &ALICE, &first, None).unwrap();
        assert!(accepted.creates_vault);
        assert_eq!(accepted.checkpoint.seq, 0);
        assert_eq!(accepted.item, None);
        // Someone else cannot upload Alice's entry, and the first entry must
        // create the vault.
        assert_eq!(
            accept_append(&VAULT, None, false, &BOB, &first, None),
            Err(Error::NotAllowed)
        );
        let item_first = entry(
            &keys,
            ALICE,
            0,
            [0; 32],
            Operation::DeleteItem {
                item_id: ItemId::from_bytes([4; 16]),
                revision: 1,
            },
        );
        assert_eq!(
            accept_append(&VAULT, None, false, &ALICE, &item_first, None),
            Err(Error::MalformedMessage)
        );
    }

    #[test]
    fn putting_items() {
        let keys = KeySet::generate().unwrap();
        let first = create(&keys);
        let head = accept_append(&VAULT, None, false, &ALICE, &first, None)
            .unwrap()
            .checkpoint;
        let vault_key = VaultKey::generate(1).unwrap();
        let item_id = ItemId::from_bytes([4; 16]);
        let item = Item {
            item_type: ItemType::Login,
            created_ms: 1,
            modified_ms: 1,
            fields: vec![Field::new(FieldKind::Password, "pw")],
        };
        let envelope = seal_item(&item, &vault_key.key, &VAULT, &item_id, 1).unwrap();
        let put = entry(
            &keys,
            ALICE,
            1,
            entry_hash(&first),
            Operation::PutItem {
                item_id,
                revision: 1,
                vault_key_version: 1,
                envelope_hash: envelope_hash(&envelope),
            },
        );

        let ok = accept_append(&VAULT, Some(&head), true, &ALICE, &put, Some(&envelope)).unwrap();
        assert_eq!(ok.checkpoint.seq, 1);
        assert_eq!(
            ok.item,
            Some(ItemWrite::Put {
                item_id,
                revision: 1,
                envelope: envelope.clone()
            })
        );

        assert_eq!(
            accept_append(&VAULT, Some(&head), false, &ALICE, &put, Some(&envelope)),
            Err(Error::NotAllowed)
        );
        assert_eq!(
            accept_append(&VAULT, Some(&head), true, &ALICE, &put, None),
            Err(Error::MalformedMessage)
        );
        let mut other = envelope.clone();
        let last = other.len() - 1;
        other[last] ^= 1;
        assert_eq!(
            accept_append(&VAULT, Some(&head), true, &ALICE, &put, Some(&other)),
            Err(Error::MalformedMessage)
        );
        // An envelope for another item, with a matching hash, is refused too.
        let wrong = seal_item(
            &item,
            &vault_key.key,
            &VAULT,
            &ItemId::from_bytes([5; 16]),
            1,
        )
        .unwrap();
        let put_wrong = entry(
            &keys,
            ALICE,
            1,
            entry_hash(&first),
            Operation::PutItem {
                item_id,
                revision: 1,
                vault_key_version: 1,
                envelope_hash: envelope_hash(&wrong),
            },
        );
        assert_eq!(
            accept_append(&VAULT, Some(&head), true, &ALICE, &put_wrong, Some(&wrong)),
            Err(Error::MalformedMessage)
        );
        // Not extending the head is a conflict.
        assert_eq!(
            accept_append(
                &VAULT,
                Some(&ok.checkpoint),
                true,
                &ALICE,
                &put,
                Some(&envelope)
            ),
            Err(Error::Conflict)
        );
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

        let bob_bundle =
            PublicKeyBundle::verify_signed(&bob.signed_public_bundle(&BOB, 1).unwrap()).unwrap();
        let share = vault_key
            .share(&VAULT, &alice, &ALICE, 1, &bob_bundle)
            .unwrap();
        let info = accept_share(&share, &ALICE, true).unwrap();
        assert_eq!((info.vault_id, info.recipient), (VAULT, BOB));
        assert_eq!(accept_share(&share, &BOB, true), Err(Error::NotAllowed));
        assert_eq!(accept_share(&share, &ALICE, false), Err(Error::NotAllowed));
        assert_eq!(
            accept_share(&share[1..], &ALICE, true),
            Err(Error::MalformedMessage)
        );
    }
}
