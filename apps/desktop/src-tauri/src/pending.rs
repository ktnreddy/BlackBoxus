//! Changes made while offline, kept sealed on this device until the server
//! can be reached again.
//!
//! A change is not a signed log entry: those are chained to the vault's
//! latest entry, which may move on while this device is offline. Instead
//! the edited item is kept with the revision it was based on. Once online,
//! the change is sent as a normal entry if nobody else changed the item
//! meanwhile; otherwise it becomes a conflict for the user to settle.
//!
//! The file is encrypted with a key derived from the account key (spec
//! section 6.8), like the vault copies next to it, so it opens only while
//! the account is unlocked.

use std::fs;
use std::path::Path;

use client_core::login::Unlocked;
use serde::{Deserialize, Serialize};
use vault_core::{Item, ItemId, VaultId, local};
use zeroize::Zeroizing;

use crate::error::AppError;
use crate::storage::write_atomically;

const FILE: &str = "pending.sealed";
const CONTEXT: &[u8] = b"pending changes v1";

/// Largest encoded item read back, well above the item format's own limits.
const MAX_ITEM_BYTES: usize = 64 * 1024;

/// Most changes kept while offline, so a stuck queue can't grow forever.
pub const MAX_CHANGES: usize = 500;

/// One change waiting to be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub vault: VaultId,
    pub item: ItemId,
    /// The item's revision when it was changed; 0 for a new item.
    pub base: u64,
    /// The new content, or `None` to delete the item.
    pub edit: Option<Item>,
    /// When it was last changed, Unix milliseconds.
    pub changed_ms: u64,
    /// The item was also changed elsewhere; the user must choose.
    pub conflict: bool,
}

impl Change {
    /// "new", "edited" or "deleted", for the item list.
    pub const fn kind(&self) -> &'static str {
        match (&self.edit, self.base) {
            (None, _) => "deleted",
            (Some(_), 0) => "new",
            (Some(_), _) => "edited",
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    vault: String,
    item: String,
    base: u64,
    edit: Option<String>,
    changed_ms: u64,
    conflict: bool,
}

/// The changes waiting to be sent, oldest first.
#[derive(Debug, Default)]
pub struct Queue {
    changes: Vec<Change>,
}

impl Queue {
    /// Reads the queue kept in `dir`. A missing file is an empty queue. A
    /// file that doesn't open with this account's keys is left alone and
    /// reported, so nothing is silently thrown away.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Storage`] if the file exists but can't be read.
    pub fn load(dir: &Path, unlocked: &Unlocked) -> Result<Self, AppError> {
        let sealed = match fs::read(dir.join(FILE)) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(_) => return Err(AppError::Storage),
        };
        let json = local::open(
            &unlocked.key_set,
            unlocked.session.account_id(),
            CONTEXT,
            &sealed,
        )
        .map_err(|_| AppError::Storage)?;
        let saved: Vec<Saved> = serde_json::from_slice(&json).map_err(|_| AppError::Storage)?;
        let changes = saved
            .into_iter()
            .map(|s| {
                let edit = match s.edit {
                    Some(text) => {
                        let bytes = Zeroizing::new(
                            wire::unb64(&text, MAX_ITEM_BYTES).ok_or(AppError::Storage)?,
                        );
                        Some(Item::decode(&bytes).map_err(|_| AppError::Storage)?)
                    }
                    None => None,
                };
                Ok(Change {
                    vault: wire::unb64_array(&s.vault)
                        .map(VaultId::from_bytes)
                        .ok_or(AppError::Storage)?,
                    item: wire::unb64_array(&s.item)
                        .map(ItemId::from_bytes)
                        .ok_or(AppError::Storage)?,
                    base: s.base,
                    edit,
                    changed_ms: s.changed_ms,
                    conflict: s.conflict,
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        Ok(Self { changes })
    }

    /// Writes the queue to `dir`, or removes the file when it is empty.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Storage`] if it can't be written.
    pub fn save(&self, dir: &Path, unlocked: &Unlocked) -> Result<(), AppError> {
        if self.changes.is_empty() {
            return match fs::remove_file(dir.join(FILE)) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(AppError::Storage),
                _ => Ok(()),
            };
        }
        let saved = self
            .changes
            .iter()
            .map(|c| {
                let edit = match &c.edit {
                    Some(item) => Some(wire::b64(&item.encode().map_err(|_| AppError::Storage)?)),
                    None => None,
                };
                Ok(Saved {
                    vault: wire::b64(c.vault.as_bytes()),
                    item: wire::b64(c.item.as_bytes()),
                    base: c.base,
                    edit,
                    changed_ms: c.changed_ms,
                    conflict: c.conflict,
                })
            })
            .collect::<Result<Vec<_>, AppError>>()?;
        let json = Zeroizing::new(serde_json::to_vec(&saved).map_err(|_| AppError::Storage)?);
        let sealed = local::seal(
            &unlocked.key_set,
            unlocked.session.account_id(),
            CONTEXT,
            &json,
        )
        .map_err(|_| AppError::Storage)?;
        write_atomically(dir, FILE, &sealed)
    }

    /// Records a change to `item`, based on revision `base` (0 for a new
    /// item). A second change to the same item keeps the first one's base,
    /// and deleting an item that was only ever added here drops it.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::TooManyChanges`] when the queue is full.
    pub fn record(
        &mut self,
        vault: VaultId,
        item: ItemId,
        base: u64,
        edit: Option<Item>,
        now_ms: u64,
    ) -> Result<(), AppError> {
        if let Some(i) = self
            .changes
            .iter()
            .position(|c| c.vault == vault && c.item == item)
        {
            let Some(existing) = self.changes.get_mut(i) else {
                return Err(AppError::Storage);
            };
            if existing.base == 0 && edit.is_none() {
                self.changes.remove(i);
            } else {
                existing.edit = edit;
                existing.changed_ms = now_ms;
            }
            return Ok(());
        }
        if self.changes.len() >= MAX_CHANGES {
            return Err(AppError::TooManyChanges);
        }
        self.changes.push(Change {
            vault,
            item,
            base,
            edit,
            changed_ms: now_ms,
            conflict: false,
        });
        Ok(())
    }

    /// The change to one item, if any.
    pub fn get(&self, vault: &VaultId, item: &ItemId) -> Option<&Change> {
        self.changes
            .iter()
            .find(|c| c.vault == *vault && c.item == *item)
    }

    /// Every change, oldest first.
    pub fn all(&self) -> &[Change] {
        &self.changes
    }

    /// Removes the change to one item.
    pub fn remove(&mut self, vault: &VaultId, item: &ItemId) -> Option<Change> {
        let i = self
            .changes
            .iter()
            .position(|c| c.vault == *vault && c.item == *item)?;
        Some(self.changes.remove(i))
    }

    /// Marks the change to one item as a conflict.
    pub fn mark_conflict(&mut self, vault: &VaultId, item: &ItemId) {
        if let Some(c) = self
            .changes
            .iter_mut()
            .find(|c| c.vault == *vault && c.item == *item)
        {
            c.conflict = true;
        }
    }

    /// Applies the changes for `vault` to its items as the server has them,
    /// so the list shows what the user did while offline.
    pub fn overlay(&self, vault: &VaultId, items: &mut Vec<(ItemId, Item)>) {
        for c in self.changes.iter().filter(|c| c.vault == *vault) {
            let at = items.iter().position(|(id, _)| *id == c.item);
            match (&c.edit, at) {
                (None, Some(i)) => {
                    items.remove(i);
                }
                (Some(edit), Some(i)) => {
                    if let Some(slot) = items.get_mut(i) {
                        slot.1 = edit.clone();
                    }
                }
                (Some(edit), None) => items.push((c.item, edit.clone())),
                (None, None) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use vault_core::{Field, FieldKind, ItemType};

    fn item(title: &str) -> Item {
        Item {
            item_type: ItemType::Login,
            created_ms: 1,
            modified_ms: 2,
            fields: vec![Field::new(FieldKind::Title, title)],
        }
    }

    #[test]
    fn a_second_change_keeps_the_first_base() {
        let (v, i) = (VaultId::from_bytes([1; 16]), ItemId::from_bytes([2; 16]));
        let mut q = Queue::default();
        q.record(v, i, 4, Some(item("a")), 10).unwrap();
        q.record(v, i, 5, Some(item("b")), 11).unwrap();
        let c = q.get(&v, &i).unwrap();
        assert_eq!(c.base, 4);
        assert_eq!(c.edit, Some(item("b")));
        assert_eq!(c.kind(), "edited");
    }

    #[test]
    fn deleting_a_new_item_drops_it() {
        let (v, i) = (VaultId::from_bytes([1; 16]), ItemId::from_bytes([2; 16]));
        let mut q = Queue::default();
        q.record(v, i, 0, Some(item("a")), 10).unwrap();
        assert_eq!(q.get(&v, &i).unwrap().kind(), "new");
        q.record(v, i, 0, None, 11).unwrap();
        assert!(q.all().is_empty());
    }

    #[test]
    fn overlay_adds_replaces_and_removes() {
        let v = VaultId::from_bytes([1; 16]);
        let (a, b, c) = (
            ItemId::from_bytes([2; 16]),
            ItemId::from_bytes([3; 16]),
            ItemId::from_bytes([4; 16]),
        );
        let mut q = Queue::default();
        q.record(v, a, 3, Some(item("a2")), 1).unwrap();
        q.record(v, b, 7, None, 1).unwrap();
        q.record(v, c, 0, Some(item("c")), 1).unwrap();
        q.record(VaultId::from_bytes([9; 16]), a, 3, None, 1)
            .unwrap();
        let mut items = vec![(a, item("a")), (b, item("b"))];
        q.overlay(&v, &mut items);
        assert_eq!(items, vec![(a, item("a2")), (c, item("c"))]);
    }

    #[test]
    fn the_queue_is_bounded() {
        let v = VaultId::from_bytes([1; 16]);
        let mut q = Queue::default();
        for n in 0..MAX_CHANGES {
            let mut id = [0_u8; 16];
            id[..8].copy_from_slice(&(n as u64).to_be_bytes());
            q.record(v, ItemId::from_bytes(id), 1, None, 1).unwrap();
        }
        assert!(matches!(
            q.record(v, ItemId::from_bytes([0xff; 16]), 1, None, 1),
            Err(AppError::TooManyChanges)
        ));
    }
}
