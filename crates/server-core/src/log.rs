//! Server-side checks when appending to a vault's revision log
//! (spec section 8.6).
//!
//! The server cannot judge whether an entry is allowed: clients do that by
//! replaying the signed log. The server only keeps the log a single chain,
//! so two devices writing at once cannot create a fork by accident.

use vault_core::VaultId;
use vault_core::log::{Checkpoint, LogEntry, entry_hash};

use crate::error::{Error, Result};

/// Maximum size of one signed log entry, in bytes.
pub const MAX_ENTRY_BYTES: usize = 4096;

/// Checks that `entry` extends the log whose last entry is `head` (`None`
/// for an empty log), and returns the new head.
///
/// Callers must apply this and store the entry atomically, so that of two
/// concurrent writers only one succeeds; the other re-reads and retries.
///
/// # Errors
///
/// Returns [`Error::MalformedMessage`] if the entry cannot be parsed or is
/// too large, or [`Error::Conflict`] if it does not extend `head`.
pub fn check_append(
    vault_id: &VaultId,
    head: Option<&Checkpoint>,
    entry: &[u8],
) -> Result<Checkpoint> {
    if entry.len() > MAX_ENTRY_BYTES {
        return Err(Error::MalformedMessage);
    }
    let (parsed, _, _) = LogEntry::parse(entry).map_err(|_| Error::MalformedMessage)?;
    if parsed.vault_id != *vault_id {
        return Err(Error::Conflict);
    }
    let (expected_seq, expected_prev) = match head {
        None => (0, [0; 32]),
        Some(h) => (h.seq.checked_add(1).ok_or(Error::Conflict)?, h.hash),
    };
    if parsed.seq != expected_seq || parsed.prev_hash != expected_prev {
        return Err(Error::Conflict);
    }
    Ok(Checkpoint {
        seq: parsed.seq,
        hash: entry_hash(entry),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::log::{Operation, bundle_hash};
    use vault_core::{AccountId, ItemId, KeySet};

    fn entry(keys: &KeySet, vault: VaultId, seq: u64, prev: [u8; 32], op: Operation) -> Vec<u8> {
        LogEntry {
            vault_id: vault,
            seq,
            prev_hash: prev,
            author: AccountId::from_bytes([1; 16]),
            author_key_set_version: 1,
            timestamp_ms: 0,
            operation: op,
        }
        .sign(keys)
        .unwrap()
    }

    #[test]
    fn accepts_only_the_next_entry() {
        let keys = KeySet::generate().unwrap();
        let vault = VaultId::from_bytes([2; 16]);
        let create = Operation::CreateVault {
            bundle_hash: bundle_hash(b"x"),
        };
        let put = |n: u8| Operation::PutItem {
            item_id: ItemId::from_bytes([n; 16]),
            revision: 1,
            vault_key_version: 1,
            envelope_hash: [0; 32],
        };

        let first = entry(&keys, vault, 0, [0; 32], create);
        let head = check_append(&vault, None, &first).unwrap();
        assert_eq!(head.seq, 0);

        let second = entry(&keys, vault, 1, head.hash, put(1));
        let head2 = check_append(&vault, Some(&head), &second).unwrap();
        assert_eq!(head2.seq, 1);

        // A concurrent writer that also built on `head` now conflicts.
        let racing = entry(&keys, vault, 1, head.hash, put(2));
        assert_eq!(
            check_append(&vault, Some(&head2), &racing),
            Err(Error::Conflict)
        );

        // Wrong sequence, wrong previous hash, wrong vault.
        let skip = entry(&keys, vault, 3, head2.hash, put(3));
        assert_eq!(
            check_append(&vault, Some(&head2), &skip),
            Err(Error::Conflict)
        );
        let wrong_prev = entry(&keys, vault, 2, [9; 32], put(3));
        assert_eq!(
            check_append(&vault, Some(&head2), &wrong_prev),
            Err(Error::Conflict)
        );
        let other = VaultId::from_bytes([3; 16]);
        let elsewhere = entry(&keys, other, 2, head2.hash, put(3));
        assert_eq!(
            check_append(&vault, Some(&head2), &elsewhere),
            Err(Error::Conflict)
        );
    }

    #[test]
    fn rejects_malformed_and_oversized_entries() {
        let vault = VaultId::from_bytes([2; 16]);
        assert_eq!(
            check_append(&vault, None, &[]),
            Err(Error::MalformedMessage)
        );
        assert_eq!(
            check_append(&vault, None, &[0; MAX_ENTRY_BYTES + 1]),
            Err(Error::MalformedMessage)
        );
    }
}
