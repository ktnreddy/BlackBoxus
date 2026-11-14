//! The signed, hash-chained vault revision log (spec section 8).
//!
//! Every change to a vault is an entry signed by its author and linked to
//! the previous entry by hash. Clients replay the whole log, checking every
//! signature and permission, so a malicious server can neither forge,
//! reorder or drop changes, nor roll the vault back to an older state.

use std::collections::{BTreeMap, HashMap};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::item::{ID_LEN, ItemId, VaultId};
use crate::keyset::{ACCOUNT_ID_LEN, AccountId, KeySet, PublicKeyBundle};
use crate::signature::{HYBRID_SIGNATURE_LEN, HybridSignature, IdentityPublicKey};

const FORMAT_VERSION: u16 = 1;
const LABEL_ENTRY: &[u8] = b"BlackBoxus v1 log-entry";
const LABEL_ENTRY_HASH: &[u8] = b"BlackBoxus v1 log-entry-hash";

/// Length of an entry header in bytes.
const HEADER_LEN: usize = 87;

/// Length of a SHA-256 hash in bytes.
pub const HASH_LEN: usize = 32;

/// A member's role in a vault (spec section 8.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Role {
    /// Full control, including membership and key replacement.
    Owner,
    /// Can add, change and delete items.
    Editor,
    /// Can only read items.
    Viewer,
}

impl Role {
    const fn code(self) -> u8 {
        match self {
            Self::Owner => 1,
            Self::Editor => 2,
            Self::Viewer => 3,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Owner),
            2 => Some(Self::Editor),
            3 => Some(Self::Viewer),
            _ => None,
        }
    }
}

/// One change to a vault (spec section 8.2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Operation {
    /// Creates the vault. Only valid as the first entry; the author becomes
    /// its first owner.
    CreateVault {
        /// SHA-256 of the author's signed public key bundle.
        bundle_hash: [u8; HASH_LEN],
    },
    /// Adds or updates an item.
    PutItem {
        /// The item.
        item_id: ItemId,
        /// The new revision: 1 for a new item, otherwise the previous plus 1.
        revision: u64,
        /// The vault key version the envelope's item key is wrapped under.
        vault_key_version: u32,
        /// SHA-256 of the item envelope.
        envelope_hash: [u8; HASH_LEN],
    },
    /// Deletes an item.
    DeleteItem {
        /// The item.
        item_id: ItemId,
        /// The previous revision plus 1.
        revision: u64,
    },
    /// Adds a member.
    AddMember {
        /// The new member.
        account_id: AccountId,
        /// The member's key set version.
        key_set_version: u32,
        /// SHA-256 of the member's verified signed public key bundle.
        bundle_hash: [u8; HASH_LEN],
        /// The member's role.
        role: Role,
    },
    /// Changes a member's role.
    ChangeRole {
        /// The member.
        account_id: AccountId,
        /// The new role.
        role: Role,
    },
    /// Removes a member. A member may also remove themself.
    RemoveMember {
        /// The member.
        account_id: AccountId,
    },
    /// Records that the vault key was replaced.
    RotateKey {
        /// The new version: the current version plus 1.
        new_version: u32,
    },
}

impl Operation {
    const fn code(&self) -> u8 {
        match self {
            Self::CreateVault { .. } => 1,
            Self::PutItem { .. } => 2,
            Self::DeleteItem { .. } => 3,
            Self::AddMember { .. } => 4,
            Self::ChangeRole { .. } => 5,
            Self::RemoveMember { .. } => 6,
            Self::RotateKey { .. } => 7,
        }
    }

    fn encode_body(&self, out: &mut Vec<u8>) {
        match self {
            Self::CreateVault { bundle_hash } => out.extend_from_slice(bundle_hash),
            Self::PutItem {
                item_id,
                revision,
                vault_key_version,
                envelope_hash,
            } => {
                out.extend_from_slice(item_id.as_bytes());
                out.extend_from_slice(&revision.to_be_bytes());
                out.extend_from_slice(&vault_key_version.to_be_bytes());
                out.extend_from_slice(envelope_hash);
            }
            Self::DeleteItem { item_id, revision } => {
                out.extend_from_slice(item_id.as_bytes());
                out.extend_from_slice(&revision.to_be_bytes());
            }
            Self::AddMember {
                account_id,
                key_set_version,
                bundle_hash,
                role,
            } => {
                out.extend_from_slice(account_id.as_bytes());
                out.extend_from_slice(&key_set_version.to_be_bytes());
                out.extend_from_slice(bundle_hash);
                out.push(role.code());
            }
            Self::ChangeRole { account_id, role } => {
                out.extend_from_slice(account_id.as_bytes());
                out.push(role.code());
            }
            Self::RemoveMember { account_id } => out.extend_from_slice(account_id.as_bytes()),
            Self::RotateKey { new_version } => out.extend_from_slice(&new_version.to_be_bytes()),
        }
    }

    fn decode_body(code: u8, r: &mut Reader<'_>) -> Result<Self> {
        let op = match code {
            1 => Self::CreateVault {
                bundle_hash: r.array()?,
            },
            2 => Self::PutItem {
                item_id: ItemId::from_bytes(r.array::<ID_LEN>()?),
                revision: r.u64()?,
                vault_key_version: r.u32()?,
                envelope_hash: r.array()?,
            },
            3 => Self::DeleteItem {
                item_id: ItemId::from_bytes(r.array::<ID_LEN>()?),
                revision: r.u64()?,
            },
            4 => Self::AddMember {
                account_id: AccountId::from_bytes(r.array::<ACCOUNT_ID_LEN>()?),
                key_set_version: r.u32()?,
                bundle_hash: r.array()?,
                role: Role::from_code(r.u8()?).ok_or(Error::MalformedMessage)?,
            },
            5 => Self::ChangeRole {
                account_id: AccountId::from_bytes(r.array::<ACCOUNT_ID_LEN>()?),
                role: Role::from_code(r.u8()?).ok_or(Error::MalformedMessage)?,
            },
            6 => Self::RemoveMember {
                account_id: AccountId::from_bytes(r.array::<ACCOUNT_ID_LEN>()?),
            },
            7 => Self::RotateKey {
                new_version: r.u32()?,
            },
            _ => return Err(Error::MalformedMessage),
        };
        Ok(op)
    }
}

/// The position of a log entry: its sequence number and hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    /// Sequence number, starting at 0.
    pub seq: u64,
    /// `SHA-256("BlackBoxus v1 log-entry-hash" ‖ signed entry)`.
    pub hash: [u8; HASH_LEN],
}

/// A parsed, not yet verified, log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// The vault.
    pub vault_id: VaultId,
    /// Sequence number, starting at 0.
    pub seq: u64,
    /// Hash of the previous entry; all zeros for the first entry.
    pub prev_hash: [u8; HASH_LEN],
    /// The author.
    pub author: AccountId,
    /// The author's key set version.
    pub author_key_set_version: u32,
    /// The author's clock, Unix milliseconds. Informational only.
    pub timestamp_ms: u64,
    /// The change.
    pub operation: Operation,
}

impl LogEntry {
    fn encode_unsigned(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN.saturating_add(64));
        out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
        out.extend_from_slice(self.vault_id.as_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.prev_hash);
        out.extend_from_slice(self.author.as_bytes());
        out.extend_from_slice(&self.author_key_set_version.to_be_bytes());
        out.extend_from_slice(&self.timestamp_ms.to_be_bytes());
        out.push(self.operation.code());
        self.operation.encode_body(&mut out);
        out
    }

    /// Signs the entry with the author's identity key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signing`] or [`Error::RandomUnavailable`].
    pub fn sign(&self, author: &KeySet) -> Result<Vec<u8>> {
        let mut out = self.encode_unsigned();
        let signature = author.identity().sign(LABEL_ENTRY, &out)?;
        out.extend_from_slice(signature.as_bytes());
        Ok(out)
    }

    /// Parses a signed entry without verifying it. Returns the entry, the
    /// signed part and the signature.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if the encoding is invalid.
    pub fn parse(signed: &[u8]) -> Result<(Self, &[u8], HybridSignature)> {
        let body_len = signed
            .len()
            .checked_sub(HYBRID_SIGNATURE_LEN)
            .ok_or(Error::MalformedMessage)?;
        let (unsigned, signature) = signed.split_at(body_len);
        let mut r = Reader(unsigned);
        if r.u16()? != FORMAT_VERSION {
            return Err(Error::MalformedMessage);
        }
        let vault_id = VaultId::from_bytes(r.array::<ID_LEN>()?);
        let seq = r.u64()?;
        let prev_hash = r.array()?;
        let author = AccountId::from_bytes(r.array::<ACCOUNT_ID_LEN>()?);
        let author_key_set_version = r.u32()?;
        let timestamp_ms = r.u64()?;
        let code = r.u8()?;
        let operation = Operation::decode_body(code, &mut r)?;
        if !r.0.is_empty() {
            return Err(Error::MalformedMessage);
        }
        Ok((
            Self {
                vault_id,
                seq,
                prev_hash,
                author,
                author_key_set_version,
                timestamp_ms,
                operation,
            },
            unsigned,
            HybridSignature::from_bytes(signature)?,
        ))
    }
}

/// Hash of a signed entry, used to chain the next entry.
#[must_use]
pub fn entry_hash(signed: &[u8]) -> [u8; HASH_LEN] {
    Sha256::new()
        .chain_update(LABEL_ENTRY_HASH)
        .chain_update(signed)
        .finalize()
        .into()
}

/// SHA-256 of a signed public key bundle, as pinned in the log.
#[must_use]
pub fn bundle_hash(signed_bundle: &[u8]) -> [u8; HASH_LEN] {
    Sha256::digest(signed_bundle).into()
}

/// SHA-256 of an item envelope, as recorded in the log.
#[must_use]
pub fn envelope_hash(envelope: &[u8]) -> [u8; HASH_LEN] {
    Sha256::digest(envelope).into()
}

/// A vault member as recorded in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The member's role.
    pub role: Role,
    /// The member's key set version.
    pub key_set_version: u32,
    /// SHA-256 of the member's signed public key bundle.
    pub bundle_hash: [u8; HASH_LEN],
}

/// The latest state of an item as recorded in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemState {
    /// The current revision.
    pub revision: u64,
    /// `true` if the item has been deleted.
    pub deleted: bool,
    /// The vault key version of the current envelope.
    pub vault_key_version: u32,
    /// SHA-256 of the current envelope; all zeros if deleted.
    pub envelope_hash: [u8; HASH_LEN],
    /// Who made the latest change.
    pub last_author: AccountId,
}

/// The verified state of a vault after replaying its log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultState {
    /// The vault.
    pub vault_id: VaultId,
    /// Current members.
    pub members: BTreeMap<AccountId, Member>,
    /// Every item ever created, including deleted ones.
    pub items: BTreeMap<ItemId, ItemState>,
    /// The current vault key version.
    pub vault_key_version: u32,
    /// `true` after a member is removed and before the key is replaced.
    /// No items may be written while this is set.
    pub rotation_required: bool,
    /// The last entry.
    pub head: Checkpoint,
}

impl VaultState {
    /// Checks that an envelope is the current, authorised revision of an
    /// item (spec section 8.5). Returns the vault key version to open it
    /// with.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LogMismatch`] if the item is unknown, deleted, or the
    /// envelope is not exactly the one the log records for its latest
    /// revision.
    pub fn check_item(&self, item_id: &ItemId, revision: u64, envelope: &[u8]) -> Result<u32> {
        let state = self.items.get(item_id).ok_or(Error::LogMismatch)?;
        if state.deleted
            || state.revision != revision
            || state.envelope_hash != envelope_hash(envelope)
        {
            return Err(Error::LogMismatch);
        }
        Ok(state.vault_key_version)
    }

    /// The checkpoint to create the next entry after.
    #[must_use]
    pub const fn next_seq(&self) -> u64 {
        self.head.seq.saturating_add(1)
    }
}

/// Verifies a complete log and returns the vault state (spec section 8.4).
///
/// - `entries`: every signed entry, in order, starting at sequence 0.
/// - `bundles`: signed public key bundles for every author, keyed by account
///   and key set version. Each is checked against the hash pinned in the log.
/// - `known_head`: the latest checkpoint this device has seen before, if any.
///   The log must contain it unchanged, so rollbacks and forks are detected.
///
/// # Errors
///
/// Returns [`Error::LogRollback`] if the log is shorter than `known_head`,
/// [`Error::LogFork`] if it differs at `known_head`, [`Error::LogMismatch`]
/// for broken links or rule violations, [`Error::InvalidSignature`], or
/// [`Error::MalformedMessage`].
pub fn verify_log(
    vault_id: &VaultId,
    entries: &[Vec<u8>],
    bundles: &HashMap<(AccountId, u32), Vec<u8>>,
    known_head: Option<&Checkpoint>,
) -> Result<VaultState> {
    // Verified identity keys, keyed by the bundle hash pinned in the log.
    let mut identities: HashMap<[u8; HASH_LEN], IdentityPublicKey> = HashMap::new();
    let mut state: Option<VaultState> = None;
    let mut prev = [0_u8; HASH_LEN];

    for (index, signed) in entries.iter().enumerate() {
        let seq = u64::try_from(index).map_err(|_| Error::MalformedMessage)?;
        let (entry, unsigned, signature) = LogEntry::parse(signed)?;
        if entry.vault_id != *vault_id || entry.seq != seq || entry.prev_hash != prev {
            return Err(Error::LogMismatch);
        }

        // The author's identity key, pinned by hash in the log.
        let key = (entry.author, entry.author_key_set_version);
        let pinned = match (&state, &entry.operation) {
            (None, Operation::CreateVault { bundle_hash }) => *bundle_hash,
            (None, _) => return Err(Error::LogMismatch),
            (Some(s), _) => {
                let member = s.members.get(&entry.author).ok_or(Error::LogMismatch)?;
                if member.key_set_version != entry.author_key_set_version {
                    return Err(Error::LogMismatch);
                }
                member.bundle_hash
            }
        };
        let identity = match identities.entry(pinned) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let bundle_bytes = bundles.get(&key).ok_or(Error::LogMismatch)?;
                if bundle_hash(bundle_bytes) != pinned {
                    return Err(Error::LogMismatch);
                }
                let bundle = PublicKeyBundle::verify_signed(bundle_bytes)?;
                if bundle.account_id != entry.author
                    || bundle.key_set_version != entry.author_key_set_version
                {
                    return Err(Error::LogMismatch);
                }
                e.insert(bundle.identity)
            }
        };
        identity.verify(LABEL_ENTRY, unsigned, &signature)?;

        let hash = entry_hash(signed);
        let checkpoint = Checkpoint { seq, hash };
        state = Some(match state {
            None => genesis(&entry, checkpoint)?,
            Some(s) => apply(s, &entry, checkpoint)?,
        });
        prev = hash;

        if let Some(known) = known_head
            && known.seq == seq
            && known.hash != hash
        {
            return Err(Error::LogFork);
        }
    }

    let state = state.ok_or(Error::LogMismatch)?;
    if let Some(known) = known_head
        && known.seq > state.head.seq
    {
        return Err(Error::LogRollback);
    }
    Ok(state)
}

fn genesis(entry: &LogEntry, head: Checkpoint) -> Result<VaultState> {
    let Operation::CreateVault { bundle_hash } = entry.operation else {
        return Err(Error::LogMismatch);
    };
    let mut members = BTreeMap::new();
    members.insert(
        entry.author,
        Member {
            role: Role::Owner,
            key_set_version: entry.author_key_set_version,
            bundle_hash,
        },
    );
    Ok(VaultState {
        vault_id: entry.vault_id,
        members,
        items: BTreeMap::new(),
        vault_key_version: 1,
        rotation_required: false,
        head,
    })
}

/// Applies one entry, enforcing the permission rules of spec section 8.3.
fn apply(mut s: VaultState, entry: &LogEntry, head: Checkpoint) -> Result<VaultState> {
    let author_role = s
        .members
        .get(&entry.author)
        .map(|m| m.role)
        .ok_or(Error::LogMismatch)?;
    let is_owner = author_role == Role::Owner;
    let can_edit = matches!(author_role, Role::Owner | Role::Editor);

    match &entry.operation {
        Operation::CreateVault { .. } => return Err(Error::LogMismatch),

        Operation::PutItem {
            item_id,
            revision,
            vault_key_version,
            envelope_hash,
        } => {
            if !can_edit || s.rotation_required || *vault_key_version != s.vault_key_version {
                return Err(Error::LogMismatch);
            }
            let expected = match s.items.get(item_id) {
                None => 1,
                Some(i) if i.deleted => return Err(Error::LogMismatch),
                Some(i) => i.revision.checked_add(1).ok_or(Error::LogMismatch)?,
            };
            if *revision != expected {
                return Err(Error::LogMismatch);
            }
            s.items.insert(
                *item_id,
                ItemState {
                    revision: *revision,
                    deleted: false,
                    vault_key_version: *vault_key_version,
                    envelope_hash: *envelope_hash,
                    last_author: entry.author,
                },
            );
        }

        Operation::DeleteItem { item_id, revision } => {
            if !can_edit {
                return Err(Error::LogMismatch);
            }
            let item = s.items.get_mut(item_id).ok_or(Error::LogMismatch)?;
            if item.deleted
                || *revision != item.revision.checked_add(1).ok_or(Error::LogMismatch)?
            {
                return Err(Error::LogMismatch);
            }
            item.revision = *revision;
            item.deleted = true;
            item.envelope_hash = [0; HASH_LEN];
            item.last_author = entry.author;
        }

        Operation::AddMember {
            account_id,
            key_set_version,
            bundle_hash,
            role,
        } => {
            if !is_owner || s.members.contains_key(account_id) {
                return Err(Error::LogMismatch);
            }
            s.members.insert(
                *account_id,
                Member {
                    role: *role,
                    key_set_version: *key_set_version,
                    bundle_hash: *bundle_hash,
                },
            );
        }

        Operation::ChangeRole { account_id, role } => {
            if !is_owner {
                return Err(Error::LogMismatch);
            }
            let member = s.members.get_mut(account_id).ok_or(Error::LogMismatch)?;
            member.role = *role;
            ensure_an_owner(&s)?;
        }

        Operation::RemoveMember { account_id } => {
            if !is_owner && *account_id != entry.author {
                return Err(Error::LogMismatch);
            }
            s.members.remove(account_id).ok_or(Error::LogMismatch)?;
            ensure_an_owner(&s)?;
            s.rotation_required = true;
        }

        Operation::RotateKey { new_version } => {
            if !is_owner
                || *new_version
                    != s.vault_key_version
                        .checked_add(1)
                        .ok_or(Error::LogMismatch)?
            {
                return Err(Error::LogMismatch);
            }
            s.vault_key_version = *new_version;
            s.rotation_required = false;
        }
    }
    s.head = head;
    Ok(s)
}

fn ensure_an_owner(s: &VaultState) -> Result<()> {
    if s.members.values().any(|m| m.role == Role::Owner) {
        Ok(())
    } else {
        Err(Error::LogMismatch)
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            return Err(Error::MalformedMessage);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::MalformedMessage)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
}
