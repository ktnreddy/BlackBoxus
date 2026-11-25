//! Vaults: syncing a verified local copy, reading and writing items, and
//! sharing (spec sections 6–8 and 12.7).
//!
//! A [`VaultReplica`] is this device's copy of one vault. Syncing it is:
//!
//! 1. [`VaultReplica::log_request`] and [`VaultReplica::receive_log`] until
//!    no more entries follow;
//! 2. look up any authors in [`VaultReplica::missing_authors`] with
//!    [`crate::keys::KeyDirectory`] and pass them to
//!    [`VaultReplica::add_author`];
//! 3. [`VaultReplica::verify`], which replays the whole signed log;
//! 4. [`VaultReplica::keys_request`] / [`VaultReplica::receive_keys`] for the
//!    vault keys, and [`VaultReplica::items_request`] /
//!    [`VaultReplica::receive_items`] until no more items follow.
//!
//! Nothing the server sends is used until the log verifies, and every
//! envelope must be exactly the one the log records. Writes return requests
//! to send; sync again afterwards to see them.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use vault_core::log::{
    Checkpoint, LogEntry, Operation, Role, VaultState, bundle_hash, entry_hash, envelope_hash,
    verify_log,
};
use vault_core::{
    AccountId, Field, FieldKind, Item, ItemId, ItemType, MAX_ENVELOPE_LEN,
    OWNER_WRAPPED_VAULT_KEY_LEN, ShareInfo, VAULT_DETAILS_ITEM, VAULT_SHARE_LEN, VaultId, VaultKey,
    local, open_item, seal_item,
};
use wire::{
    ItemsResponse, LogAppendRequest, LogResponse, SharePostRequest, SharesResponse,
    VaultKeyPutRequest, VaultKeysResponse, VaultListResponse, b64,
};
use zeroize::Zeroizing;

use crate::http::{Method, Request, Response, field, field_array};
use crate::keys::VerifiedKeys;
use crate::login::Unlocked;
use crate::{ClientError, Result};

/// Largest signed log entry.
const MAX_ENTRY_BYTES: usize = 4096;

/// `GET /v1/vaults`: the vaults this account may read.
#[must_use]
pub fn list_request(unlocked: &Unlocked) -> Request {
    Request::get("/v1/vaults".into(), Some(&unlocked.session))
}

/// Reads the answer to [`list_request`].
///
/// # Errors
///
/// Returns a server error or [`ClientError::InvalidResponse`].
pub fn receive_list(response: &Response) -> Result<Vec<VaultId>> {
    let answer: VaultListResponse = response.parse()?;
    answer
        .vaults
        .iter()
        .map(|v| field_array(&v.vault_id).map(VaultId::from_bytes))
        .collect()
}

/// An item as stored by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredItem {
    revision: u64,
    envelope: Option<Vec<u8>>,
}

/// This device's copy of one vault.
pub struct VaultReplica {
    vault_id: VaultId,
    entries: Vec<Vec<u8>>,
    pending: Vec<Vec<u8>>,
    authors: HashMap<(AccountId, u32), Vec<u8>>,
    state: Option<VaultState>,
    items: BTreeMap<ItemId, StoredItem>,
    items_after: Option<u64>,
    keys: BTreeMap<u32, VaultKey>,
    /// This account's copies of the vault keys, still wrapped under its key
    /// set, kept so the local copy can be read offline.
    wrapped_keys: Vec<Vec<u8>>,
}

impl core::fmt::Debug for VaultReplica {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VaultReplica")
            .field("vault_id", &self.vault_id)
            .field("entries", &self.entries.len())
            .field("items", &self.items.len())
            .finish_non_exhaustive()
    }
}

impl VaultReplica {
    /// An empty copy of a vault, to be filled by syncing.
    #[must_use]
    pub fn new(vault_id: VaultId) -> Self {
        Self {
            vault_id,
            entries: Vec::new(),
            pending: Vec::new(),
            authors: HashMap::new(),
            state: None,
            items: BTreeMap::new(),
            items_after: None,
            keys: BTreeMap::new(),
            wrapped_keys: Vec::new(),
        }
    }

    /// The vault ID.
    #[must_use]
    pub const fn vault_id(&self) -> &VaultId {
        &self.vault_id
    }

    /// The verified state, after the first successful [`VaultReplica::verify`].
    #[must_use]
    pub const fn state(&self) -> Option<&VaultState> {
        self.state.as_ref()
    }

    /// The last verified log position. Keep it between sessions: a server
    /// that later shows a log without it is rolling back or forking the
    /// vault.
    #[must_use]
    pub fn checkpoint(&self) -> Option<Checkpoint> {
        self.state.as_ref().map(|s| s.head)
    }

    fn path(&self, rest: &str) -> String {
        format!("/v1/vaults/{}/{rest}", b64(self.vault_id.as_bytes()))
    }

    // -- Syncing the log ---------------------------------------------------

    /// `GET /v1/vaults/{id}/log`, for the entries after those already held.
    #[must_use]
    pub fn log_request(&self, unlocked: &Unlocked) -> Request {
        let from = self.entries.len().saturating_add(self.pending.len());
        Request::get(
            self.path(&format!("log?from={from}")),
            Some(&unlocked.session),
        )
    }

    /// Stores fetched entries until [`VaultReplica::verify`]. Returns `true`
    /// if more entries follow.
    ///
    /// # Errors
    ///
    /// Returns a server error or [`ClientError::InvalidResponse`].
    pub fn receive_log(&mut self, response: &Response) -> Result<bool> {
        let answer: LogResponse = response.parse()?;
        for entry in &answer.entries {
            self.pending.push(field(entry, MAX_ENTRY_BYTES)?);
        }
        Ok(answer.more)
    }

    /// Authors of fetched entries whose keys are not known yet. Look each up
    /// through key transparency and pass the result to
    /// [`VaultReplica::add_author`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidResponse`] if an entry cannot be parsed.
    pub fn missing_authors(&self) -> Result<Vec<AccountId>> {
        let mut missing = Vec::new();
        for entry in self.entries.iter().chain(&self.pending) {
            let (parsed, _, _) =
                LogEntry::parse(entry).map_err(|_| ClientError::InvalidResponse)?;
            let key = (parsed.author, parsed.author_key_set_version);
            if !self.authors.contains_key(&key) && !missing.contains(&parsed.author) {
                missing.push(parsed.author);
            }
        }
        Ok(missing)
    }

    /// Adds an author's keys, verified through key transparency.
    pub fn add_author(&mut self, keys: &VerifiedKeys) {
        self.authors.insert(
            (keys.bundle.account_id, keys.bundle.key_set_version),
            keys.signed.clone(),
        );
    }

    /// Replays the whole log, including the fetched entries, and accepts them
    /// only if every signature, link, role and the last checkpoint check out.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Crypto`] with [`vault_core::Error::LogRollback`],
    /// [`vault_core::Error::LogFork`] or another verification error. These
    /// mean the server is misbehaving; the fetched entries are discarded and
    /// the previous state kept.
    pub fn verify(&mut self) -> Result<&VaultState> {
        let mut all = self.entries.clone();
        all.extend(self.pending.iter().cloned());
        let known = self.checkpoint();
        let result = verify_log(&self.vault_id, &all, &self.authors, known.as_ref());
        self.pending.clear();
        let state = result?;
        self.entries = all;
        Ok(self.state.insert(state))
    }

    // -- Vault keys --------------------------------------------------------

    /// `GET /v1/vaults/{id}/keys`.
    #[must_use]
    pub fn keys_request(&self, unlocked: &Unlocked) -> Request {
        Request::get(self.path("keys"), Some(&unlocked.session))
    }

    /// Unwraps this account's copies of the vault key.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidResponse`] if a copy does not decrypt.
    pub fn receive_keys(&mut self, unlocked: &Unlocked, response: &Response) -> Result<()> {
        let answer: VaultKeysResponse = response.parse()?;
        for wrapped in &answer.keys {
            let wrapped = field(wrapped, OWNER_WRAPPED_VAULT_KEY_LEN)?;
            self.add_wrapped_key(unlocked, wrapped)?;
        }
        Ok(())
    }

    fn add_wrapped_key(&mut self, unlocked: &Unlocked, wrapped: Vec<u8>) -> Result<()> {
        let key = VaultKey::unwrap_for_owner(
            &wrapped,
            &unlocked.key_set,
            unlocked.session.account_id(),
            &self.vault_id,
        )
        .map_err(|_| ClientError::InvalidResponse)?;
        self.keys.insert(key.version, key);
        if !self.wrapped_keys.contains(&wrapped) {
            self.wrapped_keys.push(wrapped);
        }
        Ok(())
    }

    // -- Items -------------------------------------------------------------

    /// `GET /v1/vaults/{id}/items`, for items changed since the last sync.
    #[must_use]
    pub fn items_request(&self, unlocked: &Unlocked) -> Request {
        let path = match self.items_after {
            Some(after) => self.path(&format!("items?after={after}")),
            None => self.path("items"),
        };
        Request::get(path, Some(&unlocked.session))
    }

    /// Stores fetched envelopes after checking each against the verified
    /// log. Returns `true` if more items follow.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidResponse`] if the log has not been
    /// verified, or an envelope is not the one the log records for that
    /// revision.
    pub fn receive_items(&mut self, response: &Response) -> Result<bool> {
        let state = self.state.as_ref().ok_or(ClientError::InvalidResponse)?;
        let answer: ItemsResponse = response.parse()?;
        for item in &answer.items {
            // Changes after the verified log are picked up on the next sync.
            if item.seq > state.head.seq {
                continue;
            }
            let item_id = ItemId::from_bytes(field_array(&item.item_id)?);
            let recorded = state
                .items
                .get(&item_id)
                .ok_or(ClientError::InvalidResponse)?;
            if item.revision != recorded.revision {
                return Err(ClientError::InvalidResponse);
            }
            let envelope = item
                .envelope
                .as_deref()
                .map(|e| field(e, MAX_ENVELOPE_LEN))
                .transpose()?;
            match &envelope {
                Some(e) => {
                    state
                        .check_item(&item_id, item.revision, e)
                        .map_err(|_| ClientError::InvalidResponse)?;
                }
                None if recorded.deleted => {}
                None => return Err(ClientError::InvalidResponse),
            }
            self.items.insert(
                item_id,
                StoredItem {
                    revision: item.revision,
                    envelope,
                },
            );
            self.items_after = Some(self.items_after.map_or(item.seq, |a| a.max(item.seq)));
        }
        Ok(answer.more)
    }

    /// Decrypts every current item. Envelopes are checked against the log
    /// again, so a stale or swapped one is never shown.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidResponse`] if the log has not been
    /// verified or a vault key is missing, or [`ClientError::Crypto`] if an
    /// envelope does not open.
    pub fn items(&self) -> Result<Vec<(ItemId, Item)>> {
        Ok(self
            .all_items()?
            .into_iter()
            .filter(|(id, item)| {
                *id != VAULT_DETAILS_ITEM && item.item_type != ItemType::VaultDetails
            })
            .collect())
    }

    /// The vault's details (spec section 6.3), if it has any.
    ///
    /// # Errors
    ///
    /// As [`VaultReplica::items`].
    pub fn details(&self) -> Result<Option<Item>> {
        Ok(self
            .all_items()?
            .into_iter()
            .find(|(id, item)| {
                *id == VAULT_DETAILS_ITEM && item.item_type == ItemType::VaultDetails
            })
            .map(|(_, item)| item))
    }

    /// The vault's name from its details, if it has one.
    ///
    /// # Errors
    ///
    /// As [`VaultReplica::items`].
    pub fn name(&self) -> Result<Option<String>> {
        Ok(self.details()?.and_then(|d| {
            d.fields
                .into_iter()
                .find(|f| f.kind == FieldKind::Title)
                .map(|f| f.value.to_string())
                .filter(|n| !n.trim().is_empty())
        }))
    }

    /// Names the vault, keeping any description. Send the request, then
    /// sync.
    ///
    /// # Errors
    ///
    /// As [`VaultReplica::put_item`].
    pub fn rename(&self, unlocked: &Unlocked, name: &str, now_ms: u64) -> Result<Request> {
        let mut details = self.details()?.unwrap_or(Item {
            item_type: ItemType::VaultDetails,
            created_ms: now_ms,
            modified_ms: now_ms,
            fields: Vec::new(),
        });
        details.modified_ms = now_ms;
        details.fields.retain(|f| f.kind != FieldKind::Title);
        details.fields.insert(0, Field::new(FieldKind::Title, name));
        Ok(self
            .put_item(unlocked, Some(VAULT_DETAILS_ITEM), &details, now_ms)?
            .1)
    }

    /// Every item this version can read, including the vault's details.
    /// Items saved in a newer format are left out (see
    /// [`VaultReplica::newer_items`]).
    fn all_items(&self) -> Result<Vec<(ItemId, Item)>> {
        Ok(self.read_items()?.0)
    }

    /// How many items were saved by a newer version of the app, which this
    /// one can't show or change (spec section 6.3).
    ///
    /// # Errors
    ///
    /// As [`VaultReplica::items`].
    pub fn newer_items(&self) -> Result<usize> {
        Ok(self.read_items()?.1)
    }

    /// The items this version can read, and how many it can't because they
    /// are in a newer format.
    fn read_items(&self) -> Result<(Vec<(ItemId, Item)>, usize)> {
        let state = self.state.as_ref().ok_or(ClientError::InvalidResponse)?;
        let mut newer = 0_usize;
        let mut out = Vec::new();
        for (item_id, stored) in &self.items {
            let Some(envelope) = &stored.envelope else {
                continue;
            };
            let Ok(version) = state.check_item(item_id, stored.revision, envelope) else {
                // Superseded by a newer revision not yet downloaded.
                continue;
            };
            let key = self
                .keys
                .get(&version)
                .ok_or(ClientError::InvalidResponse)?;
            match open_item(envelope, &key.key, &self.vault_id, Some(item_id)) {
                Ok(opened) => out.push((*item_id, opened.item)),
                Err(vault_core::Error::NewerItemFormat) => newer = newer.saturating_add(1),
                Err(e) => return Err(e.into()),
            }
        }
        Ok((out, newer))
    }

    // -- Writing -----------------------------------------------------------

    fn sign(&self, unlocked: &Unlocked, now_ms: u64, operation: Operation) -> Result<Vec<u8>> {
        let state = self.state.as_ref().ok_or(ClientError::InvalidResponse)?;
        Ok(LogEntry {
            vault_id: self.vault_id,
            seq: state.next_seq(),
            prev_hash: state.head.hash,
            author: *unlocked.session.account_id(),
            author_key_set_version: unlocked.key_set_version,
            timestamp_ms: now_ms,
            operation,
        }
        .sign(&unlocked.key_set)?)
    }

    fn append(
        &self,
        unlocked: &Unlocked,
        entry: &[u8],
        envelope: Option<&[u8]>,
    ) -> Result<Request> {
        Request::json(
            Method::Post,
            self.path("log"),
            &LogAppendRequest {
                entry: b64(entry),
                envelope: envelope.map(b64),
            },
            Some(&unlocked.session),
        )
    }

    /// Adds an item (`item_id = None`) or replaces one, as a new revision
    /// encrypted under the current vault key. Returns the item's ID and the
    /// request. A `conflict` answer means another device wrote first: sync
    /// and try again.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidResponse`] before the first sync, while
    /// the vault key must be replaced, or without the current vault key.
    pub fn put_item(
        &self,
        unlocked: &Unlocked,
        item_id: Option<ItemId>,
        item: &Item,
        now_ms: u64,
    ) -> Result<(ItemId, Request)> {
        let state = self.state.as_ref().ok_or(ClientError::InvalidResponse)?;
        if state.rotation_required {
            return Err(ClientError::InvalidResponse);
        }
        let key = self
            .keys
            .get(&state.vault_key_version)
            .ok_or(ClientError::InvalidResponse)?;
        let item_id = match item_id {
            Some(id) => id,
            None => ItemId::generate()?,
        };
        // A vault's details live only under their reserved ID.
        if (item_id == VAULT_DETAILS_ITEM) != (item.item_type == ItemType::VaultDetails) {
            return Err(ClientError::NotAllowed);
        }
        let revision = state
            .items
            .get(&item_id)
            .map_or(1, |s| s.revision.saturating_add(1));
        let envelope = seal_item(item, &key.key, &self.vault_id, &item_id, revision)?;
        let entry = self.sign(
            unlocked,
            now_ms,
            Operation::PutItem {
                item_id,
                revision,
                vault_key_version: key.version,
                envelope_hash: envelope_hash(&envelope),
            },
        )?;
        Ok((item_id, self.append(unlocked, &entry, Some(&envelope))?))
    }

    /// Adds many new items at once, for imports: each entry is chained to
    /// the one before it, so the whole batch is verified by one sync at the
    /// end instead of one per item. Send the requests in order. If one is
    /// refused (for example `conflict`), stop, sync, and build the rest
    /// again with a new call.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidResponse`] before the first sync, while
    /// the vault key must be replaced, or without the current vault key.
    pub fn put_new_items(
        &self,
        unlocked: &Unlocked,
        items: &[Item],
        now_ms: u64,
    ) -> Result<Vec<(ItemId, Request)>> {
        let state = self.state.as_ref().ok_or(ClientError::InvalidResponse)?;
        if state.rotation_required {
            return Err(ClientError::InvalidResponse);
        }
        let key = self
            .keys
            .get(&state.vault_key_version)
            .ok_or(ClientError::InvalidResponse)?;
        if items.iter().any(|i| i.item_type == ItemType::VaultDetails) {
            return Err(ClientError::NotAllowed);
        }
        let mut seq = state.next_seq();
        let mut prev_hash = state.head.hash;
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let item_id = ItemId::generate()?;
            let envelope = seal_item(item, &key.key, &self.vault_id, &item_id, 1)?;
            let entry = LogEntry {
                vault_id: self.vault_id,
                seq,
                prev_hash,
                author: *unlocked.session.account_id(),
                author_key_set_version: unlocked.key_set_version,
                timestamp_ms: now_ms,
                operation: Operation::PutItem {
                    item_id,
                    revision: 1,
                    vault_key_version: key.version,
                    envelope_hash: envelope_hash(&envelope),
                },
            }
            .sign(&unlocked.key_set)?;
            prev_hash = entry_hash(&entry);
            seq = seq.checked_add(1).ok_or(ClientError::InvalidResponse)?;
            out.push((item_id, self.append(unlocked, &entry, Some(&envelope))?));
        }
        Ok(out)
    }

    /// Deletes an item.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidResponse`] before the first sync or for
    /// an unknown item.
    pub fn delete_item(
        &self,
        unlocked: &Unlocked,
        item_id: &ItemId,
        now_ms: u64,
    ) -> Result<Request> {
        if *item_id == VAULT_DETAILS_ITEM {
            return Err(ClientError::NotAllowed);
        }
        let state = self.state.as_ref().ok_or(ClientError::InvalidResponse)?;
        let current = state
            .items
            .get(item_id)
            .ok_or(ClientError::InvalidResponse)?;
        let entry = self.sign(
            unlocked,
            now_ms,
            Operation::DeleteItem {
                item_id: *item_id,
                revision: current.revision.saturating_add(1),
            },
        )?;
        self.append(unlocked, &entry, None)
    }

    /// Shares the vault: records the new member in the log, then sends them
    /// the vault key. `recipient` must come from a key transparency lookup,
    /// ideally confirmed with a safety number (spec section 9.5). Send the
    /// requests in order.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidResponse`] before the first sync or
    /// without the current vault key.
    pub fn share_with(
        &self,
        unlocked: &Unlocked,
        recipient: &VerifiedKeys,
        role: Role,
        now_ms: u64,
    ) -> Result<[Request; 2]> {
        let state = self.state.as_ref().ok_or(ClientError::InvalidResponse)?;
        let key = self
            .keys
            .get(&state.vault_key_version)
            .ok_or(ClientError::InvalidResponse)?;
        let entry = self.sign(
            unlocked,
            now_ms,
            Operation::AddMember {
                account_id: recipient.bundle.account_id,
                key_set_version: recipient.bundle.key_set_version,
                bundle_hash: bundle_hash(&recipient.signed),
                role,
            },
        )?;
        let share = key.share(
            &self.vault_id,
            &unlocked.key_set,
            unlocked.session.account_id(),
            unlocked.key_set_version,
            &recipient.bundle,
        )?;
        Ok([
            self.append(unlocked, &entry, None)?,
            Request::json(
                Method::Post,
                "/v1/shares".into(),
                &SharePostRequest { share: b64(&share) },
                Some(&unlocked.session),
            )?,
        ])
    }

    /// Signs `operations` as consecutive log entries after the current head,
    /// each with its envelope if it has one, and returns the append
    /// requests in order.
    fn chain(
        &self,
        unlocked: &Unlocked,
        now_ms: u64,
        operations: Vec<(Operation, Option<Vec<u8>>)>,
    ) -> Result<Vec<Request>> {
        let state = self.state.as_ref().ok_or(ClientError::InvalidResponse)?;
        let mut seq = state.next_seq();
        let mut prev_hash = state.head.hash;
        let mut out = Vec::with_capacity(operations.len());
        for (operation, envelope) in operations {
            let entry = LogEntry {
                vault_id: self.vault_id,
                seq,
                prev_hash,
                author: *unlocked.session.account_id(),
                author_key_set_version: unlocked.key_set_version,
                timestamp_ms: now_ms,
                operation,
            }
            .sign(&unlocked.key_set)?;
            prev_hash = entry_hash(&entry);
            seq = seq.checked_add(1).ok_or(ClientError::InvalidResponse)?;
            out.push(self.append(unlocked, &entry, envelope.as_deref())?);
        }
        Ok(out)
    }

    /// Changes a member's role. Only an owner can, and one owner must
    /// remain.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidResponse`] before the first sync or if
    /// the account is not a member.
    pub fn change_role(
        &self,
        unlocked: &Unlocked,
        account: &AccountId,
        role: Role,
        now_ms: u64,
    ) -> Result<Request> {
        let state = self.state.as_ref().ok_or(ClientError::InvalidResponse)?;
        if !state.members.contains_key(account) {
            return Err(ClientError::InvalidResponse);
        }
        let mut requests = self.chain(
            unlocked,
            now_ms,
            vec![(
                Operation::ChangeRole {
                    account_id: *account,
                    role,
                },
                None,
            )],
        )?;
        requests.pop().ok_or(ClientError::InvalidResponse)
    }

    /// Leaves the vault. An owner must then replace the vault key
    /// ([`VaultReplica::rotate_key`]) before anyone can write again.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidResponse`] before the first sync.
    pub fn leave(&self, unlocked: &Unlocked, now_ms: u64) -> Result<Request> {
        let mut requests = self.chain(
            unlocked,
            now_ms,
            vec![(
                Operation::RemoveMember {
                    account_id: *unlocked.session.account_id(),
                },
                None,
            )],
        )?;
        requests.pop().ok_or(ClientError::InvalidResponse)
    }

    /// Checks that `keys` are exactly the members other than this account
    /// (and `except`), each matching the bundle pinned in the log.
    fn check_members(
        &self,
        unlocked: &Unlocked,
        keys: &[VerifiedKeys],
        except: Option<&AccountId>,
    ) -> Result<()> {
        let state = self.state.as_ref().ok_or(ClientError::InvalidResponse)?;
        let me = unlocked.session.account_id();
        let expected: Vec<&AccountId> = state
            .members
            .keys()
            .filter(|a| *a != me && Some(*a) != except)
            .collect();
        if expected.len() != keys.len() {
            return Err(ClientError::InvalidResponse);
        }
        for k in keys {
            let member = state
                .members
                .get(&k.bundle.account_id)
                .ok_or(ClientError::InvalidResponse)?;
            if Some(&k.bundle.account_id) == except || bundle_hash(&k.signed) != member.bundle_hash
            {
                return Err(ClientError::InvalidResponse);
            }
        }
        Ok(())
    }

    /// The requests that replace the vault key with a new version: the
    /// key wrapped for this account, and a share for each of `members`.
    fn new_key_requests(
        &self,
        unlocked: &Unlocked,
        members: &[VerifiedKeys],
        version: u32,
    ) -> Result<Vec<Request>> {
        let key = VaultKey::generate(version)?;
        let wrapped = key.wrap_for_owner(
            &unlocked.key_set,
            unlocked.session.account_id(),
            &self.vault_id,
        )?;
        let mut out = vec![Request::json(
            Method::Put,
            self.path("keys"),
            &VaultKeyPutRequest {
                wrapped: b64(&wrapped),
            },
            Some(&unlocked.session),
        )?];
        for member in members {
            let share = key.share(
                &self.vault_id,
                &unlocked.key_set,
                unlocked.session.account_id(),
                unlocked.key_set_version,
                &member.bundle,
            )?;
            out.push(Request::json(
                Method::Post,
                "/v1/shares".into(),
                &SharePostRequest { share: b64(&share) },
                Some(&unlocked.session),
            )?);
        }
        Ok(out)
    }

    /// Removes a member and replaces the vault key (spec section 7.6).
    /// `remaining` must hold the keys of every other member except the one
    /// removed, from key transparency; each is checked against the bundle
    /// the log pins for them. Send the requests in order, sync, then
    /// re-encrypt with [`VaultReplica::reencrypt_items`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidResponse`] before the first sync, for
    /// someone who is not a member, or if `remaining` does not match the
    /// members.
    pub fn remove_member(
        &self,
        unlocked: &Unlocked,
        account: &AccountId,
        remaining: &[VerifiedKeys],
        now_ms: u64,
    ) -> Result<Vec<Request>> {
        let state = self.state.as_ref().ok_or(ClientError::InvalidResponse)?;
        if !state.members.contains_key(account) || account == unlocked.session.account_id() {
            return Err(ClientError::InvalidResponse);
        }
        self.check_members(unlocked, remaining, Some(account))?;
        let version = state
            .vault_key_version
            .checked_add(1)
            .ok_or(ClientError::InvalidResponse)?;
        let mut requests = self.chain(
            unlocked,
            now_ms,
            vec![
                (
                    Operation::RemoveMember {
                        account_id: *account,
                    },
                    None,
                ),
                (
                    Operation::RotateKey {
                        new_version: version,
                    },
                    None,
                ),
            ],
        )?;
        requests.extend(self.new_key_requests(unlocked, remaining, version)?);
        Ok(requests)
    }

    /// Replaces the vault key after a member left on their own, so writes
    /// can resume. `members` must hold the keys of every other member.
    ///
    /// # Errors
    ///
    /// As [`VaultReplica::remove_member`].
    pub fn rotate_key(
        &self,
        unlocked: &Unlocked,
        members: &[VerifiedKeys],
        now_ms: u64,
    ) -> Result<Vec<Request>> {
        let state = self.state.as_ref().ok_or(ClientError::InvalidResponse)?;
        self.check_members(unlocked, members, None)?;
        let version = state
            .vault_key_version
            .checked_add(1)
            .ok_or(ClientError::InvalidResponse)?;
        let mut requests = self.chain(
            unlocked,
            now_ms,
            vec![(
                Operation::RotateKey {
                    new_version: version,
                },
                None,
            )],
        )?;
        requests.extend(self.new_key_requests(unlocked, members, version)?);
        Ok(requests)
    }

    /// Re-encrypts every item still under an older vault key with the
    /// current one, as new revisions (spec section 7.6, step 4). Returns no
    /// requests if there is nothing to do.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::InvalidResponse`] before the first sync or
    /// without the current vault key.
    pub fn reencrypt_items(&self, unlocked: &Unlocked, now_ms: u64) -> Result<Vec<Request>> {
        let state = self.state.as_ref().ok_or(ClientError::InvalidResponse)?;
        let key = self
            .keys
            .get(&state.vault_key_version)
            .ok_or(ClientError::InvalidResponse)?;
        let mut operations = Vec::new();
        let (items, newer) = self.read_items()?;
        if newer > 0 {
            // Leaving them under the old key would let a removed member
            // keep reading them; only a newer app can re-encrypt them.
            return Err(ClientError::NeedsUpdate);
        }
        // The details too, so members added later can read the name.
        for (item_id, item) in items {
            let current = state
                .items
                .get(&item_id)
                .ok_or(ClientError::InvalidResponse)?;
            if current.vault_key_version == key.version {
                continue;
            }
            let revision = current.revision.saturating_add(1);
            let envelope = seal_item(&item, &key.key, &self.vault_id, &item_id, revision)?;
            operations.push((
                Operation::PutItem {
                    item_id,
                    revision,
                    vault_key_version: key.version,
                    envelope_hash: envelope_hash(&envelope),
                },
                Some(envelope),
            ));
        }
        if operations.is_empty() {
            return Ok(Vec::new());
        }
        self.chain(unlocked, now_ms, operations)
    }

    // -- Local copy ----------------------------------------------------------

    /// Encrypts this copy for storage on the device (spec section 6.8). It
    /// holds signed entries, authors' signed keys, envelopes and this
    /// account's wrapped vault keys, never decrypted items or vault keys.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    pub fn save(&self, unlocked: &Unlocked) -> Result<Vec<u8>> {
        let saved = Saved {
            entries: self.entries.iter().map(|e| b64(e)).collect(),
            authors: self.authors.values().map(|b| b64(b)).collect(),
            items: self
                .items
                .iter()
                .map(|(id, s)| SavedItem {
                    item_id: b64(id.as_bytes()),
                    revision: s.revision,
                    envelope: s.envelope.as_deref().map(b64),
                })
                .collect(),
            items_after: self.items_after,
            keys: self.wrapped_keys.iter().map(|k| b64(k)).collect(),
        };
        let json =
            Zeroizing::new(serde_json::to_vec(&saved).map_err(|_| ClientError::InvalidResponse)?);
        Ok(local::seal(
            &unlocked.key_set,
            unlocked.session.account_id(),
            &context(&self.vault_id),
            &json,
        )?)
    }

    /// Restores a copy saved with [`VaultReplica::save`] and verifies its log
    /// again, so the device can show the vault while offline. Only
    /// `unlocked.key_set` and the account ID are used, so an offline unlock
    /// works too.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Crypto`] if it does not decrypt for this
    /// account and vault, or its log no longer verifies.
    pub fn load(vault_id: VaultId, unlocked: &Unlocked, sealed: &[u8]) -> Result<Self> {
        let json = local::open(
            &unlocked.key_set,
            unlocked.session.account_id(),
            &context(&vault_id),
            sealed,
        )?;
        let saved: Saved =
            serde_json::from_slice(&json).map_err(|_| ClientError::InvalidResponse)?;
        let mut replica = Self::new(vault_id);
        for author in &saved.authors {
            let signed = field(author, vault_core::SIGNED_PUBLIC_BUNDLE_LEN)?;
            let bundle = vault_core::PublicKeyBundle::verify_signed(&signed)?;
            replica
                .authors
                .insert((bundle.account_id, bundle.key_set_version), signed);
        }
        for entry in &saved.entries {
            replica.pending.push(field(entry, MAX_ENTRY_BYTES)?);
        }
        replica.verify()?;
        for item in &saved.items {
            replica.items.insert(
                ItemId::from_bytes(field_array(&item.item_id)?),
                StoredItem {
                    revision: item.revision,
                    envelope: item
                        .envelope
                        .as_deref()
                        .map(|e| field(e, MAX_ENVELOPE_LEN))
                        .transpose()?,
                },
            );
        }
        replica.items_after = saved.items_after;
        for wrapped in &saved.keys {
            replica.add_wrapped_key(unlocked, field(wrapped, OWNER_WRAPPED_VAULT_KEY_LEN)?)?;
        }
        Ok(replica)
    }
}

fn context(vault_id: &VaultId) -> Vec<u8> {
    let mut c = b"vault ".to_vec();
    c.extend_from_slice(vault_id.as_bytes());
    c
}

#[derive(Serialize, Deserialize)]
struct Saved {
    entries: Vec<String>,
    authors: Vec<String>,
    items: Vec<SavedItem>,
    items_after: Option<u64>,
    /// Copies saved before vault keys were kept have none.
    #[serde(default)]
    keys: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct SavedItem {
    item_id: String,
    revision: u64,
    envelope: Option<String>,
}

/// Creates a vault: its first log entry, and the vault key wrapped for
/// the creator. `own` must be the creator's keys from a key transparency
/// lookup, whose hash the log pins. Send the two requests in order, then
/// sync the returned replica.
///
/// # Errors
///
/// Returns an error if generating or signing fails.
pub fn create_vault(
    unlocked: &Unlocked,
    own: &VerifiedKeys,
    now_ms: u64,
) -> Result<(VaultReplica, [Request; 2])> {
    if own.bundle.account_id != *unlocked.session.account_id() {
        return Err(ClientError::InvalidResponse);
    }
    let vault_id = VaultId::generate()?;
    let entry = LogEntry {
        vault_id,
        seq: 0,
        prev_hash: [0; 32],
        author: *unlocked.session.account_id(),
        author_key_set_version: unlocked.key_set_version,
        timestamp_ms: now_ms,
        operation: Operation::CreateVault {
            bundle_hash: bundle_hash(&own.signed),
        },
    }
    .sign(&unlocked.key_set)?;
    let key = VaultKey::generate(1)?;
    let wrapped =
        key.wrap_for_owner(&unlocked.key_set, unlocked.session.account_id(), &vault_id)?;
    let mut replica = VaultReplica::new(vault_id);
    replica.add_author(own);
    let requests = [
        replica.append(unlocked, &entry, None)?,
        Request::json(
            Method::Put,
            replica.path("keys"),
            &VaultKeyPutRequest {
                wrapped: b64(&wrapped),
            },
            Some(&unlocked.session),
        )?,
    ];
    Ok((replica, requests))
}

/// `GET /v1/shares`: vault keys others have shared with this account.
#[must_use]
pub fn shares_request(unlocked: &Unlocked) -> Request {
    Request::get("/v1/shares".into(), Some(&unlocked.session))
}

/// Reads the answer to [`shares_request`]: each share with its unverified
/// header. Look up each sender through key transparency, then call
/// [`accept_share`].
///
/// # Errors
///
/// Returns a server error or [`ClientError::InvalidResponse`].
pub fn receive_shares(response: &Response) -> Result<Vec<(ShareInfo, Vec<u8>)>> {
    let answer: SharesResponse = response.parse()?;
    answer
        .shares
        .iter()
        .map(|s| {
            let share = field(s, VAULT_SHARE_LEN)?;
            let info = ShareInfo::inspect(&share).map_err(|_| ClientError::InvalidResponse)?;
            Ok((info, share))
        })
        .collect()
}

/// Verifies and opens a share from `sender`, and returns the request that
/// stores the vault key wrapped for this account, so later syncs no longer
/// need the share.
///
/// # Errors
///
/// Returns [`ClientError::Crypto`] if the share is not signed by `sender`,
/// is for another account, or does not decrypt.
pub fn accept_share(
    unlocked: &Unlocked,
    share: &[u8],
    sender: &VerifiedKeys,
) -> Result<(VaultId, Request)> {
    let (vault_id, key) = VaultKey::open_share(
        share,
        &unlocked.key_set,
        unlocked.session.account_id(),
        unlocked.key_set_version,
        &sender.bundle,
    )?;
    let wrapped =
        key.wrap_for_owner(&unlocked.key_set, unlocked.session.account_id(), &vault_id)?;
    let request = Request::json(
        Method::Put,
        format!("/v1/vaults/{}/keys", b64(vault_id.as_bytes())),
        &VaultKeyPutRequest {
            wrapped: b64(&wrapped),
        },
        Some(&unlocked.session),
    )?;
    Ok((vault_id, request))
}

/// Checks a write was accepted. A `conflict` means another device wrote
/// first: sync, then make the change again.
///
/// # Errors
///
/// Returns a server error.
pub fn written(response: &Response) -> Result<()> {
    response.ok()
}
