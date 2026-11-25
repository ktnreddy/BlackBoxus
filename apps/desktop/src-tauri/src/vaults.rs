//! Keeps this computer's verified copies of the account's vaults in sync
//! with the server, and reads and writes their items.
//!
//! Every vault's signed log is replayed before anything from it is shown,
//! and a sealed copy of each vault is saved after every sync, so a server
//! that later rolls a vault back or forks it is caught (spec section 8).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use client_core::ClientError;
use client_core::keys::{KeyDirectory, VerifiedKeys};
use client_core::login::Unlocked;
use client_core::vaults::{
    VaultReplica, accept_share, create_vault, list_request, receive_list, receive_shares,
    shares_request, written,
};
use serde::{Deserialize, Serialize};
use vault_core::log::Role;
use vault_core::transparency::{TreeHead, safety_number};
use vault_core::{AccountId, IdentityPublicKey, Item, ItemId, VaultId};

use zeroize::Zeroizing;

use crate::error::AppError;
use crate::http::Transport;
use crate::pending::{Change, Queue};
use crate::sharing_id;
use crate::storage::write_atomically;

/// Most pages a sync follows before giving up on a server that never says
/// "that's all".
const MAX_PAGES: usize = 10_000;

/// The log key built into this build: `log-key.txt` next to `Cargo.toml`,
/// written after the server's first deploy. Debug builds can use another
/// with `BLACKBOXUS_LOG_KEY` (hex), for a local test server.
const BUILT_IN_LOG_KEY: &str = include_str!("../log-key.txt");

/// The key transparency log's public key.
///
/// # Errors
///
/// Returns [`AppError::NotConfigured`] if this build has no valid key.
pub fn log_key() -> Result<IdentityPublicKey, AppError> {
    let from_env = if cfg!(debug_assertions) {
        std::env::var("BLACKBOXUS_LOG_KEY").ok()
    } else {
        None
    };
    let text = from_env.unwrap_or_else(|| {
        BUILT_IN_LOG_KEY
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    });
    let bytes = hex(&text).ok_or(AppError::NotConfigured)?;
    IdentityPublicKey::from_bytes(&bytes).map_err(|_| AppError::NotConfigured)
}

fn hex(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            core::str::from_utf8(pair)
                .ok()
                .and_then(|b| u8::from_str_radix(b, 16).ok())
        })
        .collect()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

/// What the app keeps on disk for vaults: one sealed file per vault, and
/// the last verified key transparency tree head. Nothing in them is
/// readable without the account's key set.
#[derive(Debug, Clone)]
pub struct VaultFiles {
    dir: PathBuf,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelfCheck {
    checked_ms: u64,
    unknown_keys: bool,
}

/// How often the account's own keys are checked against the key log
/// (spec section 9.5 asks for at least daily).
const SELF_CHECK_EVERY_MS: u64 = 86_400_000;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedHead {
    tree_size: u64,
    root_hash: String,
    timestamp_ms: u64,
}

impl VaultFiles {
    /// Files under `dir`.
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn vault_file(id: &VaultId) -> String {
        format!("{}.vault", wire::b64(id.as_bytes()))
    }

    fn load(&self, id: VaultId, unlocked: &Unlocked) -> Option<VaultReplica> {
        let sealed = fs::read(self.dir.join(Self::vault_file(&id))).ok()?;
        VaultReplica::load(id, unlocked, &sealed).ok()
    }

    fn save(&self, replica: &VaultReplica, unlocked: &Unlocked) -> Result<(), AppError> {
        let sealed = replica.save(unlocked)?;
        write_atomically(&self.dir, &Self::vault_file(replica.vault_id()), &sealed)
    }

    fn load_accepted(&self) -> BTreeSet<String> {
        fs::read_to_string(self.dir.join("accepted-shares.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn save_accepted(&self, accepted: &BTreeSet<String>) -> Result<(), AppError> {
        let json = serde_json::to_vec_pretty(accepted).map_err(|_| AppError::Storage)?;
        write_atomically(&self.dir, "accepted-shares.json", &json)
    }

    /// When the account's own keys were last checked against the key log,
    /// and whether that check found keys this account did not publish.
    fn load_self_check(&self) -> Option<SelfCheck> {
        let text = fs::read_to_string(self.dir.join("self-check.json")).ok()?;
        serde_json::from_str(&text).ok()
    }

    fn save_self_check(&self, check: &SelfCheck) -> Result<(), AppError> {
        let json = serde_json::to_vec_pretty(check).map_err(|_| AppError::Storage)?;
        write_atomically(&self.dir, "self-check.json", &json)
    }

    fn load_head(&self) -> Option<TreeHead> {
        let text = fs::read_to_string(self.dir.join("tree-head.json")).ok()?;
        let saved: SavedHead = serde_json::from_str(&text).ok()?;
        Some(TreeHead {
            tree_size: saved.tree_size,
            root_hash: hex(&saved.root_hash)?.try_into().ok()?,
            timestamp_ms: saved.timestamp_ms,
        })
    }

    fn save_head(&self, head: &TreeHead) -> Result<(), AppError> {
        let saved = SavedHead {
            tree_size: head.tree_size,
            root_hash: head.root_hash.iter().map(|b| format!("{b:02x}")).collect(),
            timestamp_ms: head.timestamp_ms,
        };
        let json = serde_json::to_vec_pretty(&saved).map_err(|_| AppError::Storage)?;
        write_atomically(&self.dir, "tree-head.json", &json)
    }
}

/// A vault as listed in the window.
#[derive(Debug, Clone, Serialize)]
pub struct VaultSummary {
    /// The vault ID, base64url.
    pub id: String,
    /// A name for the list.
    pub name: String,
    /// How many items it holds.
    pub items: usize,
    /// Whether this account can add and change items.
    pub writable: bool,
    /// Whether this account owns it.
    pub owner: bool,
    /// Whether anyone else is a member.
    pub shared: bool,
    /// Items saved by a newer version of the app, which this one can't
    /// show until it is updated.
    pub newer: usize,
}

/// Longest vault name, in characters.
pub const MAX_VAULT_NAME_CHARS: usize = 64;

/// A vault name with surrounding spaces removed, if it is acceptable.
///
/// # Errors
///
/// Returns [`AppError::InvalidVaultName`] if it is empty or too long.
pub fn vault_name(name: &str) -> Result<String, AppError> {
    let name = name.trim();
    let chars = name.chars().count();
    if chars == 0 || chars > MAX_VAULT_NAME_CHARS || name.chars().any(char::is_control) {
        return Err(AppError::InvalidVaultName);
    }
    Ok(name.to_owned())
}

/// A member of a vault, as listed in the window.
#[derive(Debug, Clone, Serialize)]
pub struct MemberView {
    /// Their sharing ID.
    pub sharing_id: String,
    /// `owner`, `editor` or `viewer`.
    pub role: &'static str,
    /// Whether this is the signed-in account.
    pub you: bool,
}

/// Someone looked up to share with, before the user confirms.
#[derive(Debug, Clone, Serialize)]
pub struct LookedUp {
    /// Their sharing ID.
    pub sharing_id: String,
    /// The safety number, in groups of five digits.
    pub safety_number: Vec<String>,
}

/// The unlocked account's vaults.
pub struct Vaults {
    directory: KeyDirectory,
    replicas: BTreeMap<VaultId, VaultReplica>,
    /// Vault IDs in the order the server lists them.
    order: Vec<VaultId>,
    files: VaultFiles,
    /// Someone looked up for sharing, kept until shared or replaced.
    pending: Option<(VaultId, VerifiedKeys)>,
    /// Someone looked up to be the trusted contact.
    pending_contact: Option<VerifiedKeys>,
    /// Changes made while offline, read from disk the first time needed.
    queue: Option<Queue>,
}

/// Which version to keep when an item was changed in two places.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Keep {
    /// The version changed on this device while offline.
    Mine,
    /// The version on the server.
    Theirs,
    /// Both: this device's version becomes a new item.
    Both,
}

/// One version of an item in a conflict.
#[derive(Debug, Clone, Serialize)]
pub struct Version {
    /// The item was deleted in this version.
    pub deleted: bool,
    /// When it was changed, Unix milliseconds.
    pub changed_ms: u64,
    /// The fields that differ from the other version (all of them if
    /// only the title differs), concealed values left out.
    pub fields: Vec<VersionField>,
}

/// A field of one version of a conflict.
#[derive(Debug, Clone, Serialize)]
pub struct VersionField {
    /// Its position, for [`Vaults::conflict_field`].
    pub index: usize,
    /// The field as shown.
    #[serde(flatten)]
    pub field: crate::items::FieldView,
}

/// An item changed both here while offline and elsewhere.
#[derive(Debug, Clone, Serialize)]
pub struct ConflictView {
    /// The vault ID, base64url.
    pub vault: String,
    /// The item ID, base64url.
    pub item: String,
    /// The item's title, from this device's version when it has one.
    pub title: String,
    /// This device's version.
    pub mine: Version,
    /// The server's version.
    pub theirs: Version,
}

/// Changes waiting to be sent, for the window.
#[derive(Debug, Clone, Serialize)]
pub struct PendingView {
    /// Changes waiting for a connection.
    pub waiting: usize,
    /// Changes the user must settle.
    pub conflicts: Vec<ConflictView>,
}

fn role_name(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Editor => "editor",
        _ => "viewer",
    }
}

impl core::fmt::Debug for Vaults {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vaults")
            .field("count", &self.replicas.len())
            .finish_non_exhaustive()
    }
}

/// Whether an item is still as it was when a change was based on it:
/// `base` is the revision then (0 for an item added here), `current` the
/// revision and deleted flag on the server now, if it has the item.
fn unchanged_since(base: u64, current: Option<(u64, bool)>) -> bool {
    match (base, current) {
        (0, None) => true,
        (base, Some((revision, false))) => base > 0 && base == revision,
        _ => false,
    }
}

fn is_conflict(error: &ClientError) -> bool {
    matches!(error, ClientError::Server { status: 409, .. })
}

fn vault_error(error: ClientError) -> AppError {
    if is_conflict(&error) {
        AppError::Server
    } else {
        error.into()
    }
}

impl Vaults {
    /// Vaults kept in `files`, checked against `log_key`.
    pub fn new(files: VaultFiles, log_key: IdentityPublicKey) -> Self {
        let head = files.load_head();
        Self {
            directory: KeyDirectory::new(log_key, head),
            replicas: BTreeMap::new(),
            order: Vec::new(),
            files,
            pending: None,
            pending_contact: None,
            queue: None,
        }
    }

    /// A copy to sync with the server while the app keeps using this one:
    /// the same files and key log, and the keys already looked up. It holds
    /// no vaults yet; each is read from this device's copy as it syncs.
    #[must_use]
    pub fn for_sync(&self) -> Self {
        Self {
            directory: self.directory.clone(),
            replicas: BTreeMap::new(),
            order: self.order.clone(),
            files: self.files.clone(),
            pending: None,
            pending_contact: None,
            queue: None,
        }
    }

    /// Replaces this set with `synced`, made by [`Self::for_sync`], keeping
    /// what only lives in memory here: people looked up to share with.
    pub fn replace_with(&mut self, mut synced: Self) {
        synced.pending = self.pending.take();
        synced.pending_contact = self.pending_contact.take();
        *self = synced;
    }

    /// Whether no vault has been read yet, from the server or this device.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.replicas.is_empty()
    }

    // -- Changes made offline --------------------------------------------

    fn queue(&mut self, unlocked: &Unlocked) -> Result<&mut Queue, AppError> {
        if self.queue.is_none() {
            self.queue = Some(Queue::load(&self.files.dir, unlocked)?);
        }
        self.queue.as_mut().ok_or(AppError::Storage)
    }

    fn save_queue(&self, unlocked: &Unlocked) -> Result<(), AppError> {
        self.queue
            .as_ref()
            .map_or(Ok(()), |q| q.save(&self.files.dir, unlocked))
    }

    /// The current revision of a live (not deleted) item on the server.
    fn revision(&self, id: &VaultId, item_id: &ItemId) -> Option<u64> {
        self.replicas
            .get(id)?
            .state()?
            .items
            .get(item_id)
            .filter(|s| !s.deleted)
            .map(|s| s.revision)
    }

    fn require_writable(&self, id: &VaultId, unlocked: &Unlocked) -> Result<(), AppError> {
        let role = self
            .replica(id)?
            .state()
            .and_then(|s| s.members.get(unlocked.session.account_id()))
            .map(|m| m.role);
        if matches!(role, Some(Role::Owner | Role::Editor)) {
            Ok(())
        } else {
            Err(AppError::ReadOnly)
        }
    }

    /// Keeps an added (`item_id = None`) or changed item on this device to
    /// be sent once online. Returns its ID.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotFound`] for an unknown vault or item,
    /// [`AppError::ReadOnly`] without permission to edit, or a storage
    /// error.
    pub fn put_offline(
        &mut self,
        unlocked: &Unlocked,
        id: VaultId,
        item_id: Option<ItemId>,
        item: &Item,
    ) -> Result<ItemId, AppError> {
        self.require_writable(&id, unlocked)?;
        let (item_id, base) = match item_id {
            Some(i) => {
                let queued = self.queue(unlocked)?.get(&id, &i).map(|c| c.base);
                let base = match queued {
                    Some(b) => b,
                    None => self.revision(&id, &i).ok_or(AppError::NotFound)?,
                };
                (i, base)
            }
            None => (ItemId::generate().map_err(|_| AppError::Storage)?, 0),
        };
        self.queue(unlocked)?
            .record(id, item_id, base, Some(item.clone()), now_ms())?;
        self.save_queue(unlocked)?;
        Ok(item_id)
    }

    /// Keeps the deletion of an item on this device to be sent once online.
    ///
    /// # Errors
    ///
    /// As [`Vaults::put_offline`].
    pub fn delete_offline(
        &mut self,
        unlocked: &Unlocked,
        id: VaultId,
        item_id: &ItemId,
    ) -> Result<(), AppError> {
        self.require_writable(&id, unlocked)?;
        let queued = self.queue(unlocked)?.get(&id, item_id).map(|c| c.base);
        let base = match queued {
            Some(b) => b,
            None => self.revision(&id, item_id).ok_or(AppError::NotFound)?,
        };
        self.queue(unlocked)?
            .record(id, *item_id, base, None, now_ms())?;
        self.save_queue(unlocked)
    }

    /// "new", "edited", "deleted" or "conflict" for an item with a change
    /// waiting, for the item list.
    pub fn pending_kind(&self, id: &VaultId, item_id: &ItemId) -> Option<&'static str> {
        let change = self.queue.as_ref()?.get(id, item_id)?;
        Some(if change.conflict {
            "conflict"
        } else {
            change.kind()
        })
    }

    /// Sends one change if nobody else changed the item meanwhile. Returns
    /// `false` if they did, so the user must choose.
    fn send_change(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        change: &Change,
    ) -> Result<bool, AppError> {
        for attempt in 0..2 {
            let current = self
                .replica(&change.vault)?
                .state()
                .and_then(|s| s.items.get(&change.item))
                .map(|s| (s.revision, s.deleted));
            if !unchanged_since(change.base, current) {
                return Ok(false);
            }
            let replica = self.replica(&change.vault)?;
            let request = match &change.edit {
                Some(item) => {
                    replica
                        .put_item(unlocked, Some(change.item), item, now_ms())
                        .map_err(vault_error)?
                        .1
                }
                None => replica
                    .delete_item(unlocked, &change.item, now_ms())
                    .map_err(vault_error)?,
            };
            match written(&transport.send(&request)?) {
                Ok(()) => {
                    self.sync_one(transport, unlocked, change.vault)?;
                    return Ok(true);
                }
                // Someone else wrote to the vault first: look again.
                Err(e) if is_conflict(&e) && attempt == 0 => {
                    self.sync_one(transport, unlocked, change.vault)?;
                }
                Err(e) => return Err(vault_error(e)),
            }
        }
        Ok(false)
    }

    /// Sends the changes made while offline. Those that clash with changes
    /// made elsewhere wait for the user. A lost connection leaves the rest
    /// for next time.
    fn flush(&mut self, transport: &impl Transport, unlocked: &Unlocked) -> Result<(), AppError> {
        let todo: Vec<Change> = self
            .queue(unlocked)?
            .all()
            .iter()
            .filter(|c| !c.conflict)
            .cloned()
            .collect();
        for change in &todo {
            let sent = match self.send_change(transport, unlocked, change) {
                Ok(sent) => sent,
                Err(AppError::Offline) => break,
                // The vault is gone or can no longer be edited here: the
                // user decides what happens to the change.
                Err(AppError::NotFound | AppError::ReadOnly) => false,
                Err(e) => {
                    self.save_queue(unlocked)?;
                    return Err(e);
                }
            };
            let queue = self.queue(unlocked)?;
            if sent {
                queue.remove(&change.vault, &change.item);
            } else {
                queue.mark_conflict(&change.vault, &change.item);
            }
            self.save_queue(unlocked)?;
        }
        Ok(())
    }

    /// One side of a conflict, showing the fields not found in `other`.
    fn version(item_id: &ItemId, item: Option<&Item>, other: Option<&Item>, at_ms: u64) -> Version {
        let fields = item.map_or_else(Vec::new, |item| {
            let all: Vec<VersionField> = crate::items::view(item_id, item)
                .fields
                .into_iter()
                .enumerate()
                .map(|(index, field)| VersionField { index, field })
                .collect();
            let differs = |index: usize| {
                let Ok(mine) = crate::items::field_at(item, index) else {
                    return true;
                };
                !other.is_some_and(|o| {
                    o.fields.iter().any(|f| {
                        f.kind == mine.kind && f.label == mine.label && f.value == mine.value
                    })
                })
            };
            let changed: Vec<VersionField> =
                all.iter().filter(|f| differs(f.index)).cloned().collect();
            if changed.is_empty() { all } else { changed }
        });
        Version {
            deleted: item.is_none(),
            changed_ms: item.map_or(at_ms, |i| i.modified_ms.max(at_ms)),
            fields,
        }
    }

    /// Changes waiting, and those the user must settle.
    ///
    /// # Errors
    ///
    /// Returns a storage error if the queue can't be read.
    pub fn pending(&mut self, unlocked: &Unlocked) -> Result<PendingView, AppError> {
        let changes = self.queue(unlocked)?.all().to_vec();
        let mut conflicts = Vec::new();
        for c in changes.iter().filter(|c| c.conflict) {
            let theirs = self
                .replica(&c.vault)
                .ok()
                .and_then(|r| r.items().ok())
                .and_then(|items| items.into_iter().find(|(i, _)| *i == c.item))
                .map(|(_, item)| item);
            let title = c
                .edit
                .as_ref()
                .or(theirs.as_ref())
                .map(|i| crate::items::view(&c.item, i).title)
                .unwrap_or_default();
            conflicts.push(ConflictView {
                vault: wire::b64(c.vault.as_bytes()),
                item: wire::b64(c.item.as_bytes()),
                title,
                mine: Self::version(&c.item, c.edit.as_ref(), theirs.as_ref(), c.changed_ms),
                theirs: Self::version(&c.item, theirs.as_ref(), c.edit.as_ref(), 0),
            });
        }
        Ok(PendingView {
            waiting: changes.iter().filter(|c| !c.conflict).count(),
            conflicts,
        })
    }

    /// One field's value from either version of a conflict, to compare.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotFound`] if there is no such conflict or field.
    pub fn conflict_field(
        &mut self,
        unlocked: &Unlocked,
        id: &VaultId,
        item_id: &ItemId,
        mine: bool,
        index: usize,
    ) -> Result<Zeroizing<String>, AppError> {
        let change = self
            .queue(unlocked)?
            .get(id, item_id)
            .filter(|c| c.conflict)
            .cloned()
            .ok_or(AppError::NotFound)?;
        let item = if mine {
            change.edit.ok_or(AppError::NotFound)?
        } else {
            self.item_on_server(id, item_id)?
        };
        Ok(crate::items::field_at(&item, index)?.value.clone())
    }

    fn item_on_server(&self, id: &VaultId, item_id: &ItemId) -> Result<Item, AppError> {
        self.replica(id)?
            .items()
            .map_err(vault_error)?
            .into_iter()
            .find(|(i, _)| i == item_id)
            .map(|(_, item)| item)
            .ok_or(AppError::NotFound)
    }

    /// Settles a conflict by keeping one version, or both.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotFound`] if there is no such conflict, or a
    /// server, network or verification error.
    pub fn resolve(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        id: VaultId,
        item_id: ItemId,
        keep: Keep,
    ) -> Result<(), AppError> {
        let change = self
            .queue(unlocked)?
            .get(&id, &item_id)
            .filter(|c| c.conflict)
            .cloned()
            .ok_or(AppError::NotFound)?;
        let live = self.revision(&id, &item_id).is_some();
        match (keep, &change.edit) {
            (Keep::Theirs, _) | (Keep::Both, None) => {}
            (Keep::Mine, Some(edit)) => {
                // A deleted item can't come back, so it returns as a new one.
                self.put(transport, unlocked, id, live.then_some(item_id), edit)?;
            }
            (Keep::Mine, None) => {
                if live {
                    self.delete(transport, unlocked, id, &item_id)?;
                }
            }
            (Keep::Both, Some(edit)) => {
                self.put(transport, unlocked, id, None, edit)?;
            }
        }
        self.queue(unlocked)?.remove(&id, &item_id);
        self.save_queue(unlocked)
    }

    fn lookup(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        account: &AccountId,
    ) -> Result<VerifiedKeys, AppError> {
        let request = self.directory.lookup_request(account, &unlocked.session);
        let keys = self
            .directory
            .verify(account, &transport.send(&request)?)
            .map_err(vault_error)?;
        if let Some(head) = self.directory.tree_head() {
            self.files.save_head(head)?;
        }
        Ok(keys)
    }

    fn sync_one(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        id: VaultId,
    ) -> Result<(), AppError> {
        let files = self.files.clone();
        let mut replica = self
            .replicas
            .remove(&id)
            .or_else(|| files.load(id, unlocked))
            .unwrap_or_else(|| VaultReplica::new(id));
        let result = self.sync_replica(transport, unlocked, &mut replica);
        if result.is_ok() {
            files.save(&replica, unlocked)?;
        }
        // On failure the replica keeps its last verified state, which is
        // still the best copy to show.
        self.replicas.insert(id, replica);
        result?;
        self.finish_rotation(transport, unlocked, id)
    }

    /// The keys of every member of `id` other than this account and
    /// `except`, from key transparency.
    fn other_members(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        id: &VaultId,
        except: Option<&AccountId>,
    ) -> Result<Vec<VerifiedKeys>, AppError> {
        let me = *unlocked.session.account_id();
        let accounts: Vec<AccountId> = self
            .replica(id)?
            .state()
            .ok_or(AppError::NotFound)?
            .members
            .keys()
            .filter(|a| **a != me && Some(*a) != except)
            .copied()
            .collect();
        accounts
            .iter()
            .map(|a| self.lookup(transport, unlocked, a))
            .collect()
    }

    /// Sends `requests` in order. Returns `false` if another device wrote
    /// first, so the caller can sync and build them again.
    fn send_all(
        transport: &impl Transport,
        requests: &[client_core::Request],
    ) -> Result<bool, AppError> {
        for request in requests {
            match written(&transport.send(request)?) {
                Ok(()) => {}
                Err(e) if is_conflict(&e) => return Ok(false),
                Err(e) => return Err(vault_error(e)),
            }
        }
        Ok(true)
    }

    fn my_role(&self, id: &VaultId, unlocked: &Unlocked) -> Option<Role> {
        self.replicas
            .get(id)?
            .state()?
            .members
            .get(unlocked.session.account_id())
            .map(|m| m.role)
    }

    /// As an owner, replaces the vault key if a member left, and
    /// re-encrypts items still under an older key (spec section 7.6).
    fn finish_rotation(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        id: VaultId,
    ) -> Result<(), AppError> {
        if self.my_role(&id, unlocked) != Some(Role::Owner) {
            return Ok(());
        }
        for _ in 0..3 {
            let pending = self
                .replica(&id)?
                .state()
                .is_some_and(|s| s.rotation_required);
            let requests = if pending {
                let members = self.other_members(transport, unlocked, &id, None)?;
                self.replica(&id)?
                    .rotate_key(unlocked, &members, now_ms())
                    .map_err(vault_error)?
            } else {
                self.replica(&id)?
                    .reencrypt_items(unlocked, now_ms())
                    .map_err(vault_error)?
            };
            if requests.is_empty() {
                return Ok(());
            }
            let _ = Self::send_all(transport, &requests)?;
            let mut replica = self.replicas.remove(&id).ok_or(AppError::NotFound)?;
            let result = self.sync_replica(transport, unlocked, &mut replica);
            if result.is_ok() {
                self.files.save(&replica, unlocked)?;
            }
            self.replicas.insert(id, replica);
            result?;
        }
        Ok(())
    }

    fn require_owner(&self, id: &VaultId, unlocked: &Unlocked) -> Result<(), AppError> {
        if self.my_role(id, unlocked) == Some(Role::Owner) {
            Ok(())
        } else {
            Err(AppError::NotOwner)
        }
    }

    /// Changes a member's role.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotOwner`], [`AppError::LastOwner`], or a
    /// server or network error.
    pub fn change_role(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        id: VaultId,
        sharing_id: &str,
        role: Role,
    ) -> Result<(), AppError> {
        self.require_owner(&id, unlocked)?;
        let account = sharing_id::decode(sharing_id)?;
        let state = self.replica(&id)?.state().ok_or(AppError::NotFound)?;
        let owners = state
            .members
            .iter()
            .filter(|(a, m)| m.role == Role::Owner && **a != account)
            .count();
        if owners == 0 {
            return Err(AppError::LastOwner);
        }
        for _ in 0..2 {
            let request = self
                .replica(&id)?
                .change_role(unlocked, &account, role, now_ms())
                .map_err(vault_error)?;
            let done = Self::send_all(transport, std::slice::from_ref(&request))?;
            self.sync_one(transport, unlocked, id)?;
            if done {
                return Ok(());
            }
        }
        Err(AppError::Server)
    }

    /// Removes a member, replaces the vault key and re-encrypts the items.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotOwner`], or a server, network or
    /// verification error.
    pub fn remove_member(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        id: VaultId,
        sharing_id: &str,
    ) -> Result<(), AppError> {
        self.require_owner(&id, unlocked)?;
        let account = sharing_id::decode(sharing_id)?;
        if account == *unlocked.session.account_id() {
            return Err(AppError::SelfShare);
        }
        for _ in 0..2 {
            let remaining = self.other_members(transport, unlocked, &id, Some(&account))?;
            let requests = self
                .replica(&id)?
                .remove_member(unlocked, &account, &remaining, now_ms())
                .map_err(vault_error)?;
            let done = Self::send_all(transport, &requests)?;
            // Syncing also re-encrypts the items under the new key.
            self.sync_one(transport, unlocked, id)?;
            if done {
                return Ok(());
            }
        }
        Err(AppError::Server)
    }

    /// Leaves a vault someone else shared with this account.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::LastOwner`] for the only owner, or a server or
    /// network error.
    pub fn leave(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        id: VaultId,
    ) -> Result<(), AppError> {
        let me = *unlocked.session.account_id();
        let state = self.replica(&id)?.state().ok_or(AppError::NotFound)?;
        let other_owner = state
            .members
            .iter()
            .any(|(a, m)| m.role == Role::Owner && *a != me);
        if !other_owner {
            return Err(AppError::LastOwner);
        }
        for _ in 0..2 {
            let request = self
                .replica(&id)?
                .leave(unlocked, now_ms())
                .map_err(vault_error)?;
            let done = Self::send_all(transport, std::slice::from_ref(&request))?;
            if done {
                self.replicas.remove(&id);
                self.order.retain(|v| *v != id);
                return Ok(());
            }
            self.sync_one(transport, unlocked, id)?;
        }
        Err(AppError::Server)
    }

    fn sync_replica(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        replica: &mut VaultReplica,
    ) -> Result<(), AppError> {
        let mut more = true;
        for _ in 0..MAX_PAGES {
            if !more {
                break;
            }
            more = replica
                .receive_log(&transport.send(&replica.log_request(unlocked))?)
                .map_err(vault_error)?;
        }
        for author in replica.missing_authors().map_err(vault_error)? {
            let keys = self.lookup(transport, unlocked, &author)?;
            replica.add_author(&keys);
        }
        replica.verify().map_err(vault_error)?;
        replica
            .receive_keys(unlocked, &transport.send(&replica.keys_request(unlocked))?)
            .map_err(vault_error)?;
        let mut more = true;
        for _ in 0..MAX_PAGES {
            if !more {
                break;
            }
            more = replica
                .receive_items(&transport.send(&replica.items_request(unlocked))?)
                .map_err(vault_error)?;
        }
        Ok(())
    }

    /// Syncs the vaults the account can read, without changing anything:
    /// no shares are accepted and no vault is created. For an account
    /// opened by a trusted contact, whose session can only read.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Tampered`] if any vault fails verification, or a
    /// server or network error.
    pub fn sync_existing(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
    ) -> Result<(), AppError> {
        let ids = receive_list(&transport.send(&list_request(unlocked))?).map_err(vault_error)?;
        for id in &ids {
            self.sync_one(transport, unlocked, *id)?;
        }
        self.replicas.retain(|id, _| ids.contains(id));
        self.order = ids;
        Ok(())
    }

    /// Syncs every vault the account can read. A new account gets its
    /// first vault here.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Tampered`] if any vault fails verification, or a
    /// server or network error.
    pub fn sync(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
    ) -> Result<(), AppError> {
        self.accept_shares(transport, unlocked)?;
        let ids = receive_list(&transport.send(&list_request(unlocked))?).map_err(vault_error)?;
        for id in &ids {
            self.sync_one(transport, unlocked, *id)?;
        }
        self.replicas.retain(|id, _| ids.contains(id));
        self.order = ids;

        // Every account has a vault of its own; a new one gets it here.
        let me = *unlocked.session.account_id();
        let owns_one = self.replicas.values().any(|r| {
            r.state()
                .and_then(|s| s.members.get(&me))
                .is_some_and(|m| m.role == Role::Owner)
        });
        if !owns_one {
            let id = self.create(transport, unlocked, "Personal")?;
            // `create` adds it last; the first vault goes first.
            self.order.retain(|v| *v != id);
            self.order.insert(0, id);
        }
        self.flush(transport, unlocked)
    }

    /// Self-monitoring (spec section 9.5): checks, at most once a day, that
    /// the key log records no keys for this account other than its own.
    /// Once keys it did not publish have been found, checks on every sync
    /// until they are gone, and returns `true` meanwhile.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Tampered`] for a bad proof or a log that went
    /// back in time, or a server or network error.
    pub fn check_own_keys(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        now_ms: u64,
    ) -> Result<bool, AppError> {
        let last = self.files.load_self_check();
        if let Some(last) = last
            && !last.unknown_keys
            && now_ms.saturating_sub(last.checked_ms) < SELF_CHECK_EVERY_MS
        {
            return Ok(false);
        }
        let me = *unlocked.session.account_id();
        let own = self.lookup(transport, unlocked, &me)?;
        let request = self.directory.own_leaves_request(&unlocked.session);
        let result = self
            .directory
            .check_own_keys(unlocked, &own, &transport.send(&request)?);
        let unknown_keys = match result {
            Ok(()) => false,
            Err(ClientError::Crypto(vault_core::Error::UnknownKeys)) => true,
            Err(ClientError::Crypto(_)) => return Err(AppError::Tampered),
            Err(other) => return Err(vault_error(other)),
        };
        if let Some(head) = self.directory.tree_head() {
            self.files.save_head(head)?;
        }
        self.files.save_self_check(&SelfCheck {
            checked_ms: now_ms,
            unknown_keys,
        })?;
        Ok(unknown_keys)
    }

    /// Creates a vault owned by this account, with a name.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::InvalidVaultName`], or a server, network or
    /// verification error.
    pub fn create(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        name: &str,
    ) -> Result<VaultId, AppError> {
        let name = vault_name(name)?;
        let me = *unlocked.session.account_id();
        let own = self.lookup(transport, unlocked, &me)?;
        let (replica, requests) = create_vault(unlocked, &own, now_ms()).map_err(vault_error)?;
        for request in &requests {
            written(&transport.send(request)?).map_err(vault_error)?;
        }
        let id = *replica.vault_id();
        self.replicas.insert(id, replica);
        self.order.push(id);
        self.sync_one(transport, unlocked, id)?;
        self.rename(transport, unlocked, id, &name)?;
        Ok(id)
    }

    /// Renames a vault. Anyone who can edit its items can.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::InvalidVaultName`], [`AppError::ReadOnly`], or a
    /// server, network or verification error.
    pub fn rename(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        id: VaultId,
        name: &str,
    ) -> Result<(), AppError> {
        let name = vault_name(name)?;
        if !self.writable(&id, unlocked) {
            return Err(AppError::ReadOnly);
        }
        for attempt in 0..2 {
            let request = self
                .replica(&id)?
                .rename(unlocked, &name, now_ms())
                .map_err(vault_error)?;
            match written(&transport.send(&request)?) {
                Ok(()) => return self.sync_one(transport, unlocked, id),
                Err(e) if is_conflict(&e) && attempt == 0 => {
                    self.sync_one(transport, unlocked, id)?;
                }
                Err(e) => return Err(vault_error(e)),
            }
        }
        Err(AppError::Server)
    }

    fn writable(&self, id: &VaultId, unlocked: &Unlocked) -> bool {
        self.replicas
            .get(id)
            .and_then(|r| r.state())
            .and_then(|s| s.members.get(unlocked.session.account_id()))
            .is_some_and(|m| matches!(m.role, Role::Owner | Role::Editor))
    }

    /// Accepts vault keys others have shared with this account. Each share
    /// must be signed by its sender's keys from key transparency; shares
    /// that fail are skipped, since anyone could send one.
    fn accept_shares(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
    ) -> Result<(), AppError> {
        let me = *unlocked.session.account_id();
        let shares =
            receive_shares(&transport.send(&shares_request(unlocked))?).map_err(vault_error)?;
        let mut accepted = self.files.load_accepted();
        let before = accepted.len();
        for (info, share) in shares {
            let tag = format!(
                "{}:{}:{}",
                wire::b64(info.vault_id.as_bytes()),
                info.vault_key_version,
                wire::b64(info.sender.as_bytes())
            );
            if info.recipient != me || accepted.contains(&tag) {
                continue;
            }
            let Ok(sender) = self.lookup(transport, unlocked, &info.sender) else {
                continue;
            };
            let Ok((_, request)) = accept_share(unlocked, &share, &sender) else {
                continue;
            };
            written(&transport.send(&request)?).map_err(vault_error)?;
            accepted.insert(tag);
        }
        if accepted.len() != before {
            self.files.save_accepted(&accepted)?;
        }
        Ok(())
    }

    /// Looks someone up for sharing a vault: checks their keys through key
    /// transparency and returns the safety number to compare with them.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::InvalidSharingId`], [`AppError::SelfShare`],
    /// [`AppError::AlreadyMember`], or an error if the lookup fails.
    pub fn look_up(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        id: VaultId,
        sharing_id: &str,
    ) -> Result<LookedUp, AppError> {
        let them = sharing_id::decode(sharing_id)?;
        let me = *unlocked.session.account_id();
        if them == me {
            return Err(AppError::SelfShare);
        }
        let state = self.replica(&id)?.state().ok_or(AppError::NotFound)?;
        if state.members.contains_key(&them) {
            return Err(AppError::AlreadyMember);
        }
        let (number, theirs) = self.safety_number(transport, unlocked, &them)?;
        self.pending = Some((id, theirs));
        Ok(LookedUp {
            sharing_id: sharing_id::encode(&them),
            safety_number: number,
        })
    }

    fn safety_number(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        them: &AccountId,
    ) -> Result<(Vec<String>, VerifiedKeys), AppError> {
        let me = *unlocked.session.account_id();
        let own = self.lookup(transport, unlocked, &me)?;
        let theirs = self
            .lookup(transport, unlocked, them)
            .map_err(|e| match e {
                // An unknown account has no keys in the log.
                AppError::Server => AppError::InvalidSharingId,
                other => other,
            })?;
        let number = safety_number((&me, &own.signed), (them, &theirs.signed));
        let groups = number
            .chars()
            .filter(char::is_ascii_digit)
            .collect::<Vec<char>>()
            .chunks(5)
            .map(|c| c.iter().collect())
            .collect();
        Ok((groups, theirs))
    }

    /// The safety number with someone, to compare with them at any time,
    /// for example after they shared a vault with this account.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::InvalidSharingId`] or an error if the lookup fails.
    pub fn compare(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        sharing_id: &str,
    ) -> Result<LookedUp, AppError> {
        let them = sharing_id::decode(sharing_id)?;
        if them == *unlocked.session.account_id() {
            return Err(AppError::SelfShare);
        }
        let (number, _) = self.safety_number(transport, unlocked, &them)?;
        Ok(LookedUp {
            sharing_id: sharing_id::encode(&them),
            safety_number: number,
        })
    }

    /// Looks someone up to be the trusted contact (spec section 11.4):
    /// fetches their keys through key transparency and returns the safety
    /// number to compare.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::InvalidSharingId`], [`AppError::SelfShare`], or
    /// a server, network or verification error.
    pub fn look_up_contact(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        sharing_id: &str,
    ) -> Result<LookedUp, AppError> {
        let them = sharing_id::decode(sharing_id)?;
        if them == *unlocked.session.account_id() {
            return Err(AppError::SelfShare);
        }
        let (number, theirs) = self.safety_number(transport, unlocked, &them)?;
        self.pending_contact = Some(theirs);
        Ok(LookedUp {
            sharing_id: sharing_id::encode(&them),
            safety_number: number,
        })
    }

    /// The keys of the person last looked up as a trusted contact.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotVerified`] if that was someone else.
    pub fn take_contact(&mut self, sharing_id: &str) -> Result<VerifiedKeys, AppError> {
        let them = sharing_id::decode(sharing_id)?;
        match self.pending_contact.take() {
            Some(keys) if keys.bundle.account_id == them => Ok(keys),
            _ => Err(AppError::NotVerified),
        }
    }

    /// Any account's keys, verified through key transparency.
    ///
    /// # Errors
    ///
    /// Returns a server, network or verification error.
    pub fn verified_keys(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        account: &AccountId,
    ) -> Result<VerifiedKeys, AppError> {
        self.lookup(transport, unlocked, account)
    }

    /// Shares a vault with the person last looked up, once the user has
    /// confirmed the safety number or chosen to go ahead without it.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotVerified`] if they were not looked up for this
    /// vault, or a server or network error.
    pub fn share(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        id: VaultId,
        sharing_id: &str,
        role: Role,
    ) -> Result<(), AppError> {
        let them = sharing_id::decode(sharing_id)?;
        let recipient = match self.pending.take() {
            Some((vault, keys)) if vault == id && keys.bundle.account_id == them => keys,
            _ => return Err(AppError::NotVerified),
        };
        let requests = self
            .replica(&id)?
            .share_with(unlocked, &recipient, role, now_ms())
            .map_err(vault_error)?;
        for request in &requests {
            written(&transport.send(request)?).map_err(vault_error)?;
        }
        self.sync_one(transport, unlocked, id)
    }

    /// The members of a vault.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotFound`] for an unknown vault.
    pub fn members(&self, id: &VaultId, unlocked: &Unlocked) -> Result<Vec<MemberView>, AppError> {
        let me = unlocked.session.account_id();
        let state = self.replica(id)?.state().ok_or(AppError::NotFound)?;
        let mut list: Vec<MemberView> = state
            .members
            .iter()
            .map(|(account, member)| MemberView {
                sharing_id: sharing_id::encode(account),
                role: role_name(member.role),
                you: account == me,
            })
            .collect();
        list.sort_by_key(|m| (!m.you, m.role != "owner"));
        Ok(list)
    }

    /// Loads the vaults from this computer's copies, without the server.
    /// Copies that no longer open are left out.
    pub fn load_local(&mut self, unlocked: &Unlocked) {
        // A queue that can't be read is shown as empty rather than lost:
        // its file stays until a change is saved over it.
        if self.queue.is_none() {
            self.queue = Queue::load(&self.files.dir, unlocked).ok();
        }
        let Ok(dir) = fs::read_dir(&self.files.dir) else {
            return;
        };
        let mut ids: Vec<VaultId> = dir
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let id = name.strip_suffix(".vault")?;
                wire::unb64_array(id).map(VaultId::from_bytes)
            })
            .collect();
        ids.sort_by_key(|id| *id.as_bytes());
        for id in &ids {
            if !self.replicas.contains_key(id)
                && let Some(replica) = self.files.load(*id, unlocked)
            {
                self.replicas.insert(*id, replica);
            }
        }
        if self.order.is_empty() {
            self.order = ids
                .into_iter()
                .filter(|id| self.replicas.contains_key(id))
                .collect();
        }
    }

    /// The vaults, for the window. A vault without a name is shown with a
    /// default one.
    pub fn summaries(&self, unlocked: &Unlocked) -> Vec<VaultSummary> {
        let me = unlocked.session.account_id();
        let mut unnamed = 0_usize;
        let mut list = self
            .order
            .iter()
            .filter_map(|id| self.replicas.get(id).map(|r| (id, r)))
            // A vault this account left can still be listed by the server.
            .filter(|(_, r)| r.state().is_some_and(|s| s.members.contains_key(me)))
            .map(|(id, replica)| {
                let role = replica
                    .state()
                    .and_then(|s| s.members.get(me))
                    .map(|m| m.role);
                let name = replica.name().ok().flatten().unwrap_or_else(|| {
                    if role == Some(Role::Owner) {
                        unnamed = unnamed.saturating_add(1);
                        if unnamed == 1 {
                            "Personal".to_owned()
                        } else {
                            format!("Vault {unnamed}")
                        }
                    } else {
                        "Shared vault".to_owned()
                    }
                });
                VaultSummary {
                    id: wire::b64(id.as_bytes()),
                    name,
                    items: self.items(id).map(|i| i.len()).unwrap_or_default(),
                    writable: matches!(role, Some(Role::Owner | Role::Editor)),
                    owner: role == Some(Role::Owner),
                    shared: replica.state().is_some_and(|s| s.members.len() > 1),
                    newer: replica.newer_items().unwrap_or_default(),
                }
            })
            .collect::<Vec<_>>();
        // Your own vaults first, then those shared with you, each by name.
        list.sort_by_cached_key(|v| (!v.owner, v.name.to_lowercase()));
        list
    }

    fn replica(&self, id: &VaultId) -> Result<&VaultReplica, AppError> {
        self.replicas.get(id).ok_or(AppError::NotFound)
    }

    /// The decrypted items of a vault.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotFound`] for an unknown vault, or
    /// [`AppError::Tampered`] if an item fails its checks.
    pub fn items(&self, id: &VaultId) -> Result<Vec<(ItemId, Item)>, AppError> {
        let mut items = self.replica(id)?.items().map_err(vault_error)?;
        if let Some(queue) = &self.queue {
            queue.overlay(id, &mut items);
        }
        Ok(items)
    }

    /// One decrypted item.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotFound`] if there is no such item.
    pub fn item(&self, id: &VaultId, item_id: &ItemId) -> Result<Item, AppError> {
        self.items(id)?
            .into_iter()
            .find(|(i, _)| i == item_id)
            .map(|(_, item)| item)
            .ok_or(AppError::NotFound)
    }

    /// Adds or replaces an item, then syncs the vault. If another device
    /// wrote first, syncs and tries once more.
    ///
    /// # Errors
    ///
    /// Returns a server, network or verification error.
    pub fn put(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        id: VaultId,
        item_id: Option<ItemId>,
        item: &Item,
    ) -> Result<ItemId, AppError> {
        for attempt in 0..2 {
            let (new_id, request) = self
                .replica(&id)?
                .put_item(unlocked, item_id, item, now_ms())
                .map_err(vault_error)?;
            match written(&transport.send(&request)?) {
                Ok(()) => {
                    self.sync_one(transport, unlocked, id)?;
                    return Ok(new_id);
                }
                Err(e) if is_conflict(&e) && attempt == 0 => {
                    self.sync_one(transport, unlocked, id)?;
                }
                Err(e) => return Err(vault_error(e)),
            }
        }
        Err(AppError::Server)
    }

    /// Requests that add `items` as new items, chained so they are sent in
    /// order and verified by one sync afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::NotFound`] for an unknown vault, or an error if
    /// encryption or signing fails.
    pub fn new_items_batch(
        &self,
        unlocked: &Unlocked,
        id: &VaultId,
        items: &[Item],
    ) -> Result<Vec<client_core::Request>, AppError> {
        Ok(self
            .replica(id)?
            .put_new_items(unlocked, items, now_ms())
            .map_err(vault_error)?
            .into_iter()
            .map(|(_, request)| request)
            .collect())
    }

    /// Syncs one vault.
    ///
    /// # Errors
    ///
    /// Returns a server, network or verification error.
    pub fn sync_vault(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        id: VaultId,
    ) -> Result<(), AppError> {
        self.sync_one(transport, unlocked, id)
    }

    /// Deletes an item, then syncs the vault.
    ///
    /// # Errors
    ///
    /// Returns a server, network or verification error.
    pub fn delete(
        &mut self,
        transport: &impl Transport,
        unlocked: &Unlocked,
        id: VaultId,
        item_id: &ItemId,
    ) -> Result<(), AppError> {
        for attempt in 0..2 {
            let request = self
                .replica(&id)?
                .delete_item(unlocked, item_id, now_ms())
                .map_err(vault_error)?;
            match written(&transport.send(&request)?) {
                Ok(()) => return self.sync_one(transport, unlocked, id),
                Err(e) if is_conflict(&e) && attempt == 0 => {
                    self.sync_one(transport, unlocked, id)?;
                }
                Err(e) => return Err(vault_error(e)),
            }
        }
        Err(AppError::Server)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn offline_changes_go_out_only_onto_the_version_they_were_made_from() {
        use super::unchanged_since;
        // Added here and still unknown to the server.
        assert!(unchanged_since(0, None));
        // Edited here; nobody else touched it.
        assert!(unchanged_since(4, Some((4, false))));
        // Changed elsewhere meanwhile.
        assert!(!unchanged_since(4, Some((5, false))));
        // Deleted elsewhere meanwhile.
        assert!(!unchanged_since(4, Some((5, true))));
        // The server lost or never had it.
        assert!(!unchanged_since(4, None));
        // An ID clash with an item added elsewhere.
        assert!(!unchanged_since(0, Some((1, false))));
    }

    use super::*;

    #[test]
    fn vault_names() {
        assert_eq!(vault_name("  Family  "), Ok("Family".to_owned()));
        assert_eq!(vault_name("   "), Err(AppError::InvalidVaultName));
        assert_eq!(vault_name("a\nb"), Err(AppError::InvalidVaultName));
        assert!(vault_name(&"x".repeat(64)).is_ok());
        assert_eq!(vault_name(&"x".repeat(65)), Err(AppError::InvalidVaultName));
    }

    #[test]
    fn hex_decoding() {
        assert_eq!(hex("00ff10"), Some(vec![0, 255, 16]));
        assert_eq!(hex("0"), None);
        assert_eq!(hex("zz"), None);
        assert_eq!(hex(""), None);
    }
}
