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

use crate::error::AppError;
use crate::http::Transport;
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
        }
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
        Ok(())
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
                    items: replica.items().map(|i| i.len()).unwrap_or_default(),
                    writable: matches!(role, Some(Role::Owner | Role::Editor)),
                    owner: role == Some(Role::Owner),
                    shared: replica.state().is_some_and(|s| s.members.len() > 1),
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
        self.replica(id)?.items().map_err(vault_error)
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
