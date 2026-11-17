//! Looking up other accounts' public keys through key transparency
//! (spec section 9.4), and checking the log for keys published in this
//! account's name (spec section 9.5).

use vault_core::transparency::{
    KeyLookup, LEAF_LEN, MAX_PROOF_LEN, OwnLeaf, OwnLeaves, SIGNED_TREE_HEAD_LEN, TreeHead,
    verify_key_lookup, verify_own_leaves,
};
use vault_core::{AccountId, IdentityPublicKey, PublicKeyBundle, SIGNED_PUBLIC_BUNDLE_LEN};
use wire::{KeyLookupJson, OwnLeavesJson, b64};

use crate::http::{Request, Response, Session, field, field_array};
use crate::login::Unlocked;
use crate::{ClientError, Result};

/// A public key bundle verified through key transparency, with the signed
/// bytes the server published (needed to check hashes pinned in vault logs).
#[derive(Debug, Clone)]
pub struct VerifiedKeys {
    /// The verified bundle.
    pub bundle: PublicKeyBundle,
    /// The signed bundle exactly as published.
    pub signed: Vec<u8>,
}

/// Verifies key lookups and remembers the latest tree head seen.
///
/// Create one per device with the log key built into the app, and the tree
/// head saved from last time (if any). Save [`KeyDirectory::tree_head`]
/// after every successful lookup: a smaller or inconsistent tree later is
/// evidence of an attack.
#[derive(Debug, Clone)]
pub struct KeyDirectory {
    log_key: IdentityPublicKey,
    head: Option<TreeHead>,
}

impl KeyDirectory {
    /// A directory trusting `log_key`, starting from `head`.
    #[must_use]
    pub const fn new(log_key: IdentityPublicKey, head: Option<TreeHead>) -> Self {
        Self { log_key, head }
    }

    /// The latest verified tree head.
    #[must_use]
    pub const fn tree_head(&self) -> Option<&TreeHead> {
        self.head.as_ref()
    }

    /// `GET /v1/accounts/{id}/keys`, asking for a consistency proof from the
    /// tree head seen last.
    #[must_use]
    pub fn lookup_request(&self, account: &AccountId, session: &Session) -> Request {
        let mut path = format!("/v1/accounts/{}/keys", b64(account.as_bytes()));
        if let Some(head) = &self.head {
            path.push_str(&format!("?seen={}", head.tree_size));
        }
        Request::get(path, Some(session))
    }

    /// Verifies the answer: the tree head's signature, consistency with the
    /// last tree head, the bundle's self-signature, its log leaf, and its
    /// inclusion. Returns the verified keys and remembers the new head.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Crypto`] if any check fails (for example
    /// [`vault_core::Error::LogRollback`] or
    /// [`vault_core::Error::InvalidProof`]), or
    /// [`ClientError::InvalidResponse`] if the bundle is for another account.
    pub fn verify(&mut self, account: &AccountId, response: &Response) -> Result<VerifiedKeys> {
        let answer: KeyLookupJson = response.parse()?;
        let hashes = |list: &[String]| -> Result<Vec<[u8; 32]>> {
            if list.len() > MAX_PROOF_LEN {
                return Err(ClientError::InvalidResponse);
            }
            list.iter().map(|h| field_array(h)).collect()
        };
        let bundle = field(&answer.signed_bundle, SIGNED_PUBLIC_BUNDLE_LEN)?;
        let leaf = field(&answer.leaf, LEAF_LEN)?;
        let head = field(&answer.signed_tree_head, SIGNED_TREE_HEAD_LEN)?;
        let inclusion = hashes(&answer.inclusion_proof)?;
        let consistency = hashes(&answer.consistency_proof)?;
        let (verified, new_head) = verify_key_lookup(
            &KeyLookup {
                signed_bundle: &bundle,
                leaf: &leaf,
                leaf_index: answer.leaf_index,
                inclusion_proof: &inclusion,
                signed_tree_head: &head,
                consistency_proof: &consistency,
            },
            &self.log_key,
            self.head.as_ref(),
        )?;
        if verified.account_id != *account {
            return Err(ClientError::InvalidResponse);
        }
        self.head = Some(new_head);
        Ok(VerifiedKeys {
            bundle: verified,
            signed: bundle,
        })
    }

    /// `GET /v1/accounts/self/leaves`, asking for a consistency proof from
    /// the tree head seen last.
    #[must_use]
    pub fn own_leaves_request(&self, session: &Session) -> Request {
        let mut path = String::from("/v1/accounts/self/leaves");
        if let Some(head) = &self.head {
            path.push_str(&format!("?seen={}", head.tree_size));
        }
        Request::get(path, Some(session))
    }

    /// Self-monitoring (spec section 9.5). `own` is this account's keys as
    /// a lookup of its own account ID returned them; `response` answers
    /// [`KeyDirectory::own_leaves_request`]. Checks that the published
    /// bundle carries this key set's public keys, and that no leaf in the
    /// log records any other bundle for this account. Remembers the new
    /// tree head.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Crypto`] with [`vault_core::Error::UnknownKeys`]
    /// if keys this device did not publish are recorded for the account,
    /// another [`ClientError::Crypto`] error for a bad proof or a rollback,
    /// or [`ClientError::InvalidResponse`].
    pub fn check_own_keys(
        &mut self,
        unlocked: &Unlocked,
        own: &VerifiedKeys,
        response: &Response,
    ) -> Result<()> {
        let account = unlocked.session.account_id();
        let bundle = &own.bundle;
        if bundle.account_id != *account
            || bundle.key_set_version != unlocked.key_set_version
            || bundle.identity.to_bytes() != unlocked.key_set.identity().public_key().to_bytes()
            || bundle.xwing.as_bytes() != unlocked.key_set.xwing_public_key().as_bytes()
        {
            return Err(ClientError::Crypto(vault_core::Error::UnknownKeys));
        }
        let answer: OwnLeavesJson = response.parse()?;
        if answer.leaves.len() > 1000 {
            return Err(ClientError::InvalidResponse);
        }
        let hashes = |list: &[String]| -> Result<Vec<[u8; 32]>> {
            if list.len() > MAX_PROOF_LEN {
                return Err(ClientError::InvalidResponse);
            }
            list.iter().map(|h| field_array(h)).collect()
        };
        let mut decoded = Vec::with_capacity(answer.leaves.len());
        for l in &answer.leaves {
            decoded.push((
                field(&l.leaf, LEAF_LEN)?,
                l.leaf_index,
                hashes(&l.inclusion_proof)?,
            ));
        }
        let leaves: Vec<OwnLeaf<'_>> = decoded
            .iter()
            .map(|(leaf, leaf_index, proof)| OwnLeaf {
                leaf,
                leaf_index: *leaf_index,
                inclusion_proof: proof,
            })
            .collect();
        let head = field(&answer.signed_tree_head, SIGNED_TREE_HEAD_LEN)?;
        let consistency = hashes(&answer.consistency_proof)?;
        let new_head = verify_own_leaves(
            account,
            &own.signed,
            &OwnLeaves {
                leaves: &leaves,
                signed_tree_head: &head,
                consistency_proof: &consistency,
            },
            &self.log_key,
            self.head.as_ref(),
        )?;
        self.head = Some(new_head);
        Ok(())
    }
}
