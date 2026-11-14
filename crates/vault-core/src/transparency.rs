//! Key transparency, client side (spec section 9): verifying that a public
//! key bundle is recorded in the server's append-only log, that the log only
//! ever grows, and computing fingerprints users can compare in person.
//!
//! The Merkle tree follows RFC 9162 (Certificate Transparency 2.0),
//! Section 2.1.

use sha2::{Digest, Sha256, Sha512};

use crate::error::{Error, Result};
use crate::keyset::{ACCOUNT_ID_LEN, AccountId, PublicKeyBundle};
use crate::log::{HASH_LEN, bundle_hash};
use crate::signature::{
    HYBRID_SIGNATURE_LEN, HybridSignature, IdentityPublicKey, IdentitySecretKey,
};

const FORMAT_VERSION: u16 = 1;
const LABEL_TREE_HEAD: &[u8] = b"BlackBoxus v1 tree-head";
const LABEL_FINGERPRINT: &[u8] = b"BlackBoxus v1 fingerprint";

/// Length of an encoded log leaf in bytes.
pub const LEAF_LEN: usize = 62;

/// Length of an unsigned tree head in bytes.
const TREE_HEAD_LEN: usize = 50;

/// Length of a signed tree head in bytes.
pub const SIGNED_TREE_HEAD_LEN: usize = 3423;

/// Longest proof accepted: enough for a tree of 2^64 leaves.
pub const MAX_PROOF_LEN: usize = 64;

/// A 32-byte Merkle tree hash.
pub type Hash = [u8; HASH_LEN];

/// One record in the key transparency log: an account published a key set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KtLeaf {
    /// The account.
    pub account_id: AccountId,
    /// The key set version.
    pub key_set_version: u32,
    /// SHA-256 of the signed public key bundle.
    pub bundle_hash: Hash,
    /// When the server added the record, Unix milliseconds.
    pub timestamp_ms: u64,
}

impl KtLeaf {
    /// Encodes the leaf (spec section 9.2).
    #[must_use]
    pub fn encode(&self) -> [u8; LEAF_LEN] {
        let mut out = [0_u8; LEAF_LEN];
        let parts: [&[u8]; 5] = [
            &FORMAT_VERSION.to_be_bytes(),
            self.account_id.as_bytes(),
            &self.key_set_version.to_be_bytes(),
            &self.bundle_hash,
            &self.timestamp_ms.to_be_bytes(),
        ];
        for (dst, src) in out.iter_mut().zip(parts.into_iter().flatten()) {
            *dst = *src;
        }
        out
    }

    /// Parses an encoded leaf.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] for a wrong length or version.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != LEAF_LEN {
            return Err(Error::MalformedMessage);
        }
        let (version, rest) = bytes.split_at(2);
        if version != FORMAT_VERSION.to_be_bytes() {
            return Err(Error::MalformedMessage);
        }
        let (account, rest) = rest.split_at(ACCOUNT_ID_LEN);
        let (ksv, rest) = rest.split_at(4);
        let (hash, ts) = rest.split_at(HASH_LEN);
        let bad = |_| Error::MalformedMessage;
        Ok(Self {
            account_id: AccountId::from_bytes(account.try_into().map_err(bad)?),
            key_set_version: u32::from_be_bytes(ksv.try_into().map_err(bad)?),
            bundle_hash: hash.try_into().map_err(bad)?,
            timestamp_ms: u64::from_be_bytes(ts.try_into().map_err(bad)?),
        })
    }
}

/// `SHA-256(0x00 ‖ leaf)` (RFC 9162, Section 2.1.1).
#[must_use]
pub fn leaf_hash(leaf: &[u8]) -> Hash {
    Sha256::new()
        .chain_update([0x00])
        .chain_update(leaf)
        .finalize()
        .into()
}

/// `SHA-256(0x01 ‖ left ‖ right)` (RFC 9162, Section 2.1.1).
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    Sha256::new()
        .chain_update([0x01])
        .chain_update(left)
        .chain_update(right)
        .finalize()
        .into()
}

/// Root of the empty tree: `SHA-256()`.
#[must_use]
pub fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

/// Verifies an inclusion proof (RFC 9162, Section 2.1.3.2).
///
/// # Errors
///
/// Returns [`Error::InvalidProof`] if the proof does not show that
/// `leaf_hash` is leaf `leaf_index` of the tree with `root` and `tree_size`.
pub fn verify_inclusion(
    leaf_index: u64,
    tree_size: u64,
    leaf_hash: &Hash,
    proof: &[Hash],
    root: &Hash,
) -> Result<()> {
    if leaf_index >= tree_size || proof.len() > MAX_PROOF_LEN {
        return Err(Error::InvalidProof);
    }
    let mut f_n = leaf_index;
    let mut s_n = tree_size.checked_sub(1).ok_or(Error::InvalidProof)?;
    let mut r = *leaf_hash;
    for p in proof {
        if s_n == 0 {
            return Err(Error::InvalidProof);
        }
        if f_n & 1 == 1 || f_n == s_n {
            r = node_hash(p, &r);
            if f_n & 1 == 0 {
                while f_n & 1 == 0 && f_n != 0 {
                    f_n >>= 1;
                    s_n >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        f_n >>= 1;
        s_n >>= 1;
    }
    if s_n == 0 && r == *root {
        Ok(())
    } else {
        Err(Error::InvalidProof)
    }
}

/// Verifies a consistency proof between two tree heads (RFC 9162, Section
/// 2.1.4.2): the tree of `second_size` contains the tree of `first_size` as
/// a prefix.
///
/// # Errors
///
/// Returns [`Error::InvalidProof`] if the proof does not show that.
pub fn verify_consistency(
    first_size: u64,
    second_size: u64,
    first_root: &Hash,
    second_root: &Hash,
    proof: &[Hash],
) -> Result<()> {
    if first_size > second_size || proof.len() > MAX_PROOF_LEN {
        return Err(Error::InvalidProof);
    }
    if first_size == second_size {
        return if proof.is_empty() && first_root == second_root {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        };
    }
    if first_size == 0 {
        // Every tree extends the empty tree.
        return if proof.is_empty() && *first_root == empty_root() {
            Ok(())
        } else {
            Err(Error::InvalidProof)
        };
    }

    let mut path: Vec<Hash> = Vec::with_capacity(proof.len().saturating_add(1));
    if first_size.is_power_of_two() {
        path.push(*first_root);
    }
    path.extend_from_slice(proof);

    let mut f_n = first_size.checked_sub(1).ok_or(Error::InvalidProof)?;
    let mut s_n = second_size.checked_sub(1).ok_or(Error::InvalidProof)?;
    while f_n & 1 == 1 {
        f_n >>= 1;
        s_n >>= 1;
    }
    let (first, rest) = path.split_first().ok_or(Error::InvalidProof)?;
    let mut f_r = *first;
    let mut s_r = *first;
    for c in rest {
        if s_n == 0 {
            return Err(Error::InvalidProof);
        }
        if f_n & 1 == 1 || f_n == s_n {
            f_r = node_hash(c, &f_r);
            s_r = node_hash(c, &s_r);
            if f_n & 1 == 0 {
                while f_n & 1 == 0 && f_n != 0 {
                    f_n >>= 1;
                    s_n >>= 1;
                }
            }
        } else {
            s_r = node_hash(&s_r, c);
        }
        f_n >>= 1;
        s_n >>= 1;
    }
    if f_r == *first_root && s_r == *second_root && s_n == 0 {
        Ok(())
    } else {
        Err(Error::InvalidProof)
    }
}

/// A tree head: the log's size and root at a moment in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeHead {
    /// Number of leaves.
    pub tree_size: u64,
    /// Merkle tree root.
    pub root_hash: Hash,
    /// When the server signed it, Unix milliseconds.
    pub timestamp_ms: u64,
}

impl TreeHead {
    fn encode(&self) -> [u8; TREE_HEAD_LEN] {
        let mut out = [0_u8; TREE_HEAD_LEN];
        let parts: [&[u8]; 4] = [
            &FORMAT_VERSION.to_be_bytes(),
            &self.tree_size.to_be_bytes(),
            &self.root_hash,
            &self.timestamp_ms.to_be_bytes(),
        ];
        for (dst, src) in out.iter_mut().zip(parts.into_iter().flatten()) {
            *dst = *src;
        }
        out
    }

    /// Signs the tree head with the log's signing key (server side).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Signing`] or [`Error::RandomUnavailable`].
    pub fn sign(&self, log_key: &IdentitySecretKey) -> Result<Vec<u8>> {
        let unsigned = self.encode();
        let signature = log_key.sign(LABEL_TREE_HEAD, &unsigned)?;
        let mut out = Vec::with_capacity(SIGNED_TREE_HEAD_LEN);
        out.extend_from_slice(&unsigned);
        out.extend_from_slice(signature.as_bytes());
        Ok(out)
    }

    /// Verifies a signed tree head against the log's public key, which is
    /// built into the client, never fetched from the server.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] or [`Error::InvalidSignature`].
    pub fn verify_signed(signed: &[u8], log_key: &IdentityPublicKey) -> Result<Self> {
        if signed.len() != SIGNED_TREE_HEAD_LEN {
            return Err(Error::MalformedMessage);
        }
        let (unsigned, signature) = signed.split_at(TREE_HEAD_LEN);
        log_key.verify(
            LABEL_TREE_HEAD,
            unsigned,
            &HybridSignature::from_bytes(signature)?,
        )?;

        let (version, rest) = unsigned.split_at(2);
        if version != FORMAT_VERSION.to_be_bytes() {
            return Err(Error::MalformedMessage);
        }
        let (size, rest) = rest.split_at(8);
        let (root, ts) = rest.split_at(HASH_LEN);
        let bad = |_| Error::MalformedMessage;
        Ok(Self {
            tree_size: u64::from_be_bytes(size.try_into().map_err(bad)?),
            root_hash: root.try_into().map_err(bad)?,
            timestamp_ms: u64::from_be_bytes(ts.try_into().map_err(bad)?),
        })
    }
}

/// What the server returns when a client looks up an account's keys
/// (spec section 9.4).
#[derive(Debug, Clone)]
pub struct KeyLookup<'a> {
    /// The signed public key bundle.
    pub signed_bundle: &'a [u8],
    /// The encoded log leaf recording it.
    pub leaf: &'a [u8],
    /// The leaf's position in the log.
    pub leaf_index: u64,
    /// Inclusion proof for the leaf in `signed_tree_head`'s tree.
    pub inclusion_proof: &'a [Hash],
    /// The current signed tree head.
    pub signed_tree_head: &'a [u8],
    /// Consistency proof from the client's last tree head to this one.
    /// Empty if the client has none, or the sizes are equal.
    pub consistency_proof: &'a [Hash],
}

/// Verifies a key lookup and returns the bundle and the new tree head, which
/// the client must store in place of `last_tree_head` (spec section 9.4).
///
/// # Errors
///
/// Returns [`Error::InvalidSignature`] for a bad tree head or bundle,
/// [`Error::InvalidProof`] for a bad inclusion or consistency proof,
/// [`Error::LogRollback`] if the tree is smaller than one seen before, or
/// [`Error::LogMismatch`] if the leaf does not describe the bundle.
pub fn verify_key_lookup(
    lookup: &KeyLookup<'_>,
    log_key: &IdentityPublicKey,
    last_tree_head: Option<&TreeHead>,
) -> Result<(PublicKeyBundle, TreeHead)> {
    let head = TreeHead::verify_signed(lookup.signed_tree_head, log_key)?;

    if let Some(last) = last_tree_head {
        if head.tree_size < last.tree_size {
            return Err(Error::LogRollback);
        }
        verify_consistency(
            last.tree_size,
            head.tree_size,
            &last.root_hash,
            &head.root_hash,
            lookup.consistency_proof,
        )?;
    }

    let leaf = KtLeaf::decode(lookup.leaf)?;
    let bundle = PublicKeyBundle::verify_signed(lookup.signed_bundle)?;
    if leaf.bundle_hash != bundle_hash(lookup.signed_bundle)
        || leaf.account_id != bundle.account_id
        || leaf.key_set_version != bundle.key_set_version
    {
        return Err(Error::LogMismatch);
    }
    verify_inclusion(
        lookup.leaf_index,
        head.tree_size,
        &leaf_hash(lookup.leaf),
        lookup.inclusion_proof,
        &head.root_hash,
    )?;
    Ok((bundle, head))
}

/// A 30-digit fingerprint of one account's keys, in six groups of five
/// digits (spec section 9.5).
#[must_use]
pub fn fingerprint(account_id: &AccountId, signed_bundle: &[u8]) -> String {
    let digest = Sha512::new()
        .chain_update(LABEL_FINGERPRINT)
        .chain_update(account_id.as_bytes())
        .chain_update(bundle_hash(signed_bundle))
        .finalize();
    let mut groups = Vec::with_capacity(6);
    for chunk in digest.chunks_exact(5).take(6) {
        let value = chunk
            .iter()
            .fold(0_u64, |acc, &b| (acc << 8) | u64::from(b));
        groups.push(format!("{:05}", value % 100_000));
    }
    groups.join(" ")
}

/// A 60-digit safety number for two accounts: both fingerprints, in a fixed
/// order so both people see the same number.
#[must_use]
pub fn safety_number(a: (&AccountId, &[u8]), b: (&AccountId, &[u8])) -> String {
    let fa = fingerprint(a.0, a.1);
    let fb = fingerprint(b.0, b.1);
    if fa <= fb {
        format!("{fa} {fb}")
    } else {
        format!("{fb} {fa}")
    }
}

/// Signed tree head plus signature length, checked at compile time.
const _: () = assert!(TREE_HEAD_LEN + HYBRID_SIGNATURE_LEN == SIGNED_TREE_HEAD_LEN);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyset::KeySet;

    #[test]
    fn leaf_round_trip() {
        let leaf = KtLeaf {
            account_id: AccountId::from_bytes([3; 16]),
            key_set_version: 2,
            bundle_hash: [4; 32],
            timestamp_ms: 99,
        };
        assert_eq!(KtLeaf::decode(&leaf.encode()).unwrap(), leaf);
        assert!(KtLeaf::decode(&[0; LEAF_LEN - 1]).is_err());
        let mut bad = leaf.encode();
        bad[1] = 2;
        assert!(KtLeaf::decode(&bad).is_err());
    }

    #[test]
    fn inclusion_rejects_out_of_range_and_oversized_proofs() {
        let h = [0_u8; 32];
        assert!(verify_inclusion(1, 1, &h, &[], &h).is_err());
        assert!(verify_inclusion(0, 0, &h, &[], &h).is_err());
        assert!(verify_inclusion(0, 2, &h, &[h; MAX_PROOF_LEN + 1], &h).is_err());
        // Single-leaf tree: the root is the leaf hash, with an empty proof.
        let leaf = leaf_hash(b"x");
        assert!(verify_inclusion(0, 1, &leaf, &[], &leaf).is_ok());
        assert!(verify_inclusion(0, 1, &leaf, &[leaf], &leaf).is_err());
    }

    #[test]
    fn consistency_edge_cases() {
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        assert!(verify_consistency(1, 1, &a, &a, &[]).is_ok());
        assert!(verify_consistency(1, 1, &a, &b, &[]).is_err());
        assert!(verify_consistency(2, 1, &a, &a, &[]).is_err());
        assert!(verify_consistency(0, 5, &empty_root(), &a, &[]).is_ok());
        assert!(verify_consistency(0, 5, &a, &a, &[]).is_err());
        // Tree of 1 extended to 2: proof is the second leaf.
        let root2 = node_hash(&a, &b);
        assert!(verify_consistency(1, 2, &a, &root2, &[b]).is_ok());
        assert!(verify_consistency(1, 2, &b, &root2, &[b]).is_err());
    }

    #[test]
    fn tree_head_signature() {
        let key = IdentitySecretKey::generate().unwrap();
        let head = TreeHead {
            tree_size: 10,
            root_hash: [7; 32],
            timestamp_ms: 5,
        };
        let signed = head.sign(&key).unwrap();
        assert_eq!(signed.len(), SIGNED_TREE_HEAD_LEN);
        assert_eq!(
            TreeHead::verify_signed(&signed, &key.public_key()).unwrap(),
            head
        );

        let other = IdentitySecretKey::generate().unwrap().public_key();
        assert_eq!(
            TreeHead::verify_signed(&signed, &other).unwrap_err(),
            Error::InvalidSignature
        );
        let mut bumped = signed.clone();
        bumped[9] ^= 1;
        assert!(TreeHead::verify_signed(&bumped, &key.public_key()).is_err());
    }

    #[test]
    fn fingerprints_are_stable_and_distinct() {
        let keys = KeySet::generate().unwrap();
        let id = AccountId::from_bytes([1; 16]);
        let bundle = keys.signed_public_bundle(&id, 1).unwrap();
        let fp = fingerprint(&id, &bundle);
        assert_eq!(fp.len(), 35);
        assert!(
            fp.split(' ')
                .all(|g| g.len() == 5 && g.bytes().all(|b| b.is_ascii_digit()))
        );
        assert_eq!(fp, fingerprint(&id, &bundle));

        let other = KeySet::generate()
            .unwrap()
            .signed_public_bundle(&id, 1)
            .unwrap();
        assert_ne!(fp, fingerprint(&id, &other));

        let id2 = AccountId::from_bytes([2; 16]);
        assert_eq!(
            safety_number((&id, &bundle), (&id2, &other)),
            safety_number((&id2, &other), (&id, &bundle))
        );
    }
}
