//! Key transparency, server side (spec section 9): an append-only Merkle
//! log of published key bundles, with inclusion and consistency proofs and
//! signed tree heads.
//!
//! Tree hashing and proofs follow RFC 9162, Section 2.1. This in-memory
//! implementation recomputes subtrees on demand; a storage adapter can cache
//! internal nodes without changing any result.

use vault_core::IdentitySecretKey;
use vault_core::transparency::{Hash, LEAF_LEN, TreeHead, empty_root, leaf_hash, node_hash};

use crate::error::{Error, Result};

/// An append-only key transparency log.
///
/// Besides the leaf hashes, the log keeps the hash of every complete,
/// aligned subtree, so the root and any proof take `O(log n)` hashing
/// instead of rehashing the whole tree.
#[derive(Debug, Default, Clone)]
pub struct KtLog {
    /// `levels[h][i]` is the hash of leaves `i·2^h .. (i+1)·2^h`; only
    /// complete subtrees are kept, so `levels[h].len() == size >> h`.
    levels: Vec<Vec<Hash>>,
}

impl KtLog {
    /// An empty log.
    #[must_use]
    pub const fn new() -> Self {
        Self { levels: Vec::new() }
    }

    /// Rebuilds a log from stored leaves, in order.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if any leaf has the wrong length.
    pub fn from_leaves<'a>(leaves: impl IntoIterator<Item = &'a [u8]>) -> Result<Self> {
        let mut log = Self::new();
        for leaf in leaves {
            log.append(leaf)?;
        }
        Ok(log)
    }

    /// Restores a log of `size` leaves from [`KtLog::to_stored`].
    ///
    /// The stored subtree hashes are trusted as written; a storage adapter
    /// that cannot trust its own storage gains nothing from rechecking them,
    /// because clients verify every proof against a signed tree head.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if the length does not match
    /// `size`.
    pub fn from_stored(size: u64, bytes: &[u8]) -> Result<Self> {
        let n = usize::try_from(size).map_err(|_| Error::MalformedMessage)?;
        let (chunks, rest) = bytes.as_chunks::<32>();
        if !rest.is_empty() {
            return Err(Error::MalformedMessage);
        }
        let mut levels = Vec::new();
        let mut at = 0_usize;
        let mut width = n;
        while width > 0 {
            let next = at.checked_add(width).ok_or(Error::MalformedMessage)?;
            levels.push(
                chunks
                    .get(at..next)
                    .ok_or(Error::MalformedMessage)?
                    .to_vec(),
            );
            at = next;
            width >>= 1;
        }
        if at != chunks.len() {
            return Err(Error::MalformedMessage);
        }
        Ok(Self { levels })
    }

    /// Every stored subtree hash, level by level, for [`KtLog::from_stored`].
    /// About `64 × size` bytes.
    #[must_use]
    pub fn to_stored(&self) -> Vec<u8> {
        self.levels.iter().flatten().flatten().copied().collect()
    }

    /// Appends an encoded leaf and returns its index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if the leaf has the wrong length.
    pub fn append(&mut self, leaf: &[u8]) -> Result<u64> {
        if leaf.len() != LEAF_LEN {
            return Err(Error::MalformedMessage);
        }
        let index = self.size();
        let mut hash = leaf_hash(leaf);
        let mut level = 0_usize;
        loop {
            if self.levels.len() == level {
                self.levels.push(Vec::new());
            }
            let row = self.levels.get_mut(level).ok_or(Error::MalformedMessage)?;
            row.push(hash);
            let len = row.len();
            if len & 1 == 1 {
                break;
            }
            match row.get(len.wrapping_sub(2)..) {
                Some([left, right]) => hash = node_hash(left, right),
                _ => return Err(Error::MalformedMessage),
            }
            level = level.wrapping_add(1);
        }
        Ok(index)
    }

    /// Number of leaves.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.levels
            .first()
            .map_or(0, |l| u64::try_from(l.len()).unwrap_or(u64::MAX))
    }

    /// The Merkle root of the first `size` leaves.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if `size` exceeds the log size.
    pub fn root(&self, size: u64) -> Result<Hash> {
        let n = self.prefix(size)?;
        if n == 0 {
            return Ok(empty_root());
        }
        self.mth(0, n)
    }

    /// Inclusion proof for leaf `index` in the tree of `size` leaves.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if `index` or `size` is out of
    /// range.
    pub fn inclusion_proof(&self, index: u64, size: u64) -> Result<Vec<Hash>> {
        let n = self.prefix(size)?;
        let m = usize::try_from(index).map_err(|_| Error::MalformedMessage)?;
        if m >= n {
            return Err(Error::MalformedMessage);
        }
        let mut proof = Vec::new();
        self.path(m, 0, n, &mut proof)?;
        Ok(proof)
    }

    /// Consistency proof from the tree of `old_size` leaves to the tree of
    /// `new_size` leaves.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if the sizes are out of range.
    pub fn consistency_proof(&self, old_size: u64, new_size: u64) -> Result<Vec<Hash>> {
        let n = self.prefix(new_size)?;
        let m = usize::try_from(old_size).map_err(|_| Error::MalformedMessage)?;
        if m > n {
            return Err(Error::MalformedMessage);
        }
        let mut proof = Vec::new();
        if m > 0 && m < n {
            self.subproof(m, 0, n, true, &mut proof)?;
        }
        Ok(proof)
    }

    /// Signs the current tree head.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfiguration`] if signing fails.
    pub fn signed_tree_head(
        &self,
        log_key: &IdentitySecretKey,
        timestamp_ms: u64,
    ) -> Result<Vec<u8>> {
        TreeHead {
            tree_size: self.size(),
            root_hash: self.root(self.size())?,
            timestamp_ms,
        }
        .sign(log_key)
        .map_err(|_| Error::InvalidConfiguration)
    }

    fn prefix(&self, size: u64) -> Result<usize> {
        let n = usize::try_from(size).map_err(|_| Error::MalformedMessage)?;
        let have = self.levels.first().map_or(0, Vec::len);
        if n > have {
            return Err(Error::MalformedMessage);
        }
        Ok(n)
    }

    /// `MTH(D[lo:hi])` for a non-empty range (RFC 9162, Section 2.1.1),
    /// using stored subtree hashes where the range is a complete subtree.
    fn mth(&self, lo: usize, hi: usize) -> Result<Hash> {
        let n = hi.checked_sub(lo).ok_or(Error::MalformedMessage)?;
        if n == 0 {
            return Err(Error::MalformedMessage);
        }
        if n.is_power_of_two() && lo.is_multiple_of(n) {
            let level = usize::try_from(n.trailing_zeros()).map_err(|_| Error::MalformedMessage)?;
            return self
                .levels
                .get(level)
                .and_then(|row| row.get(lo >> level))
                .copied()
                .ok_or(Error::MalformedMessage);
        }
        let mid = lo.checked_add(split(n)).ok_or(Error::MalformedMessage)?;
        Ok(node_hash(&self.mth(lo, mid)?, &self.mth(mid, hi)?))
    }

    /// `PATH(m, D[lo:hi])` (RFC 9162, Section 2.1.3.1); `m` is relative to `lo`.
    fn path(&self, m: usize, lo: usize, hi: usize, out: &mut Vec<Hash>) -> Result<()> {
        let n = hi.checked_sub(lo).ok_or(Error::MalformedMessage)?;
        if n <= 1 {
            return Ok(());
        }
        let k = split(n);
        let mid = lo.checked_add(k).ok_or(Error::MalformedMessage)?;
        if m < k {
            self.path(m, lo, mid, out)?;
            out.push(self.mth(mid, hi)?);
        } else {
            self.path(m.wrapping_sub(k), mid, hi, out)?;
            out.push(self.mth(lo, mid)?);
        }
        Ok(())
    }

    /// `SUBPROOF(m, D[lo:hi], b)` (RFC 9162, Section 2.1.4.1).
    fn subproof(
        &self,
        m: usize,
        lo: usize,
        hi: usize,
        complete: bool,
        out: &mut Vec<Hash>,
    ) -> Result<()> {
        let n = hi.checked_sub(lo).ok_or(Error::MalformedMessage)?;
        if m == n {
            if !complete {
                out.push(self.mth(lo, hi)?);
            }
            return Ok(());
        }
        let k = split(n);
        let mid = lo.checked_add(k).ok_or(Error::MalformedMessage)?;
        if m <= k {
            self.subproof(m, lo, mid, complete, out)?;
            out.push(self.mth(mid, hi)?);
        } else {
            self.subproof(m.wrapping_sub(k), mid, hi, false, out)?;
            out.push(self.mth(lo, mid)?);
        }
        Ok(())
    }
}

/// Largest power of two strictly less than `n` (`n` ≥ 2).
const fn split(n: usize) -> usize {
    let p = n.next_power_of_two();
    if p == n { n >> 1 } else { p >> 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::transparency::{verify_consistency, verify_inclusion};

    fn leaf(i: u64) -> [u8; LEAF_LEN] {
        let mut l = [0_u8; LEAF_LEN];
        l[1] = 1;
        l[2..10].copy_from_slice(&i.to_be_bytes());
        l
    }

    #[test]
    fn stored_form_round_trips_and_matches_a_plain_tree() {
        for n in [0_u64, 1, 2, 3, 7, 8, 13, 64, 100] {
            let log = log_of(n);
            let stored = log.to_stored();
            let restored = KtLog::from_stored(n, &stored).unwrap();
            assert_eq!(restored.size(), n);
            for size in 0..=n {
                assert_eq!(restored.root(size).unwrap(), plain_root(&leaves(size)));
            }
            if n > 0 {
                assert!(KtLog::from_stored(n, &stored[..stored.len() - 32]).is_err());
                assert!(KtLog::from_stored(n + 1, &stored).is_err());
                assert!(KtLog::from_stored(n, &stored[..stored.len() - 1]).is_err());
            }
        }
    }

    fn leaves(n: u64) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(&leaf(i))).collect()
    }

    /// RFC 9162 `MTH` computed directly, as an independent reference.
    fn plain_root(hashes: &[Hash]) -> Hash {
        match hashes {
            [] => empty_root(),
            [one] => *one,
            _ => {
                let (l, r) = hashes.split_at(split(hashes.len()));
                node_hash(&plain_root(l), &plain_root(r))
            }
        }
    }

    fn log_of(n: u64) -> KtLog {
        let mut log = KtLog::new();
        for i in 0..n {
            log.append(&leaf(i)).unwrap();
        }
        log
    }

    #[test]
    fn every_inclusion_proof_verifies() {
        let log = log_of(70);
        for size in 1..=70 {
            let root = log.root(size).unwrap();
            for index in 0..size {
                let proof = log.inclusion_proof(index, size).unwrap();
                let lh = leaf_hash(&leaf(index));
                assert!(
                    verify_inclusion(index, size, &lh, &proof, &root).is_ok(),
                    "index {index} size {size}"
                );
                // A wrong leaf, index or root must fail.
                let other = leaf_hash(&leaf(index + 1000));
                assert!(verify_inclusion(index, size, &other, &proof, &root).is_err());
                if size > 1 {
                    let wrong_index = (index + 1) % size;
                    assert!(verify_inclusion(wrong_index, size, &lh, &proof, &root).is_err());
                }
            }
        }
    }

    #[test]
    fn every_consistency_proof_verifies() {
        let log = log_of(70);
        for new in 1..=70 {
            let new_root = log.root(new).unwrap();
            for old in 0..=new {
                let old_root = log.root(old).unwrap();
                let proof = log.consistency_proof(old, new).unwrap();
                assert!(
                    verify_consistency(old, new, &old_root, &new_root, &proof).is_ok(),
                    "{old} -> {new}"
                );
                if old > 0 && old < new {
                    // A different history must not verify.
                    let mut forged = proof.clone();
                    forged[0][0] ^= 1;
                    assert!(
                        verify_consistency(old, new, &old_root, &new_root, &forged).is_err(),
                        "forged {old} -> {new}"
                    );
                    assert!(
                        verify_consistency(old, new, &new_root, &old_root, &proof).is_err(),
                        "swapped roots {old} -> {new}"
                    );
                }
            }
        }
    }

    #[test]
    fn rewritten_history_is_detected() {
        let honest = log_of(20);
        let old_root = honest.root(10).unwrap();

        // A server that changes leaf 3 and then grows the log cannot prove
        // consistency with the tree head clients already saw.
        let mut forked = KtLog::new();
        for i in 0..20 {
            forked.append(&leaf(if i == 3 { 999 } else { i })).unwrap();
        }
        let proof = forked.consistency_proof(10, 20).unwrap();
        assert!(verify_consistency(10, 20, &old_root, &forked.root(20).unwrap(), &proof).is_err());
    }

    #[test]
    fn rejects_bad_input() {
        let mut log = log_of(5);
        assert!(log.append(&[0; LEAF_LEN - 1]).is_err());
        assert!(log.inclusion_proof(5, 5).is_err());
        assert!(log.inclusion_proof(0, 6).is_err());
        assert!(log.consistency_proof(6, 5).is_err());
        assert!(log.root(6).is_err());
        assert_eq!(KtLog::new().root(0).unwrap(), empty_root());
    }

    #[test]
    fn self_monitoring_catches_keys_the_account_did_not_publish() {
        use crate::api::Api;
        use vault_core::log::bundle_hash;
        use vault_core::transparency::{KtLeaf, OwnLeaf, OwnLeaves, verify_own_leaves};
        use vault_core::{AccountId, Error as CoreError, IdentitySecretKey, KeySet};

        let me = AccountId::from_bytes([7; 16]);
        let other = AccountId::from_bytes([8; 16]);
        let mine = KeySet::generate()
            .unwrap()
            .signed_public_bundle(&me, 1)
            .unwrap();
        let theirs = KeySet::generate()
            .unwrap()
            .signed_public_bundle(&me, 1)
            .unwrap();
        let rec = |account, version, bundle: &[u8]| {
            KtLeaf {
                account_id: account,
                key_set_version: version,
                bundle_hash: bundle_hash(bundle),
                timestamp_ms: 5,
            }
            .encode()
            .to_vec()
        };
        let key = IdentitySecretKey::generate().unwrap();
        let public = key.public_key();
        let check = |entries: &[(AccountId, u32, &[u8])], mine_at: &[usize], last| {
            let mut log = KtLog::new();
            let leaves: Vec<Vec<u8>> = entries.iter().map(|(a, v, b)| rec(*a, *v, b)).collect();
            for l in &leaves {
                log.append(l).unwrap();
            }
            let head = log.signed_tree_head(&key, 9).unwrap();
            let own: Vec<(u64, Vec<u8>)> = mine_at
                .iter()
                .map(|&i| (i as u64, leaves[i].clone()))
                .collect();
            let answer = Api::own_leaves(&log, &own, None, head).unwrap();
            let items: Vec<OwnLeaf<'_>> = answer
                .leaves
                .iter()
                .map(|l| OwnLeaf {
                    leaf: &l.leaf,
                    leaf_index: l.leaf_index,
                    inclusion_proof: &l.inclusion_proof,
                })
                .collect();
            verify_own_leaves(
                &me,
                &mine,
                &OwnLeaves {
                    leaves: &items,
                    signed_tree_head: &answer.signed_tree_head,
                    consistency_proof: &answer.consistency_proof,
                },
                &public,
                last,
            )
        };

        // Only its own bundle: clean, among other accounts' leaves.
        let head = check(&[(other, 1, &theirs), (me, 1, &mine)], &[1], None).unwrap();
        assert_eq!(head.tree_size, 2);
        // A second bundle at the same version, which a malicious server
        // could hand to people sharing with this account, is caught.
        assert_eq!(
            check(&[(me, 1, &mine), (me, 1, &theirs)], &[0, 1], None),
            Err(CoreError::UnknownKeys)
        );
        // So is a newer version, and a log that leaves out its own bundle.
        assert_eq!(
            check(&[(me, 1, &mine), (me, 2, &theirs)], &[0, 1], None),
            Err(CoreError::UnknownKeys)
        );
        assert_eq!(
            check(&[(me, 1, &mine)], &[], None),
            Err(CoreError::UnknownKeys)
        );
        // Another account's leaf passed off as this one's is refused.
        assert_eq!(
            check(&[(other, 1, &mine), (me, 1, &mine)], &[0, 1], None),
            Err(CoreError::LogMismatch)
        );
        // A tree smaller than one seen before is a rollback.
        let bigger = check(
            &[(other, 1, &theirs), (other, 1, &theirs), (me, 1, &mine)],
            &[2],
            None,
        )
        .unwrap();
        assert_eq!(
            check(&[(me, 1, &mine)], &[0], Some(&bigger)),
            Err(CoreError::LogRollback)
        );
    }
}
