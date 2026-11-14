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
#[derive(Debug, Default, Clone)]
pub struct KtLog {
    leaf_hashes: Vec<Hash>,
}

impl KtLog {
    /// An empty log.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            leaf_hashes: Vec::new(),
        }
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

    /// Appends an encoded leaf and returns its index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if the leaf has the wrong length.
    pub fn append(&mut self, leaf: &[u8]) -> Result<u64> {
        if leaf.len() != LEAF_LEN {
            return Err(Error::MalformedMessage);
        }
        let index = u64::try_from(self.leaf_hashes.len()).map_err(|_| Error::MalformedMessage)?;
        self.leaf_hashes.push(leaf_hash(leaf));
        Ok(index)
    }

    /// Number of leaves.
    #[must_use]
    pub fn size(&self) -> u64 {
        u64::try_from(self.leaf_hashes.len()).unwrap_or(u64::MAX)
    }

    /// The Merkle root of the first `size` leaves.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if `size` exceeds the log size.
    pub fn root(&self, size: u64) -> Result<Hash> {
        let leaves = self.prefix(size)?;
        Ok(if leaves.is_empty() {
            empty_root()
        } else {
            mth(leaves)
        })
    }

    /// Inclusion proof for leaf `index` in the tree of `size` leaves.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if `index` or `size` is out of
    /// range.
    pub fn inclusion_proof(&self, index: u64, size: u64) -> Result<Vec<Hash>> {
        let leaves = self.prefix(size)?;
        let m = usize::try_from(index).map_err(|_| Error::MalformedMessage)?;
        if m >= leaves.len() {
            return Err(Error::MalformedMessage);
        }
        let mut proof = Vec::new();
        path(m, leaves, &mut proof);
        Ok(proof)
    }

    /// Consistency proof from the tree of `old_size` leaves to the tree of
    /// `new_size` leaves.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedMessage`] if the sizes are out of range.
    pub fn consistency_proof(&self, old_size: u64, new_size: u64) -> Result<Vec<Hash>> {
        let leaves = self.prefix(new_size)?;
        let m = usize::try_from(old_size).map_err(|_| Error::MalformedMessage)?;
        if m > leaves.len() {
            return Err(Error::MalformedMessage);
        }
        let mut proof = Vec::new();
        if m > 0 && m < leaves.len() {
            subproof(m, leaves, true, &mut proof);
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

    fn prefix(&self, size: u64) -> Result<&[Hash]> {
        let n = usize::try_from(size).map_err(|_| Error::MalformedMessage)?;
        self.leaf_hashes.get(..n).ok_or(Error::MalformedMessage)
    }
}

/// Largest power of two strictly less than `n` (`n` ≥ 2).
const fn split(n: usize) -> usize {
    let p = n.next_power_of_two();
    if p == n { n >> 1 } else { p >> 1 }
}

/// `MTH(D[n])` for a non-empty list (RFC 9162, Section 2.1.1).
fn mth(leaves: &[Hash]) -> Hash {
    match leaves {
        [] => empty_root(),
        [one] => *one,
        _ => {
            let (left, right) = leaves.split_at(split(leaves.len()));
            node_hash(&mth(left), &mth(right))
        }
    }
}

/// `PATH(m, D[n])` (RFC 9162, Section 2.1.3.1).
fn path(m: usize, leaves: &[Hash], out: &mut Vec<Hash>) {
    if leaves.len() <= 1 {
        return;
    }
    let k = split(leaves.len());
    let (left, right) = leaves.split_at(k);
    if m < k {
        path(m, left, out);
        out.push(mth(right));
    } else {
        path(m.saturating_sub(k), right, out);
        out.push(mth(left));
    }
}

/// `SUBPROOF(m, D[n], b)` (RFC 9162, Section 2.1.4.1).
fn subproof(m: usize, leaves: &[Hash], complete: bool, out: &mut Vec<Hash>) {
    let n = leaves.len();
    if m == n {
        if !complete {
            out.push(mth(leaves));
        }
        return;
    }
    let k = split(n);
    let (left, right) = leaves.split_at(k);
    if m <= k {
        subproof(m, left, complete, out);
        out.push(mth(right));
    } else {
        subproof(m.saturating_sub(k), right, false, out);
        out.push(mth(left));
    }
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
}
