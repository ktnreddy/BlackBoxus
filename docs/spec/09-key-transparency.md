# 9. Key Transparency

## 9.1 Overview

Sharing (Section 7) is only as safe as the recipient's public key. If a malicious server could hand Alice a key it controls when she asks for Bob's, it could read everything she shares with "Bob". Key transparency prevents this from happening silently:

- Every public key bundle an account publishes is recorded in an **append-only log**, a Merkle tree as in Certificate Transparency (RFC 9162).
- The server signs the log's **tree head** (its size and root hash) with a log key that is built into every client.
- When Alice looks up Bob's keys, the server must prove the bundle is **in** the log (inclusion proof), and that the log only **grew** since Alice last looked (consistency proof).
- Bob's devices regularly check every entry recorded for his own account. A key Bob never published is therefore visible to him.

For the strongest guarantee, two people can also compare a **safety number** in person or on a call (9.5).

## 9.2 Log leaves

```
leaf = u16be(1) ‖ account_id ‖ u32be(key_set_version) ‖ bundle_hash ‖ u64be(timestamp_ms)
                                                                              (62 bytes)
```

`bundle_hash` is `SHA-256` of the signed public key bundle (Section 5.5). `timestamp_ms` is when the server accepted it.

The server appends a leaf when an account is created and whenever it replaces its key set. It MUST NOT remove or change leaves.

The log contains account IDs, which are random and unrelated to email addresses, and hashes of public data. It reveals nothing about vault contents.

## 9.3 Tree, proofs and tree heads

Tree hashing, inclusion proofs and consistency proofs follow RFC 9162, Section 2.1 exactly:

```
leaf_hash   = SHA-256(0x00 ‖ leaf)
node_hash   = SHA-256(0x01 ‖ left ‖ right)
empty root  = SHA-256()
```

Clients MUST reject proofs longer than 64 hashes.

A **signed tree head** is:

```
tree_head = u16be(1) ‖ u64be(tree_size) ‖ root_hash ‖ u64be(timestamp_ms)      (50 bytes)
signed    = tree_head ‖ HybridSign(log_key, "BlackBoxus v1 tree-head", tree_head)
                                                                              (3423 bytes)
```

The log key is a hybrid Ed25519 + ML-DSA-65 key (Section 5.5). Its public half is compiled into every client and MUST NOT be fetched from the server. Replacing it requires a client update.

## 9.4 Looking up an account's keys

The server answers a key lookup with: the signed bundle, its leaf, the leaf's index, an inclusion proof, the current signed tree head, and a consistency proof from the tree size the client last saw.

The client:

1. verifies the tree head's signature with the built-in log key;
2. if it has seen a tree head before: rejects a smaller tree as a rollback, and verifies the consistency proof from the old head to the new one;
3. verifies the bundle's self-signature (Section 5.5), and checks that the leaf's account ID, key set version and bundle hash all match the bundle;
4. verifies the inclusion proof;
5. stores the new tree head, replacing the old one.

Clients MUST do this every time they use someone else's keys: before sharing a vault (Section 7.4), before opening a share (Section 7.5), and before trusting a revision-log author (Section 8.4).

## 9.5 Monitoring and safety numbers

### Self-monitoring

Each device SHOULD, at least daily, request all leaves for its own account ID, each with an inclusion proof against a fresh tree head, and alert the user if any leaf records a bundle this account did not publish.

### Safety numbers

A **fingerprint** identifies one account's current keys:

```
d           = SHA-512("BlackBoxus v1 fingerprint" ‖ account_id ‖ bundle_hash)
fingerprint = six groups of five digits; group i = (d[5i .. 5i+5] as big-endian integer) mod 100000
```

The **safety number** of two accounts is both fingerprints, the smaller first, so both people see the same 60 digits. When they match, both people know they have each other's real keys, independently of the server and the log. Clients SHOULD offer this check when sharing a vault, and show it as a QR code for scanning.

## 9.6 Security considerations

- **Split views.** A server could try to show Alice a log that differs from the one Bob monitors. Consistency proofs stop it from changing what any single device has already seen, but two devices with different views must compare tree heads to notice. Devices of the same account SHOULD compare tree heads during enrolment (Section 10), and a later version can add gossip between vault members or an independent auditor.
- **Detection, not prevention.** Key transparency does not stop a malicious server from publishing a false key. It makes doing so visible to the victim and leaves cryptographic evidence. Safety numbers prevent it outright for people who compare them.
- **Log key compromise.** Someone holding the log key can sign false tree heads, but still cannot make two different histories consistent for a device that has seen either one.
- **Privacy.** The log reveals how many accounts exist and when keys change, but not who owns which account ID.

## 9.7 Test vectors

[`vectors/09-key-transparency.json`](vectors/09-key-transparency.json) contains seven leaves with the root for every tree size, an inclusion proof, a consistency proof, a signed tree head and a fingerprint. They are checked independently by [`tools/vectors/verify_key_transparency.py`](../../tools/vectors/verify_key_transparency.py), which implements RFC 9162 in plain Python and verifies the signature with OpenSSL.
