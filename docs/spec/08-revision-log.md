# 8. Revision Log

## 8.1 Overview

Every vault has an append-only **revision log**. Each change, such as saving an item or adding a member, is one **entry**, signed by its author and linked to the previous entry by hash. Clients replay the whole log and check every signature and permission. As a result, a malicious server cannot:

- forge a change, or attribute one to the wrong member;
- reorder, edit or silently drop changes;
- roll a vault back to an older state, or show different devices different histories (fork);
- serve an outdated revision of an item as if it were current.

The server stores the log and keeps it a single chain (8.6), but every decision about what is valid is made by clients.

## 8.2 Entries

```
entry = u16be(1) ‖ vault_id ‖ u64be(seq) ‖ prev_hash
      ‖ author_account_id ‖ u32be(author_key_set_version) ‖ u64be(timestamp_ms)
      ‖ u8(operation) ‖ body                                   (87-byte header)

signed     = entry ‖ HybridSign(author_identity, "BlackBoxus v1 log-entry", entry)
entry_hash = SHA-256("BlackBoxus v1 log-entry-hash" ‖ signed)
```

- `seq` is 0 for the first entry and increases by exactly 1.
- `prev_hash` is the previous entry's `entry_hash`, or 32 zero bytes for the first entry.
- `timestamp_ms` is the author's clock. It is shown to users but never used for any decision.
- The hash covers the signature, so the chain commits to who signed each entry.

### Operations

| Code | Operation | Body | Body bytes |
| --- | --- | --- | --- |
| 1 | Create vault | `bundle_hash` | 32 |
| 2 | Put item | `item_id ‖ u64be(revision) ‖ u32be(vault_key_version) ‖ envelope_hash` | 60 |
| 3 | Delete item | `item_id ‖ u64be(revision)` | 24 |
| 4 | Add member | `account_id ‖ u32be(key_set_version) ‖ bundle_hash ‖ u8(role)` | 53 |
| 5 | Change role | `account_id ‖ u8(role)` | 17 |
| 6 | Remove member | `account_id` | 16 |
| 7 | Rotate key | `u32be(new_version)` | 4 |

- `bundle_hash` is `SHA-256` of a member's signed public key bundle (Section 5.5), which the author verified before writing the entry.
- `envelope_hash` is `SHA-256` of the item envelope (Section 6.4).
- Roles: 1 = owner, 2 = editor, 3 = viewer.

Parsers MUST reject an unknown operation or role code, a wrong body length, and trailing bytes.

## 8.3 Rules

An entry is valid only if every rule below holds in the state produced by all earlier entries:

| Operation | Allowed author | Further conditions |
| --- | --- | --- |
| Create vault | Anyone | Only as entry 0. The author becomes the first owner, pinned by `bundle_hash`; the vault key version starts at 1. |
| Put item | Owner, editor | `revision` is 1 for a new item, otherwise the current revision plus 1. The item must not be deleted. `vault_key_version` equals the current version. No key rotation is pending. |
| Delete item | Owner, editor | `revision` is the current revision plus 1. The item must exist and not already be deleted. |
| Add member | Owner | The account is not already a member. |
| Change role | Owner | The account is a member. At least one owner remains. |
| Remove member | Owner, or the member themself | The account is a member. At least one owner remains. Sets "key rotation pending". |
| Rotate key | Owner | `new_version` is the current version plus 1. Clears "key rotation pending". |

In addition, for every entry after the first:

- the author MUST be a current member;
- `author_key_set_version` MUST equal the member's pinned key set version;
- the signature MUST verify with the identity key from the bundle whose hash is pinned for that member.

The "key rotation pending" state blocks all writes after a member is removed until an owner has replaced the vault key (Section 7.6). This prevents new data from being encrypted under a key the removed member still holds.

## 8.4 Verifying a log

A client verifies the log by replaying it from entry 0:

1. Parse the entry; check `vault_id`, `seq` and `prev_hash`.
2. Find the author's pinned bundle hash: from the entry's own body for entry 0, otherwise from the member list. Obtain the matching signed bundle, check that its hash equals the pinned hash, and verify the bundle (Section 5.5).
3. Verify the entry's signature.
4. Apply the operation under the rules in 8.3.

### Rollback and fork detection

Each device remembers the **checkpoint** (`seq` and `entry_hash`) of the latest entry it has verified. On every later verification:

- if the log is shorter than the checkpoint, the server has rolled the vault back;
- if the entry at the checkpoint's `seq` has a different hash, the server is showing a different history (a fork).

Either case MUST be reported to the user as a possible attack, and the client MUST NOT write to the vault until it is resolved.

A server can still withhold *new* entries from a device (a "freeze"). Devices SHOULD show when a vault was last updated and SHOULD compare checkpoints with each other when they can, for example during device enrolment (Section 10).

## 8.5 Checking items against the log

Before showing or using an item, a client MUST check that:

- the log records the item as not deleted;
- the envelope's revision equals the log's current revision for the item;
- `SHA-256(envelope)` equals the recorded `envelope_hash`.

The client then opens the envelope (Section 6.5) with the vault key version recorded in the log. A valid envelope is therefore not enough on its own: it must also be the latest one, written by a member allowed to write.

## 8.6 Server responsibilities

When a client appends an entry, the server MUST, atomically:

- check that `seq` is the current head's `seq` plus 1 (or 0 for a new vault) and `prev_hash` is the current head's hash;
- reject entries larger than 4096 bytes;
- store the entry and update the head.

A write that loses a race is rejected; the client re-reads the log, re-applies its change and tries again. The server does not check signatures or permissions; clients do.

## 8.7 Security considerations

- **Size.** Clients replay the full log, which costs one hybrid signature check per entry. Signed snapshots that let a device skip already-verified history can be added in a later protocol version.
- **Concurrency.** Two devices editing the same item at once both produce revision `n + 1`. The server accepts only one; the other client re-reads and either merges or keeps both versions as separate items.
- **What the server learns.** The log is not encrypted: the server sees who changed which item ID, when, and membership changes. It never sees item contents or titles.

## 8.8 Test vectors

[`vectors/08-revision-log.json`](vectors/08-revision-log.json) contains a two-entry log made with fixed keys. It is checked independently, including signatures and the hash chain, with OpenSSL by [`tools/vectors/verify_log.py`](../../tools/vectors/verify_log.py).
