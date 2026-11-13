# 7. Vaults and Sharing

## 7.1 Overview

A **vault** is a collection of items (Section 6) protected by one 32-byte **vault key**. Every member of a vault holds the vault key; the server never does.

- The vault's creator keeps the key wrapped under their own **account key** (7.3).
- Each other member receives the key in a **vault share**: the key encrypted to the member's X-Wing public key and signed by the person who shared it (7.4).

Vault keys have a 32-bit **version**, starting at 1, which increases every time the key is replaced (7.6). Members, their roles (owner, editor, viewer) and the current key version are recorded in the vault's signed revision log (Section 8).

## 7.2 Creating a vault

1. Generate `vault_id = random(16)` and `vault_key = random(32)`, version 1.
2. Wrap the vault key for the creator (7.3).
3. Start the vault's revision log with the creator as owner (Section 8).

Every account starts with one personal vault created this way.

## 7.3 Wrapping for the owner

```
aad     = "BlackBoxus v1 vault-key" ‖ u16be(1) ‖ owner_account_id ‖ vault_id ‖ u32be(version)
nonce   = random(24)
wrapped = u16be(1) ‖ vault_id ‖ u32be(version)
          ‖ nonce ‖ XChaCha20-Poly1305(account_key, nonce, vault_key, aad)     (94 bytes)
```

To unwrap, the client checks that the length is 94 bytes, the format version is 1 and the vault ID is the one requested, then decrypts using its own account ID.

## 7.4 Sharing a vault key

Before sharing, the sender MUST have verified that the recipient's public key bundle (Section 5.5) really belongs to the intended person, through key transparency or a fingerprint comparison (Section 9). Encrypting to an unverified key would let a malicious server read the vault.

```
header = u16be(1) ‖ vault_id ‖ u32be(vault_key_version)
       ‖ sender_account_id ‖ u32be(sender_key_set_version)
       ‖ recipient_account_id ‖ u32be(recipient_key_set_version)          (62 bytes)

(enc, ss) = X-Wing.Encapsulate(recipient_xwing_pk)                         (1120, 32 bytes)

wrap_key  = HKDF-SHA-256(salt = SHA-256(recipient_xwing_pk), IKM = ss,
                         info = "BlackBoxus v1 vault-share" ‖ header ‖ enc, L = 32)

nonce     = random(24)
sealed    = nonce ‖ XChaCha20-Poly1305(wrap_key, nonce, vault_key, aad = header)   (72 bytes)

body      = header ‖ enc ‖ sealed
share     = body ‖ HybridSign(sender_identity, "BlackBoxus v1 vault-share", body)
                                                                           (4627 bytes)
```

X-Wing encapsulation follows draft-connolly-cfrg-xwing-kem Section 5.3, including the FIPS 203 check of the ML-KEM public key. A recipient key that fails the check MUST NOT be used.

### Why not HPKE

This is the same KEM-plus-key-derivation-plus-AEAD structure as single-shot HPKE (RFC 9180) base mode. BlackBoxus spells it out directly because HPKE codepoints for X-Wing are not yet final, and because every input that matters (both identities, both key-set versions, the vault and the ciphertext) is bound explicitly into the key derivation and associated data. An HPKE suite can replace it in a later protocol version.

## 7.5 Opening a share

The recipient:

1. MUST check that the share is exactly 4627 bytes and its format version is 1.
2. MUST check that the recipient account ID and key-set version are its own.
3. Fetches the sender's public key bundle, verified through key transparency (Section 9), and MUST check that the sender account ID and key-set version in the header match it.
4. MUST verify the sender's hybrid signature over `body` **before** decrypting anything.
5. Decapsulates `enc` with its X-Wing secret key, derives `wrap_key`, and decrypts `sealed`.
6. MUST check the vault's revision log (Section 8) to confirm that the sender was allowed to add it to the vault, and with which role.

Step 4 stops a malicious server from slipping a key for a vault it controls into a user's account: without the signature, a user could be tricked into saving new passwords into a vault the attacker can read.

## 7.6 Removing members and replacing keys

When a member is removed, or a vault key may have been exposed, a member with the owner role:

1. generates a new vault key with the next version;
2. wraps it for themselves (7.3) and shares it with every remaining member (7.4);
3. records the change in the revision log (Section 8);
4. encrypts all new revisions with the new key, and SHOULD re-encrypt existing items with it.

A removed member may still have copies of the old key and of items they could read while they were a member. No system can take that back. Users SHOULD change any password a removed member could have seen.

## 7.7 Security considerations

- **Quantum safety.** Shares stay confidential as long as either X25519 or ML-KEM-768 is unbroken, so shares recorded today are safe from a future quantum computer.
- **No forward secrecy for shares.** Anyone who later steals a recipient's X-Wing secret key can open shares sent to it. Replacing the key set (Section 5.6) limits this to shares sent before the replacement.
- **Header binding.** Every header field is in both the key derivation and the associated data, so even the sender cannot alter a share after signing it without decryption failing.
- **Implicit rejection.** X-Wing decapsulation never fails; a modified `enc` simply yields a different `wrap_key`, which the authenticated decryption then rejects.

## 7.8 Test vectors

[`vectors/07-vaults-and-sharing.json`](vectors/07-vaults-and-sharing.json) contains an owner-wrapped vault key and a vault share made with fixed keys, nonces and encapsulation randomness. The share is checked independently with OpenSSL (ML-KEM-768 decapsulation, X25519, ML-DSA-65 and Ed25519 signatures) and libsodium (XChaCha20-Poly1305) by [`tools/vectors/verify_vaults.py`](../../tools/vectors/verify_vaults.py).
