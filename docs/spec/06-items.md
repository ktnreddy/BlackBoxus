# 6. Vault Items

## 6.1 Overview

A vault holds **items**: logins, secure notes, cards, identities and similar records. Each saved version of an item is stored on the server as one **item envelope**:

- The item's entire content, including its title, URLs and field labels, is encrypted as **one** ciphertext. Nothing about the item is visible to the server except its vault, its identifier, its revision number and a padded size.
- Each revision is encrypted under a fresh random **item key**, which is in turn wrapped under the **vault key** (Section 7).
- The vault ID, item ID and revision number are bound into both encryptions, so a malicious server cannot move ciphertext between items or vaults, or relabel an old revision as a new one.

Encrypting the whole item as one unit, rather than each field separately, rules out "field swap" attacks, in which a server moves an encrypted password into a field the client later leaks, such as the URL used to fetch a website icon. It also hides how many fields an item has.

Who may write an item, and which revision is current, is enforced by the signed revision log (Section 8), not by the envelope.

## 6.2 Identifiers

| Value | Encoding | Chosen by |
| --- | --- | --- |
| Vault ID | 16 bytes | The client that creates the vault, `random(16)` |
| Item ID | 16 bytes | The client that creates the item, `random(16)` |
| Revision | `u64`, starting at 1 | Incremented by one for each saved version |

## 6.3 Item content

### Item types

| Code | Type |
| --- | --- |
| 1 | Login |
| 2 | Secure note |
| 3 | Payment card |
| 4 | Identity |
| 5 | API credential |

### Field kinds

| Code | Kind | Concealed by default |
| --- | --- | --- |
| 1 | Title | No |
| 2 | Username | No |
| 3 | Password | Yes |
| 4 | Website URL | No |
| 5 | Notes | No |
| 6 | TOTP secret | Yes |
| 7 | Cardholder name | No |
| 8 | Card number | Yes |
| 9 | Card expiry | No |
| 10 | Card security code | Yes |
| 11 | Custom text | No |
| 12 | Custom concealed text | Yes |

"Concealed" is a display hint: clients hide these values until the user chooses to reveal or copy them.

### Encoding

```
content = u8(1)                       schema version
        ‖ u8(item_type)
        ‖ u64be(created_ms) ‖ u64be(modified_ms)   Unix time in milliseconds
        ‖ u16be(field_count)
        ‖ field × field_count

field   = u8(kind) ‖ u16be(len(label)) ‖ label ‖ u32be(len(value)) ‖ value
```

- `label` and `value` are UTF-8. A label is optional for every kind (for example "Work email" on a username) and is usually empty.
- Limits: at most 256 fields, labels at most 256 bytes, values at most 16 384 bytes.
- The order of fields is preserved and meaningful (it is the display order).

A parser MUST reject: an unknown schema version, item type or field kind; invalid UTF-8; lengths over the limits; and any bytes left over after the last field.

Rejecting unknown types and kinds, instead of skipping them, prevents a silent loss of data: a client that dropped a field it did not understand would delete it the next time it saved the item. New types and kinds arrive with a new schema version.

### Padding

Before encryption, the content is padded to hide its exact length:

```
padded = content ‖ 0x80 ‖ 0x00 …
```

The total length is the smallest bucket that fits `len(content) + 1`, from: 256, 512, 1024, 2048, 4096, 8192, 16 384 and 32 768 bytes. Content that does not fit in 32 768 bytes MUST be rejected.

When removing padding, a client MUST find the last non-zero byte, require it to be `0x80`, and reject the item otherwise. It MUST also reject a padded length that is not one of the buckets.

## 6.4 Envelope

```
item_key     = random(32)

key_aad      = "BlackBoxus v1 item-key" ‖ u16be(1) ‖ vault_id ‖ item_id ‖ u64be(revision)
wrapped_key  = nonce₁ ‖ XChaCha20-Poly1305(vault_key, nonce₁, item_key, key_aad)      (72 bytes)

content_aad  = "BlackBoxus v1 item" ‖ u16be(1) ‖ vault_id ‖ item_id ‖ u64be(revision)
sealed       = nonce₂ ‖ XChaCha20-Poly1305(item_key, nonce₂, padded, content_aad)

envelope     = u16be(1) ‖ vault_id ‖ item_id ‖ u64be(revision) ‖ wrapped_key ‖ sealed
```

`nonce₁` and `nonce₂` are each `random(24)`. A new `item_key` is generated for every revision.

The envelope is between 410 and 32 922 bytes.

## 6.5 Opening an envelope

A client opening an envelope:

1. MUST check the length is valid for one of the padding buckets, and the protocol version is 1.
2. MUST check that the vault ID equals the vault it is reading, and, when it requested a specific item, that the item ID matches.
3. Unwraps the item key, decrypts the content, removes padding and parses it, rejecting the envelope if any step fails.
4. MUST check the revision against the vault's signed revision log (Section 8) before showing or using the item.

Because the header values are bound into both associated-data strings, editing any of them causes decryption to fail.

## 6.6 Security considerations

- **Metadata.** The server learns how many items a vault has, when they change, and each item's size bucket. It does not learn types, titles, URLs or field counts.
- **Vault-key holders can forge items.** Anyone with the vault key can create a valid envelope. Read-only sharing is therefore enforced by the writer's signature in the revision log (Section 8).
- **Memory.** Decrypted content is held in buffers that are erased when dropped. Clients SHOULD keep decrypted items only while they are displayed or being used for autofill.

## 6.7 Test vectors

[`vectors/06-items.json`](vectors/06-items.json) gives encoded content, padded content and a complete envelope made with fixed keys and nonces. They are checked independently with libsodium by [`tools/vectors/verify_items.py`](../../tools/vectors/verify_items.py).
