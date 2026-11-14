# 11. Account Recovery

## 11.1 Overview

Because BlackBoxus is zero-knowledge, the service cannot reset a forgotten master password: nobody but the user can decrypt the key set. Recovery therefore only works through secrets the user set up in advance:

- a **recovery key**, printed in the Emergency Kit and kept offline (11.2, 11.3);
- a **trusted contact**, another BlackBoxus user who can be granted access after a waiting period (11.4, 11.5).

Both are optional, and both work like any other unlock method: each holds its own wrapped copy of the key set (Section 5.4). Neither gives the server any new power.

If the user loses the master password and has neither, the account cannot be recovered. Clients MUST say so clearly at sign-up.

## 11.2 Recovery key

A recovery key is 32 random bytes. It is shown as `BR1-` followed by nine groups of six characters, using the Secret Key alphabet of Section 3.2:

```
bits     = 0000 ‖ key                                        (260 bits)
digits   = the 52 five-bit groups of bits, most significant first
c        = SHA-256("BlackBoxus v1 recovery-key checksum" ‖ key)
check    = the first 10 bits of c, as two five-bit digits
display  = "BR1-" ‖ digits ‖ check, split into nine groups of six with "-"
```

Parsing follows Section 3.2: spaces, tabs, hyphens and case are ignored, and `O`, `I`, `L` are read as `0`, `1`, `1`. Clients MUST reject a key whose padding bits are not zero or whose checksum does not match.

From the recovery key, the client derives:

```
wrapping_key = HKDF-SHA-256(salt = account_id, IKM = key, info = "BlackBoxus v1 recovery-wrap", L = 32)
auth_token   = HKDF-SHA-256(salt = account_id, IKM = key, info = "BlackBoxus v1 recovery-auth", L = 32)
auth_verifier = SHA-256(auth_token)
```

When the user creates a recovery key, the client wraps the key set with `wrapping_key` using method 4, and uploads the wrapped copy and `auth_verifier`. The client shows the recovery key once, offers to print it in the Emergency Kit (Section 3.7), and then erases it.

The user can replace or remove the recovery key at any time; the server MUST then delete the old wrapped copy and verifier.

## 11.3 Recovering with a recovery key

1. The user enters their email address and recovery key. The Secret Key is not needed: if the device does not have it, the client generates a new one in step 3 and shows a new Emergency Kit. The account ID returned in step 2 comes from the server, but a wrong one only makes unwrapping fail.
2. The client sends `auth_token` to the server. The server compares `SHA-256(auth_token)` with the stored verifier in constant time, rate-limits attempts per account, and on success returns the method-4 wrapped key set.
3. The client unwraps the key set, then the user chooses a new master password. The client derives new keys from it and the Secret Key (Section 3.5), registers with OPAQUE (Section 4.4), wraps the key set again with method 1, and uploads it with `recovery/finish` (Section 12.6). The server MUST end all other sessions and notify the user by email. Other devices that held an old Secret Key must be added again (Section 10).
4. The client SHOULD then create a new recovery key, because the old one has been typed on this device.

`auth_token` only proves the user holds the recovery key so the server will hand over the wrapped copy; it cannot decrypt anything. The wrapped copy alone is useless to the server: it needs the 256-bit recovery key.

## 11.4 Emergency grant (trusted contact)

The owner can let a trusted contact unlock their account after a waiting period. The owner's client:

1. looks up the contact's public key bundle and verifies it with key transparency (Section 9.4), or with a safety number (Section 9.5);
2. generates `emergency_key = random(32)` and wraps the key set with it using method 5;
3. seals `emergency_key` to the contact, signs the result, and uploads both:

```
header = u16be(1) ‖ owner_account_id ‖ u32be(owner_key_set_version)
       ‖ contact_account_id ‖ u32be(contact_key_set_version) ‖ u16be(wait_days)
                                                                       (44 bytes)
(enc, ss) = X-Wing.Encapsulate(contact_xwing_public_key)                (Section 2)
key    = HKDF-SHA-256(salt = SHA-256(contact_xwing_public_key), IKM = ss,
                      info = "BlackBoxus v1 emergency-grant" ‖ header ‖ enc, L = 32)
sealed = nonce ‖ XChaCha20-Poly1305(key, nonce, emergency_key, aad = header)
body   = header ‖ enc ‖ sealed
grant  = body ‖ HybridSign(owner_identity, "BlackBoxus v1 emergency-grant", body)
                                                                     (4609 bytes)
```

`wait_days` is between 0 and 90. Clients SHOULD default to 7.

The contact's client opens a released grant by checking that it is the named contact, looking up the owner's bundle with key transparency, verifying the owner's signature, and only then decrypting.

## 11.5 Waiting period

The server holds each grant in one of three states:

| State | Meaning |
|---|---|
| Idle | Stored; nobody has asked for access. |
| Requested | The contact asked for access at time `t`. |
| Released | The grant was handed to the contact. |

- Only the grant's owner may upload it, and only its contact may request or receive it.
- On a request, the server MUST notify the owner immediately and again before release.
- While a request is pending, the owner can **deny** it, returning the grant to idle.
- The server releases the grant only when `now ≥ t + wait_days × 86400000` ms.
- The owner can delete a grant at any time. A contact that already received the grant keeps access until the owner replaces their key set (Section 5.6), which every client SHOULD offer after a release.

After a release, the server lets the contact download every vault the owner may read (Section 12.8). The contact can unlock the owner's key set, which includes the owner's identity signing key, so the contact can read the owner's vaults **and** make changes signed as the owner. Owners MUST be told this when they add a trusted contact. The contact cannot sign in as the owner, because login needs the owner's master password and Secret Key, and cannot change them; a later version may let the contact take over the account.

## 11.6 Security considerations

- **Malicious server.** The server never holds a recovery key or emergency key, so it cannot use either path. It could release a grant early, which would only give the contact the access the owner already granted; the owner's choice of contact is what matters. Because the owner verifies the contact's keys through key transparency, the server cannot substitute its own key for the contact's.
- **Recovery key theft.** Someone holding the recovery key and the user's email address can take over the account. The Emergency Kit SHOULD be stored like a passport. Email notification and session revocation (11.3) make a takeover visible.
- **Brute force.** The recovery key has 256 bits of entropy, so `auth_token` and the wrapped copy cannot be guessed; rate limiting is a second line of defence.
- **Notification suppression.** A malicious server could skip the notification in 11.5. Clients SHOULD show pending emergency requests in the app, read from the server on every sync, in addition to email.

## 11.7 Test vectors

[`vectors/11-recovery.json`](vectors/11-recovery.json) contains a recovery key in both forms with its derived keys, and an emergency grant made from fixed key sets. They are checked independently by [`tools/vectors/verify_recovery.py`](../../tools/vectors/verify_recovery.py), which uses only the Python standard library, OpenSSL and libsodium.
