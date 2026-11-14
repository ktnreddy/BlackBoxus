# 13. Security Considerations

## 13.1 Purpose

This section brings together the security properties of Sections 3–12: what BlackBoxus protects, against whom, what it does not protect, and what risks remain. It is written for reviewers and for anyone deciding whether to trust BlackBoxus with their passwords. Each section's own "Security considerations" has the details; this one gives the whole picture and records the gaps found when the sections were reviewed together.

## 13.2 Assets

| Asset | Where it exists in plaintext |
|---|---|
| Item contents: passwords, notes, titles, URLs, field names | Only on the user's unlocked devices |
| Master password | Only while the user types it on their device |
| Secret Key | The user's devices and Emergency Kit |
| Recovery key | The Emergency Kit, and briefly on a device during recovery |
| Account key set, vault keys, item keys | Only on unlocked devices |
| Vault membership and change history | The server sees it (13.5) |
| Public keys and account IDs | Public by design |

## 13.3 Adversaries and guarantees

| Adversary | Can | Cannot |
|---|---|---|
| **Malicious server** (operator, insider, or anyone controlling Cloudflare's view of the service) | Refuse service; delete data; withhold recent changes from a device that has not seen them (13.6.1); see metadata (13.5); run login and pre-login against any address within rate limits | Read any item; learn any password or key; change, substitute, reorder or roll back data a device has seen without detection (Sections 6, 8); substitute a public key without leaving evidence in the key log (Section 9); weaken key derivation (Section 3.4) |
| **Stolen server database or backups** | Everything a passive malicious server sees | Guess passwords offline: every guess also needs the 128-bit Secret Key (Section 3.5) and the server's OPRF key (Section 4) |
| **Network attacker**, including one who breaks or intercepts TLS | Everything a malicious server can do with the traffic it sees; replay or drop requests | Learn the master password or login credential (OPAQUE); read items; reuse a login transcript |
| **Stolen locked device** | Guess the master password at Argon2id speed, if it also holds the Secret Key | Read items without the master password, the secure element's biometric or PIN check (Section 10.4), or a passkey |
| **Removed vault member** | Keep what they could already read (Section 7.6) | Read revisions encrypted with a newer vault key; make changes other members accept (Section 8.4) |
| **Other BlackBoxus users** | Look up anyone's public keys and account ID | Read vaults not shared with them; make a share appear to come from someone else |
| **Future quantum computer** | Break X25519, Ed25519 and ristretto255 | Read shares (X-Wing) or forge identity signatures (ML-DSA-65); break 256-bit symmetric encryption. See 13.6.6 for login. |
| **Malware on an unlocked device** | Read everything the device can decrypt | — This is out of scope for confidentiality. Auto-lock and revealing one item at a time limit exposure. |

## 13.4 What each section protects

| Section | Protects against | Does not protect against |
|---|---|---|
| 3. Account creation | Offline guessing after a server breach; weak or extreme KDF parameters from the server | A weak master password on a device that also holds the Secret Key |
| 4. Login | The server or network learning the password; offline guessing from login transcripts; account enumeration through login responses | Online guessing (rate limits, 12.5); a stolen session token (12.4) |
| 5. Key sets | Swapping or replaying wrapped key sets; forged public key bundles | A device that is already compromised |
| 6. Items | Reading, swapping, splitting or truncating items; learning item types, titles or field counts | Anyone holding the vault key creating a valid envelope (Section 8 handles this) |
| 7. Sharing | A server reading or forging shares; quantum decryption of recorded shares | A sender encrypting to a key they did not verify (Section 9 handles this); later theft of a recipient's key (no forward secrecy) |
| 8. Revision log | Forged changes; viewers writing; rollback or forks after a device has seen the newer state | Withholding changes a device has never seen (13.6.1) |
| 9. Key transparency | Silent key substitution; split views between devices that compare tree heads | Substitution that the victim never checks for; split views nobody compares (13.6.2) |
| 10. Devices | The server learning the Secret Key during enrolment; device keys leaving the secure element | Someone who photographs the QR code and also knows the master password |
| 11. Recovery | The server using either recovery path | Theft of the recovery key (13.6.4); a trusted contact misusing a released grant (13.6.5) |
| 12. Server API | Account enumeration; session reuse after expiry; replayed logins and enrolment transfers | A server that ignores its own rules: every check here protects availability, never confidentiality |

## 13.5 What the server learns

The server, and anyone who can see its data, learns:

- each account's email address and account ID, when it was created, and when its keys change;
- which accounts share which vaults, and when membership changes;
- how many items each vault holds, which account changed which item and when, and each item's size bucket (Section 6.4);
- the client's IP address and approximate timing of every request, including through Cloudflare as the hosting provider;
- which unlock methods each account has (passkeys, recovery key, trusted contacts) and who each trusted contact is.

It never learns item contents, titles, URLs, item types, field names, passwords, or any key that decrypts them.

## 13.6 Known limitations

### 13.6.1 Freshness

A device detects any history that conflicts with what it has seen, but cannot tell whether it has seen the latest state. A malicious server can stop showing a device new changes ("freezing" it) without detection, as long as it shows nothing that contradicts the device's checkpoint. Devices SHOULD show when they last received a change, and a later version can add signed checkpoints exchanged between devices and vault members.

### 13.6.2 Split views of the key log

Consistency proofs stop a server from rewriting what one device has seen, but a server could keep two consistent logs and show each to different people. Devices of the same account compare tree heads during enrolment (Section 10.3). Comparing across accounts needs gossip between vault members or an independent auditor, which is planned but not yet specified. Until then, safety numbers (Section 9.5) are the only defence against a targeted split view.

### 13.6.3 Metadata

The revision log is signed but not encrypted (Section 8.7), so the membership and change history in 13.5 is visible. Encrypting log metadata is possible, but would stop the server from keeping a single chain, so it is deferred to a later version.

### 13.6.4 Recovery key

Anyone with a user's recovery key and email address can take over the account and read everything: the recovery key unlocks the key set without the master password or Secret Key (Section 11.3). This is the purpose of a recovery key, and the reason it is optional and kept offline. Email notification and ending all sessions make a takeover visible, but only if the server sends them.

### 13.6.5 Trusted contacts

A released emergency grant gives the contact the whole key set, including the identity signing key. The contact can then read every vault the owner can read and make changes signed as the owner (Section 11.5). The waiting period and the owner's right to deny are enforced by the server, so a malicious server could release a grant early; this only gives the contact access the owner already chose to give them.

### 13.6.6 Login is not post-quantum

OPAQUE in protocol version 1 uses ristretto255, which a quantum computer could break. Someone who records login traffic today and breaks it later could recover old session tokens, which expire within 90 days (Section 12.4), and the OPRF output for that login. Vault data does not depend on login: it is protected by keys derived separately (Section 3.5) and by 256-bit symmetric encryption. A post-quantum OPAQUE variant can replace this in a later protocol version once one is standardised.

### 13.6.7 No forward secrecy for shares

Someone who steals a recipient's X-Wing secret key can open every share sent to that key (Section 7.7). Replacing the key set limits this to shares sent before the replacement.

### 13.6.8 Account enumeration

Pre-login, login and recovery answer unknown addresses like real ones, with two exceptions: registration necessarily fails for a taken address, and an account created with non-default Argon2id parameters is distinguishable, because unknown addresses are answered with the defaults (Section 3.4).

### 13.6.9 Email ownership

Version 1 does not verify email addresses (Section 12.9). Someone can register an address first and so stop its owner from using it. This gives no access to any data.

### 13.6.10 Availability

A malicious or failing server can delete everything it stores. Clients SHOULD keep a local copy of the encrypted vault and offer encrypted exports.

## 13.7 Issues found in this review

Reviewing the sections together found these problems, which are fixed in this version of the specification:

1. **Recovery needed the Secret Key unnecessarily.** Section 11.3 said a user without their Secret Key could not use a recovery key. The recovery key alone unlocks the key set, so the client now creates a new Secret Key when needed.
2. **Released trusted contacts could not download anything.** The server only let a vault's creator and share recipients read a vault, so a released contact had keys but no data. Section 12.8 now gives a released contact read access to the owner's vaults.
3. **Trusted contacts get the signing key.** Section 11.5 said what a contact cannot do but not that they can sign as the owner. It now says so, and owners must be told.
4. **Custom Argon2id parameters reveal an account.** Section 3.4 now requires the defaults unless the user chooses otherwise, with a warning.

## 13.8 Implementation assurance

- **Memory safety.** `vault-core` and `server-core` are written in Rust with `unsafe` code forbidden, and with lints that reject `unwrap`, `expect`, `panic` and unchecked indexing.
- **Libraries.** Cryptography comes from widely used, maintained crates: libcrux (formally verified ML-KEM, ML-DSA and SHA-3), RustCrypto, dalek (Ed25519, X25519) and opaque-ke. Dependencies are pinned in `Cargo.lock` and checked by `cargo-deny` for advisories and licences in CI.
- **Test vectors.** Every section with new cryptography publishes vectors that are checked by an independent implementation: Python with OpenSSL and libsodium, and the separate RustCrypto crates.
- **Secret handling.** Keys are erased when dropped and compared in constant time (Section 1.6), and `Debug` output never shows them.
- **Not yet done.** No independent security audit has taken place. BlackBoxus SHOULD NOT be used for real passwords until one has, and its findings are fixed and published.

## 13.9 Reporting vulnerabilities

Security issues SHOULD be reported privately, as described in `SECURITY.md`, rather than in a public issue.
