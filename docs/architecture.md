# BlackBoxus Architecture

This document summarises the design. The normative protocol is in [`spec/`](spec/).

## Threat model

| Adversary | Guarantee |
| --- | --- |
| Fully malicious server or insider | Confidentiality and integrity of all vault data and metadata; rollback, deletion and forked histories are detected |
| Stolen server database or backups | Nothing can be cracked offline without each user's Secret Key |
| Network attacker, including TLS interception | OPAQUE and end-to-end encryption make TLS a second layer, not the only one |
| Malicious website | No autofill to the wrong origin; no autofill UI inside the page |
| Stolen locked device | Vault encrypted at rest; unlock keys held in the platform secure element |
| Future quantum computer | Hybrid post-quantum key exchange for sharing; 256-bit symmetric keys |
| Compromised build pipeline | Pinned dependencies, dependency audits, signed and reproducible releases |
| Malware on an unlocked device | Out of scope for confidentiality; exposure limited by auto-lock and per-item reveal |

## Key hierarchy

1. **Two secrets.** The master password (Unicode NFKC-normalised) and a 128-bit random Secret Key created on the first device. The Secret Key never reaches the server and is saved by the user in an Emergency Kit.
2. **Stretching.** Argon2id over the master password, 128 MiB and 4 passes by default. Clients refuse parameters below 64 MiB and 3 passes, or above safe maximums, regardless of what the server says.
3. **Account Unlock Key.** HKDF-SHA-256 combines the Argon2id output with the Secret Key. A separate, domain-separated output is used for OPAQUE login, so the login credential and the encryption key are independent.
4. **Account key set.** Random keys wrapped by the Account Unlock Key: a 256-bit symmetric key, an X-Wing key pair for receiving shares, and an Ed25519 + ML-DSA-65 identity signing key pair.
5. **Vault keys.** One random key per vault, wrapped to each member's X-Wing public key with HPKE.
6. **Item keys.** One random key per item, wrapped by the vault key. Each field is encrypted separately with XChaCha20-Poly1305 and bound, through associated data, to the protocol version, vault, item, field and revision.
7. **Device unlock.** Biometric or PIN unlock uses a random device key held in the Secure Enclave, StrongBox or TPM.
8. **Passkey unlock.** The WebAuthn PRF output, through HKDF, wraps another copy of the account key set.

## Integrity

- Each vault has a hash-chained revision log signed by its members. Clients remember the latest revision they have seen and reject rollbacks or diverging histories.
- Public keys are published to an append-only key transparency log and can be verified out of band.
- Algorithms are fixed per protocol version; there is no negotiation.
- All metadata is encrypted, and ciphertexts are padded to size buckets.

## Components

| Component | Technology | Trust |
| --- | --- | --- |
| `vault-core` | Rust | Trusted; all cryptography |
| Desktop app | Tauri 2, TypeScript UI | Trusted device |
| Browser extension | TypeScript, `vault-core` compiled to WebAssembly | Trusted device; autofill picker outside page DOM |
| Android app | Kotlin, Jetpack Compose, `vault-core` via UniFFI | Trusted device |
| iOS app | Swift, SwiftUI, `vault-core` via UniFFI | Trusted device |
| API | Rust on Cloudflare Workers | Untrusted |
| Database | Cloudflare D1 (SQLite) | Untrusted; ciphertext and public data only |
| Sync coordination | Cloudflare Durable Objects (one per vault), WebSocket "vault changed" notifications | Untrusted |
| Website | Cloudflare Pages | Information only; there is no web vault |

There is deliberately no browser-served web vault. A web vault downloads its code from the server, so a compromised server could ship code that steals passwords.

## Sync

1. A device edits an item, re-encrypts it, appends a signed entry to the vault log, and uploads both.
2. The vault's Durable Object accepts the write only if it extends the current head, then notifies other devices that the vault changed.
3. Other devices fetch new entries, verify the signature chain from their last known head, and decrypt.
4. Conflicting edits to the same item keep both versions for the user to resolve.
5. A history that is older than, or does not extend, the cached head triggers a tamper alert.
