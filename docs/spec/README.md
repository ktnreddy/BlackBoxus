# BlackBoxus Protocol Specification

**Status: draft.** Sections are written before the code that implements them, and every section ships with test vectors.

| # | Section | Status |
| --- | --- | --- |
| 1 | [Conventions](01-conventions.md): notation, randomness, domain separation, secret handling | Draft |
| 2 | [Primitives](02-primitives.md): algorithms and key sizes for protocol version 1 | Draft |
| 3 | [Account creation](03-account-creation.md): Secret Key, master password, Argon2id, key derivation, Emergency Kit | Draft, implemented |
| 4 | [Login](04-login.md): OPAQUE registration and login, identities, session tokens | Draft, implemented |
| 5 | [Key sets](05-key-sets.md): account keys, wrapping, signed public keys, rotation | Draft, implemented |
| 6 | [Vault items](06-items.md): content encoding, padding, encrypted envelopes | Draft, implemented |
| 7 | [Vaults and sharing](07-vaults-and-sharing.md): vault keys, signed X-Wing shares, key replacement | Draft, implemented |
| 8 | [Revision log](08-revision-log.md): signed hash chain, roles, rollback and fork detection | Draft, implemented |
| 9 | [Key transparency](09-key-transparency.md): append-only key log, proofs, safety numbers | Draft, implemented |
| 10 | Device enrolment: adding devices, QR transfer, biometric and passkey unlock | Planned |
| 11 | Recovery: Emergency Kit and trusted-contact access | Planned |
| 12 | Server API: endpoints and the checks each one performs | Planned |
| 13 | Security considerations: what each section protects against, and what it does not | Planned |

Test vectors live in [`vectors/`](vectors/).
