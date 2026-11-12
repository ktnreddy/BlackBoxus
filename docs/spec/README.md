# BlackBoxus Protocol Specification

**Status: draft.** Sections are written before the code that implements them, and every section ships with test vectors.

| # | Section | Status |
| --- | --- | --- |
| 1 | [Conventions](01-conventions.md): notation, randomness, domain separation, secret handling | Draft |
| 2 | [Primitives](02-primitives.md): algorithms and key sizes for protocol version 1 | Draft |
| 3 | [Account creation](03-account-creation.md): Secret Key, master password, Argon2id, key derivation, Emergency Kit | Draft, implemented |
| 4 | [Login](04-login.md): OPAQUE registration and login, identities, session tokens | Draft, implemented |
| 5 | [Key sets](05-key-sets.md): account keys, wrapping, signed public keys, rotation | Draft, implemented |
| 6 | Item format: envelope layout, per-field encryption, associated data | Planned |
| 7 | Vaults and sharing: vault keys, HPKE wrapping, membership changes | Planned |
| 8 | Revision log: hash chain, signatures, rollback and fork detection | Planned |
| 9 | Key transparency: log structure and verification | Planned |
| 10 | Device enrolment: adding devices, QR transfer, biometric and passkey unlock | Planned |
| 11 | Recovery: Emergency Kit and trusted-contact access | Planned |
| 12 | Server API: endpoints and the checks each one performs | Planned |
| 13 | Security considerations: what each section protects against, and what it does not | Planned |

Test vectors live in [`vectors/`](vectors/).
