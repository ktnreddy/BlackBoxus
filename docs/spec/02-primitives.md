# 2. Primitives (protocol version 1)

Protocol version 1 uses exactly the algorithms below. There are no options.

| Purpose | Algorithm | Reference |
| --- | --- | --- |
| Password stretching | Argon2id, version 0x13 | RFC 9106 |
| Key derivation | HKDF with SHA-256 | RFC 5869 |
| Hashing | SHA-256 | FIPS 180-4 |
| Authenticated encryption | XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha |
| Password-authenticated login | OPAQUE-3DH, ristretto255, SHA-512 | RFC 9807 |
| Public-key encryption | HPKE with the X-Wing KEM | RFC 9180, draft-connolly-cfrg-xwing-kem |
| Signatures | Ed25519 and ML-DSA-65; both MUST verify | RFC 8032, FIPS 204 |
| Unicode normalisation | NFKC | Unicode Standard Annex #15 |
| Text encoding of keys | Crockford Base32 | Section 3.2 |

## 2.1 Key sizes

- All symmetric keys are 32 bytes (256 bits).
- XChaCha20-Poly1305 nonces are 24 bytes and MUST be generated with `random(24)` for every encryption.
- Salts are 16 bytes.

## 2.2 Why these choices

- **Argon2id** is memory-hard, which makes large-scale guessing with GPUs and custom hardware expensive. It is the default recommended by RFC 9106 and the OWASP Password Storage Cheat Sheet.
- **XChaCha20-Poly1305** has nonces long enough to generate at random without a realistic risk of reuse, and is fast and constant-time in software on every platform.
- **OPAQUE** lets the server verify a login without ever receiving the password, even during registration.
- **X-Wing** combines X25519 and ML-KEM-768, so shared data stays confidential as long as either algorithm remains unbroken, including against future quantum computers.
- **Dual signatures** protect long-lived identity keys against both classical and quantum forgery.
