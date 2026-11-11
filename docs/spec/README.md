# BlackBoxus Protocol Specification

**Status: draft outline.** Sections are written before the code that implements them, and every section ships with test vectors.

The key words MUST, MUST NOT, SHOULD and MAY are used as described in RFC 2119.

## Planned sections

1. **Conventions** — encodings, byte order, domain-separation labels
2. **Primitives** — exact algorithms and parameters for protocol version 1
3. **Account creation** — Secret Key generation, key derivation, Emergency Kit
4. **Login** — OPAQUE registration and login, session keys
5. **Key sets** — account keys, wrapping, rotation
6. **Item format** — envelope layout, per-field encryption, associated data
7. **Vaults and sharing** — vault keys, HPKE wrapping, membership changes
8. **Revision log** — hash chain, signatures, rollback and fork detection
9. **Key transparency** — log structure and verification
10. **Device enrolment** — adding devices, QR transfer, biometric and passkey unlock
11. **Recovery** — Emergency Kit and trusted-contact access
12. **Server API** — endpoints and the checks each one performs
13. **Security considerations** — what each section protects against, and what it does not

Test vectors live alongside each section in `vectors/`.
