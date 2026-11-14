# 1. Conventions

## 1.1 Requirements language

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174.

## 1.2 Notation

| Notation | Meaning |
| --- | --- |
| `a ‖ b` | Concatenation of byte strings `a` and `b` |
| `len(a)` | Length of `a` in bytes |
| `u32be(n)` | `n` encoded as 4 bytes, big-endian |
| `lp(a)` | Length-prefixed bytes: `u32be(len(a)) ‖ a` |
| `random(n)` | `n` bytes from the operating system's CSPRNG |
| `"text"` | The ASCII bytes of `text`, with no terminator |

## 1.3 Randomness

All random values MUST come from the operating system's cryptographically secure random number generator (`getrandom(2)`, `BCryptGenRandom`, `SecRandomCopyBytes`, or `crypto.getRandomValues` in browsers). User-space generators MUST NOT be used.

If the generator fails, the operation MUST fail. Implementations MUST NOT fall back to a weaker source.

## 1.4 Domain separation

Every key derivation, hash and signature input carries a label that names the protocol, its version and the purpose. Labels have the form:

```
"BlackBoxus v1 " ‖ purpose
```

Two derivations with different purposes therefore never produce related outputs, even from the same input key. Labels used by this specification are listed in [Appendix A](#appendix-a-labels).

## 1.5 Protocol version

Every stored or transmitted structure begins with, or is bound to, the protocol version (currently `1`). A version fixes the complete set of algorithms and parameters.

Implementations MUST reject any structure whose version they do not support. They MUST NOT guess, negotiate, or fall back to another version.

## 1.6 Secret handling

Implementations MUST:

- erase secret values (passwords, keys, derived material) from memory as soon as they are no longer needed;
- compare secret values in constant time;
- never write secret values to logs, crash reports, analytics, or error messages;
- never panic or abort on malformed input from the network or from storage, and instead return an error.

## Appendix A: Labels

| Label | Defined in |
| --- | --- |
| `"BlackBoxus v1 secret-key checksum"` | [3.2](03-account-creation.md#32-secret-key) |
| `"BlackBoxus v1 account-unlock-key"` | [3.5](03-account-creation.md#35-two-secret-key-derivation) |
| `"BlackBoxus v1 opaque-password"` | [3.5](03-account-creation.md#35-two-secret-key-derivation) |
| `"BlackBoxus v1 fake-salt"` | [3.8](03-account-creation.md#38-signing-in-on-a-new-device) |
| `"BlackBoxus v1 login"` | [4.2](04-login.md#42-configuration) |
| `"BlackBoxus v1 session-token"` | [4.6](04-login.md#46-session-token) |
| `"BlackBoxus v1 key-set"` | [5.4](05-key-sets.md#54-wrapping) |
| `"BlackBoxus v1 public-key-bundle"` | [5.5](05-key-sets.md#55-public-key-bundle) |
| `"BlackBoxus v1 item-key"` | [6.4](06-items.md#64-envelope) |
| `"BlackBoxus v1 item"` | [6.4](06-items.md#64-envelope) |
| `"BlackBoxus v1 vault-key"` | [7.3](07-vaults-and-sharing.md#73-wrapping-for-the-owner) |
| `"BlackBoxus v1 vault-share"` | [7.4](07-vaults-and-sharing.md#74-sharing-a-vault-key) |
| `"BlackBoxus v1 log-entry"` | [8.2](08-revision-log.md#82-entries) |
| `"BlackBoxus v1 log-entry-hash"` | [8.2](08-revision-log.md#82-entries) |
| `"BlackBoxus v1 tree-head"` | [9.3](09-key-transparency.md#93-tree-proofs-and-tree-heads) |
| `"BlackBoxus v1 fingerprint"` | [9.5](09-key-transparency.md#95-monitoring-and-safety-numbers) |
| `"BlackBoxus v1 enrolment"` | [10.3](10-devices.md#103-adding-a-device-with-a-qr-code) |
| `"BlackBoxus v1 passkey-prf-input"` | [10.5](10-devices.md#105-passkey-unlock-webauthn-prf) |
| `"BlackBoxus v1 passkey-unlock"` | [10.5](10-devices.md#105-passkey-unlock-webauthn-prf) |
| `"BlackBoxus v1 recovery-key checksum"` | [11.2](11-recovery.md#112-recovery-key) |
| `"BlackBoxus v1 recovery-wrap"` | [11.2](11-recovery.md#112-recovery-key) |
| `"BlackBoxus v1 recovery-auth"` | [11.2](11-recovery.md#112-recovery-key) |
| `"BlackBoxus v1 emergency-grant"` | [11.4](11-recovery.md#114-emergency-grant-trusted-contact) |
