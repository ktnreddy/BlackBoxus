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
