# 4. Login (OPAQUE)

## 4.1 Overview

BlackBoxus authenticates users with OPAQUE (RFC 9807), an asymmetric password-authenticated key exchange. The client proves it knows the OPAQUE password `OPW` (Section 3.5), and the two sides agree on a fresh session key, without the server ever receiving `OPW` or anything that allows an offline guessing attack, not even during registration.

`OPW` is derived from the master password *and* the Secret Key, so it has at least 128 bits of entropy. Online guessing through the login endpoint is therefore hopeless, and a stolen OPAQUE record cannot be cracked offline.

## 4.2 Configuration

| Item | Value |
| --- | --- |
| OPRF | ristretto255-SHA512 |
| Key exchange | 3DH over ristretto255 with SHA-512 |
| Key stretching function | Identity. `OPW` is already stretched by Argon2id (Section 3.5) |
| Context | `"BlackBoxus v1 login"` |
| Client identity | Canonical email address (4.3) |
| Server identity | Canonical server origin (4.3) |
| Credential identifier | Canonical email address |

Both identities are bound into the key exchange. A login transcript made with one server or account cannot be replayed to another.

## 4.3 Identities

### Client identity

The client identity is the user's email address, canonicalised by:

1. removing leading and trailing white space;
2. normalising to Unicode NFKC;
3. converting to lower case.

The result MUST be at most 254 bytes of UTF-8 and MUST contain exactly one `@` with at least one character on each side.

Changing the email address therefore requires a new OPAQUE registration (Section 4.6).

### Server identity

The server identity is the server's origin as configured in the client, for example `https://api.example.org`: scheme and host in lower case, an optional port, and no path or trailing slash. It MUST use `https`, except that `http://localhost` and `http://127.0.0.1`, with an optional port, are allowed for local development.

The origin comes from the client's own configuration, never from the server.

## 4.4 Registration

Registration happens when an account is created (Section 3.6), and again whenever `OPW` changes.

```
Client                                            Server
------                                            ------
(state, request) = RegistrationStart(OPW)
                     request, email  ──────────►
                                                  response = RegistrationResponse(
                                                      setup, request, credential_id)
                                     ◄──────────  response
upload = RegistrationFinish(state, OPW, response,
                            client_id, server_id)
                     upload          ──────────►
                                                  record = RegistrationFinish(upload)
                                                  store record for credential_id
```

The client MUST discard the OPAQUE export key. Protocol version 1 does not use it.

The server MUST NOT accept a registration upload that would replace an existing record, except during an authenticated password or email change for that same account.

## 4.5 Login

Login has three round trips. The first only fetches the inputs the client needs to compute `OPW`.

```
Client                                            Server
------                                            ------
                     email           ──────────►
                                     ◄──────────  salt, Argon2id parameters  (Section 3.8)
validate parameters; derive OPW (Section 3.5)
(state, KE1) = LoginStart(OPW)
                     email, KE1      ──────────►
                                                  (state, KE2) = LoginStart(setup, record,
                                                      KE1, credential_id, identities, context)
                                     ◄──────────  KE2
(KE3, session_key) = LoginFinish(state, OPW, KE2,
                                 identities, context)
                     KE3             ──────────►
                                                  session_key = LoginFinish(state, KE3,
                                                      identities, context)
```

If `LoginFinish` fails on the client, the client MUST stop and report that the password, Secret Key or server is wrong, without distinguishing between them. If it fails on the server, the server MUST reject the session.

### Unknown accounts

When no record exists for the credential identifier, the server MUST still answer with a well-formed `KE2`, created from a fake record as described in RFC 9807 Section 10.9, so that responses do not reveal which email addresses have accounts. Login then fails at the client in the same way as a wrong password.

### Server login state

The server's state between `KE2` and `KE3` contains ephemeral secrets. It MUST be kept only on the server, MUST expire within 60 seconds, and MUST be deleted after one use.

## 4.6 Session token

Both sides derive a session token from the OPAQUE session key:

```
session_token = HKDF-SHA-256(salt = empty, IKM = session_key,
                             info = "BlackBoxus v1 session-token", L = 32)
```

The token is never sent during login; each side computes it independently. Afterwards the client presents it as a bearer token on API requests.

The server MUST store only `SHA-256(session_token)`, never the token itself, together with the account, device and expiry. Session lifetimes are defined with the server API (Section 12).

## 4.7 Server setup

The OPAQUE server setup (the OPRF seed and the server's long-term key pair) is the server's most sensitive secret:

- It MUST be generated with a CSPRNG and kept in the hosting platform's secret store, never in source control.
- Losing it does not expose any user data, but it invalidates every registration: users must then re-register from a signed-in device.
- If it is stolen, an attacker could impersonate the server to clients. They still learn nothing about `OPW`, the Secret Key or vault contents, which stay protected by Sections 3 and 5.

## 4.8 Security considerations

- **No password at the server.** The server sees only blinded values and an OPAQUE record. Neither allows offline guessing without the server's OPRF key, and even then `OPW` includes the 128-bit Secret Key.
- **Independence from encryption.** Logging in grants access to *ciphertext* only. Decryption needs `AUK`, which is derived separately (Section 3.5) and never involved in OPAQUE.
- **Rate limiting.** Login attempts SHOULD still be rate-limited per account and per network address to limit abuse and resource use.
- **Implementation.** BlackBoxus uses the `opaque-ke` crate, which implements RFC 9807 and is validated against its test vectors. An earlier version of the crate was audited by NCC Group in 2021; the version used here has not been separately audited.

## 4.9 Test vectors

OPAQUE itself is covered by the RFC 9807 test vectors. The BlackBoxus-specific parts (identity canonicalisation and session-token derivation) are covered by [`vectors/04-login.json`](vectors/04-login.json).
