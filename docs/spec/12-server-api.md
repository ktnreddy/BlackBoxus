# 12. Server API

## 12.1 Overview

This section defines the HTTP API between clients and the BlackBoxus server, and the checks the server performs on each request.

The server is untrusted (see `docs/architecture.md`). Its checks protect availability and keep honest clients from making mistakes; clients never rely on them for confidentiality or integrity, which come from the cryptography of Sections 3–11.

The request handling lives in `server-core` and does no I/O: each handler receives the records the hosting adapter loaded and returns what to store or send. The adapter, `server-worker` on Cloudflare Workers and D1 (12.11), is responsible only for storage, atomicity, deleting one-time records, and rate limiting.

## 12.2 Transport and encoding

- The API is served only over HTTPS. Responses carry `Strict-Transport-Security: max-age=63072000`, `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. The server sets no cookies and sends no CORS headers: there is no web vault, so no browser origin needs access.
- All paths start with `/v1`. Request and response bodies are JSON objects (`Content-Type: application/json`).
- Binary values are base64url without padding (RFC 4648, Section 5), including IDs in paths. Clients and the server MUST reject padded or non-canonical encodings.
- Integers are JSON numbers and never exceed 2^53 − 1. Times are Unix milliseconds.
- Request bodies are limited to 1 MiB. Unknown JSON fields MUST be rejected.

## 12.3 Errors

Errors are returned as `{"error": "<code>"}`:

| Code | HTTP status | Meaning |
|---|---|---|
| `malformed` | 400 | The request could not be parsed or breaks a limit. |
| `unauthenticated` | 401 | Missing, wrong or expired session, or a failed login. |
| `not_allowed` | 403 | Not allowed for this account or in the current state. |
| `too_early` | 403 | A waiting period (Section 11.5) has not passed. |
| `conflict` | 409 | The write does not extend the current state; re-read and retry. |
| `rate_limited` | 429 | Too many requests; `Retry-After` says when to retry. |
| `not_found` | 404 | No such endpoint, or an ID that does not exist. |
| `not_implemented` | 501 | An endpoint of this section that the running version does not serve yet. |
| `server_error` | 500 | The server is misconfigured or its storage failed. |

Error responses never reveal whether an email address has an account.

## 12.4 Sessions

A session starts with a successful login (Section 4.5). The client sends the session token (Section 4.6) as:

```
Authorization: Bearer <base64url(session_token)>
```

The server stores only `SHA-256(session_token)` and compares it in constant time.

- A session expires after **14 days** without use, and **90 days** after login however it is used.
- The server deletes a session on logout, on a password change or recovery (all sessions), and when the user removes a device.
- A login between `KE1` and `KE3` is kept server-side for at most **60 seconds** and used at most once.

## 12.5 Rate limits

The server MUST apply at least these limits, per window of 15 minutes:

| Requests | Limit |
|---|---|
| `prelogin` and `login/start` | 10 per email address, 100 per client IP address |
| `login/finish` failures | 5 per email address; then the address is locked for 15 minutes |
| `recovery/finish` | 5 per email address per hour |
| `enrolment` downloads | 20 per client IP address |
| Everything else | 600 per session |

Limits per email address apply equally to addresses without an account, so they do not reveal which addresses exist.

## 12.6 Endpoints without a session

| Method and path | Request → response | Server checks |
|---|---|---|
| `POST /v1/prelogin` | `{email}` → `{salt, kdf: {m, t, p}}` | Canonical email (4.3). Unknown addresses get a stable fake salt and the default parameters (3.8). |
| `POST /v1/register/start` | `{email, request}` → `{response}` | OPAQUE registration request parses exactly (4.4). |
| `POST /v1/register/finish` | `{email, salt, kdf, upload, signed_bundle, wrapped_key_set}` → `{account_id}` | KDF parameters within limits (3.4); upload parses exactly; bundle self-signature verifies (5.5) and is for key set version 1; wrapped key set is 175 bytes for version 1 and method 1 (5.4). Email address and account ID must be unused. Appends a key transparency leaf (9.2) atomically with the account. |
| `POST /v1/login/start` | `{email, ke1}` → `{login_id, ke2}` | `KE1` parses exactly. Unknown addresses get a fake `KE2` (4.5). |
| `POST /v1/login/finish` | `{login_id, ke3}` → `{}` | Login exists, is unexpired and is deleted before checking. `KE3` verifies. Creates the session. |
| `GET /v1/enrolment/{session_id}` | → `{sealed}` | Transfer exists and is under 300 seconds old; deleted before answering (10.3). |
| `POST /v1/recovery/finish` | `{email, auth_token, upload, salt, kdf, wrapped_key_set}` → `{}` | `SHA-256(auth_token)` matches the stored verifier (11.3); then as for `register/finish`, but replaces the login and the method-1 key set for the same key set version, and ends all sessions. The client first calls `recovery/start`. |
| `POST /v1/recovery/start` | `{email, auth_token}` → `{account_id, wrapped_key_set}` | Same token check; returns the method-4 wrapped key set. Unknown addresses fail like a wrong token. |

`register/start` is answered for any address, so it does not reveal whether one is taken; only `register/finish` fails with `conflict`.

## 12.7 Endpoints with a session

| Method and path | Request → response | Server checks |
|---|---|---|
| `POST /v1/logout` | → `{}` | Deletes this session. |
| `GET /v1/keyset` | → `{key_set_version, wrapped: [{method, credential_id?, data}]}` | Only this account's wrapped copies. Device-key copies are never stored (10.4). |
| `PUT /v1/keyset/wrapped` | `{method, credential_id?, data}` → `{}` | Method is 2 (passkey, with a credential ID of at most 1023 bytes), 4 or 5; header matches the current key set version and the method. |
| `DELETE /v1/keyset/wrapped` | `{method, credential_id?}` → `{}` | Deletes that copy. Method 1 cannot be deleted. |
| `POST /v1/password` | `{upload, salt, kdf, wrapped_key_set}` → `{}` | Session less than 5 minutes old. As for `register/finish`; ends all other sessions. |
| `GET /v1/accounts/{account_id}/keys?seen={tree_size}` | → `{signed_bundle, leaf, leaf_index, inclusion_proof, signed_tree_head, consistency_proof}` | `seen` is not larger than the log. Proofs are against the latest signed tree head, which the server signs on the first lookup after the log grows (9.4). |
| `GET /v1/accounts/self/leaves` | → `{leaves: [{leaf, leaf_index, inclusion_proof}], signed_tree_head}` | All leaves for this account, for self-monitoring (9.5). |
| `PUT /v1/enrolment/{session_id}` | `{sealed}` → `{}` | 96 to 8192 bytes; no transfer already stored under this ID (10.3). |
| `POST /v1/vaults/{vault_id}/log` | `{entry, items: [{item_id, revision, envelope}]}` → `{seq}` | Entry is at most 4096 bytes, parses, is for this vault and extends the current head (8.6); envelopes are within the size limits (6.4). Entry and envelopes are stored atomically. |
| `GET /v1/vaults/{vault_id}/log?after={seq}` | → `{entries: [...]}` | Account may read this vault (12.8). At most 1000 entries per response. |
| `GET /v1/vaults/{vault_id}/items?ids=...` | → `{items: [{item_id, revision, envelope}]}` | Account may read this vault. |
| `POST /v1/shares` | `{share}` → `{}` | Share is 4627 bytes and its sender is this account (7.4). Records the recipient as allowed to read the vault. |
| `GET /v1/shares` | → `{shares: [...]}` | Shares addressed to this account. |
| `PUT /v1/recovery` | `{verifier, wrapped_key_set}` → `{}` | Wrapped key set uses method 4. Replaces any earlier recovery key (11.2). |
| `PUT /v1/emergency` | `{grant}` → `{}` | Grant is 4609 bytes and its owner is this account (11.4). |
| `POST /v1/emergency/{owner_id}/request` | → `{release_at}` | This account is the grant's contact and it is idle. Notifies the owner (11.5). |
| `POST /v1/emergency/{contact_id}/deny` | → `{}` | This account is the grant's owner and a request is pending. |
| `GET /v1/emergency/{owner_id}` | → `{grant}` | This account is the contact, and the waiting period has passed. |

## 12.8 Vault access

The server cannot check vault roles, because they are defined by the signed revision log (Section 8), which clients verify. It only filters who may **read** a vault, to limit what one account can download: the account that created the vault's first log entry, any account a share for that vault was uploaded to, and a trusted contact whose emergency grant for one of those accounts has been released (11.5). Any account that may read a vault may append to its log; clients reject entries whose authors lack the role (8.4).

## 12.9 Security considerations

- **Account enumeration.** `prelogin`, `login/start` and `recovery/start` answer unknown addresses exactly like real ones, and rate limits are per address whether or not it exists. `register/finish` necessarily reveals a taken address, but requires a full OPAQUE registration to reach.
- **Email ownership.** Version 1 does not verify email addresses, so anyone can register an address first. This blocks the owner from using that address, but gives no access to anything. A later version can add verification once the service has a way to send email.
- **Stolen session token.** A session token lets its holder download encrypted data and append to logs, but not decrypt anything or forge signed entries. Short idle expiry limits the window.
- **Denial of service.** A malicious server can always refuse service; clients SHOULD keep a local copy of the encrypted vault so users can still read it while the server is unavailable.
- **Timing.** The server performs the same OPAQUE work for unknown addresses as for real ones, and compares tokens in constant time.

## 12.10 Tests

`server-core` tests the handlers directly, and `crates/server-core/tests/api_flow.rs` runs a complete account lifecycle against an in-memory adapter: account creation, real and fake prelogin, login with right and wrong credentials, key lookups verified through key transparency, adding a device by QR code, session expiry and logout. `crates/server-worker` tests routing, encodings, errors and rate limit keys natively, and the same lifecycle has been run against the Worker locally with a D1 database.

## 12.11 Deployment

The server runs on Cloudflare Workers (Free plan) with one D1 database, and is served at `https://api.blackboxus.workers.dev`. Every check in this section is made by `server-core`; `crates/server-worker` only connects it to HTTP and storage.

- **Secrets.** The OPAQUE server setup, the fake-salt key (3.8) and the key transparency log key (9.3) are generated once, by the deploy workflow, and sent straight to Cloudflare's secret store. They never appear in the repository or in logs. The workflow refuses to replace them, because new secrets would invalidate every login and every client's trust in the log.
- **Atomicity.** Creating an account and appending its key transparency leaf happen in one D1 transaction. Leaf indexes are primary keys, so two concurrent appends cannot both succeed; the loser receives `conflict`.
- **Rate limits.** The limits of 12.5 are fixed 15-minute windows counted in D1, which makes them exact across Cloudflare locations. Counters store only a hash of the email address, IP address or session they limit.
- **CPU budget.** Each request must use under 10 ms of CPU. Measured in WebAssembly with SIMD enabled, the most expensive operations take about 1.5 ms (signing a tree head) and 1.8 ms (a full OPAQUE login, client and server together).
- **Key log size.** The log's subtree hashes are kept in one D1 row of about 85 bytes per account, which D1's 2 MB row limit caps at roughly 23,000 accounts. Before then, the tree must move to one row per level.
- **Clean-up.** A daily scheduled job deletes expired logins, enrolment transfers, sessions and rate limit windows.

This version serves the endpoints for accounts, login, sessions, key lookups and device enrolment. The vault, sharing, recovery, emergency access, password change and self-monitoring endpoints answer `not_implemented` until the clients that use them exist.

