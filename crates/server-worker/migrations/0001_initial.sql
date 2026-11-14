-- BlackBoxus server storage (spec section 12). Binary values are stored as
-- base64url text, times as Unix milliseconds. Nothing here can decrypt any
-- vault data.

CREATE TABLE accounts (
  account_id      TEXT PRIMARY KEY,
  email           TEXT NOT NULL UNIQUE,
  salt            TEXT NOT NULL,
  kdf_m           INTEGER NOT NULL,
  kdf_t           INTEGER NOT NULL,
  kdf_p           INTEGER NOT NULL,
  opaque_record   TEXT NOT NULL,
  signed_bundle   TEXT NOT NULL,
  key_set_version INTEGER NOT NULL,
  wrapped_key_set TEXT NOT NULL,
  created_ms      INTEGER NOT NULL
) STRICT;

-- Key transparency (spec section 9). Each leaf index is a primary key, so
-- two concurrent appends cannot both succeed.
CREATE TABLE kt_leaves (
  leaf_index INTEGER PRIMARY KEY,
  account_id TEXT NOT NULL,
  leaf       TEXT NOT NULL
) STRICT;
CREATE INDEX kt_leaves_by_account ON kt_leaves (account_id, leaf_index);

-- The whole Merkle tree's stored subtree hashes, and the latest signed tree
-- head with the size it was signed for.
CREATE TABLE kt_state (
  id       INTEGER PRIMARY KEY CHECK (id = 1),
  size     INTEGER NOT NULL,
  tree     TEXT NOT NULL,
  sth      TEXT,
  sth_size INTEGER
) STRICT;
INSERT INTO kt_state (id, size, tree) VALUES (1, 0, '');

-- Logins between KE1 and KE3 (at most 60 seconds).
CREATE TABLE logins (
  login_id   TEXT PRIMARY KEY,
  email      TEXT NOT NULL,
  account_id TEXT,
  state      TEXT NOT NULL,
  expires_ms INTEGER NOT NULL
) STRICT;

-- Sessions, keyed by SHA-256 of the session token.
CREATE TABLE sessions (
  token_hash   TEXT PRIMARY KEY,
  account_id   TEXT NOT NULL,
  created_ms   INTEGER NOT NULL,
  last_used_ms INTEGER NOT NULL
) STRICT;
CREATE INDEX sessions_by_account ON sessions (account_id);

-- Device enrolment transfers (at most 300 seconds, downloaded once).
CREATE TABLE enrolments (
  session_id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  sealed     TEXT NOT NULL,
  expires_ms INTEGER NOT NULL
) STRICT;

-- Fixed-window rate limit counters. Keys hold only a hash of the email
-- address, IP address or session they limit.
CREATE TABLE limits (
  key             TEXT PRIMARY KEY,
  window_start_ms INTEGER NOT NULL,
  count           INTEGER NOT NULL
) STRICT;
