-- Vaults (spec sections 6–8 and 12.7). Entries and envelopes are signed or
-- encrypted by clients; the server cannot read or forge them.

-- Each vault's revision log. (vault_id, seq) is the primary key, so of two
-- concurrent appends only one succeeds.
CREATE TABLE vault_log (
  vault_id TEXT NOT NULL,
  seq      INTEGER NOT NULL,
  entry    TEXT NOT NULL,
  hash     TEXT NOT NULL,
  PRIMARY KEY (vault_id, seq)
) STRICT;

-- The current envelope of each item, and the log entry that set it.
CREATE TABLE vault_items (
  vault_id TEXT NOT NULL,
  item_id  TEXT NOT NULL,
  revision INTEGER NOT NULL,
  envelope TEXT,
  seq      INTEGER NOT NULL,
  PRIMARY KEY (vault_id, item_id)
) STRICT;
CREATE INDEX vault_items_by_seq ON vault_items (vault_id, seq);

-- Who may read each vault (spec section 12.8).
CREATE TABLE vault_access (
  vault_id   TEXT NOT NULL,
  account_id TEXT NOT NULL,
  PRIMARY KEY (vault_id, account_id)
) STRICT;
CREATE INDEX vault_access_by_account ON vault_access (account_id);

-- Vault keys each member wrapped for themself (spec section 7.3).
CREATE TABLE vault_keys (
  vault_id   TEXT NOT NULL,
  account_id TEXT NOT NULL,
  version    INTEGER NOT NULL,
  wrapped    TEXT NOT NULL,
  PRIMARY KEY (vault_id, account_id, version)
) STRICT;

-- Vault shares waiting for their recipients (spec section 7.4).
CREATE TABLE shares (
  recipient  TEXT NOT NULL,
  vault_id   TEXT NOT NULL,
  version    INTEGER NOT NULL,
  sender     TEXT NOT NULL,
  share      TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  PRIMARY KEY (recipient, vault_id, version, sender)
) STRICT;
