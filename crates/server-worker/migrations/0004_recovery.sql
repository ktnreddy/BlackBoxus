-- Recovery keys (spec section 11.2): a hash of each account's recovery
-- token, and its key set wrapped with the recovery key. Neither lets the
-- server decrypt anything.
CREATE TABLE recovery (
  account_id      TEXT PRIMARY KEY,
  verifier        TEXT NOT NULL,
  wrapped_key_set TEXT NOT NULL
) STRICT;
