-- What the server keeps of each vault's state to apply the log's permission
-- rules to appends (spec section 8.3): the head it is current at, members,
-- vault key version and whether a key replacement is due. Rebuilt from the
-- log when missing or behind, so vaults stored before this migration work.
CREATE TABLE vault_rules (
  vault_id TEXT PRIMARY KEY,
  rules    TEXT NOT NULL
) STRICT;
