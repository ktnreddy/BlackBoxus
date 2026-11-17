-- Trusted contacts (spec sections 11.4 and 11.5): at most one grant per
-- owner, with the owner's key set wrapped with the grant's emergency key.
-- The server can open neither. `state` is 0 idle, 1 requested (at
-- `requested_ms`), 2 released.
CREATE TABLE emergency (
  owner_id        TEXT PRIMARY KEY,
  contact_id      TEXT NOT NULL,
  grant_data      TEXT NOT NULL,
  wrapped_key_set TEXT NOT NULL,
  state           INTEGER NOT NULL,
  requested_ms    INTEGER
) STRICT;
CREATE INDEX emergency_by_contact ON emergency (contact_id);

-- Emergency sessions, given to a contact whose grant was released, can
-- only read.
ALTER TABLE sessions ADD COLUMN read_only INTEGER NOT NULL DEFAULT 0;
