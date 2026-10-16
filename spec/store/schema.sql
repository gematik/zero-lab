-- Schema of state.db and cache.db, spec/store README.md section H (STORE-070 to STORE-078).
-- Run as is, once, on a new, empty database. auto_vacuum only takes effect before the
-- first page is written, which includes the switch to WAL, and the journal mode cannot
-- change inside a transaction; hence the order.

PRAGMA auto_vacuum = INCREMENTAL;
PRAGMA journal_mode = WAL;

BEGIN IMMEDIATE;

PRAGMA application_id = 1514951508;

CREATE TABLE records (
  ns         TEXT    NOT NULL,
  name       BLOB    NOT NULL CHECK (length(name) = 32),
  value      BLOB    NOT NULL,
  expires_at INTEGER CHECK (expires_at IS NULL OR expires_at > 0),
  PRIMARY KEY (ns, name)
) WITHOUT ROWID;

-- cleanup removes expired records across namespaces
CREATE INDEX records_expires_at ON records (expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE tags (
  ns    TEXT NOT NULL,
  field TEXT NOT NULL,
  tag   BLOB NOT NULL CHECK (length(tag) = 32),
  name  BLOB NOT NULL,
  PRIMARY KEY (ns, field, tag, name),
  FOREIGN KEY (ns, name) REFERENCES records (ns, name) ON DELETE CASCADE
) WITHOUT ROWID;

-- the cascade from records looks tags up by record
CREATE INDEX tags_record ON tags (ns, name);

-- format level and the lowest level a reader must support (STORE-100, STORE-101)
CREATE TABLE meta (
  key   TEXT    PRIMARY KEY,
  value INTEGER NOT NULL
) WITHOUT ROWID;

INSERT INTO meta (key, value) VALUES ('level', 1), ('min_compatible', 1);

PRAGMA user_version = 1;

COMMIT;
