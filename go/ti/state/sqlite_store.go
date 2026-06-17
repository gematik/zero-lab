package state

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// schemaSQL is applied idempotently on every OpenSQLite.
const schemaSQL = `
-- created_at and expires_at are unix milliseconds (not seconds) so we don't
-- lose resolution on short TTLs and the values still fit in INTEGER for the
-- next ~100 years.
CREATE TABLE IF NOT EXISTS kv (
  key        TEXT PRIMARY KEY,
  value      BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_kv_expires_at ON kv(expires_at);
`

// pragmas tune SQLite for our workload: WAL gives concurrent readers + one
// writer cleanly; NORMAL fsync is the right durability trade for a cache; the
// 2s busy timeout absorbs cross-process write contention without falling over.
const pragmaSQL = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 2000;
`

// SQLiteStore implements Store on top of a single SQLite file. All operations
// are safe for concurrent use; cross-process writers are serialized by the
// busy_timeout pragma.
type SQLiteStore struct {
	path string
	db   *sql.DB
}

// OpenSQLite opens (or creates) the SQLite store at path. The containing
// directory is created with 0700 if missing. The file itself ends up with the
// process's default permissions; for a cache file that's acceptable on macOS
// and Linux (the parent dir is 0700).
func OpenSQLite(path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("state: path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("state: creating %s: %w", filepath.Dir(path), err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("state: open sqlite %s: %w", path, err)
	}
	// Pragmas must be applied per-connection. The simplest way is to cap
	// the pool to one connection — fine because our access pattern is
	// short-lived from a single CLI process.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(pragmaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("state: applying pragmas: %w", err)
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("state: applying schema: %w", err)
	}
	return &SQLiteStore{path: path, db: db}, nil
}

// Path returns the on-disk path of the SQLite file (for diagnostics / tests).
func (s *SQLiteStore) Path() string { return s.path }

func (s *SQLiteStore) Get(key string) ([]byte, bool, error) {
	if s.db == nil {
		return nil, false, errors.New("state: store closed")
	}
	var value []byte
	var expiresAt sql.NullInt64
	err := s.db.QueryRow(`SELECT value, expires_at FROM kv WHERE key = ?`, key).Scan(&value, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("state: get %q: %w", key, err)
	}
	if expiresAt.Valid && time.UnixMilli(expiresAt.Int64).Before(time.Now()) {
		// Lazy expiry — drop it now so future Keys()/Entries() stay clean.
		if _, derr := s.db.Exec(`DELETE FROM kv WHERE key = ? AND expires_at <= ?`, key, time.Now().UnixMilli()); derr != nil {
			return nil, false, fmt.Errorf("state: dropping expired %q: %w", key, derr)
		}
		return nil, false, nil
	}
	return value, true, nil
}

func (s *SQLiteStore) Set(key string, value []byte, opts ...SetOption) error {
	if s.db == nil {
		return errors.New("state: store closed")
	}
	o := resolveSetOptions(opts)
	now := time.Now()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("state: begin tx: %w", err)
	}
	defer tx.Rollback()

	// NX/XX/KeepTTL all need to know what's currently stored.
	var prevExpires sql.NullInt64
	var hasPrev bool
	row := tx.QueryRow(`SELECT expires_at FROM kv WHERE key = ?`, key)
	switch err := row.Scan(&prevExpires); {
	case errors.Is(err, sql.ErrNoRows):
		hasPrev = false
	case err != nil:
		return fmt.Errorf("state: pre-Set lookup %q: %w", key, err)
	default:
		hasPrev = true
		// Treat expired previous as absent for NX/XX semantics.
		if prevExpires.Valid && time.UnixMilli(prevExpires.Int64).Before(now) {
			hasPrev = false
		}
	}
	if o.nx && hasPrev {
		return tx.Commit() // NX-on-existing or XX-on-missing is a no-op success
	}
	if o.xx && !hasPrev {
		return tx.Commit()
	}

	var expiresAt sql.NullInt64
	createdAt := now.UnixMilli()
	switch {
	case o.expiresAt != nil:
		expiresAt = sql.NullInt64{Int64: o.expiresAt.UnixMilli(), Valid: true}
	case o.keepTTL && hasPrev && prevExpires.Valid:
		expiresAt = prevExpires
	}

	if _, err := tx.Exec(
		`INSERT INTO kv(key, value, created_at, expires_at) VALUES (?, ?, ?, ?)
		   ON CONFLICT(key) DO UPDATE SET value=excluded.value,
		                                  created_at=excluded.created_at,
		                                  expires_at=excluded.expires_at`,
		key, value, createdAt, expiresAt,
	); err != nil {
		return fmt.Errorf("state: set %q: %w", key, err)
	}
	return tx.Commit()
}

func (s *SQLiteStore) Delete(key string) error {
	if s.db == nil {
		return errors.New("state: store closed")
	}
	if _, err := s.db.Exec(`DELETE FROM kv WHERE key = ?`, key); err != nil {
		return fmt.Errorf("state: delete %q: %w", key, err)
	}
	return nil
}

func (s *SQLiteStore) Keys(prefix string) ([]string, error) {
	if s.db == nil {
		return nil, errors.New("state: store closed")
	}
	now := time.Now().UnixMilli()
	rows, err := s.db.Query(
		`SELECT key FROM kv
		  WHERE (expires_at IS NULL OR expires_at > ?)
		    AND key LIKE ? || '%'
		  ORDER BY key`,
		now, prefix,
	)
	if err != nil {
		return nil, fmt.Errorf("state: list keys: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) Cleanup() (int, error) {
	if s.db == nil {
		return 0, errors.New("state: store closed")
	}
	res, err := s.db.Exec(
		`DELETE FROM kv WHERE expires_at IS NOT NULL AND expires_at <= ?`,
		time.Now().UnixMilli(),
	)
	if err != nil {
		return 0, fmt.Errorf("state: cleanup: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

func (s *SQLiteStore) Close() error {
	if s.db == nil {
		return nil
	}
	db := s.db
	s.db = nil
	return db.Close()
}

// Entries exposes a snapshot of every non-expired entry. Used by the
// `ti epa cache list` / `get` commands; not part of the public Store interface
// because most callers should reach for Get/Keys instead.
func (s *SQLiteStore) Entries() (map[string]Entry, error) {
	if s.db == nil {
		return nil, errors.New("state: store closed")
	}
	now := time.Now().UnixMilli()
	rows, err := s.db.Query(
		`SELECT key, value, created_at, expires_at FROM kv
		  WHERE expires_at IS NULL OR expires_at > ?`,
		now,
	)
	if err != nil {
		return nil, fmt.Errorf("state: list entries: %w", err)
	}
	defer rows.Close()
	out := make(map[string]Entry)
	for rows.Next() {
		var k string
		var v []byte
		var createdAt int64
		var expiresAt sql.NullInt64
		if err := rows.Scan(&k, &v, &createdAt, &expiresAt); err != nil {
			return nil, err
		}
		e := Entry{
			Value:     append([]byte(nil), v...),
			CreatedAt: time.UnixMilli(createdAt).UTC(),
		}
		if expiresAt.Valid {
			t := time.UnixMilli(expiresAt.Int64).UTC()
			e.ExpiresAt = &t
		}
		out[k] = e
	}
	return out, rows.Err()
}

// Entry is the public view of a stored entry, returned by Entries.
type Entry struct {
	Value     []byte
	CreatedAt time.Time
	ExpiresAt *time.Time
}
