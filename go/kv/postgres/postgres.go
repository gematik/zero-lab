// Package postgres is the PostgreSQL backend for the kv.Store interface. It is a separate package from
// kv so that importing kv never pulls in a database driver (Go prunes pgx from modules that import only
// kv); only code that wires Postgres imports this package. Open returns a kv.Store (the duck type), so
// callers stay decoupled from this backend.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// schemaSQL is applied idempotently on Open (no migration tool). value is jsonb — the JSON store.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS kv (
  key        text PRIMARY KEY,
  value      jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_kv_expires_at ON kv(expires_at);
`

type store struct {
	db *sql.DB
}

// Open connects to Postgres at dsn, applies the kv schema, and returns a kv.Store.
func Open(ctx context.Context, dsn string) (kv.Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("kv/postgres: open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("kv/postgres: ping: %w", err)
	}
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("kv/postgres: schema: %w", err)
	}
	return &store{db: db}, nil
}

func (s *store) Get(ctx context.Context, key string) ([]byte, bool, error) {
	var v []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT value FROM kv WHERE key=$1 AND (expires_at IS NULL OR expires_at > now())`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("kv/postgres: get %q: %w", key, err)
	}
	return v, true, nil
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func upsert(ctx context.Context, e execer, ent kv.Entry) error {
	var expiresAt any
	if ent.TTL > 0 {
		expiresAt = time.Now().Add(ent.TTL)
	}
	_, err := e.ExecContext(ctx,
		`INSERT INTO kv(key, value, expires_at) VALUES($1, $2::jsonb, $3)
		   ON CONFLICT(key) DO UPDATE SET value=excluded.value, created_at=now(), expires_at=excluded.expires_at`,
		ent.Key, string(ent.Value), expiresAt)
	if err != nil {
		return fmt.Errorf("kv/postgres: set %q: %w", ent.Key, err)
	}
	return nil
}

func (s *store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return upsert(ctx, s.db, kv.Entry{Key: key, Value: value, TTL: ttl})
}

func (s *store) SetMany(ctx context.Context, entries ...kv.Entry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("kv/postgres: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, e := range entries {
		if err := upsert(ctx, tx, e); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *store) Take(ctx context.Context, key string) ([]byte, bool, error) {
	var v []byte
	err := s.db.QueryRowContext(ctx,
		`DELETE FROM kv WHERE key=$1 AND (expires_at IS NULL OR expires_at > now()) RETURNING value`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		// Absent or expired — drop a possibly-expired row so it doesn't linger.
		_, _ = s.db.ExecContext(ctx, `DELETE FROM kv WHERE key=$1`, key)
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("kv/postgres: take %q: %w", key, err)
	}
	return v, true, nil
}

func (s *store) Delete(ctx context.Context, key string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM kv WHERE key=$1`, key); err != nil {
		return fmt.Errorf("kv/postgres: delete %q: %w", key, err)
	}
	return nil
}

func (s *store) Keys(ctx context.Context, prefix string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT key FROM kv WHERE (expires_at IS NULL OR expires_at > now()) AND key LIKE $1 ORDER BY key`,
		likePrefix(prefix))
	if err != nil {
		return nil, fmt.Errorf("kv/postgres: keys: %w", err)
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

func (s *store) Cleanup(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM kv WHERE expires_at IS NOT NULL AND expires_at <= now()`)
	if err != nil {
		return 0, fmt.Errorf("kv/postgres: cleanup: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func (s *store) Close() error { return s.db.Close() }

// likePrefix escapes LIKE wildcards in a literal prefix (Postgres LIKE uses backslash as the default
// escape character) and appends '%' so the query matches "<prefix>...".
func likePrefix(prefix string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(prefix) + "%"
}
