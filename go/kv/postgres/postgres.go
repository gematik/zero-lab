// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

// Package postgres is the PostgreSQL backend for the kv.Store interface. It is a module of its own, so
// that a module requiring kv has no database driver in its module graph; only a program that wires
// Postgres requires this one. It requires a kv that no longer holds this package: an older kv beside it
// would provide the same import path twice. Open returns a kv.Store (the duck type), so
// callers stay decoupled from this backend.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	// Registers the "pgx" driver with database/sql.
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/gematik/zero-lab/go/kv"
)

// schemaSQL is applied idempotently on Open (no migration tool). value is bytea — an opaque binary store
// (the kv never queries inside values), so JSON, snapshots, and at-rest ciphertext all store as raw bytes
// with no base64/jsonb overhead. The DO block migrates pre-existing jsonb tables in place. The metadata column
// is no longer read or written, but stays: during a rolling deploy an older replica's upsert still names it
// (server rule 22). A later release drops it.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS kv (
  key        text PRIMARY KEY,
  value      bytea NOT NULL,
  metadata   jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_kv_expires_at ON kv(expires_at);
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns
             WHERE table_name='kv' AND column_name='value' AND data_type='jsonb') THEN
    ALTER TABLE kv ALTER COLUMN value TYPE bytea USING convert_to(value::text, 'UTF8');
  END IF;
END $$;
ALTER TABLE kv ADD COLUMN IF NOT EXISTS metadata jsonb;
ALTER TABLE kv ADD COLUMN IF NOT EXISTS mark text;
ALTER TABLE kv ADD COLUMN IF NOT EXISTS marked_at timestamptz;
`

// The mark of a record (kv.Marker) is two columns, both added without rewriting the table: mark, and
// marked_at, which every write of this version sets to the same now() as created_at. A replica of a version
// before the marks names neither in its statements, so a row it wrote has a created_at of its own and no
// longer the marked_at of the mark it left standing: such a mark does not count (server rule 22).
const markedOther = `(mark IS DISTINCT FROM $2 OR marked_at IS DISTINCT FROM created_at)`

type store struct {
	db   *sql.DB
	mark func(key string, value []byte) string
}

// Option adjusts the store [Open] returns.
type Option func(*store)

// WithMark makes the store a kv.Marker: beside each record it keeps what mark says of the record's key and
// value, kv.SealedMarker for a store that is sealed.
func WithMark(mark func(key string, value []byte) string) Option {
	return func(s *store) { s.mark = mark }
}

// markOf is the statement parameter for the mark of a value: NULL without one.
func (s *store) markOf(key string, value []byte) any {
	if s.mark == nil {
		return nil
	}
	if mark := s.mark(key, value); mark != "" {
		return mark
	}
	return nil
}

// Open connects to Postgres at dsn, applies the kv schema, and returns a kv.Store.
func Open(ctx context.Context, dsn string, opts ...Option) (kv.Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("kv/postgres: open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("kv/postgres: ping: %w", err)
	}
	if err := applySchema(ctx, db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("kv/postgres: schema: %w", err)
	}
	s := &store{db: db}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// schemaLock is the advisory lock every Open holds while it applies the schema, a number of this package's
// choosing: advisory locks are per database, and a database holds one kv table.
const schemaLock = 0x6b765f736368656d // "kv_schem"

// applySchema runs schemaSQL in one transaction under schemaLock. Replicas start together, and IF NOT EXISTS
// does not make concurrent DDL safe: two sessions that create the table at once collide on the catalog's
// unique index, and two that alter it deadlock. With the lock the second waits for the first one's commit
// and then finds the schema in place.
func applySchema(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(schemaLock)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, schemaSQL); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkedOther implements kv.Marker.
func (s *store) MarkedOther(ctx context.Context, prefix, mark, after string, limit int) ([]string, error) {
	if s.mark == nil {
		return nil, kv.ErrNotMarker
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT key FROM kv WHERE (expires_at IS NULL OR expires_at > now()) AND key LIKE $1 AND `+markedOther+`
		   AND key > $3 ORDER BY key LIMIT $4`, likePrefix(prefix), mark, after, limit)
	if err != nil {
		return nil, fmt.Errorf("kv/postgres: marked other: %w", err)
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

// Marks implements kv.Marker.
func (s *store) Marks(ctx context.Context, prefix string) (map[string]int, error) {
	if s.mark == nil {
		return nil, kv.ErrNotMarker
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT CASE WHEN marked_at IS DISTINCT FROM created_at THEN '' ELSE coalesce(mark, '') END, count(*)
		   FROM kv WHERE (expires_at IS NULL OR expires_at > now()) AND key LIKE $1 GROUP BY 1`, likePrefix(prefix))
	if err != nil {
		return nil, fmt.Errorf("kv/postgres: marks: %w", err)
	}
	defer rows.Close()
	marks := map[string]int{}
	for rows.Next() {
		var mark string
		var n int
		if err := rows.Scan(&mark, &n); err != nil {
			return nil, err
		}
		marks[mark] = n
	}
	return marks, rows.Err()
}

// CountMarkedOther implements kv.Marker.
func (s *store) CountMarkedOther(ctx context.Context, prefix, mark string) (int, error) {
	if s.mark == nil {
		return 0, kv.ErrNotMarker
	}
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM kv WHERE (expires_at IS NULL OR expires_at > now()) AND key LIKE $1 AND `+markedOther,
		likePrefix(prefix), mark).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("kv/postgres: count marked other: %w", err)
	}
	return n, nil
}

func (s *store) Get(ctx context.Context, key string) ([]byte, bool, error) {
	var v []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT value FROM kv WHERE key=$1 AND (expires_at IS NULL OR expires_at > now())`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("kv/postgres: get: %w", err)
	}
	return v, true, nil
}

// The errors of this store name the operation and never the key: a key names what it holds, as:code:<the code> or
// pep:state:<the state>, and errors reach logs.

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// ttlMicroseconds is the statement parameter for an expiry of now() + TTL: the expiry comes from the database
// clock, the one every read compares against, so skew between the replicas and the database cannot stretch or
// cut short a TTL. NULL makes the sum NULL, which is no expiry.
func ttlMicroseconds(ttl time.Duration) any {
	if ttl <= 0 {
		return nil
	}
	return ttl.Microseconds()
}

func (s *store) upsert(ctx context.Context, e execer, ent kv.Entry) error {
	_, err := e.ExecContext(ctx,
		`INSERT INTO kv(key, value, expires_at, mark, marked_at)
		   VALUES($1, $2, now() + $3::bigint * interval '1 microsecond', $4, now())
		   ON CONFLICT(key) DO UPDATE SET value=excluded.value, created_at=now(), expires_at=excluded.expires_at,
		     mark=excluded.mark, marked_at=now()`,
		ent.Key, ent.Value, ttlMicroseconds(ent.TTL), s.markOf(ent.Key, ent.Value))
	if err != nil {
		return fmt.Errorf("kv/postgres: set: %w", err)
	}
	return nil
}

func (s *store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return s.upsert(ctx, s.db, kv.Entry{Key: key, Value: value, TTL: ttl})
}

// SetIfAbsent is one statement, so two replicas cannot both win: the loser of a race for an expired row waits
// for the winner's commit and then re-evaluates the WHERE on the new row, which is no longer expired.
func (s *store) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO kv(key, value, expires_at, mark, marked_at)
		   VALUES($1, $2, now() + $3::bigint * interval '1 microsecond', $4, now())
		   ON CONFLICT(key) DO UPDATE SET value=excluded.value, created_at=now(), expires_at=excluded.expires_at,
		     mark=excluded.mark, marked_at=now()
		   WHERE kv.expires_at IS NOT NULL AND kv.expires_at <= now()`,
		key, value, ttlMicroseconds(ttl), s.markOf(key, value))
	if err != nil {
		return false, fmt.Errorf("kv/postgres: set if absent: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("kv/postgres: set if absent: %w", err)
	}
	return n == 1, nil
}

// Swap is one statement: the row is locked while its value is compared, so of two replicas that swap the same
// value the second finds the first one's.
func (s *store) Swap(ctx context.Context, key string, old, value []byte, ttl time.Duration) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE kv SET value=$3, created_at=now(), expires_at=now() + $4::bigint * interval '1 microsecond',
		        mark=$5, marked_at=now()
		  WHERE key=$1 AND value=$2 AND (expires_at IS NULL OR expires_at > now())`,
		key, old, value, ttlMicroseconds(ttl), s.markOf(key, value))
	if err != nil {
		return false, fmt.Errorf("kv/postgres: swap: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("kv/postgres: swap: %w", err)
	}
	return n == 1, nil
}

func (s *store) SetMany(ctx context.Context, entries ...kv.Entry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("kv/postgres: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, e := range entries {
		if err := s.upsert(ctx, tx, e); err != nil {
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
		return nil, false, fmt.Errorf("kv/postgres: take: %w", err)
	}
	return v, true, nil
}

func (s *store) Delete(ctx context.Context, key string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM kv WHERE key=$1`, key); err != nil {
		return fmt.Errorf("kv/postgres: delete: %w", err)
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
