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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/gematik/zero-lab/go/kv"
)

// schemaSQL is step 1 of the schema (migrate.go), and what releases before the steps applied on every Open:
// every statement of it changes nothing where it has run before, which is how such a database is adopted.
// value is bytea — an opaque binary store
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

// keyIndexSQL is step 2. Keys are text in the database's collation, and an index in that collation serves
// neither a prefix nor the order by bytes that keys have in memory and in every other backend. This index
// is in the collation "C", and every statement that reads by prefix or in order names that collation, so
// that it is a range of the index: before it, each Keys and each walk of the marks read the whole table.
// The index is built in the step's transaction, which keeps writers out of the table while it is built: a
// moment for the tables kv holds; a table of many millions of records wants the index built beforehand
// with CREATE INDEX CONCURRENTLY under this name, which the step then finds.
const keyIndexSQL = `CREATE INDEX IF NOT EXISTS idx_kv_key_c ON kv (key COLLATE "C")`

// The mark of a record (kv.Marker) is two columns, both added without rewriting the table: mark, and
// marked_at, which every write of this version sets to the same now() as created_at. A replica of a version
// before the marks names neither in its statements, so a row it wrote has a created_at of its own and no
// longer the marked_at of the mark it left standing: such a mark does not count (server rule 22).
const markedOther = `(mark IS DISTINCT FROM $3 OR marked_at IS DISTINCT FROM created_at)`

// live is the condition of a record that has not expired, expired that of one whose time is over.
const (
	live    = `(expires_at IS NULL OR expires_at > now())`
	expired = `(expires_at IS NOT NULL AND expires_at <= now())`
)

// underPrefix is the condition of the keys with a literal prefix, $1, whose LIKE pattern is $2. The first
// half bounds the range of the index even where the plan does not know the pattern; the second is the
// prefix itself.
const underPrefix = `key COLLATE "C" >= $1 AND key COLLATE "C" LIKE $2`

// byKey is the order of keys: by their bytes, as in memory.
const byKey = `ORDER BY key COLLATE "C"`

type store struct {
	pool    *pgxpool.Pool
	mark    func(key string, value []byte) string
	migrate bool
}

// Option adjusts the store [Open] returns.
type Option func(*store)

// WithMark makes the store a kv.Marker: beside each record it keeps what mark says of the record's key and
// value, kv.SealedMarker for a store that is sealed.
func WithMark(mark func(key string, value []byte) string) Option {
	return func(s *store) { s.mark = mark }
}

// WithMigrate makes [Open] apply the schema steps the database lacks before it checks the version, as
// [Migrate] does, but never a contract step. It is for a deployment without a migration job (a compose
// file, a first installation by hand): the server's role then needs the right to change the schema, which
// the default exists to take away.
func WithMigrate() Option {
	return func(s *store) { s.migrate = true }
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

// Open connects to Postgres at dsn as user, checks the schema and returns a kv.Store. The DSN is the
// address alone (postgres://host:port/database, with sslmode and the like as its parameters); user and
// password are given beside it, as a deployment has them: an address in its configuration and the two in a
// secret. It runs no DDL: it refuses a database that lacks a step this release needs, or on which a
// contract step it does not know was applied (an error that is a schema.ErrVersion and names the versions).
// The steps are applied by [Migrate], or by Open itself with [WithMigrate]. The role needs SELECT, INSERT,
// UPDATE and DELETE on the table kv and SELECT on kv_schema, and with [WithMigrate] the right to create and
// alter tables in the schema.
func Open(ctx context.Context, dsn, user, password string, opts ...Option) (kv.Store, error) {
	return open(ctx, dsn, user, password, steps, opts...)
}

func open(ctx context.Context, dsn, user, password string, steps []step, opts ...Option) (kv.Store, error) {
	s := &store{}
	for _, opt := range opts {
		opt(s)
	}
	cfg, err := poolConfig(dsn, user, password)
	if err != nil {
		return nil, err
	}
	// The schema is read, and with WithMigrate changed, over a connection of its own, which is closed
	// before the store serves.
	db := stdlib.OpenDB(*cfg.ConnConfig)
	defer func() { _ = db.Close() }()
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("kv/postgres: ping: %w", err)
	}
	if s.migrate {
		if _, err := migrate(ctx, db, steps, migrateOptions{}); err != nil {
			return nil, fmt.Errorf("kv/postgres: schema: %w", err)
		}
	}
	if err := checkSchema(ctx, db, steps); err != nil {
		return nil, fmt.Errorf("kv/postgres: schema: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("kv/postgres: open: %w", err)
	}
	s.pool = pool
	return s, nil
}

// The errors of this store name the operation and never the key: a key names what it holds, as:code:<the code> or
// pep:state:<the state>, and errors reach logs.

// ttlMicroseconds is the statement parameter for an expiry of now() + TTL: the expiry comes from the database
// clock, the one every read compares against, so skew between the replicas and the database cannot stretch or
// cut short a TTL. NULL makes the sum NULL, which is no expiry.
func ttlMicroseconds(ttl time.Duration) any {
	if ttl <= 0 {
		return nil
	}
	return ttl.Microseconds()
}

const upsertSQL = `INSERT INTO kv(key, value, expires_at, mark, marked_at)
	VALUES($1, $2, now() + $3::bigint * interval '1 microsecond', $4, now())
	ON CONFLICT(key) DO UPDATE SET value=excluded.value, created_at=now(), expires_at=excluded.expires_at,
	  mark=excluded.mark, marked_at=now()`

func (s *store) Get(ctx context.Context, key string) ([]byte, bool, error) {
	var v []byte
	err := s.pool.QueryRow(ctx, `SELECT value FROM kv WHERE key=$1 AND `+live, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("kv/postgres: get: %w", err)
	}
	return nonNil(v), true, nil
}

// nonNil is a value as a caller gets it and as a parameter: an empty value is a value, not NULL.
func nonNil(value []byte) []byte {
	if value == nil {
		return []byte{}
	}
	return value
}

func (s *store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if _, err := s.pool.Exec(ctx, upsertSQL, key, nonNil(value), ttlMicroseconds(ttl), s.markOf(key, value)); err != nil {
		return fmt.Errorf("kv/postgres: set: %w", err)
	}
	return nil
}

// SetIfAbsent is one statement, so two replicas cannot both win: the loser of a race for an expired row waits
// for the winner's commit and then re-evaluates the WHERE on the new row, which is no longer expired.
func (s *store) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	tag, err := s.pool.Exec(ctx, upsertSQL+` WHERE kv.expires_at IS NOT NULL AND kv.expires_at <= now()`,
		key, nonNil(value), ttlMicroseconds(ttl), s.markOf(key, value))
	if err != nil {
		return false, fmt.Errorf("kv/postgres: set if absent: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Swap is one statement: the row is locked while its value is compared, so of two replicas that swap the same
// value the second finds the first one's.
func (s *store) Swap(ctx context.Context, key string, old, value []byte, ttl time.Duration) (bool, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE kv SET value=$3, created_at=now(), expires_at=now() + $4::bigint * interval '1 microsecond',
		        mark=$5, marked_at=now()
		  WHERE key=$1 AND value=$2 AND `+live,
		key, nonNil(old), nonNil(value), ttlMicroseconds(ttl), s.markOf(key, value))
	if err != nil {
		return false, fmt.Errorf("kv/postgres: swap: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// SetMany sends its statements as one batch in one transaction: one round trip, all or nothing.
func (s *store) SetMany(ctx context.Context, entries ...kv.Entry) error {
	if len(entries) == 0 {
		return nil
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		batch := &pgx.Batch{}
		for _, e := range entries {
			batch.Queue(upsertSQL, e.Key, nonNil(e.Value), ttlMicroseconds(e.TTL), s.markOf(e.Key, e.Value))
		}
		return tx.SendBatch(ctx, batch).Close()
	})
	if err != nil {
		return fmt.Errorf("kv/postgres: set many: %w", err)
	}
	return nil
}

func (s *store) Take(ctx context.Context, key string) ([]byte, bool, error) {
	var v []byte
	err := s.pool.QueryRow(ctx, `DELETE FROM kv WHERE key=$1 AND `+live+` RETURNING value`, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		// Absent or expired: an expired row is dropped so that it does not linger.
		_, _ = s.pool.Exec(ctx, `DELETE FROM kv WHERE key=$1 AND `+expired, key)
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("kv/postgres: take: %w", err)
	}
	return nonNil(v), true, nil
}

func (s *store) Delete(ctx context.Context, key string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM kv WHERE key=$1`, key); err != nil {
		return fmt.Errorf("kv/postgres: delete: %w", err)
	}
	return nil
}

func (s *store) keys(ctx context.Context, op, query string, args ...any) ([]string, error) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("kv/postgres: %s: %w", op, err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("kv/postgres: %s: %w", op, err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// keysSQL lists the keys under a prefix; a statement of its own so that a test can ask for its plan.
const keysSQL = `SELECT key FROM kv WHERE ` + live + ` AND ` + underPrefix + ` ` + byKey

// markedOtherSQL lists the keys under a prefix whose mark is another one, after a key.
const markedOtherSQL = `SELECT key FROM kv WHERE ` + live + ` AND ` + underPrefix + ` AND ` + markedOther + `
	AND key COLLATE "C" > $4 ` + byKey + ` LIMIT $5`

func (s *store) Keys(ctx context.Context, prefix string) ([]string, error) {
	return s.keys(ctx, "keys", keysSQL, prefix, likePrefix(prefix))
}

// cleanupBatch is how many expired records one statement of Cleanup deletes: a backlog of them is removed
// in transactions that each end soon, and never under one lock that every writer of those rows waits for.
var cleanupBatch = 1000

// cleanupLock is the advisory lock a replica holds while it deletes a batch. It is a transaction's lock,
// so it also holds behind a pooler that hands each transaction another session.
const cleanupLock = 0x6b765f636c65616e // "kv_clean"

// Cleanup deletes the records whose time is over, batch by batch. Every replica calls it; only one at a
// time deletes, and one that finds another at it returns with what it has removed so far, which may be
// nothing: the records are gone all the same.
func (s *store) Cleanup(ctx context.Context) (int, error) {
	total := 0
	for {
		var removed int64
		var held bool
		err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, int64(cleanupLock)).Scan(&held); err != nil || !held {
				return err
			}
			tag, err := tx.Exec(ctx, `DELETE FROM kv WHERE ctid IN (
				SELECT ctid FROM kv WHERE `+expired+` LIMIT $1 FOR UPDATE SKIP LOCKED)`, cleanupBatch)
			removed = tag.RowsAffected()
			return err
		})
		if err != nil {
			return total, fmt.Errorf("kv/postgres: cleanup: %w", err)
		}
		total += int(removed)
		if !held || removed < int64(cleanupBatch) {
			return total, nil
		}
	}
}

func (s *store) Close() error {
	s.pool.Close()
	return nil
}

// MarkedOther implements kv.Marker.
func (s *store) MarkedOther(ctx context.Context, prefix, mark, after string, limit int) ([]string, error) {
	if s.mark == nil {
		return nil, kv.ErrNotMarker
	}
	return s.keys(ctx, "marked other", markedOtherSQL, prefix, likePrefix(prefix), mark, after, limit)
}

// Marks implements kv.Marker.
func (s *store) Marks(ctx context.Context, prefix string) (map[string]int, error) {
	if s.mark == nil {
		return nil, kv.ErrNotMarker
	}
	rows, err := s.pool.Query(ctx,
		`SELECT CASE WHEN marked_at IS DISTINCT FROM created_at THEN '' ELSE coalesce(mark, '') END, count(*)
		   FROM kv WHERE `+live+` AND `+underPrefix+` GROUP BY 1`, prefix, likePrefix(prefix))
	if err != nil {
		return nil, fmt.Errorf("kv/postgres: marks: %w", err)
	}
	marks := map[string]int{}
	var mark string
	var n int
	if _, err := pgx.ForEachRow(rows, []any{&mark, &n}, func() error {
		marks[mark] = n
		return nil
	}); err != nil {
		return nil, fmt.Errorf("kv/postgres: marks: %w", err)
	}
	return marks, nil
}

// CountMarkedOther implements kv.Marker.
func (s *store) CountMarkedOther(ctx context.Context, prefix, mark string) (int, error) {
	if s.mark == nil {
		return 0, kv.ErrNotMarker
	}
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM kv WHERE `+live+` AND `+underPrefix+` AND `+markedOther,
		prefix, likePrefix(prefix), mark).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("kv/postgres: count marked other: %w", err)
	}
	return n, nil
}

// likePrefix escapes LIKE wildcards in a literal prefix (Postgres LIKE uses backslash as the default
// escape character) and appends '%' so the query matches "<prefix>...".
func likePrefix(prefix string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(prefix) + "%"
}
