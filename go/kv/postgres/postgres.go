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

func upsert(ctx context.Context, e execer, ent kv.Entry) error {
	_, err := e.ExecContext(ctx,
		`INSERT INTO kv(key, value, expires_at) VALUES($1, $2, now() + $3::bigint * interval '1 microsecond')
		   ON CONFLICT(key) DO UPDATE SET value=excluded.value, created_at=now(), expires_at=excluded.expires_at`,
		ent.Key, ent.Value, ttlMicroseconds(ent.TTL))
	if err != nil {
		return fmt.Errorf("kv/postgres: set: %w", err)
	}
	return nil
}

func (s *store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return upsert(ctx, s.db, kv.Entry{Key: key, Value: value, TTL: ttl})
}

// SetIfAbsent is one statement, so two replicas cannot both win: the loser of a race for an expired row waits
// for the winner's commit and then re-evaluates the WHERE on the new row, which is no longer expired.
func (s *store) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO kv(key, value, expires_at) VALUES($1, $2, now() + $3::bigint * interval '1 microsecond')
		   ON CONFLICT(key) DO UPDATE SET value=excluded.value, created_at=now(), expires_at=excluded.expires_at
		   WHERE kv.expires_at IS NOT NULL AND kv.expires_at <= now()`,
		key, value, ttlMicroseconds(ttl))
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
		`UPDATE kv SET value=$3, created_at=now(), expires_at=now() + $4::bigint * interval '1 microsecond'
		  WHERE key=$1 AND value=$2 AND (expires_at IS NULL OR expires_at > now())`,
		key, old, value, ttlMicroseconds(ttl))
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
