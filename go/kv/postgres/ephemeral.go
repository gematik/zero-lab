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

package postgres

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/gematik/zero-lab/go/kv"
)

// cacheSQL is step 4: the table of ephemeral records (kv.Ephemeral), with the columns and indexes of kv.
// It is UNLOGGED: its rows are not written to the write-ahead log, which is what makes writing them cheap,
// and so the table is empty after a crash of the database and is not there on a streaming replica. That
// is the promise of the class, no less and no more.
const cacheSQL = `
CREATE UNLOGGED TABLE IF NOT EXISTS kv_cache (
  key        text PRIMARY KEY,
  value      bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  mark       text,
  marked_at  timestamptz
);
CREATE INDEX IF NOT EXISTS idx_kv_cache_expires_at ON kv_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_kv_cache_key_c ON kv_cache (key COLLATE "C");
`

// asyncCommitSQL lets the transaction it is in return before its commit is flushed to disk. It is set for
// each transaction of an ephemeral store, not for a session: that also holds behind a pooler that hands
// every transaction another session. What it risks is the last moment of writes in a crash, which the
// class allows and the table loses anyway.
const asyncCommitSQL = `SET LOCAL synchronous_commit = off`

// WithEphemeral makes the store of the class kv.Ephemeral: its records are in a table of their own, written
// faster and lost when the database crashes or fails over. It is for what a loss only costs a fetch; a
// consumer of what must not be lost checks kv.DurabilityOf and refuses it. An ephemeral store runs
// transactions over its records and publishes no events (kv.ErrEphemeralEvent): the feed is durable, and a
// transaction is of one class. The role needs on kv_cache what it needs on kv.
func WithEphemeral() Option {
	return func(s *store) { s.ephemeral, s.table = true, "kv_cache" }
}

// Durability implements kv.Classed.
func (s *store) Durability() kv.Durability {
	if s.ephemeral {
		return kv.Ephemeral
	}
	return kv.Durable
}

// q is a statement for the table of this store: statements name the table of the records as @kv.
func (s *store) q(query string) string {
	return strings.ReplaceAll(query, "@kv", s.table)
}

func (s *store) cleanupLock() int64 {
	if s.ephemeral {
		return int64(cleanupLock) + 1
	}
	return int64(cleanupLock)
}

func (s *store) query(ctx context.Context, query string, args ...any) (pgx.Rows, error) {
	return s.pool.Query(ctx, s.q(query), args...)
}

func (s *store) queryRow(ctx context.Context, query string, args ...any) pgx.Row {
	return s.pool.QueryRow(ctx, s.q(query), args...)
}

// exec runs a statement that writes. For an ephemeral store it is sent together with asyncCommitSQL, as one
// transaction in one round trip.
func (s *store) exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if !s.ephemeral {
		return s.pool.Exec(ctx, s.q(query), args...)
	}
	batch := &pgx.Batch{}
	batch.Queue(asyncCommitSQL)
	batch.Queue(s.q(query), args...)
	results := s.pool.SendBatch(ctx, batch)
	if _, err := results.Exec(); err != nil {
		_ = results.Close()
		return pgconn.CommandTag{}, err
	}
	tag, err := results.Exec()
	if closeErr := results.Close(); err == nil {
		err = closeErr
	}
	return tag, err
}

// writeRow runs a statement that writes and returns a row, as exec runs one that returns none.
func (s *store) writeRow(ctx context.Context, query string, args []any, dest ...any) error {
	if !s.ephemeral {
		return s.pool.QueryRow(ctx, s.q(query), args...).Scan(dest...)
	}
	batch := &pgx.Batch{}
	batch.Queue(asyncCommitSQL)
	batch.Queue(s.q(query), args...)
	results := s.pool.SendBatch(ctx, batch)
	if _, err := results.Exec(); err != nil {
		_ = results.Close()
		return err
	}
	err := results.QueryRow().Scan(dest...)
	if closeErr := results.Close(); err == nil {
		err = closeErr
	}
	return err
}
