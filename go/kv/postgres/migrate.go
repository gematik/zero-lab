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
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/gematik/zero-lab/go/kv/schema"
)

// step is a schema step with its statements. A step's statements run in one transaction: Postgres rolls
// DDL back, so a step that fails leaves nothing behind.
type step struct {
	schema.Step
	sql string
}

// The steps of this backend, in order. A released step never changes: a database that has it applied is
// not looked at again. What changes is a new step.
var steps = []step{
	{schema.Step{Version: 1, Name: "the kv table with expiry and marks"}, schemaSQL},
	{schema.Step{Version: 2, Name: "an index of the keys by their bytes, for prefixes and order"}, keyIndexSQL},
}

// schemaTableSQL creates the record of applied steps. It is the one statement outside the steps: it has to
// be there before the first of them can be recorded.
const schemaTableSQL = `
CREATE TABLE IF NOT EXISTS kv_schema (
  version    integer PRIMARY KEY,
  name       text NOT NULL,
  contract   boolean NOT NULL DEFAULT false,
  applied_at timestamptz NOT NULL DEFAULT now()
)`

// schemaLock is the advisory lock a migrator holds while it applies a step, a number of this package's
// choosing: advisory locks are per database, and a database holds one kv schema. IF NOT EXISTS does not make
// concurrent DDL safe: two sessions that create a table at once collide on the catalog's unique index, and
// two that alter it deadlock. With the lock the second waits for the first one's commit and finds the step
// applied.
const schemaLock = 0x6b765f736368656d // "kv_schem"

// undefinedTable is the SQLSTATE of a statement that names a table that is not there.
const undefinedTable = "42P01"

type migrateOptions struct {
	to       int
	contract bool
}

// MigrateOption adjusts [Migrate].
type MigrateOption func(*migrateOptions)

// To stops after the step of the given version; without it every step is applied.
func To(version int) MigrateOption { return func(o *migrateOptions) { o.to = version } }

// Contract lets [Migrate] apply contract steps as well: steps that remove what a release of before them
// still uses. Run it only when no replica of such a release is left (server rule 22).
func Contract() MigrateOption { return func(o *migrateOptions) { o.contract = true } }

// Migrate applies the schema steps a database lacks and returns the version it is at afterwards. It is what
// a migration job runs before a rollout, over connections opened as a role that may change the schema
// ([OpenDB]); a server's own role then needs no such rights, and [Open] only checks the version. Any number of migrators may run at once: each step is one transaction under an
// advisory lock, applied once. Without [Contract] it stops before the first contract step.
//
// A database that an earlier release created without recording steps is adopted: step 1 changes nothing
// there and is recorded.
func Migrate(ctx context.Context, db *sql.DB, opts ...MigrateOption) (version int, err error) {
	var o migrateOptions
	for _, opt := range opts {
		opt(&o)
	}
	version, err = migrate(ctx, db, steps, o)
	if err != nil {
		return version, fmt.Errorf("kv/postgres: migrate: %w", err)
	}
	return version, nil
}

func plain(steps []step) []schema.Step {
	out := make([]schema.Step, len(steps))
	for i, s := range steps {
		out[i] = s.Step
	}
	return out
}

func migrate(ctx context.Context, db *sql.DB, steps []step, o migrateOptions) (int, error) {
	for {
		version, more, err := migrateOne(ctx, db, steps, o)
		if err != nil || !more {
			return version, err
		}
	}
}

// migrateOne applies the next pending step, if there is one, and reports the version after it.
func migrateOne(ctx context.Context, db *sql.DB, steps []step, o migrateOptions) (version int, more bool, err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(schemaLock)); err != nil {
		return 0, false, err
	}
	if _, err := tx.ExecContext(ctx, schemaTableSQL); err != nil {
		return 0, false, err
	}
	applied, err := readApplied(ctx, tx)
	if err != nil {
		return 0, false, err
	}
	version, err = schema.Version(applied)
	if err != nil {
		return 0, false, err
	}
	pending, _, err := schema.Pending(plain(steps), version, o.to, o.contract)
	if err != nil || len(pending) == 0 {
		return version, false, err
	}
	next := steps[pending[0].Version-1]
	if _, err := tx.ExecContext(ctx, next.sql); err != nil {
		return version, false, fmt.Errorf("step %d (%s): %w", next.Version, next.Name, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO kv_schema(version, name, contract) VALUES($1, $2, $3)`,
		next.Version, next.Name, next.Contract); err != nil {
		return version, false, fmt.Errorf("step %d (%s): %w", next.Version, next.Name, err)
	}
	if err := tx.Commit(); err != nil {
		return version, false, fmt.Errorf("step %d (%s): %w", next.Version, next.Name, err)
	}
	slog.InfoContext(ctx, "kv/postgres: schema step applied", "version", next.Version, "name", next.Name, "contract", next.Contract)
	return next.Version, len(pending) > 1, nil
}

type queryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// readApplied reads the steps the database records. A database without the record has none applied.
func readApplied(ctx context.Context, q queryer) ([]schema.Applied, error) {
	rows, err := q.QueryContext(ctx, `SELECT version, contract FROM kv_schema`)
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == undefinedTable {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var applied []schema.Applied
	for rows.Next() {
		var a schema.Applied
		if err := rows.Scan(&a.Version, &a.Contract); err != nil {
			return nil, err
		}
		applied = append(applied, a)
	}
	return applied, rows.Err()
}

// checkSchema is what Open does instead of DDL: it reads the applied steps and refuses a schema this
// release does not work on.
func checkSchema(ctx context.Context, db *sql.DB, steps []step) error {
	applied, err := readApplied(ctx, db)
	if err != nil {
		return err
	}
	return schema.Check(plain(steps), applied)
}
