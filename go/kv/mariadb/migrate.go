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

package mariadb

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/go-sql-driver/mysql"

	"github.com/gematik/zero-lab/go/kv/schema"
)

// step is a schema step with its statement. MariaDB commits at every DDL statement, so a step cannot be a
// transaction: it is one statement, written so that running it again changes nothing (IF NOT EXISTS, IF
// EXISTS). That is what makes steps safe to apply by several migrators at once and after one that died
// between a statement and its record: neither a lock of one node (GET_LOCK) nor a row lock, which the DDL's
// commit would release, holds across a cluster.
type step struct {
	schema.Step
	sql string
}

// The steps of this backend, in order. A released step never changes; what changes is a new step.
var steps = []step{
	{schema.Step{Version: 1, Name: "the kv table with expiry and marks"}, kvTableSQL},
}

// The key is binary: it compares byte by byte, as keys do in memory and in Postgres, and a prefix scan
// uses the primary key. Times are DATETIME(6) in UTC, which every session of this package sets.
const kvTableSQL = "CREATE TABLE IF NOT EXISTS kv (" + `
  ` + "`key`" + `      VARBINARY(1024) NOT NULL PRIMARY KEY,
  value      LONGBLOB NOT NULL,
  created_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NULL,
  mark       VARBINARY(255) NULL,
  marked_at  DATETIME(6) NULL,
  KEY idx_kv_expires_at (expires_at)
) ENGINE=InnoDB`

const schemaTableSQL = `
CREATE TABLE IF NOT EXISTS kv_schema (
  version    INT NOT NULL PRIMARY KEY,
  name       VARCHAR(255) NOT NULL,
  contract   BOOLEAN NOT NULL DEFAULT FALSE,
  applied_at DATETIME(6) NOT NULL
) ENGINE=InnoDB`

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
// a migration job runs before a rollout, over connections opened with credentials that may change the
// schema ([OpenDB]); a server's own user then needs no such rights, and [Open] only checks the version. Any
// number of migrators may run at once, through any nodes of a cluster: a step run twice changes nothing.
// Without [Contract] it stops before the first contract step.
func Migrate(ctx context.Context, db *sql.DB, opts ...MigrateOption) (version int, err error) {
	var o migrateOptions
	for _, opt := range opts {
		opt(&o)
	}
	version, err = migrate(ctx, db, steps, o)
	if err != nil {
		return version, fmt.Errorf("kv/mariadb: migrate: %w", err)
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
	if err := again(ctx, func() error {
		_, err := db.ExecContext(ctx, schemaTableSQL)
		return err
	}); err != nil {
		return 0, err
	}
	for {
		applied, err := readApplied(ctx, db)
		if err != nil {
			return 0, err
		}
		version, err := schema.Version(applied)
		if err != nil {
			return 0, err
		}
		pending, _, err := schema.Pending(plain(steps), version, o.to, o.contract)
		if err != nil || len(pending) == 0 {
			return version, err
		}
		next := steps[pending[0].Version-1]
		if err := again(ctx, func() error {
			_, err := db.ExecContext(ctx, next.sql)
			return err
		}); err != nil {
			return version, fmt.Errorf("step %d (%s): %w", next.Version, next.Name, err)
		}
		// Another migrator may have recorded the step in the meantime: then this changes nothing.
		var recorded int64
		if err := again(ctx, func() error {
			res, err := db.ExecContext(ctx, `INSERT INTO kv_schema(version, name, contract, applied_at)
				VALUES(?, ?, ?, NOW(6)) ON DUPLICATE KEY UPDATE version=version`, next.Version, next.Name, next.Contract)
			if err != nil {
				return err
			}
			recorded, err = res.RowsAffected()
			return err
		}); err != nil {
			return version, fmt.Errorf("step %d (%s): %w", next.Version, next.Name, err)
		}
		if recorded > 0 {
			slog.InfoContext(ctx, "kv/mariadb: schema step applied", "version", next.Version, "name", next.Name, "contract", next.Contract)
		}
	}
}

// readApplied reads the steps the database records. A database without the record has none applied.
func readApplied(ctx context.Context, db *sql.DB) ([]schema.Applied, error) {
	var applied []schema.Applied
	err := again(ctx, func() error {
		applied = applied[:0]
		rows, err := db.QueryContext(ctx, `SELECT version, contract FROM kv_schema`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a schema.Applied
			if err := rows.Scan(&a.Version, &a.Contract); err != nil {
				return err
			}
			applied = append(applied, a)
		}
		return rows.Err()
	})
	var my *mysql.MySQLError
	if errors.As(err, &my) && my.Number == errNoSuchTable {
		return nil, nil
	}
	return applied, err
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
