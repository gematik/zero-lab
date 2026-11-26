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
	"strings"

	"github.com/gematik/zero-lab/go/kv"
)

// cacheTableSQL is the table of ephemeral records (kv.Ephemeral), with the columns and the index of kv.
// MariaDB has no table that is both cheaper to write and still transactional: InnoDB always logs, MEMORY
// holds no value of any length, and Aria without transactions is neither crash-safe nor part of a
// transaction with InnoDB. So this is an InnoDB table like kv: the class is kept by what it promises, which
// is less than the table gives, and not by speed.
const cacheTableSQL = "CREATE TABLE IF NOT EXISTS kv_cache (" + `
  ` + "`key`" + `      VARBINARY(1024) NOT NULL PRIMARY KEY,
  value      LONGBLOB NOT NULL,
  created_at DATETIME(6) NOT NULL,
  expires_at DATETIME(6) NULL,
  mark       VARBINARY(255) NULL,
  marked_at  DATETIME(6) NULL,
  KEY idx_kv_cache_expires_at (expires_at)
) ENGINE=InnoDB`

// WithEphemeral makes the store of the class kv.Ephemeral: its records are in a table of their own. It is
// for what a loss only costs a fetch; a consumer of what must not be lost checks kv.DurabilityOf and
// refuses it. On MariaDB the table is written no faster than the durable one; the class is the same as in
// the other backends, so that a host runs alike on each. An ephemeral store runs transactions over its
// records and publishes no events (kv.ErrEphemeralEvent). The user needs on kv_cache what it needs on kv.
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

// Statements name the table of the records as @kv; tabled and tabledTx run them on the table of a store.
func forTable(query, table string) string { return strings.ReplaceAll(query, "@kv", table) }

type tabled struct {
	*sql.DB
	table string
}

func (c tabled) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return c.DB.ExecContext(ctx, forTable(query, c.table), args...)
}

func (c tabled) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return c.DB.QueryContext(ctx, forTable(query, c.table), args...)
}

func (c tabled) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return c.DB.QueryRowContext(ctx, forTable(query, c.table), args...)
}

type tabledTx struct {
	*sql.Tx
	table string
}

func (c tabledTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return c.Tx.ExecContext(ctx, forTable(query, c.table), args...)
}

func (c tabledTx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return c.Tx.QueryRowContext(ctx, forTable(query, c.table), args...)
}
