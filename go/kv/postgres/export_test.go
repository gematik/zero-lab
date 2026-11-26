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
	"strings"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/schema"
)

// Step is a schema step for tests that need steps of their own: a contract step, a release ahead.
type Step = step

// SchemaSQL is what releases before the steps applied on every Open.
const SchemaSQL = schemaSQL

func NewStep(version int, name string, contract bool, sql string) Step {
	return step{schema.Step{Version: version, Name: name, Contract: contract}, sql}
}

// ReleasedSteps are the steps of this release.
func ReleasedSteps() []Step { return steps }

func MigrateSteps(ctx context.Context, db *sql.DB, steps []Step, opts ...MigrateOption) (int, error) {
	var o migrateOptions
	for _, opt := range opts {
		opt(&o)
	}
	return migrate(ctx, db, steps, o)
}

func OpenSteps(ctx context.Context, dsn, user, password string, steps []Step, opts ...Option) (kv.Store, error) {
	return open(ctx, dsn, user, password, steps, opts...)
}

// The statements that read by prefix, for tests that ask the database for their plan.
var (
	KeysSQL        = strings.ReplaceAll(keysSQL, "@kv", "kv")
	MarkedOtherSQL = strings.ReplaceAll(markedOtherSQL, "@kv", "kv")
)

// CommitOfWrites is the synchronous_commit setting a write of the store runs under: the write path is asked
// to return it instead of writing.
func CommitOfWrites(ctx context.Context, s kv.Store) (string, error) {
	var setting string
	err := s.(*store).writeRow(ctx, `SELECT current_setting('synchronous_commit')`, nil, &setting)
	return setting, err
}

// CommitOfTx is the same for a transaction of the store.
func CommitOfTx(ctx context.Context, s kv.Store) (string, error) {
	var setting string
	err := s.(kv.Transactor).Tx(ctx, func(tx kv.Tx) error {
		return tx.(*pgTx).tx.QueryRow(ctx, `SELECT current_setting('synchronous_commit')`).Scan(&setting)
	})
	return setting, err
}

// LikePrefix is the LIKE pattern of a literal prefix.
func LikePrefix(prefix string) string { return likePrefix(prefix) }

// CleanupLock is the advisory lock of a replica that deletes expired records.
const CleanupLock = int64(cleanupLock)

// SetCleanupBatch sets how many records a statement of Cleanup deletes and returns what to call to set it
// back.
func SetCleanupBatch(n int) (restore func()) {
	old := cleanupBatch
	cleanupBatch = n
	return func() { cleanupBatch = old }
}

// Config is what a DSN and the credentials beside it become: the host, the database, and the user and the
// password the driver logs in with.
func Config(dsn, user, password string, opts ...Option) (host, database, asUser, withPassword string, err error) {
	cfg, err := poolConfig(dsn, user, password, transportOf(opts))
	if err != nil {
		return "", "", "", "", err
	}
	c := cfg.ConnConfig
	return c.Host, c.Database, c.User, c.Password, nil
}

// Transport is how a DSN with options is reached: whether with TLS, the name its certificate is verified
// for, and how many other ways the driver would fall back to.
func Transport(dsn string, opts ...Option) (withTLS bool, serverName string, fallbacks int, err error) {
	cfg, err := poolConfig(dsn, "kv", "", transportOf(opts))
	if err != nil {
		return false, "", 0, err
	}
	c := cfg.ConnConfig
	if c.TLSConfig != nil {
		serverName = c.TLSConfig.ServerName
	}
	return c.TLSConfig != nil, serverName, len(c.Fallbacks), nil
}
