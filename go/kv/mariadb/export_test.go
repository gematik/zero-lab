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

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/schema"
)

// Step is a schema step for tests that need steps of their own: a contract step, a release ahead.
type Step = step

func NewStep(version int, name string, contract bool, sql string) Step {
	return step{schema.Step{Version: version, Name: name, Contract: contract}, sql}
}

// ReleasedSteps are the steps of this release.
func ReleasedSteps() []Step { return steps }

// StepSQL is the statement of a step.
func StepSQL(s Step) string { return s.sql }

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

// Config is what a DSN and the credentials beside it become: the address, the database, the user and the
// password the driver logs in with, whether TLS is on, and the session parameters.
func Config(dsn, user, password string) (addr, database, asUser, withPassword string, tlsOn bool, params map[string]string, err error) {
	cfg, err := config(dsn, user, password, nil)
	if err != nil {
		return "", "", "", "", false, nil, err
	}
	return cfg.Addr, cfg.DBName, cfg.User, cfg.Passwd, cfg.TLS != nil, cfg.Params, nil
}
