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

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/gematik/zero-lab/go/kv/postgres"
)

// migrateCommand applies the schema steps of the session store and stops: what a migration job runs before a
// rollout (servers.md rule 22), with the image of the server and the configuration of its database, but with
// a PEP_DATABASE_URL whose user may change the schema, which no server holds. "migrate contract" applies the
// steps that remove what an older release uses as well, once no replica of it is left.
func migrateCommand(ctx context.Context, args []string, getenv func(string) string, out io.Writer) error {
	contract := false
	switch {
	case len(args) == 0:
	case len(args) == 1 && args[0] == "contract":
		contract = true
	default:
		return errors.New("usage: zero-pep-proxy migrate [contract]")
	}
	db, err := databaseOfEnv(getenv)
	if err != nil {
		return err
	}
	if db.address == "" {
		return errors.New(databaseURLEnv + " is not set: there is no database to migrate")
	}
	conn, err := postgres.OpenDB(db.address, db.user, db.password, db.transport...)
	if err != nil {
		return err
	}
	defer conn.Close()
	var opts []postgres.MigrateOption
	if contract {
		opts = append(opts, postgres.Contract())
	}
	version, err := postgres.Migrate(ctx, conn, opts...)
	if err != nil {
		return err
	}
	slog.InfoContext(ctx, "the session store's schema is migrated", "version", version, "contract", contract)
	_, err = fmt.Fprintf(out, "schema version %d\n", version)
	return err
}
