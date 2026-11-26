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
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv/postgres"
	"github.com/gematik/zero-lab/go/kv/schema"
)

func TestDatabaseOf_Rule22TheServerAppliesTheSchemaOnlyWhenTold(t *testing.T) {
	dsn := "postgres://pep:" + testPassword + "@db.example:5432/pep"
	if db, err := databaseOf(dsn, databaseEnv(nil), nil); err != nil || db.migrate {
		t.Fatalf("without a setting: migrate %v, err %v", db.migrate, err)
	}
	if db, err := databaseOf(dsn, databaseEnv(map[string]string{databaseMigrateEnv: "true"}), nil); err != nil || !db.migrate {
		t.Fatalf("with the setting: migrate %v, err %v", db.migrate, err)
	}
	for _, value := range []string{"false", "yes", "1"} {
		if _, err := databaseOf(dsn, databaseEnv(map[string]string{databaseMigrateEnv: value}), nil); err == nil {
			t.Errorf("%s=%q was read as something", databaseMigrateEnv, value)
		}
	}
}

func TestMigrateCommand_RefusesWhatItDoesNotKnow(t *testing.T) {
	ctx := context.Background()
	for name, args := range map[string][]string{"another word": {"down"}, "two words": {"contract", "now"}} {
		if err := migrateCommand(ctx, args, databaseEnv(nil), &bytes.Buffer{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := migrateCommand(ctx, nil, databaseEnv(nil), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), databaseURLEnv) {
		t.Errorf("without a database: %v", err)
	}
}

// pgEnv is the environment of zero-pep-proxy for the test database of PEP_PG_DSN in the database named
// name: the URL with its user and password, and the acceptance of plaintext where the URL says the
// database has no TLS.
func pgEnv(t *testing.T, name string) func(string) string {
	t.Helper()
	dsn := os.Getenv("PEP_PG_DSN")
	if dsn == "" {
		t.Skip("PEP_PG_DSN not set — skipping the migration of zero-pep-proxy's store against Postgres")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("PEP_PG_DSN is not a URL")
	}
	plaintext := u.Query().Get("sslmode") == "disable"
	u.RawQuery = ""
	if name != "" {
		u.Path = "/" + name
	}
	values := map[string]string{databaseURLEnv: u.String()}
	if plaintext {
		values[databasePlaintextEnv] = "true"
	}
	return databaseEnv(values)
}

// Server rule 22: on a database no migration job prepared, the server does not start, and says why; after
// zero-pep-proxy migrate it starts without the right to change the schema, which it does not use.
func TestMigrateCommand_Rule22TheJobPreparesTheDatabaseTheServerOpens(t *testing.T) {
	ctx := context.Background()
	admin, err := databaseOfEnv(pgEnv(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := postgres.OpenDB(admin.address, admin.user, admin.password, admin.transport...)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	name := fmt.Sprintf("pep_migrate_%d", time.Now().UnixNano())
	if _, err := conn.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = conn.ExecContext(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)") })

	getenv := pgEnv(t, name)
	db, err := databaseOfEnv(getenv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.Open(ctx, db.address, db.user, db.password, db.transport...); !errors.Is(err, schema.ErrVersion) {
		t.Fatalf("the server on a database without its schema: %v", err)
	}
	var out bytes.Buffer
	if err := migrateCommand(ctx, nil, getenv, &out); err != nil {
		t.Fatal(err)
	}
	migrated, err := postgres.OpenDB(db.address, db.user, db.password, db.transport...)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	if !strings.HasPrefix(out.String(), "schema version ") {
		t.Errorf("the job says %q", out.String())
	}
	// The server's own user reads and writes rows and may not change the schema.
	role := fmt.Sprintf("pep_server_%d", time.Now().UnixNano())
	for _, stmt := range []string{
		"CREATE ROLE " + role + " LOGIN PASSWORD '" + testPassword + "'",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON kv, kv_cache, kv_feed, kv_topic TO " + role,
		"GRANT SELECT ON kv_schema TO " + role,
	} {
		if _, err := migrated.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = migrated.ExecContext(context.Background(), "DROP OWNED BY "+role)
		_, _ = conn.ExecContext(context.Background(), "DROP ROLE IF EXISTS "+role)
	})
	store, err := postgres.Open(ctx, db.address, role, testPassword, db.transport...)
	if err != nil {
		t.Fatalf("the server after the job, as a user without schema rights: %v", err)
	}
	if err := store.Set(ctx, "pep:session:x", []byte("v"), time.Minute); err != nil {
		t.Fatalf("a write of that server: %v", err)
	}
	_ = store.Close()
	if err := migrateCommand(ctx, nil, getenv, &bytes.Buffer{}); err != nil {
		t.Fatalf("the job run again: %v", err)
	}
}
