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

package postgres_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv/postgres"
	"github.com/gematik/zero-lab/go/kv/schema"
)

func adminOf(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func appliedVersions(t *testing.T, db *sql.DB) []int {
	t.Helper()
	rows, err := db.Query(`SELECT version FROM kv_schema ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// hasProbe reports whether kv has the column the steps of ahead add and remove.
func hasProbe(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_name='kv' AND column_name='probe'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// released is how many steps this release has.
var released = len(postgres.ReleasedSteps())

// ahead are the steps of this release and, after them, those of releases to come: an expand step, a
// contract step that undoes it, and an expand step after that.
func ahead() []postgres.Step {
	return slices.Concat(postgres.ReleasedSteps(), []postgres.Step{
		postgres.NewStep(released+1, "a probe column", false, `ALTER TABLE kv ADD COLUMN probe text`),
		postgres.NewStep(released+2, "the probe column goes", true, `ALTER TABLE kv DROP COLUMN probe`),
		postgres.NewStep(released+3, "a probe table", false, `CREATE TABLE kv_probe (id integer PRIMARY KEY)`),
	})
}

// upTo is the versions 1 to n as appliedVersions prints them.
func upTo(n int) string {
	versions := make([]int, n)
	for i := range versions {
		versions[i] = i + 1
	}
	return fmt.Sprint(versions)
}

// Several migration jobs, or replicas that apply the schema themselves, start together: each step is
// applied once and every one of them succeeds.
func TestMigrate_Task428ByManyAtOnceAppliesEachStepOnce(t *testing.T) {
	ctx := context.Background()
	const migrators = 8
	for round := range 5 {
		dsn := freshDatabase(t)
		start := make(chan struct{})
		errs := make(chan error, migrators)
		for range migrators {
			go func() {
				<-start
				db, err := sql.Open("pgx", dsn)
				if err == nil {
					var version int
					version, err = postgres.MigrateSteps(ctx, db, ahead(), postgres.Contract())
					if err == nil && version != released+3 {
						err = fmt.Errorf("at version %d", version)
					}
					_ = db.Close()
				}
				errs <- err
			}()
		}
		close(start)
		for range migrators {
			if err := <-errs; err != nil {
				t.Errorf("round %d: %v", round, err)
			}
		}
		if got := appliedVersions(t, adminOf(t, dsn)); fmt.Sprint(got) != upTo(released+3) {
			t.Errorf("round %d: applied %v", round, got)
		}
	}
}

// A database that a release before the steps created has the table and no record of steps. Open refuses it
// until it is migrated; migrating records step 1 and leaves the data as it was.
func TestMigrate_Task428AdoptsADatabaseOfBeforeTheStepsWithItsData(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t)
	db := adminOf(t, dsn)
	if _, err := db.Exec(postgres.SchemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO kv(key, value) VALUES('of-before', 'kept')`); err != nil {
		t.Fatal(err)
	}

	_, err := openKV(ctx, dsn)
	var v *schema.VersionError
	if !errors.As(err, &v) || v.Found != 0 || v.Needs != released {
		t.Fatalf("Open before migrating: %v", err)
	}

	if version, err := postgres.Migrate(ctx, db); err != nil || version != released {
		t.Fatalf("version %d, err %v", version, err)
	}
	s, err := openKV(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got, found, err := s.Get(ctx, "of-before"); err != nil || !found || string(got) != "kept" {
		t.Fatalf("the record of before: %q, found %v, err %v", got, found, err)
	}
	if version, err := postgres.Migrate(ctx, db); err != nil || version != released {
		t.Fatalf("migrating again: version %d, err %v", version, err)
	}
}

// A server's role has no right to change the schema: Open and every operation work with SELECT, INSERT,
// UPDATE and DELETE on kv and SELECT on kv_schema, and the role cannot create or alter a table.
func TestOpen_Task428RunsNoDDLAndWorksWithARoleThatMayNotChangeTheSchema(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t)
	db := adminOf(t, dsn)
	if _, err := postgres.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	role := fmt.Sprintf("kv_server_%d", time.Now().UnixNano())
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(secret)
	for _, stmt := range []string{
		`CREATE ROLE ` + role + ` LOGIN PASSWORD '` + password + `'`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON kv TO ` + role,
		`GRANT SELECT ON kv_schema TO ` + role,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DROP OWNED BY ` + role)
		_, _ = db.Exec(`DROP ROLE ` + role)
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, password)

	asRole := adminOf(t, u.String())
	for _, ddl := range []string{`CREATE TABLE made_by_the_server (id integer)`, `ALTER TABLE kv ADD COLUMN made_by_the_server text`, `DROP TABLE kv`} {
		if _, err := asRole.Exec(ddl); err == nil {
			t.Fatalf("the role may run: %s", ddl)
		}
	}

	s, err := openKV(ctx, u.String())
	if err != nil {
		t.Fatalf("Open with a role without schema rights: %v", err)
	}
	defer s.Close()
	if err := s.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if set, err := s.SetIfAbsent(ctx, "k", []byte("w"), 0); err != nil || set {
		t.Fatalf("SetIfAbsent: set %v, err %v", set, err)
	}
	if keys, err := s.Keys(ctx, "k"); err != nil || len(keys) != 1 {
		t.Fatalf("Keys: %v, err %v", keys, err)
	}
	if got, found, err := s.Take(ctx, "k"); err != nil || !found || string(got) != "v" {
		t.Fatalf("Take: %q, found %v, err %v", got, found, err)
	}
	if _, err := s.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}

// Server rule 17: a release that needs a step the database lacks does not start, and says both versions.
func TestOpen_Rule17RefusesADatabaseThatLacksAStepItNeeds(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t)
	steps := ahead()[:released+1]
	if _, err := postgres.MigrateSteps(ctx, adminOf(t, dsn), steps, postgres.To(released)); err != nil {
		t.Fatal(err)
	}
	_, err := openSteps(ctx, dsn, steps)
	var v *schema.VersionError
	if !errors.As(err, &v) || !errors.Is(err, schema.ErrVersion) || v.Found != released || v.Needs != released+1 {
		t.Fatalf("got %v", err)
	}
	for _, word := range []string{fmt.Sprintf("version %d", released), fmt.Sprintf("needs %d", released+1)} {
		if !strings.Contains(err.Error(), word) {
			t.Errorf("the error does not say %q: %v", word, err)
		}
	}
}

// Server rule 22: during a rollout the next release's expand steps are applied while replicas of this one
// still start. They work on such a database.
func TestOpen_Rule22StartsOnExpandStepsOfANewerRelease(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t)
	if _, err := postgres.MigrateSteps(ctx, adminOf(t, dsn), ahead()[:released+1]); err != nil {
		t.Fatal(err)
	}
	s, err := openKV(ctx, dsn)
	if err != nil {
		t.Fatalf("this release on a database one expand step ahead: %v", err)
	}
	defer s.Close()
	if err := s.Set(ctx, "k", []byte("v"), 0); err != nil {
		t.Fatal(err)
	}
}

// Server rule 17: a contract step this release does not know removed something it may use. It does not
// start, and says which step.
func TestOpen_Rule17RefusesADatabaseWithAContractStepItDoesNotKnow(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t)
	if _, err := postgres.MigrateSteps(ctx, adminOf(t, dsn), ahead(), postgres.Contract()); err != nil {
		t.Fatal(err)
	}
	_, err := openKV(ctx, dsn)
	var v *schema.VersionError
	if !errors.As(err, &v) || v.Contract != released+2 || v.Found != released+3 || v.Knows != released {
		t.Fatalf("got %v", err)
	}
}

// WithMigrate applies the expand steps the database lacks and stops before a contract step, which only a
// migrator that was told to applies.
func TestOpen_Task428WithMigrateAppliesExpandStepsAndNeverAContractStep(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t)
	db := adminOf(t, dsn)

	s, err := openSteps(ctx, dsn, ahead()[:released+2], postgres.WithMigrate())
	if err != nil {
		t.Fatalf("a release whose last step is a contract step: %v", err)
	}
	_ = s.Close()
	if got := appliedVersions(t, db); fmt.Sprint(got) != upTo(released+1) {
		t.Fatalf("applied %v", got)
	}
	if !hasProbe(t, db) {
		t.Fatal("the contract step ran: the column it removes is gone")
	}

	// The release after it needs step 4, which stands behind the contract step: it does not start, and
	// leaves the contract step alone.
	_, err = openSteps(ctx, dsn, ahead(), postgres.WithMigrate())
	var v *schema.VersionError
	if !errors.As(err, &v) || v.Found != released+1 || v.Needs != released+3 {
		t.Fatalf("got %v", err)
	}
	if !hasProbe(t, db) {
		t.Fatal("the contract step ran")
	}
}

// Migrate stops before a contract step unless told, and at the step it is told to stop at.
func TestMigrate_Task428AppliesAContractStepOnlyWhenAsked(t *testing.T) {
	ctx := context.Background()
	db := adminOf(t, freshDatabase(t))
	if version, err := postgres.MigrateSteps(ctx, db, ahead(), postgres.To(released)); err != nil || version != released {
		t.Fatalf("to 1: version %d, err %v", version, err)
	}
	if version, err := postgres.MigrateSteps(ctx, db, ahead()); err != nil || version != released+1 {
		t.Fatalf("without contract: version %d, err %v", version, err)
	}
	if version, err := postgres.MigrateSteps(ctx, db, ahead(), postgres.Contract()); err != nil || version != released+3 {
		t.Fatalf("with contract: version %d, err %v", version, err)
	}
	if hasProbe(t, db) {
		t.Fatal("the contract step did not run")
	}
}

// A step is one transaction: when a statement of it fails, the statements before it are undone, the step
// is not recorded, and the error names it.
func TestMigrate_Task428AFailedStepLeavesNothingBehind(t *testing.T) {
	ctx := context.Background()
	db := adminOf(t, freshDatabase(t))
	steps := slices.Concat(postgres.ReleasedSteps(), []postgres.Step{postgres.NewStep(released+1, "half a step", false,
		`ALTER TABLE kv ADD COLUMN probe text; ALTER TABLE no_such_table ADD COLUMN probe text`)})
	version, err := postgres.MigrateSteps(ctx, db, steps)
	if err == nil || version != released || !strings.Contains(err.Error(), fmt.Sprintf("step %d (half a step)", released+1)) {
		t.Fatalf("version %d, err %v", version, err)
	}
	if hasProbe(t, db) {
		t.Fatal("the first statement of the failed step stands")
	}
	if got := appliedVersions(t, db); fmt.Sprint(got) != upTo(released) {
		t.Fatalf("applied %v", got)
	}
}
