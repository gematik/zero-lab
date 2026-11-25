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

package mariadb_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/kvtest"
	"github.com/gematik/zero-lab/go/kv/mariadb"
	"github.com/gematik/zero-lab/go/kv/schema"
)

// The database of the tests is named by three variables, as a deployment has it: the address, and the user
// and the password beside it.
const (
	dsnEnv      = "TEST_MARIADB_DSN"
	userEnv     = "TEST_MARIADB_USER"
	passwordEnv = "TEST_MARIADB_PASSWORD"
)

func openDB(dsn string) (*sql.DB, error) {
	return mariadb.OpenDB(dsn, os.Getenv(userEnv), os.Getenv(passwordEnv))
}

func openKV(ctx context.Context, dsn string, opts ...mariadb.Option) (kv.Store, error) {
	return mariadb.Open(ctx, dsn, os.Getenv(userEnv), os.Getenv(passwordEnv), opts...)
}

func openSteps(ctx context.Context, dsn string, steps []mariadb.Step, opts ...mariadb.Option) (kv.Store, error) {
	return mariadb.OpenSteps(ctx, dsn, os.Getenv(userEnv), os.Getenv(passwordEnv), steps, opts...)
}

// The tests share the database of TEST_MARIADB_DSN, which a migrator has to have prepared: Open applies no
// schema.
func TestMain(m *testing.M) {
	if dsn := os.Getenv(dsnEnv); dsn != "" {
		db, err := openDB(dsn)
		if err == nil {
			_, err = mariadb.Migrate(context.Background(), db)
			_ = db.Close()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, dsnEnv+":", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skip(dsnEnv + " not set: skipping the MariaDB kv tests (go/docs/development.md, gated tests)")
	}
	return dsn
}

func adminOf(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := openDB(dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// freshDatabase creates an empty database beside the one of the DSN, drops it afterwards, and returns its
// DSN: the schema is created once per database, so a test of its creation needs one of its own.
func freshDatabase(t *testing.T, dsn string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("the DSN is not a URL")
	}
	admin := adminOf(t, dsn)
	name := fmt.Sprintf("kv_fresh_%d", time.Now().UnixNano())
	if _, err := admin.Exec("CREATE DATABASE " + name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec("DROP DATABASE IF EXISTS " + name) })
	u.Path = "/" + name
	return u.String()
}

func TestMariaDB_Contract(t *testing.T) {
	dsn := testDSN(t)
	kvtest.Store(t, func(t *testing.T) kv.Store {
		s, err := openKV(context.Background(), dsn)
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

func TestMariaDB_MarkerContract(t *testing.T) {
	dsn := testDSN(t)
	kvtest.Marker(t, func(t *testing.T, mark func(string, []byte) string) kv.Store {
		s, err := openKV(context.Background(), dsn, mariadb.WithMark(mark))
		if err != nil {
			t.Fatal(err)
		}
		return s
	})
}

// A key is the primary key of the table and the database bounds it. A longer key is refused: cut short, two
// keys that differ after the bound would be one record.
func TestMariaDB_AKeyLongerThanTheBoundIsRefusedNotCutShort(t *testing.T) {
	ctx := context.Background()
	s, err := openKV(ctx, testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	base := fmt.Sprintf("long:%d:", time.Now().UnixNano())
	atBound := base + strings.Repeat("k", mariadb.MaxKeyLen-len(base))
	over := atBound + "x"
	defer func() { _ = s.Delete(ctx, atBound) }()
	if err := s.Set(ctx, atBound, []byte("at the bound"), time.Minute); err != nil {
		t.Fatalf("a key of the bound: %v", err)
	}
	if err := s.Set(ctx, over, []byte("over"), time.Minute); !errors.Is(err, mariadb.ErrKeyTooLong) {
		t.Fatalf("Set of a key over the bound: %v", err)
	}
	if set, err := s.SetIfAbsent(ctx, over, []byte("over"), time.Minute); !errors.Is(err, mariadb.ErrKeyTooLong) || set {
		t.Fatalf("SetIfAbsent of a key over the bound: set %v, err %v", set, err)
	}
	if err := s.SetMany(ctx, kv.Entry{Key: over, Value: []byte("over")}); !errors.Is(err, mariadb.ErrKeyTooLong) {
		t.Fatalf("SetMany of a key over the bound: %v", err)
	}
	if _, found, err := s.Get(ctx, over); err != nil || found {
		t.Fatalf("Get of a key over the bound: found %v, err %v", found, err)
	}
	if _, found, err := s.Take(ctx, over); err != nil || found {
		t.Fatalf("Take of a key over the bound: found %v, err %v", found, err)
	}
	if got, _, _ := s.Get(ctx, atBound); string(got) != "at the bound" {
		t.Fatalf("the record at the bound: %q", got)
	}
}

// An empty value is a value: it is found, and is not NULL to the database.
func TestMariaDB_AnEmptyValueIsStoredAndFound(t *testing.T) {
	ctx := context.Background()
	s, err := openKV(ctx, testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	key := fmt.Sprintf("empty:%d", time.Now().UnixNano())
	defer func() { _ = s.Delete(ctx, key) }()
	if err := s.Set(ctx, key, nil, time.Minute); err != nil {
		t.Fatal(err)
	}
	if got, found, err := s.Get(ctx, key); err != nil || !found || len(got) != 0 {
		t.Fatalf("got %v, found %v, err %v", got, found, err)
	}
}

// The expiry is the database's clock plus the TTL, whatever the client's clock says.
func TestMariaDB_ExpiryFromTheDatabaseClock(t *testing.T) {
	ctx := context.Background()
	dsn := testDSN(t)
	s, err := openKV(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	key := fmt.Sprintf("clock:%d", time.Now().UnixNano())
	defer func() { _ = s.Delete(ctx, key) }()
	if err := s.Set(ctx, key, []byte("v"), time.Hour); err != nil {
		t.Fatal(err)
	}
	var left float64
	if err := adminOf(t, dsn).QueryRow("SELECT TIMESTAMPDIFF(MICROSECOND, NOW(6), expires_at) / 1e6 FROM kv WHERE `key`=?",
		[]byte(key)).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left < 3590 || left > 3600 {
		t.Fatalf("an hour of TTL leaves %.1f seconds by the database's clock", left)
	}
}

// ahead are the steps of releases to come, after the one of this release: an expand step, a contract step
// that undoes it, and an expand step after that. Each is one statement that can run again.
func ahead() []mariadb.Step {
	return slices.Concat(mariadb.ReleasedSteps()[:1], []mariadb.Step{
		mariadb.NewStep(2, "a probe column", false, `ALTER TABLE kv ADD COLUMN IF NOT EXISTS probe TEXT`),
		mariadb.NewStep(3, "the probe column goes", true, `ALTER TABLE kv DROP COLUMN IF EXISTS probe`),
		mariadb.NewStep(4, "a probe table", false, `CREATE TABLE IF NOT EXISTS kv_probe (id INT PRIMARY KEY)`),
	})
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
	if err := db.QueryRow(`SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema=DATABASE() AND table_name='kv' AND column_name='probe'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// migrateTogether runs migrators at once, one per DSN and round robin over them, and reports their errors.
func migrateTogether(t *testing.T, dsns []string, migrators int) {
	t.Helper()
	ctx := context.Background()
	start := make(chan struct{})
	errs := make(chan error, migrators)
	for i := range migrators {
		go func() {
			<-start
			db, err := openDB(dsns[i%len(dsns)])
			if err == nil {
				var version int
				version, err = mariadb.MigrateSteps(ctx, db, ahead(), mariadb.Contract())
				if err == nil && version != 4 {
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
			t.Error(err)
		}
	}
}

// Several migration jobs, or replicas that apply the schema themselves, start together: every one of them
// succeeds and each step is recorded once. No lock makes that so: a step run twice changes nothing.
func TestMigrate_Task429ByManyAtOnceSucceedsForAll(t *testing.T) {
	admin := testDSN(t)
	for range 5 {
		dsn := freshDatabase(t, admin)
		migrateTogether(t, []string{dsn}, 8)
		if got := appliedVersions(t, adminOf(t, dsn)); fmt.Sprint(got) != "[1 2 3 4]" {
			t.Errorf("applied %v", got)
		}
	}
}

// MariaDB commits at every DDL statement, so a migrator can die between a step's statement and its record,
// and two can run the same step. Every released step must therefore be right to run again.
func TestMigrate_Task429EveryReleasedStepCanRunAgain(t *testing.T) {
	db := adminOf(t, freshDatabase(t, testDSN(t)))
	for _, s := range mariadb.ReleasedSteps() {
		for run := range 2 {
			if _, err := db.Exec(mariadb.StepSQL(s)); err != nil {
				t.Fatalf("step %d, run %d: %v", s.Version, run+1, err)
			}
		}
	}
	if version, err := mariadb.Migrate(context.Background(), db); err != nil || version != len(mariadb.ReleasedSteps()) {
		t.Fatalf("migrating a database whose steps ran without a record: version %d, err %v", version, err)
	}
}

// A server's user has no right to change the schema: Open and every operation work with SELECT, INSERT,
// UPDATE and DELETE on kv and SELECT on kv_schema, and the user cannot create, alter or drop a table.
func TestOpen_Task429RunsNoDDLAndWorksWithAUserThatMayNotChangeTheSchema(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t, testDSN(t))
	db := adminOf(t, dsn)
	if _, err := mariadb.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("the DSN is not a URL")
	}
	database := strings.TrimPrefix(u.Path, "/")
	user := fmt.Sprintf("kv_server_%d", time.Now().UnixNano()%1e12)
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(secret)
	for _, stmt := range []string{
		"CREATE USER '" + user + "'@'%' IDENTIFIED BY '" + password + "'",
		"GRANT SELECT, INSERT, UPDATE, DELETE ON " + database + ".kv TO '" + user + "'@'%'",
		"GRANT SELECT ON " + database + ".kv_schema TO '" + user + "'@'%'",
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = db.Exec("DROP USER IF EXISTS '" + user + "'@'%'") })

	asUser, err := mariadb.OpenDB(dsn, user, password)
	if err != nil {
		t.Fatal(err)
	}
	defer asUser.Close()
	for _, ddl := range []string{`CREATE TABLE made_by_the_server (id INT)`, `ALTER TABLE kv ADD COLUMN made_by_the_server TEXT`, `DROP TABLE kv`} {
		if _, err := asUser.Exec(ddl); err == nil {
			t.Fatalf("the user may run: %s", ddl)
		}
	}

	s, err := mariadb.Open(ctx, dsn, user, password, mariadb.WithMark(func(string, []byte) string { return "m" }))
	if err != nil {
		t.Fatalf("Open with a user without schema rights: %v", err)
	}
	defer s.Close()
	if err := s.Set(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if set, err := s.SetIfAbsent(ctx, "k", []byte("w"), 0); err != nil || set {
		t.Fatalf("SetIfAbsent: set %v, err %v", set, err)
	}
	if swapped, err := s.(kv.Swapper).Swap(ctx, "k", []byte("v"), []byte("x"), time.Minute); err != nil || !swapped {
		t.Fatalf("Swap: swapped %v, err %v", swapped, err)
	}
	if err := s.SetMany(ctx, kv.Entry{Key: "a", Value: []byte("1")}, kv.Entry{Key: "b", Value: []byte("2")}); err != nil {
		t.Fatalf("SetMany: %v", err)
	}
	if keys, err := s.Keys(ctx, ""); err != nil || len(keys) != 3 {
		t.Fatalf("Keys: %v, err %v", keys, err)
	}
	if marks, err := s.(kv.Marker).Marks(ctx, ""); err != nil || marks["m"] != 3 {
		t.Fatalf("Marks: %v, err %v", marks, err)
	}
	if got, found, err := s.Take(ctx, "k"); err != nil || !found || string(got) != "x" {
		t.Fatalf("Take: %q, found %v, err %v", got, found, err)
	}
	if _, err := s.Cleanup(ctx); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}

// Server rule 17: a release that needs a step the database lacks does not start, and says both versions.
func TestOpen_Rule17RefusesADatabaseThatLacksAStepItNeeds(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t, testDSN(t))
	_, err := openKV(ctx, dsn)
	var v *schema.VersionError
	if !errors.As(err, &v) || v.Found != 0 || v.Needs != 1 {
		t.Fatalf("an empty database: %v", err)
	}
	steps := ahead()[:2]
	if _, err := mariadb.MigrateSteps(ctx, adminOf(t, dsn), steps, mariadb.To(1)); err != nil {
		t.Fatal(err)
	}
	_, err = openSteps(ctx, dsn, steps)
	if !errors.As(err, &v) || !errors.Is(err, schema.ErrVersion) || v.Found != 1 || v.Needs != 2 {
		t.Fatalf("got %v", err)
	}
}

// Server rule 22: during a rollout the next release's expand steps are applied while replicas of this one
// still start. They work on such a database.
func TestOpen_Rule22StartsOnExpandStepsOfANewerRelease(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t, testDSN(t))
	if _, err := mariadb.MigrateSteps(ctx, adminOf(t, dsn), ahead()[:2]); err != nil {
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
	dsn := freshDatabase(t, testDSN(t))
	if _, err := mariadb.MigrateSteps(ctx, adminOf(t, dsn), ahead(), mariadb.Contract()); err != nil {
		t.Fatal(err)
	}
	_, err := openKV(ctx, dsn)
	var v *schema.VersionError
	if !errors.As(err, &v) || v.Contract != 3 || v.Found != 4 || v.Knows != 1 {
		t.Fatalf("got %v", err)
	}
}

// WithMigrate applies the expand steps the database lacks and stops before a contract step, which only a
// migrator that was told to applies.
func TestOpen_Task429WithMigrateAppliesExpandStepsAndNeverAContractStep(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t, testDSN(t))
	db := adminOf(t, dsn)

	s, err := openSteps(ctx, dsn, ahead()[:3], mariadb.WithMigrate())
	if err != nil {
		t.Fatalf("a release whose last step is a contract step: %v", err)
	}
	_ = s.Close()
	if got := appliedVersions(t, db); fmt.Sprint(got) != "[1 2]" {
		t.Fatalf("applied %v", got)
	}
	if !hasProbe(t, db) {
		t.Fatal("the contract step ran: the column it removes is gone")
	}

	_, err = openSteps(ctx, dsn, ahead(), mariadb.WithMigrate())
	var v *schema.VersionError
	if !errors.As(err, &v) || v.Found != 2 || v.Needs != 4 {
		t.Fatalf("got %v", err)
	}
	if !hasProbe(t, db) {
		t.Fatal("the contract step ran")
	}
}

// Migrate stops before a contract step unless told, and at the step it is told to stop at.
func TestMigrate_Task429AppliesAContractStepOnlyWhenAsked(t *testing.T) {
	ctx := context.Background()
	db := adminOf(t, freshDatabase(t, testDSN(t)))
	if version, err := mariadb.MigrateSteps(ctx, db, ahead(), mariadb.To(1)); err != nil || version != 1 {
		t.Fatalf("to 1: version %d, err %v", version, err)
	}
	if version, err := mariadb.MigrateSteps(ctx, db, ahead()); err != nil || version != 2 {
		t.Fatalf("without contract: version %d, err %v", version, err)
	}
	if version, err := mariadb.MigrateSteps(ctx, db, ahead(), mariadb.Contract()); err != nil || version != 4 {
		t.Fatalf("with contract: version %d, err %v", version, err)
	}
	if hasProbe(t, db) {
		t.Fatal("the contract step did not run")
	}
}

// A step that fails is not recorded, and the error names it.
func TestMigrate_Task429AFailedStepIsNotRecorded(t *testing.T) {
	ctx := context.Background()
	db := adminOf(t, freshDatabase(t, testDSN(t)))
	steps := slices.Concat(mariadb.ReleasedSteps()[:1], []mariadb.Step{
		mariadb.NewStep(2, "a step that fails", false, `ALTER TABLE no_such_table ADD COLUMN probe TEXT`),
	})
	version, err := mariadb.MigrateSteps(ctx, db, steps)
	if err == nil || version != 1 || !strings.Contains(err.Error(), "step 2 (a step that fails)") {
		t.Fatalf("version %d, err %v", version, err)
	}
	if got := appliedVersions(t, db); fmt.Sprint(got) != "[1]" {
		t.Fatalf("applied %v", got)
	}
}
