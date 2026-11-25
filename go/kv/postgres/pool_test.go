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
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv/postgres"
)

func secretOf(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func TestConfig_UserAndPasswordAreTakenBesideTheDSN(t *testing.T) {
	secret := secretOf(t)
	// What the driver would take from the environment is not what it logs in with.
	t.Setenv("PGUSER", "from-the-environment")
	t.Setenv("PGPASSWORD", "from-the-environment")
	host, database, user, with, err := postgres.Config("postgres://db.example:5433/store?sslmode=verify-full", "kv", secret)
	if err != nil || host != "db.example" || database != "store" {
		t.Fatalf("host %q, database %q, err %v", host, database, err)
	}
	if user != "kv" || with != secret {
		t.Errorf("the driver logs in as %q, not with the user and the password given beside the DSN", user)
	}
	for _, as := range []string{"p@ss:w/rd#?%41", " leading and trailing ", ""} {
		if _, _, _, with, err := postgres.Config("postgresql://db.example/store", "kv", as); err != nil || with != as {
			t.Errorf("a password of %d bytes was changed or refused: %v", len(as), err)
		}
	}
}

// A DSN is an address. One that carries a user or a password, in the URL or as a parameter, is refused,
// and the error does not repeat it.
func TestConfig_ADSNWithAUserOrAPasswordIsRefused(t *testing.T) {
	secret := secretOf(t)
	for name, dsn := range map[string]string{
		"a user and a password":  "postgres://kv:" + secret + "@db.example/store",
		"a user alone":           "postgres://" + secret + "@db.example/store",
		"a password parameter":   "postgres://db.example/store?password=" + secret,
		"a user parameter":       "postgres://db.example/store?user=" + secret,
		"a password file":        "postgres://db.example/store?passfile=/" + secret,
		"a service":              "postgres://db.example/store?service=" + secret,
		"keywords, not a URL":    "host=db.example user=kv password=" + secret,
		"another scheme":         "mariadb://db.example/store",
		"a port that is no port": "postgres://db.example:port/store",
	} {
		if _, _, _, _, err := postgres.Config(dsn, "kv", "beside"); err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: the error repeats what the DSN carried: %v", name, err)
		}
	}
	if _, _, _, _, err := postgres.Config("postgres://db.example/store", "", "beside"); err == nil {
		t.Error("no user: accepted")
	}
}

func TestSplitURL_TakesAConnectionURLApart(t *testing.T) {
	address, user, password, err := postgres.SplitURL("postgres://kv:p%40ss@db.example:5433/store?sslmode=disable")
	if err != nil || address != "postgres://db.example:5433/store?sslmode=disable" || user != "kv" || password != "p@ss" {
		t.Fatalf("address %q, user %q, password of %d bytes, err %v", address, user, len(password), err)
	}
	if _, _, _, _, err := postgres.Config(address, user, password); err != nil {
		t.Errorf("what SplitURL returns is not what Open takes: %v", err)
	}
	address, user, _, err = postgres.SplitURL("postgres://db.example/store")
	if err != nil || address != "postgres://db.example/store" || user != "" {
		t.Errorf("a URL without a user: address %q, user %q, err %v", address, user, err)
	}
}

// plan asks the database how it would run a statement with sequential scans made as dear as they can be:
// what it then still scans in sequence, no index can serve.
func plan(t *testing.T, db *sql.DB, query string, args ...any) string {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `SET enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	rows, err := conn.QueryContext(ctx, `EXPLAIN `+query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// keyRange reports whether a plan bounds its reading of an index by the keys of a prefix: a condition of an
// index, not a filter over rows already read, that holds the prefix and the first key after it.
func keyRange(plan string) bool {
	for line := range strings.SplitSeq(plan, "\n") {
		if strings.Contains(line, "Index Cond") && strings.Contains(line, "'session:'") && strings.Contains(line, "< 'session;'") {
			return true
		}
	}
	return false
}

// Keys and the walk of the marks read a range of an index, not the table. Before step 2 the only index of
// the keys is in the database's collation, which serves neither a prefix nor the order by bytes: the
// prefix is then a filter over every record. With the step it bounds a range of the keys' index.
func TestPostgres_Task430KeysAndMarksByPrefixReadARangeOfAnIndex(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t)
	db := adminOf(t, dsn)
	statements := map[string][]any{
		postgres.KeysSQL:        {"session:", postgres.LikePrefix("session:")},
		postgres.MarkedOtherSQL: {"session:", postgres.LikePrefix("session:"), "mark", "session:m", 200},
	}

	if _, err := postgres.Migrate(ctx, db, postgres.To(1)); err != nil {
		t.Fatal(err)
	}
	for query, args := range statements {
		if got := plan(t, db, query, args...); keyRange(got) {
			t.Errorf("before step 2 no index was expected to serve the prefix:\n%s", got)
		}
	}

	if _, err := postgres.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	for query, args := range statements {
		got := plan(t, db, query, args...)
		if !keyRange(got) || !strings.Contains(got, "idx_kv_key_c") || strings.Contains(got, "Seq Scan") {
			t.Errorf("the prefix does not bound a range of the keys' index:\n%s", got)
		}
	}
}

// expire writes n records under a prefix that are expired when it returns.
func expire(t *testing.T, db *sql.DB, prefix string, n int) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO kv(key, value, expires_at)
		SELECT $1 || i, 'v', now() - interval '1 second' FROM generate_series(1, $2) AS i`, prefix, n); err != nil {
		t.Fatal(err)
	}
}

func countUnder(t *testing.T, db *sql.DB, prefix string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM kv WHERE key LIKE $1`, postgres.LikePrefix(prefix)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A backlog of expired records is deleted in batches, each a transaction of its own, and all of it.
func TestPostgres_Task430CleanupDeletesABacklogInBatches(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t)
	db := adminOf(t, dsn)
	if _, err := postgres.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	defer postgres.SetCleanupBatch(10)()
	expire(t, db, "gone:", 95)
	if _, err := db.Exec(`INSERT INTO kv(key, value, expires_at) VALUES('stays', 'v', NULL), ('later', 'v', now() + interval '1 hour')`); err != nil {
		t.Fatal(err)
	}
	s, err := openKV(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	removed, err := s.Cleanup(ctx)
	if err != nil || removed != 95 {
		t.Fatalf("removed %d, err %v", removed, err)
	}
	if left := countUnder(t, db, ""); left != 2 {
		t.Fatalf("%d records are left, of the two that have not expired", left)
	}
}

// Every replica calls Cleanup; one at a time deletes. A replica that finds another at it leaves the
// records to that one and returns.
func TestPostgres_Task430OnlyOneReplicaCleansAtATime(t *testing.T) {
	ctx := context.Background()
	dsn := freshDatabase(t)
	db := adminOf(t, dsn)
	if _, err := postgres.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	expire(t, db, "gone:", 20)
	s, err := openKV(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	other, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Exec(`SELECT pg_advisory_xact_lock($1)`, postgres.CleanupLock); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var removed int
	go func() {
		defer close(done)
		removed, err = s.Cleanup(ctx)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Cleanup waits for the replica that is cleaning")
	}
	if err != nil || removed != 0 || countUnder(t, db, "gone:") != 20 {
		t.Fatalf("while another replica cleans: removed %d, err %v, %d left", removed, err, countUnder(t, db, "gone:"))
	}
	if err := other.Rollback(); err != nil {
		t.Fatal(err)
	}
	if removed, err := s.Cleanup(ctx); err != nil || removed != 20 {
		t.Fatalf("after it: removed %d, err %v", removed, err)
	}
}
