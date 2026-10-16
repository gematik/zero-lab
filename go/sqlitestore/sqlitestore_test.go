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

package sqlitestore_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/sqlitestore"
	"github.com/gematik/zero-lab/go/store"
	"github.com/gematik/zero-lab/go/store/storetest"
)

func open(t *testing.T, path string, kind sqlitestore.DB) *sqlitestore.Backend {
	t.Helper()
	b, err := sqlitestore.Open(t.Context(), path, kind)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

// raw opens a database without the backend, to set it up or look inside.
func raw(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func name(i uint32) store.Name {
	var n store.Name
	n[28], n[29], n[30], n[31] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
	return n
}

// TestSTORE_078_Corpus runs spec/store's capabilities and operation scenarios of the
// SQLite backend, including 100,000 records, each on a new database.
func TestSTORE_078_Corpus(t *testing.T) {
	storetest.RunCorpus(t, "../../spec/store/testdata/manifest.json",
		func(c storetest.Case) bool {
			return (c.Kind == "capabilities" || c.Kind == "scenario") && c.Input["backend"] == "sqlite"
		},
		func(backend string) (store.Backend, func(), error) {
			if backend != "sqlite" {
				return nil, nil, nil
			}
			b, err := sqlitestore.Open(context.Background(), filepath.Join(t.TempDir(), "state.db"), sqlitestore.State)
			if err != nil {
				return nil, nil, err
			}
			return b, func() { _ = b.Close() }, nil
		})
}

// TestSTORE_071_SchemaIsTheSpecification: the embedded schema is spec/store/schema.sql.
func TestSTORE_071_SchemaIsTheSpecification(t *testing.T) {
	spec, err := os.ReadFile("../../spec/store/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile("schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	if string(spec) != string(copied) {
		t.Fatal("schema.sql differs from spec/store/schema.sql: copy it again")
	}
}

// TestSTORE_071_NewDatabaseIsCreatedFromTheSchema: application id, level, incremental
// vacuum and WAL.
func TestSTORE_071_NewDatabaseIsCreatedFromTheSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db")
	_ = open(t, path, sqlitestore.Cache).Close()
	db := raw(t, path)
	for pragma, want := range map[string]any{
		"application_id": int64(0x5A4C5354),
		"user_version":   int64(1),
		"auto_vacuum":    int64(2),
		"journal_mode":   "wal",
	} {
		var got any
		if err := db.QueryRow("PRAGMA " + pragma).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s = %v, want %v", pragma, got, want)
		}
	}
}

// TestSTORE_071_ConcurrentCreationOfOneDatabaseSucceeds: processes that create the same
// new database at once all open it.
func TestSTORE_071_ConcurrentCreationOfOneDatabaseSucceeds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			b, err := sqlitestore.Open(t.Context(), path, sqlitestore.State)
			if err == nil {
				err = b.Close()
			}
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

// TestSTORE_070_AnotherApplicationIDIsMalformed, and the database is left as it is.
func TestSTORE_070_AnotherApplicationIDIsMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db := raw(t, path)
	if _, err := db.Exec("CREATE TABLE other (x); INSERT INTO other VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlitestore.Open(t.Context(), path, sqlitestore.State); !errors.Is(err, store.ErrMalformed) {
		t.Fatalf("got %v, want malformed", err)
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM other").Scan(&n); err != nil || n != 1 {
		t.Fatalf("foreign database changed: %d, %v", n, err)
	}
}

// TestSTORE_070_AFileThatIsNotADatabaseIsMalformed.
func TestSTORE_070_AFileThatIsNotADatabaseIsMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	garbage := make([]byte, 4096)
	for i := range garbage {
		garbage[i] = 0x5a
	}
	if err := os.WriteFile(path, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlitestore.Open(t.Context(), path, sqlitestore.State); !errors.Is(err, store.ErrMalformed) {
		t.Fatalf("got %v, want malformed", err)
	}
}

// TestSTORE_100_DatabaseLevelsOpenAsSpecified: a newer compatible level opens, a newer
// incompatible one is unsupported_version, levels that disagree are malformed (STORE-101).
func TestSTORE_100_DatabaseLevelsOpenAsSpecified(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	_ = open(t, path, sqlitestore.State).Close()
	db := raw(t, path)
	for _, c := range []struct {
		userVersion, level, minCompatible int
		want                              error
	}{
		{2, 2, 1, nil},
		{2, 2, 2, store.ErrUnsupportedVersion},
		{1, 2, 1, store.ErrMalformed},
	} {
		_, err := db.Exec(fmt.Sprintf(
			"PRAGMA user_version = %d; UPDATE meta SET value = %d WHERE key = 'level'; UPDATE meta SET value = %d WHERE key = 'min_compatible'",
			c.userVersion, c.level, c.minCompatible))
		if err != nil {
			t.Fatal(err)
		}
		b, err := sqlitestore.Open(t.Context(), path, sqlitestore.State)
		if c.want == nil && err == nil {
			_ = b.Close()
			continue
		}
		if !errors.Is(err, c.want) {
			t.Errorf("levels %d/%d/%d: got %v, want %v", c.userVersion, c.level, c.minCompatible, err, c.want)
		}
	}
}

// TestSTORE_012_ConcurrentTakesReturnTheRecordOnce: of 16 connections taking one record
// at once, exactly one gets it.
func TestSTORE_012_ConcurrentTakesReturnTheRecordOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	backends := make([]*sqlitestore.Backend, 16)
	for i := range backends {
		backends[i] = open(t, path, sqlitestore.State)
	}
	if err := backends[0].Put(t.Context(), "popp", name(1), store.StoredRecord{Value: []byte("once")}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, len(backends))
	for _, b := range backends {
		wg.Go(func() {
			<-start
			_, err := b.Take(t.Context(), "popp", name(1), time.Unix(10, 0))
			results <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)
	won := 0
	for err := range results {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, store.ErrNotFound):
			t.Errorf("take: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d takes won, want 1", won)
	}
}

// TestSTORE_075_TagsGoWithTheirRecord: replacing a record replaces its tags; deleting
// removes them.
func TestSTORE_075_TagsGoWithTheirRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	b := open(t, path, sqlitestore.State)
	tag := func(v byte) store.Tag {
		var tg [32]byte
		tg[0] = v
		return store.Tag{Field: "patient", Tag: tg}
	}
	count := func(tg store.Tag) int {
		p, err := b.Query(t.Context(), &store.Query{NS: "popp", Filters: []store.Tag{tg}, Limit: 10, Now: time.Unix(1, 0)})
		if err != nil {
			t.Fatal(err)
		}
		return len(p.Records)
	}
	ctx := t.Context()
	if err := b.Put(ctx, "popp", name(1), store.StoredRecord{Value: []byte("v"), Tags: []store.Tag{tag(1)}}); err != nil {
		t.Fatal(err)
	}
	if err := b.Put(ctx, "popp", name(1), store.StoredRecord{Value: []byte("v"), Tags: []store.Tag{tag(2)}}); err != nil {
		t.Fatal(err)
	}
	if count(tag(1)) != 0 || count(tag(2)) != 1 {
		t.Fatal("replacing a record did not replace its tags")
	}
	if err := b.Delete(ctx, "popp", name(1)); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := raw(t, path).QueryRow("SELECT count(*) FROM tags").Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d tags left after delete (%v)", n, err)
	}
}

// TestSTORE_014_FailedBatchAppliesNothing: a batch whose last operation is invalid
// applies none of them.
func TestSTORE_014_FailedBatchAppliesNothing(t *testing.T) {
	b := open(t, filepath.Join(t.TempDir(), "state.db"), sqlitestore.State)
	err := b.Batch(t.Context(), []store.BatchOp{
		{NS: "popp", Name: name(1), Record: &store.StoredRecord{Value: []byte("a")}},
		{NS: "Not-A-Namespace", Name: name(2), Record: &store.StoredRecord{Value: []byte("b")}},
	})
	if !errors.Is(err, store.ErrInvalidArgument) {
		t.Fatalf("got %v, want invalid_argument", err)
	}
	if _, err := b.Get(t.Context(), "popp", name(1), time.Unix(1, 0)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("got %v, want not_found", err)
	}
}

// TestSTORE_077_DatabaseFilesArePrivate: the database and its WAL and shared-memory files
// are 0600 on POSIX systems.
func TestSTORE_077_DatabaseFilesArePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are POSIX (STORE-077)")
	}
	dir := t.TempDir()
	b := open(t, filepath.Join(dir, "state.db"), sqlitestore.State)
	if err := b.Put(t.Context(), "popp", name(1), store.StoredRecord{Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"state.db", "state.db-wal", "state.db-shm"} {
		info, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		if m := info.Mode().Perm(); m != 0o600 {
			t.Errorf("%s: mode %o, want 600", f, m)
		}
	}
}

// TestSTORE_016_Load100kRecordsWithinBudget is TASK-103.7's load check: 100,000 records
// of 400 bytes with a tag each. Writing in batches, paging through all of them, a tag
// query, an expiry range and cleaning them all up stay within the budget recorded in
// the task; the tag query is bounded on its own, so that a lost index fails here.
func TestSTORE_016_Load100kRecordsWithinBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("load check: run without -short")
	}
	const n = 100_000
	ctx := t.Context()
	b := open(t, filepath.Join(t.TempDir(), "state.db"), sqlitestore.State)
	tagOf := func(i uint32) store.Tag {
		var tg [32]byte
		v := i % 1000
		tg[0], tg[1], tg[2], tg[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
		return store.Tag{Field: "patient", Tag: tg}
	}
	var total time.Duration
	lap := func(what string, start time.Time) time.Duration {
		d := time.Since(start)
		total += d
		t.Logf("%s: %v", what, d)
		return d
	}

	start := time.Now()
	value := make([]byte, 400)
	for c := uint32(0); c < n; c += 1000 {
		ops := make([]store.BatchOp, 0, 1000)
		for i := c; i < c+1000; i++ {
			ops = append(ops, store.BatchOp{NS: "popp", Name: name(i), Record: &store.StoredRecord{
				Value: value, ExpiresAt: time.Unix(int64(1000+i), 0), Tags: []store.Tag{tagOf(i)},
			}})
		}
		if err := b.Batch(ctx, ops); err != nil {
			t.Fatal(err)
		}
	}
	lap("write 100 batches of 1000", start)

	start = time.Now()
	seen := 0
	q := &store.Query{NS: "popp", Limit: 1000, Now: time.Unix(1, 0)}
	for {
		p, err := b.Query(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		seen += len(p.Records)
		if p.Cursor == nil {
			break
		}
		q.Cursor = p.Cursor
	}
	if seen != n {
		t.Fatalf("paged %d, want %d", seen, n)
	}
	lap("page through all", start)

	start = time.Now()
	p, err := b.Query(ctx, &store.Query{NS: "popp", Filters: []store.Tag{tagOf(7)}, Limit: 1000, Now: time.Unix(1, 0)})
	if err != nil || len(p.Records) != 100 {
		t.Fatalf("tag query: %d records, %v", len(p.Records), err)
	}
	if d := lap("one tag value", start); d > 50*time.Millisecond {
		t.Errorf("tag query took %v: it no longer starts from the tags table", d)
	}

	start = time.Now()
	p, err = b.Query(ctx, &store.Query{NS: "popp", From: time.Unix(51_000, 0), To: time.Unix(51_500, 0), Limit: 1000, Now: time.Unix(1, 0)})
	if err != nil || len(p.Records) != 500 {
		t.Fatalf("range query: %d records, %v", len(p.Records), err)
	}
	lap("expiry range", start)

	start = time.Now()
	removed := 0
	for {
		k, err := b.Cleanup(ctx, time.Unix(1<<40, 0), 1000)
		if err != nil {
			t.Fatal(err)
		}
		if k == 0 {
			break
		}
		removed += k
	}
	if removed != n {
		t.Fatalf("cleaned up %d, want %d", removed, n)
	}
	lap("clean up all", start)

	if budget := 60 * time.Second; total > budget {
		t.Fatalf("%v over the budget of %v", total, budget)
	}
}
