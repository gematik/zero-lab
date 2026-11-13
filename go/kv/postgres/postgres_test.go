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
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/kv/postgres"
)

// testStore opens the Postgres store from TEST_DATABASE_URL (skipping when unset) and namespaces all
// keys under a unique prefix it cleans up afterwards, so the test is isolated from a shared database.
func testStore(t *testing.T) (kv.Store, string) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping Postgres kv test (see pdp/docker-compose.yaml)")
	}
	s, err := postgres.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	prefix := fmt.Sprintf("test:%d:%s:", time.Now().UnixNano(), t.Name())
	t.Cleanup(func() {
		ctx := context.Background()
		keys, _ := s.Keys(ctx, prefix)
		for _, k := range keys {
			_ = s.Delete(ctx, k)
		}
		_ = s.Close()
	})
	return s, prefix
}

func TestPostgres_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s, p := testStore(t)

	if err := s.Set(ctx, p+"a", []byte(`{"x":1}`), 0); err != nil {
		t.Fatal(err)
	}
	v, found, err := s.Get(ctx, p+"a")
	if err != nil || !found || string(v) != `{"x": 1}` && string(v) != `{"x":1}` {
		t.Fatalf("get: %q found=%v err=%v", v, found, err)
	}

	// SetMany writes a record + index keys atomically.
	if err := s.SetMany(ctx,
		kv.Entry{Key: p + "rec", Value: []byte(`{"id":"1"}`), TTL: time.Minute},
		kv.Entry{Key: p + "idx", Value: []byte(`"1"`), TTL: time.Minute},
	); err != nil {
		t.Fatal(err)
	}
	keys, _ := s.Keys(ctx, p)
	if len(keys) != 3 {
		t.Fatalf("keys = %v, want 3", keys)
	}
}

func TestPostgres_TakeSingleUseConcurrent(t *testing.T) {
	ctx := context.Background()
	s, p := testStore(t)

	const n = 100
	for i := range n {
		key := fmt.Sprintf("%sonce:%d", p, i)
		if err := s.Set(ctx, key, []byte(`1`), time.Minute); err != nil {
			t.Fatal(err)
		}
		var wins int64
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				if _, found, err := s.Take(ctx, key); err == nil && found {
					atomic.AddInt64(&wins, 1)
				}
			})
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("key %s: %d winners, want exactly 1 (atomic DELETE … RETURNING)", key, wins)
		}
	}
}

func TestPostgres_Expiry(t *testing.T) {
	ctx := context.Background()
	s, p := testStore(t)
	if err := s.Set(ctx, p+"tmp", []byte(`1`), 300*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := s.Get(ctx, p+"tmp"); !found {
		t.Fatal("expected present before expiry")
	}
	time.Sleep(500 * time.Millisecond)
	if _, found, _ := s.Get(ctx, p+"tmp"); found {
		t.Fatal("expected gone after expiry")
	}
}

// created_at and expires_at come from now() of the same statement, so with the database clock
// their difference is the TTL exactly; a client-side expiry would add latency and clock skew.
func TestPostgres_ExpiryFromDatabaseClock(t *testing.T) {
	ctx := context.Background()
	s, p := testStore(t)
	ttl := 90 * time.Second
	if err := s.Set(ctx, p+"ttl", []byte(`1`), ttl); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMany(ctx, kv.Entry{Key: p + "many", Value: []byte(`1`), TTL: ttl}); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, p+"forever", []byte(`1`), 0); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("pgx", os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, key := range []string{p + "ttl", p + "many"} {
		var micros int64
		if err := db.QueryRowContext(ctx,
			`SELECT (EXTRACT(EPOCH FROM expires_at - created_at) * 1000000)::bigint FROM kv WHERE key=$1`,
			key).Scan(&micros); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		if got := time.Duration(micros) * time.Microsecond; got != ttl {
			t.Fatalf("%s: expires_at - created_at = %v, want %v", key, got, ttl)
		}
	}
	var expires sql.NullTime
	if err := db.QueryRowContext(ctx, `SELECT expires_at FROM kv WHERE key=$1`, p+"forever").Scan(&expires); err != nil {
		t.Fatal(err)
	}
	if expires.Valid {
		t.Fatalf("no TTL: expires_at = %v, want NULL", expires.Time)
	}
}

// Under concurrency exactly one replica wins a fresh key, and exactly one wins a key whose row has expired:
// the second is the race Set-then-check could not survive.
func TestPostgres_SetIfAbsentConcurrencyHasExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	s, p := testStore(t)

	race := func(key string) int64 {
		var wins atomic.Int64
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				set, err := s.SetIfAbsent(ctx, key, []byte(`1`), time.Minute)
				if err != nil {
					t.Error(err)
				}
				if set {
					wins.Add(1)
				}
			})
		}
		wg.Wait()
		return wins.Load()
	}
	for i := range 50 {
		key := fmt.Sprintf("%sfresh:%d", p, i)
		if wins := race(key); wins != 1 {
			t.Fatalf("%s: %d winners on a fresh key", key, wins)
		}
	}
	for i := range 20 {
		key := fmt.Sprintf("%sexpired:%d", p, i)
		if err := s.Set(ctx, key, []byte(`0`), time.Millisecond); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Millisecond)
		if wins := race(key); wins != 1 {
			t.Fatalf("%s: %d winners on an expired row", key, wins)
		}
	}
}

func TestPostgres_SetIfAbsentExpiredCountsAsAbsent(t *testing.T) {
	ctx := context.Background()
	s, p := testStore(t)
	key := p + "k"
	if set, err := s.SetIfAbsent(ctx, key, []byte(`old`), 200*time.Millisecond); err != nil || !set {
		t.Fatalf("first: set=%v err=%v", set, err)
	}
	if set, err := s.SetIfAbsent(ctx, key, []byte(`new`), time.Minute); err != nil || set {
		t.Fatalf("over a live row: set=%v err=%v", set, err)
	}
	if v, _, _ := s.Get(ctx, key); string(v) != "old" {
		t.Fatalf("live row overwritten: %q", v)
	}
	time.Sleep(300 * time.Millisecond)
	if set, err := s.SetIfAbsent(ctx, key, []byte(`new`), time.Minute); err != nil || !set {
		t.Fatalf("over an expired row: set=%v err=%v", set, err)
	}
	if v, _, _ := s.Get(ctx, key); string(v) != "new" {
		t.Fatalf("got %q", v)
	}
}

func TestPostgres_SetIfAbsentWithoutTTLNeverExpires(t *testing.T) {
	ctx := context.Background()
	s, p := testStore(t)
	key := p + "k"
	if set, err := s.SetIfAbsent(ctx, key, []byte(`1`), 0); err != nil || !set {
		t.Fatalf("set=%v err=%v", set, err)
	}
	if set, err := s.SetIfAbsent(ctx, key, []byte(`2`), 0); err != nil || set {
		t.Fatalf("a row without expiry counted as absent: set=%v err=%v", set, err)
	}
}

func TestPostgres_SetIfAbsentExpiryFromDatabaseClock(t *testing.T) {
	ctx := context.Background()
	s, p := testStore(t)
	ttl := 90 * time.Second
	if set, err := s.SetIfAbsent(ctx, p+"ttl", []byte(`1`), ttl); err != nil || !set {
		t.Fatalf("set=%v err=%v", set, err)
	}
	db, err := sql.Open("pgx", os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var micros int64
	if err := db.QueryRowContext(ctx,
		`SELECT (EXTRACT(EPOCH FROM expires_at - created_at) * 1000000)::bigint FROM kv WHERE key=$1`,
		p+"ttl").Scan(&micros); err != nil {
		t.Fatal(err)
	}
	if got := time.Duration(micros) * time.Microsecond; got != ttl {
		t.Fatalf("expires_at - created_at = %v, want %v", got, ttl)
	}
}

// Rule 22: during a rolling deploy a replica of the previous release still upserts naming metadata.
func TestPostgres_MetadataColumnStaysForOldReplicas(t *testing.T) {
	ctx := context.Background()
	s, p := testStore(t)
	db, err := sql.Open("pgx", os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO kv(key, value, metadata, expires_at) VALUES($1, $2, $3::jsonb, now() + interval '1 minute')
		   ON CONFLICT(key) DO UPDATE SET value=excluded.value, metadata=excluded.metadata,
		     created_at=now(), expires_at=excluded.expires_at`,
		p+"old", []byte(`1`), `{"codec":"x"}`); err != nil {
		t.Fatalf("an old replica's upsert fails: %v", err)
	}
	if v, found, err := s.Get(ctx, p+"old"); err != nil || !found || string(v) != "1" {
		t.Fatalf("%q found=%v err=%v", v, found, err)
	}
	if err := s.Set(ctx, p+"old", []byte(`2`), time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestPostgres_CleanupRemovesExpiredRows(t *testing.T) {
	ctx := context.Background()
	s, p := testStore(t)
	if err := s.Set(ctx, p+"gone", []byte(`1`), time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(ctx, p+"stays", []byte(`1`), time.Minute); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if _, err := s.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("pgx", os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var rows int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM kv WHERE key=$1`, p+"gone").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatal("the expired row is still in the table")
	}
	if _, found, _ := s.Get(ctx, p+"stays"); !found {
		t.Fatal("a live row was removed")
	}
}

func TestPostgres_SealedStoreHoldsCiphertextAndDetectsAMovedRecord(t *testing.T) {
	ctx := context.Background()
	s, p := testStore(t)
	ring, err := kv.ParseKeyring([]byte("k1 " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	sealed := kv.NewSealed(s, ring, "test")
	secret := []byte("refresh-token-super-secret")
	if err := sealed.Set(ctx, p+"a", secret, time.Minute); err != nil {
		t.Fatal(err)
	}
	if set, err := sealed.SetIfAbsent(ctx, p+"b", secret, time.Minute); err != nil || !set {
		t.Fatalf("set=%v err=%v", set, err)
	}
	stored, found, err := s.Get(ctx, p+"a")
	if err != nil || !found || bytes.Contains(stored, secret) {
		t.Fatalf("stored %q found=%v err=%v", stored, found, err)
	}
	if got, _, err := sealed.Get(ctx, p+"a"); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("%q err=%v", got, err)
	}
	if got, _, err := sealed.Take(ctx, p+"b"); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("%q err=%v", got, err)
	}
	if err := s.Set(ctx, p+"moved", stored, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, _, err := sealed.Get(ctx, p+"moved"); !errors.Is(err, kv.ErrIntegrity) {
		t.Fatalf("got %v, want ErrIntegrity", err)
	}
}

// A key names what it holds, as:code:<the code> or pep:state:<the state>, and the store's errors reach logs.
func TestPostgres_ErrorsDoNotNameTheKey(t *testing.T) {
	store, prefix := testStore(t)
	ctx := context.Background()
	key := prefix + "as:code:code-value"
	closer, ok := store.(interface{ Close() error })
	if !ok {
		t.Fatal("the store cannot be closed")
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, getErr := store.Get(ctx, key)
	_, _, takeErr := store.Take(ctx, key)
	_, ifAbsentErr := store.SetIfAbsent(ctx, key, []byte("v"), time.Minute)
	for name, err := range map[string]error{
		"get":           getErr,
		"take":          takeErr,
		"set":           store.Set(ctx, key, []byte("v"), time.Minute),
		"set if absent": ifAbsentErr,
		"set many":      store.SetMany(ctx, kv.Entry{Key: key, Value: []byte("v"), TTL: time.Minute}),
		"delete":        store.Delete(ctx, key),
	} {
		if err == nil {
			t.Errorf("%s: no error from a closed store", name)
		} else if strings.Contains(err.Error(), "code-value") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Swap replaces only the value that was read, for exactly one of the replicas that try at once, also through
// the sealed store, and not once the row has expired.
func TestPostgres_SwapHasExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	raw, p := testStore(t)
	ring, err := kv.ParseKeyring([]byte("k1 AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n"))
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]kv.Store{"plain": raw, "sealed": kv.NewSealed(raw, ring, "test", kv.WithSealedExpiry(time.Now))} {
		swapper, ok := s.(kv.Swapper)
		if !ok {
			t.Fatalf("%s: %T cannot swap", name, s)
		}
		for i := range 20 {
			key := fmt.Sprintf("%s%s:%d", p, name, i)
			if err := s.Set(ctx, key, []byte("old"), time.Minute); err != nil {
				t.Fatal(err)
			}
			var wins atomic.Int64
			var wg sync.WaitGroup
			for n := range 8 {
				wg.Go(func() {
					swapped, err := swapper.Swap(ctx, key, []byte("old"), fmt.Appendf(nil, "new-%d", n), time.Minute)
					if err != nil {
						t.Error(err)
					}
					if swapped {
						wins.Add(1)
					}
				})
			}
			wg.Wait()
			if wins.Load() != 1 {
				t.Fatalf("%s: %d winners", key, wins.Load())
			}
			if v, found, err := s.Get(ctx, key); err != nil || !found || !strings.HasPrefix(string(v), "new-") {
				t.Fatalf("%s: holds %q, %v, %v", key, v, found, err)
			}
		}
		key := p + name + ":absent"
		if swapped, err := swapper.Swap(ctx, key, []byte("old"), []byte("new"), 0); err != nil || swapped {
			t.Errorf("%s: an absent key: %v, %v", name, swapped, err)
		}
		_ = s.Set(ctx, key, []byte("old"), time.Millisecond)
		time.Sleep(5 * time.Millisecond)
		if swapped, err := swapper.Swap(ctx, key, []byte("old"), []byte("new"), 0); err != nil || swapped {
			t.Errorf("%s: an expired row: %v, %v", name, swapped, err)
		}
	}
}
