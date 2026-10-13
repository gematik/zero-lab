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
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
