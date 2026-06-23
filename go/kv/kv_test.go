package kv_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

func TestMemory_GetSetDeleteKeys(t *testing.T) {
	ctx := context.Background()
	s := kv.NewMemory()

	if _, found, err := s.Get(ctx, "missing"); err != nil || found {
		t.Fatalf("get missing: found=%v err=%v", found, err)
	}
	if err := s.Set(ctx, "a:1", []byte(`{"x":1}`), 0); err != nil {
		t.Fatal(err)
	}
	v, found, err := s.Get(ctx, "a:1")
	if err != nil || !found || string(v) != `{"x":1}` {
		t.Fatalf("get a:1: %q found=%v err=%v", v, found, err)
	}
	_ = s.Set(ctx, "a:2", []byte(`2`), 0)
	_ = s.Set(ctx, "b:1", []byte(`3`), 0)
	keys, _ := s.Keys(ctx, "a:")
	if len(keys) != 2 || keys[0] != "a:1" || keys[1] != "a:2" {
		t.Fatalf("keys a: = %v", keys)
	}
	if err := s.Delete(ctx, "a:1"); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := s.Get(ctx, "a:1"); found {
		t.Fatal("a:1 still present after delete")
	}
}

func TestMemory_Expiry(t *testing.T) {
	ctx := context.Background()
	s := kv.NewMemory()
	_ = s.Set(ctx, "tmp", []byte(`1`), 20*time.Millisecond)
	if _, found, _ := s.Get(ctx, "tmp"); !found {
		t.Fatal("expected present before expiry")
	}
	time.Sleep(40 * time.Millisecond)
	if _, found, _ := s.Get(ctx, "tmp"); found {
		t.Fatal("expected gone after expiry")
	}
	n, _ := s.Cleanup(ctx)
	_ = n
}

func TestMemory_SetManyAtomicReadback(t *testing.T) {
	ctx := context.Background()
	s := kv.NewMemory()
	err := s.SetMany(ctx,
		kv.Entry{Key: "rec:1", Value: []byte(`{"id":"1"}`), TTL: time.Minute},
		kv.Entry{Key: "idx:state:s1", Value: []byte(`"1"`), TTL: time.Minute},
		kv.Entry{Key: "idx:code:c1", Value: []byte(`"1"`), TTL: time.Minute},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"rec:1", "idx:state:s1", "idx:code:c1"} {
		if _, found, _ := s.Get(ctx, k); !found {
			t.Fatalf("%s missing after SetMany", k)
		}
	}
}

// TestMemory_TakeIsSingleUse is the ACID property nonce-redeem and auth-code exchange depend on: under
// concurrency exactly one Take of a key succeeds.
func TestMemory_TakeIsSingleUse(t *testing.T) {
	ctx := context.Background()
	s := kv.NewMemory()

	const n = 200
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("once:%d", i)
		_ = s.Set(ctx, key, []byte(`1`), time.Minute)

		var wins int64
		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, found, err := s.Take(ctx, key); err == nil && found {
					atomic.AddInt64(&wins, 1)
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("key %s: %d winners, want exactly 1", key, wins)
		}
	}
}

func TestMemory_Closed(t *testing.T) {
	s := kv.NewMemory()
	_ = s.Close()
	if _, _, err := s.Get(context.Background(), "x"); err != kv.ErrClosed {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}
