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

package authzserver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

func TestReplays_SecondSightingIsSeen(t *testing.T) {
	replays := newKVReplays(kv.NewMemory())
	until := time.Now().Add(time.Minute)
	if seen, err := replays.Seen(t.Context(), "proof", until); err != nil || seen {
		t.Fatalf("first: seen=%v err=%v", seen, err)
	}
	if seen, err := replays.Seen(t.Context(), "proof", until); err != nil || !seen {
		t.Fatalf("second: seen=%v err=%v", seen, err)
	}
	if seen, err := replays.Seen(t.Context(), "other", until); err != nil || seen {
		t.Fatalf("other id: seen=%v err=%v", seen, err)
	}
}

func TestReplays_ReplicasOnOneStoreShareThem(t *testing.T) {
	store := kv.NewMemory()
	until := time.Now().Add(time.Minute)
	if seen, err := newKVReplays(store).Seen(t.Context(), "proof", until); err != nil || seen {
		t.Fatalf("first: seen=%v err=%v", seen, err)
	}
	if seen, err := newKVReplays(store).Seen(t.Context(), "proof", until); err != nil || !seen {
		t.Fatalf("at the other replica: seen=%v err=%v", seen, err)
	}
}

func TestReplays_StoreFailureIsAnError(t *testing.T) {
	store := kv.NewMemory()
	_ = store.Close()
	if _, err := newKVReplays(store).Seen(t.Context(), "proof", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("no error from a store that cannot answer")
	}
}

// The request's context reaches the store, so its deadline bounds the call.
func TestReplays_TheStoreCallRunsUnderTheRequestContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	store := &ttlRecorder{Store: kv.NewMemory()}
	_, _ = newKVReplays(store).Seen(ctx, "proof", time.Now().Add(time.Minute))
	if store.ctx != ctx {
		t.Fatal("the store got another context")
	}
}

func TestReplays_KeyIsAHashOfTheID(t *testing.T) {
	store := kv.NewMemory()
	_, _ = newKVReplays(store).Seen(t.Context(), "proof-id", time.Now().Add(time.Minute))
	keys, err := store.Keys(t.Context(), "")
	if err != nil || len(keys) != 1 || !strings.HasPrefix(keys[0], "dpop:replay:") || strings.Contains(keys[0], "proof-id") {
		t.Fatalf("keys %v, err %v", keys, err)
	}
}

// An until already past must still leave a record with an expiry: a zero TTL means none,
// and such a row would never be reaped.
func TestReplays_PastUntilStillExpires(t *testing.T) {
	store := &ttlRecorder{Store: kv.NewMemory()}
	if _, err := newKVReplays(store).Seen(t.Context(), "proof", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if store.ttl <= 0 {
		t.Fatalf("ttl %v", store.ttl)
	}
}

func TestRedemptions_OutliveTheNonceByTheClockSkew(t *testing.T) {
	store := &ttlRecorder{Store: kv.NewMemory()}
	until := time.Now().Add(time.Minute)
	if seen, err := newKVRedemptions(store).Seen(t.Context(), "abc", until); err != nil || seen {
		t.Fatalf("first: seen=%v err=%v", seen, err)
	}
	if store.key != "nonce:abc" {
		t.Fatalf("key %q", store.key)
	}
	if store.ttl <= time.Minute || store.ttl > time.Minute+seenClockSkew {
		t.Fatalf("ttl %v", store.ttl)
	}
	if seen, err := newKVRedemptions(store).Seen(t.Context(), "abc", until); err != nil || !seen {
		t.Fatalf("again: seen=%v err=%v", seen, err)
	}
}

// ttlRecorder records what the last SetIfAbsent was called with.
type ttlRecorder struct {
	kv.Store
	ctx context.Context
	key string
	ttl time.Duration
}

func (s *ttlRecorder) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	s.ctx, s.key, s.ttl = ctx, key, ttl
	return s.Store.SetIfAbsent(ctx, key, value, ttl)
}
