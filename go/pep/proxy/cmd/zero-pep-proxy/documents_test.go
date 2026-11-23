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
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/kv"
)

func TestDocuments_GetAfterKeepReturnsTheBytes(t *testing.T) {
	docs := newKVDocuments(kv.NewMemory())
	if _, found, err := docs.Get(t.Context(), "https://fed.example/a"); err != nil || found {
		t.Fatalf("before: found=%v err=%v", found, err)
	}
	if err := docs.Keep(t.Context(), "https://fed.example/a", []byte("jws"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, found, err := docs.Get(t.Context(), "https://fed.example/a")
	if err != nil || !found || !bytes.Equal(got, []byte("jws")) {
		t.Fatalf("got %q found=%v err=%v", got, found, err)
	}
	if _, found, _ := docs.Get(t.Context(), "https://fed.example/b"); found {
		t.Fatal("a document of another URL")
	}
}

func TestDocuments_KeyIsAHashOfTheURL(t *testing.T) {
	store := kv.NewMemory()
	url := "https://fed.example/.well-known/openid-federation"
	if err := newKVDocuments(store).Keep(t.Context(), url, []byte("jws"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	keys, err := store.Keys(t.Context(), "")
	if err != nil || len(keys) != 1 || !strings.HasPrefix(keys[0], "oidf:doc:") || strings.Contains(keys[0], "fed.example") {
		t.Fatalf("keys %v, err %v", keys, err)
	}
}

func TestDocuments_ExpiredDocumentIsNotStored(t *testing.T) {
	store := kv.NewMemory()
	if err := newKVDocuments(store).Keep(t.Context(), "https://fed.example/a", []byte("jws"), time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if keys, err := store.Keys(t.Context(), ""); err != nil || len(keys) != 0 {
		t.Fatalf("keys %v, err %v", keys, err)
	}
}

func TestDocuments_StoreFailureIsAnError(t *testing.T) {
	store := kv.NewMemory()
	_ = store.Close()
	docs := newKVDocuments(store)
	if _, _, err := docs.Get(t.Context(), "https://fed.example/a"); err == nil {
		t.Fatal("Get: no error from a store that cannot answer")
	}
	if err := docs.Keep(t.Context(), "https://fed.example/a", []byte("jws"), time.Now().Add(time.Hour)); err == nil {
		t.Fatal("Keep: no error from a store that cannot answer")
	}
}

// ctxRecorder records the context of the last Get and Set.
type ctxRecorder struct {
	kv.Store
	getCtx, setCtx context.Context
}

func (s *ctxRecorder) Get(ctx context.Context, key string) ([]byte, bool, error) {
	s.getCtx = ctx
	return s.Store.Get(ctx, key)
}

func (s *ctxRecorder) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	s.setCtx = ctx
	return s.Store.Set(ctx, key, value, ttl)
}

// The store calls run under the caller's context, so a caller that ends ends them, and under a deadline of
// their own, as that context may have none.
func TestDocuments_TheStoreCallFollowsTheCallerAndIsBounded(t *testing.T) {
	ended, cancel := context.WithCancel(t.Context())
	cancel()
	store := &ctxRecorder{Store: kv.NewMemory()}
	docs := newKVDocuments(store)
	_, _, _ = docs.Get(ended, "https://fed.example/a")
	_ = docs.Keep(ended, "https://fed.example/a", []byte("jws"), time.Now().Add(time.Hour))
	if store.getCtx == nil || store.getCtx.Err() == nil || store.setCtx == nil || store.setCtx.Err() == nil {
		t.Fatal("a store call outlives the caller")
	}

	store = &ctxRecorder{Store: kv.NewMemory()}
	docs = newKVDocuments(store)
	_, _, _ = docs.Get(t.Context(), "https://fed.example/a")
	_ = docs.Keep(t.Context(), "https://fed.example/a", []byte("jws"), time.Now().Add(time.Hour))
	for name, ctx := range map[string]context.Context{"Get": store.getCtx, "Keep": store.setCtx} {
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > documentsTimeout {
			t.Fatalf("%s is not bounded: deadline=%v ok=%v", name, deadline, ok)
		}
	}
}
