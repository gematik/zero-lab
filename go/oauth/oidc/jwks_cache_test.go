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

package oidc

import (
	"context"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// issuerStub serves a JWKS and counts the requests; failing switches it to 500s.
type issuerStub struct {
	*httptest.Server
	requests atomic.Int32
	failing  atomic.Bool
	mu       sync.Mutex
	body     []byte
}

func newIssuerStub(t *testing.T, kids ...string) *issuerStub {
	t.Helper()
	stub := new(issuerStub)
	stub.publish(t, kids...)
	stub.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		stub.requests.Add(1)
		if stub.failing.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		stub.mu.Lock()
		defer stub.mu.Unlock()
		_, _ = w.Write(stub.body)
	}))
	t.Cleanup(stub.Close)
	return stub
}

func (s *issuerStub) publish(t *testing.T, kids ...string) {
	t.Helper()
	set := jose.JSONWebKeySet{}
	for _, kid := range kids {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: newECKey(t, elliptic.P256()).Public(), KeyID: kid})
	}
	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = body
}

// fakeClock moves only when a test says so.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newCacheOf(stub *issuerStub) (*keySetCache, *fakeClock) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	cache := newKeySetCache(stub.URL, stub.Client())
	cache.now = clock.Now
	return cache, clock
}

func mustKeySet(t *testing.T, cache *keySetCache, kid string) *jose.JSONWebKeySet {
	t.Helper()
	keys, err := cache.keySet(context.Background(), kid)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestKeySetCacheFetchesOnceWithinTTL(t *testing.T) {
	stub := newIssuerStub(t, "a")
	cache, clock := newCacheOf(stub)
	mustKeySet(t, cache, "a")
	clock.Advance(jwksTTL - time.Second)
	mustKeySet(t, cache, "a")
	mustKeySet(t, cache, "")
	if got := stub.requests.Load(); got != 1 {
		t.Errorf("%d requests, want 1", got)
	}
}

func TestKeySetCacheRefreshesWhenTTLIsOver(t *testing.T) {
	stub := newIssuerStub(t, "a")
	cache, clock := newCacheOf(stub)
	mustKeySet(t, cache, "a")
	stub.publish(t, "b")
	clock.Advance(jwksTTL)
	keys := mustKeySet(t, cache, "")
	if stub.requests.Load() != 2 || len(keys.Key("b")) != 1 {
		t.Errorf("requests %d, keys %+v", stub.requests.Load(), keys.Keys)
	}
}

func TestKeySetCachePicksUpARotatedKeyByItsUnknownKid(t *testing.T) {
	stub := newIssuerStub(t, "a")
	cache, clock := newCacheOf(stub)
	mustKeySet(t, cache, "a")
	stub.publish(t, "a", "b")
	clock.Advance(jwksMinFetchInterval)
	if keys := mustKeySet(t, cache, "b"); len(keys.Key("b")) != 1 {
		t.Errorf("rotated key not found: %+v", keys.Keys)
	}
}

func TestKeySetCacheRateLimitsFetchesForUnknownKids(t *testing.T) {
	stub := newIssuerStub(t, "a")
	cache, clock := newCacheOf(stub)
	mustKeySet(t, cache, "a")
	for _, kid := range []string{"random-1", "random-2", "random-3", "random-4"} {
		mustKeySet(t, cache, kid)
	}
	if got := stub.requests.Load(); got != 1 {
		t.Errorf("%d requests within the interval, want 1", got)
	}
	clock.Advance(jwksMinFetchInterval)
	for _, kid := range []string{"random-5", "random-6", "random-7"} {
		mustKeySet(t, cache, kid)
	}
	if got := stub.requests.Load(); got != 2 {
		t.Errorf("%d requests after the interval, want 2", got)
	}
}

func TestKeySetCacheServesLastGoodSetWhileRefreshFails(t *testing.T) {
	stub := newIssuerStub(t, "a")
	cache, clock := newCacheOf(stub)
	mustKeySet(t, cache, "a")
	stub.failing.Store(true)
	clock.Advance(jwksTTL + jwksMaxStale - time.Second)
	if keys := mustKeySet(t, cache, "a"); len(keys.Key("a")) != 1 {
		t.Errorf("keys = %+v", keys.Keys)
	}
}

func TestKeySetCacheFailsClosedWhenLastGoodSetIsTooOld(t *testing.T) {
	stub := newIssuerStub(t, "a")
	cache, clock := newCacheOf(stub)
	mustKeySet(t, cache, "a")
	stub.failing.Store(true)
	clock.Advance(jwksTTL + jwksMaxStale)
	if keys, err := cache.keySet(context.Background(), "a"); err == nil {
		t.Errorf("served %+v past the bound", keys.Keys)
	}
}

func TestKeySetCacheRecoversAfterFailingClosed(t *testing.T) {
	stub := newIssuerStub(t, "a")
	cache, clock := newCacheOf(stub)
	mustKeySet(t, cache, "a")
	stub.failing.Store(true)
	clock.Advance(jwksTTL + jwksMaxStale)
	if _, err := cache.keySet(context.Background(), "a"); err == nil {
		t.Fatal("expected a refusal")
	}
	stub.failing.Store(false)
	clock.Advance(jwksMinFetchInterval)
	mustKeySet(t, cache, "a")
}

func TestKeySetCacheRateLimitsFailingRefreshes(t *testing.T) {
	stub := newIssuerStub(t, "a")
	cache, clock := newCacheOf(stub)
	mustKeySet(t, cache, "a")
	stub.failing.Store(true)
	clock.Advance(jwksTTL)
	for range 5 {
		mustKeySet(t, cache, "a")
	}
	if got := stub.requests.Load(); got != 2 {
		t.Errorf("%d requests, want 2", got)
	}
}

func TestKeySetCacheWithoutAnyGoodSetFails(t *testing.T) {
	stub := newIssuerStub(t, "a")
	stub.failing.Store(true)
	cache, _ := newCacheOf(stub)
	if _, err := cache.keySet(context.Background(), ""); err == nil {
		t.Error("expected an error")
	}
}

func TestKeySetCacheRefusesOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[],"padding":"` + strings.Repeat("x", jwksMaxSize) + `"}`))
	}))
	defer server.Close()
	cache := newKeySetCache(server.URL, server.Client())
	_, err := cache.keySet(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("err = %v", err)
	}
}

func TestKeySetCacheKeepsLastGoodSetWhenRefreshBringsNoKeys(t *testing.T) {
	stub := newIssuerStub(t, "a")
	cache, clock := newCacheOf(stub)
	mustKeySet(t, cache, "a")
	stub.publish(t)
	clock.Advance(jwksTTL)
	if keys := mustKeySet(t, cache, "a"); len(keys.Key("a")) != 1 {
		t.Errorf("an empty answer replaced the keys: %+v", keys.Keys)
	}
}

func TestKeySetCacheUsesTheCallersHTTPClient(t *testing.T) {
	stub := newIssuerStub(t, "a")
	var used atomic.Bool
	client := *stub.Client()
	client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		used.Store(true)
		return stub.Client().Transport.RoundTrip(req)
	})
	if _, err := newKeySetCache(stub.URL, &client).keySet(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if !used.Load() {
		t.Error("the caller's client was not used")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestKeySetCacheFetchRunsUnderTheCallersContext(t *testing.T) {
	type contextKey struct{}
	stub := newIssuerStub(t, "a")
	var seen atomic.Bool
	client := *stub.Client()
	client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen.Store(req.Context().Value(contextKey{}) == "caller")
		return stub.Client().Transport.RoundTrip(req)
	})
	ctx := context.WithValue(context.Background(), contextKey{}, "caller")
	if _, err := newKeySetCache(stub.URL, &client).keySet(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if !seen.Load() {
		t.Error("the request did not carry the caller's context")
	}
}

func TestKeySetCacheCallerCancelledDuringFetchDoesNotUseUpTheNextFetch(t *testing.T) {
	stub := newIssuerStub(t, "a")
	cache, _ := newCacheOf(stub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelling := *stub.Client()
	cancelling.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		cancel()
		return nil, context.Canceled
	})
	cache.httpClient = &cancelling
	if _, err := cache.keySet(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	cache.httpClient = stub.Client()
	if keys := mustKeySet(t, cache, ""); len(keys.Key("a")) != 1 {
		t.Errorf("keys = %+v", keys.Keys)
	}
}

func TestKeySetCacheWaitingCallerHonoursItsContext(t *testing.T) {
	stub := newIssuerStub(t, "a")
	cache, _ := newCacheOf(stub)
	cache.fetching <- struct{}{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := cache.keySet(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func TestKeySetCacheConcurrentCallersShareOneFetch(t *testing.T) {
	stub := newIssuerStub(t, "a")
	cache, _ := newCacheOf(stub)
	var group sync.WaitGroup
	for range 32 {
		group.Go(func() {
			if _, err := cache.keySet(context.Background(), "a"); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	if got := stub.requests.Load(); got != 1 {
		t.Errorf("%d requests, want 1", got)
	}
}
