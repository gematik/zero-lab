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

package oidf

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// fakeDocuments is a store a test can read, alter and break.
type fakeDocuments struct {
	mu      sync.Mutex
	kept    map[string][]byte
	until   map[string]time.Time
	failing bool
}

func newFakeDocuments() *fakeDocuments {
	return &fakeDocuments{kept: make(map[string][]byte), until: make(map[string]time.Time)}
}

var errStoreDown = errors.New("store down")

func (d *fakeDocuments) Get(_ context.Context, url string) ([]byte, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failing {
		return nil, false, errStoreDown
	}
	signed, ok := d.kept[url]
	return signed, ok, nil
}

func (d *fakeDocuments) Keep(_ context.Context, url string, signed []byte, until time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.failing {
		return errStoreDown
	}
	d.kept[url], d.until[url] = signed, until
	return nil
}

func (d *fakeDocuments) entry(url string) ([]byte, time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.kept[url], d.until[url]
}

func (d *fakeDocuments) set(url string, signed []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.kept[url] = signed
}

// fetchCounter counts the requests that reach the stub, by path.
type fetchCounter struct {
	mu     sync.Mutex
	counts map[string]int
}

func (c *fetchCounter) count(path string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[path]
}

func (s *federationStub) countFetches() *fetchCounter {
	counter := &fetchCounter{counts: make(map[string]int)}
	handler := s.Config.Handler
	s.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		counter.mu.Lock()
		counter.counts[r.URL.Path]++
		counter.mu.Unlock()
		handler.ServeHTTP(w, r)
	})
	return counter
}

func (s *federationStub) federationWith(t *testing.T, opts ...Option) *OpenidFederation {
	t.Helper()
	opts = append([]Option{WithHTTPClient(s.Client())}, opts...)
	federation, err := NewOpenidFederation(t.Context(), s.URL, keySetOf(s.masterKey, "master"), opts...)
	if err != nil {
		t.Fatal(err)
	}
	return federation
}

func TestServerRule12_AStoredDocumentIsVerifiedAgainOnRead(t *testing.T) {
	stub := newFederationStub(t)
	documents := newFakeDocuments()
	federation := stub.federationWith(t, WithDocuments(documents))
	fetches := stub.countFetches()
	opURL := stub.URL + "/op/.well-known/openid-federation"

	if _, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op"); err != nil {
		t.Fatal(err)
	}
	genuine, _ := documents.entry(opURL)
	if string(genuine) != stub.opStatement {
		t.Fatalf("kept %q", genuine)
	}
	if _, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op"); err != nil {
		t.Fatal(err)
	}
	if n := fetches.count("/op/.well-known/openid-federation"); n != 1 {
		t.Fatalf("a kept statement was fetched %d times", n)
	}

	forged := signJWS(t, newTestKey(t), "op", stub.opClaims(map[string]any{"authorization_endpoint": "https://attacker.example/auth"}))
	documents.set(opURL, []byte(forged))
	op, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op")
	if err != nil {
		t.Fatal(err)
	}
	if op.Metadata.OpenidProvider.AuthorizationEndpoint != stub.URL+"/op/auth" {
		t.Errorf("took the forged entry: %s", op.Metadata.OpenidProvider.AuthorizationEndpoint)
	}
	if n := fetches.count("/op/.well-known/openid-federation"); n != 2 {
		t.Errorf("the forged entry was not replaced by a fetch: %d fetches", n)
	}
	if kept, _ := documents.entry(opURL); string(kept) != stub.opStatement {
		t.Errorf("the forged entry stays: %q", kept)
	}
}

func TestServerRule12_AnExpiredEntryIsFetchedAgain(t *testing.T) {
	stub := newFederationStub(t)
	now := time.Now()
	clock := now
	documents := newFakeDocuments()
	shortLived := stub.opClaims(nil)
	shortLived["exp"] = now.Add(2 * statementClockTolerance).Unix()
	stub.opStatement = signJWS(t, stub.opKey, "op", shortLived)
	federation := stub.federationWith(t, WithDocuments(documents), WithClock(func() time.Time { return clock }))
	fetches := stub.countFetches()
	opURL := stub.URL + "/op/.well-known/openid-federation"

	if _, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op"); err != nil {
		t.Fatal(err)
	}
	if _, until := documents.entry(opURL); until.Unix() != shortLived["exp"] {
		t.Errorf("kept until %v, not the statement's exp", until)
	}

	clock = now.Add(2 * statementClockTolerance)
	stub.opStatement = signJWS(t, stub.opKey, "op", stub.opClaims(nil))
	if _, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op"); err != nil {
		t.Fatal(err)
	}
	if n := fetches.count("/op/.well-known/openid-federation"); n != 2 {
		t.Errorf("%d fetches; the expired entry was taken", n)
	}
	if kept, _ := documents.entry(opURL); string(kept) != stub.opStatement {
		t.Error("the expired entry was not replaced")
	}
}

// The master's own statement names the endpoints; it is resolved again once it expires instead of being read once.
func TestServerRule12_TheMastersStatementIsResolvedAgainWhenItExpires(t *testing.T) {
	stub := newFederationStub(t)
	now := time.Now()
	clock := now
	master := map[string]any{
		"iss": stub.URL, "sub": stub.URL, "exp": now.Add(2 * statementClockTolerance).Unix(),
		"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": stub.URL + "/fetch", "idp_list_endpoint": stub.URL + "/idps"}},
	}
	stub.masterStatement = signJWS(t, stub.masterKey, "master", master)
	federation := stub.federationWith(t, WithDocuments(newFakeDocuments()), WithClock(func() time.Time { return clock }))
	fetches := stub.countFetches()

	clock = now.Add(2 * statementClockTolerance)
	if _, err := federation.FetchIdpList(t.Context()); err == nil {
		t.Fatal("went on with an expired master statement")
	}
	master["exp"] = now.Add(time.Hour).Unix()
	stub.masterStatement = signJWS(t, stub.masterKey, "master", master)
	if _, err := federation.FetchIdpList(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := fetches.count("/.well-known/openid-federation"); n != 2 {
		t.Errorf("the master's statement was fetched %d times", n)
	}
}

func TestServerRule12_AStoreThatFailsCostsAFetchNotALogin(t *testing.T) {
	stub := newFederationStub(t)
	documents := newFakeDocuments()
	documents.failing = true
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	federation := stub.federationWith(t, WithDocuments(documents), WithLogger(logger))
	fetches := stub.countFetches()

	for range 2 {
		op, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := federation.FetchSignedJwks(t.Context(), op); err != nil {
			t.Fatal(err)
		}
	}
	if n := fetches.count("/op/jwks"); n != 2 {
		t.Errorf("%d fetches of the signed JWKS", n)
	}
	if !strings.Contains(logs.String(), errStoreDown.Error()) {
		t.Errorf("the failing store was not reported:\n%s", logs.String())
	}

	silent := stub.federationWith(t, WithDocuments(documents))
	if _, err := silent.FetchIdpList(t.Context()); err != nil {
		t.Errorf("without a logger: %v", err)
	}
}

func TestServerRule17_AFederationWithoutADocumentStoreIsRefused(t *testing.T) {
	stub := newFederationStub(t)
	fetches := stub.countFetches()
	if _, err := NewOpenidFederation(t.Context(), stub.URL, keySetOf(stub.masterKey, "master"), WithHTTPClient(stub.Client())); err == nil || !strings.Contains(err.Error(), "store") {
		t.Errorf("err = %v", err)
	}
	cfg := testRelyingPartyConfig(t, stub)
	cfg.Documents = nil
	if _, err := NewRelyingParty(t.Context(), cfg, ""); err == nil || !strings.Contains(err.Error(), "store") {
		t.Errorf("err = %v", err)
	}
	if n := fetches.count("/.well-known/openid-federation"); n != 0 {
		t.Errorf("%d fetches before the refusal", n)
	}
}

// gatedTransport serves the stub's handler in memory, so that a test in a synctest bubble controls when a fetch
// answers: each request waits for gate, or for its context.
type gatedTransport struct {
	handler http.Handler
	gate    chan struct{}
	mu      sync.Mutex
	counts  map[string]int
}

func (g *gatedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	g.mu.Lock()
	g.counts[r.URL.Path]++
	g.mu.Unlock()
	select {
	case <-g.gate:
	case <-r.Context().Done():
		return nil, r.Context().Err()
	}
	recorder := httptest.NewRecorder()
	g.handler.ServeHTTP(recorder, r)
	return recorder.Result(), nil
}

func (g *gatedTransport) count(path string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.counts[path]
}

// inBubble builds a federation of stub whose fetches go through a gatedTransport made inside the current bubble. The
// master's statement is resolved before the gate closes. The stub signed at the real time, so the federation judges
// at it too.
func inBubble(t *testing.T, stub *federationStub, realNow time.Time) (*OpenidFederation, *gatedTransport) {
	t.Helper()
	transport := &gatedTransport{handler: stub.Config.Handler, gate: make(chan struct{}), counts: make(map[string]int)}
	close(transport.gate)
	start := time.Now()
	federation, err := NewOpenidFederation(t.Context(), stub.URL, keySetOf(stub.masterKey, "master"),
		WithHTTPClient(&http.Client{Transport: transport}), WithDocuments(NewMemoryDocuments(16, nil)),
		WithClock(func() time.Time { return realNow.Add(time.Since(start)) }))
	if err != nil {
		t.Fatal(err)
	}
	transport.gate = make(chan struct{})
	return federation, transport
}

func TestServerRule12_ConcurrentLoginsFetchOnce(t *testing.T) {
	stub := newFederationStub(t)
	realNow := time.Now()
	synctest.Test(t, func(t *testing.T) {
		federation, transport := inBubble(t, stub, realNow)
		const logins = 20
		errs := make(chan error, logins)
		for range logins {
			go func() {
				op, err := federation.FetchEntityStatement(t.Context(), stub.URL+"/op")
				if err == nil {
					_, err = federation.FetchSignedJwks(t.Context(), op)
				}
				errs <- err
			}()
		}
		synctest.Wait()
		if n := transport.count("/fetch"); n != 1 {
			t.Errorf("%d logins asked the master at once", n)
		}
		close(transport.gate)
		for range logins {
			if err := <-errs; err != nil {
				t.Error(err)
			}
		}
		for _, path := range []string{"/fetch", "/op/.well-known/openid-federation", "/op/jwks"} {
			if n := transport.count(path); n != 1 {
				t.Errorf("%s fetched %d times", path, n)
			}
		}
	})
}

func TestServerRule24_AFetchEndsWithItsContext(t *testing.T) {
	stub := newFederationStub(t)
	realNow := time.Now()
	synctest.Test(t, func(t *testing.T) {
		federation, transport := inBubble(t, stub, realNow)

		leading, cancelLeading := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancelLeading()
		leader := make(chan error, 1)
		go func() {
			_, err := federation.FetchIdpList(leading)
			leader <- err
		}()
		synctest.Wait()

		waiting, cancelWaiting := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancelWaiting()
		if _, err := federation.FetchIdpList(waiting); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("a waiting fetch: %v", err)
		}
		if err := <-leader; !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("the fetch under way: %v", err)
		}
		if n := transport.count("/idps"); n != 1 {
			t.Errorf("%d fetches of the list", n)
		}
	})
}

// Servers rule 12: a fetch is shared, a judgement is not. A caller whose keys refuse the document does not make
// another caller, whose keys take it, fail.
func TestServerRule12_EachCallerJudgesASharedFetchWithItsOwnKeys(t *testing.T) {
	stub := newFederationStub(t)
	realNow := time.Now()
	synctest.Test(t, func(t *testing.T) {
		federation, transport := inBubble(t, stub, realNow)
		location := stub.URL + "/op/.well-known/openid-federation"
		read := func(keys *jose.JSONWebKeySet) error {
			_, err := document(t.Context(), federation, location, false, keys, memberKeys, parseEntityStatement)
			return err
		}
		wrong := make(chan error, 1)
		go func() { wrong <- read(keySetOf(newTestKey(t), "op")) }()
		synctest.Wait()
		right := make(chan error, 1)
		go func() { right <- read(keySetOf(stub.opKey, "op")) }()
		synctest.Wait()
		close(transport.gate)
		if err := <-wrong; err == nil {
			t.Error("the caller with the wrong keys took the document")
		}
		if err := <-right; err != nil {
			t.Errorf("the caller with the right keys: %v", err)
		}
		if n := transport.count("/op/.well-known/openid-federation"); n != 1 {
			t.Errorf("%d fetches", n)
		}
	})
}

// Servers rule 24: a fetch under way that ends with its leader's context is fetched again for a caller whose context
// is still live, instead of failing it for another's.
func TestServerRule24_AWaiterOutlivesTheLeadersContext(t *testing.T) {
	stub := newFederationStub(t)
	realNow := time.Now()
	synctest.Test(t, func(t *testing.T) {
		federation, transport := inBubble(t, stub, realNow)
		leading, cancel := context.WithCancel(t.Context())
		leader := make(chan error, 1)
		go func() {
			_, err := federation.FetchIdpList(leading)
			leader <- err
		}()
		synctest.Wait()
		waiter := make(chan error, 1)
		go func() {
			_, err := federation.FetchIdpList(t.Context())
			waiter <- err
		}()
		synctest.Wait()

		cancel()
		if err := <-leader; !errors.Is(err, context.Canceled) {
			t.Errorf("the leader: %v", err)
		}
		synctest.Wait()
		close(transport.gate)
		if err := <-waiter; err != nil {
			t.Errorf("the waiter: %v", err)
		}
		if n := transport.count("/idps"); n != 2 {
			t.Errorf("%d fetches of the list", n)
		}
	})
}

// Internal invariant of MemoryDocuments: it holds no more than its capacity, makes room by dropping the document that
// expires first, and does not return an expired one.
func TestMemoryDocumentsIsBoundedAndForgetsExpiredDocuments(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	documents := NewMemoryDocuments(2, func() time.Time { return now })
	ctx := t.Context()
	keep := func(url string, until time.Duration) {
		if err := documents.Keep(ctx, url, []byte(url), now.Add(until)); err != nil {
			t.Fatal(err)
		}
	}
	found := func(url string) bool {
		_, ok, err := documents.Get(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	keep("a", time.Hour)
	keep("b", time.Minute)
	keep("c", 2*time.Hour)
	if found("b") || !found("a") || !found("c") {
		t.Error("full: the document expiring first should have made room")
	}
	keep("a", 3*time.Hour)
	if !found("a") || !found("c") {
		t.Error("replacing an entry dropped another")
	}
	now = now.Add(2 * time.Hour)
	if found("c") {
		t.Error("returned an expired document")
	}
	keep("d", -time.Second)
	if found("d") {
		t.Error("kept an expired document")
	}
}
