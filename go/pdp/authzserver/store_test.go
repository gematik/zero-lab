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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/dpop"
	"github.com/gematik/zero-lab/go/kv"
	"github.com/gematik/zero-lab/go/nonce"
)

// The interfaces are met by shape, so that the modules need not import each other; this is where that holds.
var (
	_ dpop.ReplayCache = (*kv.ReplayCache)(nil)
	_ dpop.NonceSource = (*nonce.Source)(nil)
	_ nonce.Keys       = (*kv.Keyring)(nil)
	_ kv.Keys          = nonce.Keys(nil)
)

func testKeyring(t *testing.T) *kv.Keyring {
	t.Helper()
	ring, err := kv.ParseKeyring([]byte("k1 " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

// replicas builds two servers that share a store and keys, as replicas behind one endpoint do.
func replicas(t *testing.T, store kv.Store) (a, b *Server, signKey *jose.JSONWebKey) {
	t.Helper()
	prk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signKey = &jose.JSONWebKey{Key: prk, KeyID: "test-client-key"}
	pubKey := signKey.Public()
	signer := newP256(t)
	ring := testKeyring(t)
	build := func() *Server {
		server, err := New(Config{
			Issuer:     testIssuer,
			SigningKey: &SigningKey{Signer: signer, KeyID: "test-server-key"},
			Products: []Product{{
				ProductID:    testProductID,
				RedirectURIs: []string{"https://rp.example.com/callback"},
				Scopes:       []string{testScope},
			}},
			Clients:   []Client{{ClientID: testClientID, ProductID: testProductID, PublicJWK: jwkToMap(t, &pubKey)}},
			Store:     store,
			NonceKeys: ring,
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	return build(), build(), signKey
}

func requireStatus(t *testing.T, err error, status int, code string) {
	t.Helper()
	var authzErr *Error
	if !errors.As(err, &authzErr) || authzErr.HTTPStatus != status || authzErr.Code != code {
		t.Fatalf("got %v, want %d %s", err, status, code)
	}
}

func TestNew_RefusesAStoreWithoutNonceKeys(t *testing.T) {
	_, err := New(Config{Issuer: testIssuer, SigningKey: &SigningKey{Signer: newP256(t), KeyID: "k"}, Store: kv.NewMemory()})
	if err == nil {
		t.Fatal("started with a store and a per-process nonce key")
	}
}

// A nonce issued at one replica is good at another, and single use holds across them.
func TestPrivateKeyJWTNonce_IsAcceptedOnceAcrossReplicas(t *testing.T) {
	a, b, signKey := replicas(t, kv.NewSealed(kv.NewMemory(), testKeyring(t), "test"))
	assertion := signClientAssertion(t, a, signKey, nil)
	if err := b.TokenEndpoint(httptest.NewRecorder(), clientCredentialsRequest(t, assertion)); err != nil {
		t.Fatalf("redeeming at the other replica: %v", err)
	}
	assertInvalidClient(t, a.TokenEndpoint(httptest.NewRecorder(), clientCredentialsRequest(t, assertion)))
}

// RFC 9449 Section 11.1: a proof accepted at one replica is refused at another.
func TestRFC9449_11_1_ProofReplayedAtAnotherReplicaIsRefused(t *testing.T) {
	a, b, signKey := replicas(t, kv.NewMemory())
	proofed := clientCredentialsRequest(t, signClientAssertion(t, a, signKey, nil))
	if err := a.TokenEndpoint(httptest.NewRecorder(), proofed); err != nil {
		t.Fatalf("first use: %v", err)
	}
	replay := clientCredentialsRequestWithProof(t, signClientAssertion(t, a, signKey, nil), nil)
	replay.Header.Set(dpop.HeaderName, proofed.Header.Get(dpop.HeaderName))
	err := b.TokenEndpoint(httptest.NewRecorder(), replay)
	requireStatus(t, err, http.StatusBadRequest, "invalid_dpop_proof")
	if !strings.Contains(err.Error(), "used before") {
		t.Fatalf("refused for another reason: %v", err)
	}
}

// failingOn fails the writes to keys with the given prefix, as a store outage would.
type failingOn struct {
	kv.Store
	prefix string
}

func (s *failingOn) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if strings.HasPrefix(key, s.prefix) {
		return false, errors.New("kv/postgres: store down, secret detail")
	}
	return s.Store.SetIfAbsent(ctx, key, value, ttl)
}

func TestNonceRedeem_AStoreOutageFailsClosedAndLeaksNothing(t *testing.T) {
	a, _, signKey := replicas(t, &failingOn{Store: kv.NewMemory(), prefix: "nonce:"})
	err := a.TokenEndpoint(httptest.NewRecorder(), clientCredentialsRequest(t, signClientAssertion(t, a, signKey, nil)))
	requireStatus(t, err, http.StatusInternalServerError, "server_error")
	if strings.Contains(err.Error(), "secret detail") {
		t.Fatalf("the response carries the store's error: %v", err)
	}
}

func TestDPoPReplayCache_AStoreOutageRefusesTheProof(t *testing.T) {
	a, _, signKey := replicas(t, &failingOn{Store: kv.NewMemory(), prefix: "dpop:replay:"})
	resp := httptest.NewRecorder()
	err := a.TokenEndpoint(resp, clientCredentialsRequest(t, signClientAssertion(t, a, signKey, nil)))
	requireStatus(t, err, http.StatusInternalServerError, "server_error")
	if resp.Code == http.StatusOK && resp.Body.Len() > 0 {
		t.Fatal("tokens were issued")
	}
}

// writeCounter counts every call that could write to the store.
type writeCounter struct {
	kv.Store
	writes atomic.Int64
}

func (s *writeCounter) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	s.writes.Add(1)
	return s.Store.Set(ctx, key, value, ttl)
}

func (s *writeCounter) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	s.writes.Add(1)
	return s.Store.SetIfAbsent(ctx, key, value, ttl)
}

func (s *writeCounter) SetMany(ctx context.Context, entries ...kv.Entry) error {
	s.writes.Add(1)
	return s.Store.SetMany(ctx, entries...)
}

func TestNonceEndpoint_AnAnonymousGetCausesNoWrite(t *testing.T) {
	store := &writeCounter{Store: kv.NewMemory()}
	a, _, _ := replicas(t, store)
	resp := httptest.NewRecorder()
	if err := a.NonceEndpoint(resp, httptest.NewRequest(http.MethodGet, testIssuer+"/nonce", nil)); err != nil {
		t.Fatal(err)
	}
	if resp.Code != http.StatusOK || resp.Body.Len() == 0 {
		t.Fatalf("status %d, %q", resp.Code, resp.Body)
	}
	if n := store.writes.Load(); n != 0 {
		t.Fatalf("%d writes", n)
	}
}

func TestNonceRecord_OutlivesTheNonceByTheClockSkew(t *testing.T) {
	ctx := context.Background()
	store := &ttlRecorder{Store: kv.NewMemory()}
	until := time.Now().Add(time.Minute)
	if first, err := recordNonce(store)(ctx, "abc", until); err != nil || !first {
		t.Fatalf("first=%v err=%v", first, err)
	}
	if store.key != "nonce:abc" {
		t.Fatalf("key %q", store.key)
	}
	if store.ttl <= time.Minute || store.ttl > time.Minute+nonceClockSkew {
		t.Fatalf("ttl %v", store.ttl)
	}
	if first, err := recordNonce(store)(ctx, "abc", until); err != nil || first {
		t.Fatalf("again: first=%v err=%v", first, err)
	}
}

type ttlRecorder struct {
	kv.Store
	key string
	ttl time.Duration
}

func (s *ttlRecorder) SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	s.key, s.ttl = key, ttl
	return s.Store.SetIfAbsent(ctx, key, value, ttl)
}

// RFC 9449 Section 8 stays possible on the same keys: a proof must carry a nonce from the source, and one
// issued at another replica counts. nonce_required itself is TASK-131.
func TestRFC9449_8_ASourceOnTheKeyringServesAVerifier(t *testing.T) {
	ring := testKeyring(t)
	source, err := nonce.NewSource(ring, "pep/dpop-nonce", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := dpop.NewVerifier(dpop.Config{Nonces: source})
	if err != nil {
		t.Fatal(err)
	}
	key, err := dpop.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	req := dpop.Request{Method: http.MethodPost, URI: testIssuer + "/token"}
	withNonce := func(value string) http.Header {
		proof, err := key.Proof(req.Method, req.URI, dpop.ProofOptions{Nonce: value})
		if err != nil {
			t.Fatal(err)
		}
		header := http.Header{}
		header.Set(dpop.HeaderName, proof)
		return header
	}
	if _, err := verifier.Verify(withNonce(""), req); err == nil {
		t.Fatal("accepted a proof without a nonce")
	}
	fresh, err := source.Fresh()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(withNonce(fresh), req); err != nil {
		t.Fatalf("refused the source's nonce: %v", err)
	}
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

// After the upgrade an old record does not open, and it may also mean tampering: the client sees a session that
// does not exist, not a server error, and the log has it at error level.
func TestSessionLookup_ARecordThatDoesNotOpenIsAnInvalidSessionAndLogged(t *testing.T) {
	raw := kv.NewMemory()
	sealed := kv.NewSealed(raw, testKeyring(t), "test")
	sessions := newKVSessionStore(sealed, time.Hour)
	ctx := context.Background()
	if err := sessions.SaveAutzhServerSession(&Session{
		ID: "s1", Code: "c1", RequestURI: "r1", RefreshToken: "t1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := raw.Set(ctx, asSessionKey("s1"), []byte(`{"id":"s1"}`), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := raw.Set(ctx, asRefreshKey("t2"), []byte(`"s1"`), time.Hour); err != nil {
		t.Fatal(err)
	}

	lookups := map[string]func() (*Session, error){
		"record by id":          func() (*Session, error) { return sessions.GetAuthzServerSessionByID("s1") },
		"record behind a code":  func() (*Session, error) { return sessions.GetAuthzServerSessionByCode("c1") },
		"record behind a uri":   func() (*Session, error) { return sessions.GetAutzhServerSessionByRequestURI("r1") },
		"index in the clear":    func() (*Session, error) { return sessions.GetAuthzServerSessionByRefreshToken("t2") },
		"index behind a secret": func() (*Session, error) { return sessions.GetAuthzServerSessionByRefreshToken("t1") },
	}
	for name, lookup := range lookups {
		logs := captureLogs(t)
		if _, err := lookup(); !errors.Is(err, errSessionNotFound) {
			t.Errorf("%s: got %v", name, err)
		}
		if !strings.Contains(logs.String(), "level=ERROR") {
			t.Errorf("%s: not logged at error level: %q", name, logs)
		}
	}
}

func TestSessionRecords_ReachASealedStoreAsCiphertext(t *testing.T) {
	raw := kv.NewMemory()
	sessions := newKVSessionStore(kv.NewSealed(raw, testKeyring(t), "test"), time.Hour)
	if err := sessions.SaveAutzhServerSession(&Session{ID: "s1", RefreshToken: "refresh-secret", Code: "code-secret"}); err != nil {
		t.Fatal(err)
	}
	stored, found, err := raw.Get(context.Background(), asSessionKey("s1"))
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if bytes.Contains(stored, []byte("refresh-secret")) || bytes.Contains(stored, []byte("code-secret")) {
		t.Fatal("the store holds the session in the clear")
	}
	got, err := sessions.GetAuthzServerSessionByID("s1")
	if err != nil || got.RefreshToken != "refresh-secret" {
		t.Fatalf("%+v %v", got, err)
	}
}
